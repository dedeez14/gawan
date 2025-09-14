#!/bin/bash

# Script untuk menjalankan Kafka integration tests
# Usage: ./scripts/run-kafka-tests.sh [options]

set -e

# Default values
ENVIRONMENT="development"
TEST_PATTERN="TestKafkaIntegration"
TIMEOUT=60
WITH_UI=false
WITH_BENCHMARK=false
CLEANUP=false
SKIP_SETUP=false
VERBOSE=false
HELP=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;37m'
NC='\033[0m' # No Color

function show_help() {
    echo -e "${GREEN}Kafka Integration Test Runner${NC}"
    echo ""
    echo -e "${YELLOW}Usage: ./scripts/run-kafka-tests.sh [options]${NC}"
    echo ""
    echo -e "${CYAN}Options:${NC}"
    echo "  -e, --environment <env>     Test environment (development/production/ci) [default: development]"
    echo "  -t, --test-pattern <pattern> Test pattern to run [default: TestKafkaIntegration]"
    echo "  -T, --timeout <seconds>     Test timeout in seconds [default: 60]"
    echo "  -u, --with-ui              Start Kafka UI for monitoring"
    echo "  -b, --with-benchmark       Run benchmark tests"
    echo "  -c, --cleanup              Clean up Docker containers after tests"
    echo "  -s, --skip-setup           Skip Kafka setup (assume already running)"
    echo "  -v, --verbose              Enable verbose output"
    echo "  -h, --help                 Show this help message"
    echo ""
    echo -e "${MAGENTA}Examples:${NC}"
    echo "  ./scripts/run-kafka-tests.sh"
    echo "  ./scripts/run-kafka-tests.sh --environment production --with-ui"
    echo "  ./scripts/run-kafka-tests.sh --test-pattern TestMessageProduction --verbose"
    echo "  ./scripts/run-kafka-tests.sh --with-benchmark --cleanup"
}

function write_status() {
    local message="$1"
    local color="${2:-$WHITE}"
    echo -e "${color}[$(date +'%H:%M:%S')] $message${NC}"
}

function test_docker_available() {
    if ! command -v docker &> /dev/null; then
        return 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        return 1
    fi
    
    return 0
}

function wait_for_kafka() {
    local max_wait_seconds=${1:-120}
    local waited=0
    
    write_status "Waiting for Kafka to be ready..." "$YELLOW"
    
    while [ $waited -lt $max_wait_seconds ]; do
        if docker-compose -f docker-compose.kafka.yml exec -T kafka kafka-broker-api-versions --bootstrap-server localhost:9092 &>/dev/null; then
            write_status "Kafka is ready!" "$GREEN"
            return 0
        fi
        
        sleep 2
        waited=$((waited + 2))
        
        if [ $((waited % 10)) -eq 0 ]; then
            write_status "Still waiting for Kafka... ($waited/$max_wait_seconds seconds)" "$YELLOW"
        fi
    done
    
    write_status "Timeout waiting for Kafka to be ready" "$RED"
    return 1
}

function start_kafka_cluster() {
    write_status "Starting Kafka cluster..." "$CYAN"
    
    local compose_args=("up" "-d" "kafka" "zookeeper")
    
    if [ "$WITH_UI" = true ]; then
        write_status "Including Kafka UI..." "$CYAN"
        compose_args+=("--profile" "ui")
    fi
    
    if docker-compose -f docker-compose.kafka.yml "${compose_args[@]}"; then
        if wait_for_kafka; then
            write_status "Kafka cluster started successfully" "$GREEN"
            
            if [ "$WITH_UI" = true ]; then
                write_status "Kafka UI available at: http://localhost:8080" "$GREEN"
            fi
            
            return 0
        else
            write_status "Kafka cluster failed to become ready" "$RED"
            return 1
        fi
    else
        write_status "Failed to start Kafka cluster" "$RED"
        return 1
    fi
}

function stop_kafka_cluster() {
    write_status "Stopping Kafka cluster..." "$YELLOW"
    
    if docker-compose -f docker-compose.kafka.yml down -v; then
        write_status "Kafka cluster stopped" "$GREEN"
    else
        write_status "Error stopping Kafka cluster" "$RED"
    fi
}

function run_tests() {
    write_status "Running Kafka integration tests..." "$CYAN"
    write_status "Environment: $ENVIRONMENT" "$WHITE"
    write_status "Test Pattern: $TEST_PATTERN" "$WHITE"
    write_status "Timeout: $TIMEOUT seconds" "$WHITE"
    
    # Set environment variables
    export KAFKA_BROKERS="localhost:9092"
    export TEST_ENV="$ENVIRONMENT"
    export KAFKA_TEST_TIMEOUT="${TIMEOUT}s"
    
    # Build test command
    local test_args=("test" "-v" "./test" "-run" "$TEST_PATTERN" "-timeout" "${TIMEOUT}s")
    
    if [ "$VERBOSE" = true ]; then
        test_args+=("-args" "-test.v")
    fi
    
    write_status "Executing: go ${test_args[*]}" "$GRAY"
    
    if go "${test_args[@]}"; then
        write_status "Tests completed successfully!" "$GREEN"
        return 0
    else
        write_status "Tests failed with exit code: $?" "$RED"
        return 1
    fi
}

function run_benchmarks() {
    write_status "Running Kafka benchmarks..." "$CYAN"
    
    export KAFKA_BROKERS="localhost:9092"
    export TEST_ENV="$ENVIRONMENT"
    
    local bench_args=("test" "-v" "./test" "-bench=BenchmarkKafka" "-benchmem" "-timeout" "${TIMEOUT}s")
    
    write_status "Executing: go ${bench_args[*]}" "$GRAY"
    
    if go "${bench_args[@]}"; then
        write_status "Benchmarks completed successfully!" "$GREEN"
        return 0
    else
        write_status "Benchmarks failed with exit code: $?" "$RED"
        return 1
    fi
}

function show_kafka_status() {
    write_status "Kafka Cluster Status:" "$CYAN"
    
    docker-compose -f docker-compose.kafka.yml ps
    
    echo ""
    write_status "Available endpoints:" "$CYAN"
    echo -e "  - Kafka Broker: ${WHITE}localhost:9092${NC}"
    echo -e "  - Zookeeper: ${WHITE}localhost:2181${NC}"
    
    if [ "$WITH_UI" = true ]; then
        echo -e "  - Kafka UI: ${WHITE}http://localhost:8080${NC}"
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -t|--test-pattern)
            TEST_PATTERN="$2"
            shift 2
            ;;
        -T|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -u|--with-ui)
            WITH_UI=true
            shift
            ;;
        -b|--with-benchmark)
            WITH_BENCHMARK=true
            shift
            ;;
        -c|--cleanup)
            CLEANUP=true
            shift
            ;;
        -s|--skip-setup)
            SKIP_SETUP=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            HELP=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Show help if requested
if [ "$HELP" = true ]; then
    show_help
    exit 0
fi

echo -e "${GREEN}=== Kafka Integration Test Runner ===${NC}"
echo ""

# Check prerequisites
if ! test_docker_available; then
    write_status "Docker or docker-compose not found. Please install Docker." "$RED"
    exit 1
fi

# Change to project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

write_status "Project root: $PROJECT_ROOT" "$GRAY"

# Trap to ensure cleanup on exit
trap 'if [ "$CLEANUP" = true ] && [ "$SKIP_SETUP" = false ]; then stop_kafka_cluster; fi' EXIT

# Setup Kafka cluster
if [ "$SKIP_SETUP" = false ]; then
    if ! start_kafka_cluster; then
        exit 1
    fi
    
    # Show status
    show_kafka_status
    echo ""
else
    write_status "Skipping Kafka setup (assuming already running)" "$YELLOW"
fi

# Run tests
test_success=true
if ! run_tests; then
    test_success=false
fi

# Run benchmarks if requested
if [ "$WITH_BENCHMARK" = true ]; then
    echo ""
    if ! run_benchmarks; then
        test_success=false
    fi
fi

# Show final status
echo ""
if [ "$test_success" = true ]; then
    write_status "All tests completed successfully!" "$GREEN"
    exit_code=0
else
    write_status "Some tests failed!" "$RED"
    exit_code=1
fi

# Cleanup message
if [ "$CLEANUP" = false ] && [ "$SKIP_SETUP" = false ]; then
    echo ""
    write_status "Kafka cluster is still running. Use --cleanup to stop it." "$YELLOW"
    write_status "Or run: docker-compose -f docker-compose.kafka.yml down -v" "$GRAY"
fi

exit $exit_code