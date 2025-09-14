#!/usr/bin/env pwsh

# Script untuk menjalankan Kafka integration tests
# Usage: .\scripts\run-kafka-tests.ps1 [options]

param(
    [string]$Environment = "development",
    [string]$TestPattern = "TestKafkaIntegration",
    [int]$Timeout = 60,
    [switch]$WithUI,
    [switch]$WithBenchmark,
    [switch]$Cleanup,
    [switch]$SkipSetup,
    [switch]$Verbose,
    [switch]$Help
)

function Show-Help {
    Write-Host "Kafka Integration Test Runner" -ForegroundColor Green
    Write-Host ""
    Write-Host "Usage: .\scripts\run-kafka-tests.ps1 [options]" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Options:" -ForegroundColor Cyan
    Write-Host "  -Environment <env>     Test environment (development/production/ci) [default: development]"
    Write-Host "  -TestPattern <pattern> Test pattern to run [default: TestKafkaIntegration]"
    Write-Host "  -Timeout <seconds>     Test timeout in seconds [default: 60]"
    Write-Host "  -WithUI               Start Kafka UI for monitoring"
    Write-Host "  -WithBenchmark        Run benchmark tests"
    Write-Host "  -Cleanup              Clean up Docker containers after tests"
    Write-Host "  -SkipSetup            Skip Kafka setup (assume already running)"
    Write-Host "  -Verbose              Enable verbose output"
    Write-Host "  -Help                 Show this help message"
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Magenta
    Write-Host "  .\scripts\run-kafka-tests.ps1"
    Write-Host "  .\scripts\run-kafka-tests.ps1 -Environment production -WithUI"
    Write-Host "  .\scripts\run-kafka-tests.ps1 -TestPattern TestMessageProduction -Verbose"
    Write-Host "  .\scripts\run-kafka-tests.ps1 -WithBenchmark -Cleanup"
}

function Write-Status {
    param([string]$Message, [string]$Color = "White")
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor $Color
}

function Test-DockerAvailable {
    try {
        docker --version | Out-Null
        docker-compose --version | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Wait-ForKafka {
    param([int]$MaxWaitSeconds = 120)
    
    Write-Status "Waiting for Kafka to be ready..." "Yellow"
    $waited = 0
    
    while ($waited -lt $MaxWaitSeconds) {
        try {
            $result = docker-compose -f docker-compose.kafka.yml exec -T kafka kafka-broker-api-versions --bootstrap-server localhost:9092 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Status "Kafka is ready!" "Green"
                return $true
            }
        } catch {
            # Continue waiting
        }
        
        Start-Sleep -Seconds 2
        $waited += 2
        
        if ($waited % 10 -eq 0) {
            Write-Status "Still waiting for Kafka... ($waited/$MaxWaitSeconds seconds)" "Yellow"
        }
    }
    
    Write-Status "Timeout waiting for Kafka to be ready" "Red"
    return $false
}

function Start-KafkaCluster {
    Write-Status "Starting Kafka cluster..." "Cyan"
    
    $composeArgs = @("-f", "docker-compose.kafka.yml", "up", "-d", "kafka", "zookeeper")
    
    if ($WithUI) {
        Write-Status "Including Kafka UI..." "Cyan"
        $composeArgs += @("--profile", "ui")
    }
    
    try {
        & docker-compose @composeArgs
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to start Kafka cluster"
        }
        
        if (-not (Wait-ForKafka)) {
            throw "Kafka cluster failed to become ready"
        }
        
        Write-Status "Kafka cluster started successfully" "Green"
        
        if ($WithUI) {
            Write-Status "Kafka UI available at: http://localhost:8080" "Green"
        }
        
        return $true
    } catch {
        Write-Status "Error starting Kafka cluster: $_" "Red"
        return $false
    }
}

function Stop-KafkaCluster {
    Write-Status "Stopping Kafka cluster..." "Yellow"
    
    try {
        docker-compose -f docker-compose.kafka.yml down -v
        Write-Status "Kafka cluster stopped" "Green"
    } catch {
        Write-Status "Error stopping Kafka cluster: $_" "Red"
    }
}

function Run-Tests {
    Write-Status "Running Kafka integration tests..." "Cyan"
    Write-Status "Environment: $Environment" "White"
    Write-Status "Test Pattern: $TestPattern" "White"
    Write-Status "Timeout: $Timeout seconds" "White"
    
    # Set environment variables
    $env:KAFKA_BROKERS = "localhost:9092"
    $env:TEST_ENV = $Environment
    $env:KAFKA_TEST_TIMEOUT = "${Timeout}s"
    
    # Build test command
    $testArgs = @(
        "test",
        "-v",
        "./test",
        "-run", $TestPattern,
        "-timeout", "${Timeout}s"
    )
    
    if ($Verbose) {
        $testArgs += @("-args", "-test.v")
    }
    
    try {
        Write-Status "Executing: go $($testArgs -join ' ')" "Gray"
        & go @testArgs
        
        if ($LASTEXITCODE -eq 0) {
            Write-Status "Tests completed successfully!" "Green"
            return $true
        } else {
            Write-Status "Tests failed with exit code: $LASTEXITCODE" "Red"
            return $false
        }
    } catch {
        Write-Status "Error running tests: $_" "Red"
        return $false
    }
}

function Run-Benchmarks {
    Write-Status "Running Kafka benchmarks..." "Cyan"
    
    $env:KAFKA_BROKERS = "localhost:9092"
    $env:TEST_ENV = $Environment
    
    $benchArgs = @(
        "test",
        "-v",
        "./test",
        "-bench=BenchmarkKafka",
        "-benchmem",
        "-timeout", "${Timeout}s"
    )
    
    try {
        Write-Status "Executing: go $($benchArgs -join ' ')" "Gray"
        & go @benchArgs
        
        if ($LASTEXITCODE -eq 0) {
            Write-Status "Benchmarks completed successfully!" "Green"
            return $true
        } else {
            Write-Status "Benchmarks failed with exit code: $LASTEXITCODE" "Red"
            return $false
        }
    } catch {
        Write-Status "Error running benchmarks: $_" "Red"
        return $false
    }
}

function Show-KafkaStatus {
    Write-Status "Kafka Cluster Status:" "Cyan"
    
    try {
        docker-compose -f docker-compose.kafka.yml ps
        
        Write-Host ""
        Write-Status "Available endpoints:" "Cyan"
        Write-Host "  - Kafka Broker: localhost:9092" -ForegroundColor White
        Write-Host "  - Zookeeper: localhost:2181" -ForegroundColor White
        
        if ($WithUI) {
            Write-Host "  - Kafka UI: http://localhost:8080" -ForegroundColor White
        }
    } catch {
        Write-Status "Error getting Kafka status: $_" "Red"
    }
}

# Main execution
if ($Help) {
    Show-Help
    exit 0
}

Write-Host "=== Kafka Integration Test Runner ===" -ForegroundColor Green
Write-Host ""

# Check prerequisites
if (-not (Test-DockerAvailable)) {
    Write-Status "Docker or docker-compose not found. Please install Docker Desktop." "Red"
    exit 1
}

# Change to project root
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
Set-Location $projectRoot

Write-Status "Project root: $projectRoot" "Gray"

try {
    # Setup Kafka cluster
    if (-not $SkipSetup) {
        if (-not (Start-KafkaCluster)) {
            exit 1
        }
        
        # Show status
        Show-KafkaStatus
        Write-Host ""
    } else {
        Write-Status "Skipping Kafka setup (assuming already running)" "Yellow"
    }
    
    # Run tests
    $testSuccess = Run-Tests
    
    # Run benchmarks if requested
    if ($WithBenchmark) {
        Write-Host ""
        $benchSuccess = Run-Benchmarks
        $testSuccess = $testSuccess -and $benchSuccess
    }
    
    # Show final status
    Write-Host ""
    if ($testSuccess) {
        Write-Status "All tests completed successfully!" "Green"
        $exitCode = 0
    } else {
        Write-Status "Some tests failed!" "Red"
        $exitCode = 1
    }
    
} finally {
    # Cleanup if requested
    if ($Cleanup -and -not $SkipSetup) {
        Write-Host ""
        Stop-KafkaCluster
    } elseif (-not $SkipSetup) {
        Write-Host ""
        Write-Status "Kafka cluster is still running. Use -Cleanup to stop it." "Yellow"
        Write-Status "Or run: docker-compose -f docker-compose.kafka.yml down -v" "Gray"
    }
}

exit $exitCode