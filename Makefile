# Gawan Framework Makefile

# Build variables
APP_NAME := gawan
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GO_VERSION := $(shell go version | cut -d' ' -f3)

# Build flags
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.Date=$(DATE)"
BUILD_DIR := bin
CMD_DIR := cmd/gawan

# Go build flags
GOFLAGS := -trimpath
GCFLAGS := -gcflags="-N -l"

# Default target
.PHONY: all
all: build

# Build the CLI tool
.PHONY: build
build: clean
	@echo "Building $(APP_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME) ./$(CMD_DIR)
	@echo "✓ Built $(APP_NAME) successfully"

# Build for development (with debug symbols)
.PHONY: build-dev
build-dev: clean
	@echo "Building $(APP_NAME) for development..."
	@mkdir -p $(BUILD_DIR)
	go build $(GOFLAGS) $(GCFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME) ./$(CMD_DIR)
	@echo "✓ Built $(APP_NAME) for development"

# Build for multiple platforms
.PHONY: build-all
build-all: clean
	@echo "Building $(APP_NAME) for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	# Windows
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-windows-amd64.exe ./$(CMD_DIR)
	GOOS=windows GOARCH=386 go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-windows-386.exe ./$(CMD_DIR)
	# Linux
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64 ./$(CMD_DIR)
	GOOS=linux GOARCH=386 go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-linux-386 ./$(CMD_DIR)
	GOOS=linux GOARCH=arm64 go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-linux-arm64 ./$(CMD_DIR)
	# macOS
	GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-darwin-amd64 ./$(CMD_DIR)
	GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-darwin-arm64 ./$(CMD_DIR)
	@echo "✓ Built $(APP_NAME) for all platforms"

# Install the CLI tool to GOPATH/bin
.PHONY: install
install:
	@echo "Installing $(APP_NAME)..."
	go install $(LDFLAGS) ./$(CMD_DIR)
	@echo "✓ Installed $(APP_NAME) to $(shell go env GOPATH)/bin"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "✓ Cleaned build artifacts"

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	go test -v ./...
	@echo "✓ Tests completed"

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "✓ Coverage report generated: coverage.html"

# Run linter
.PHONY: lint
lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed. Install it with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	go fmt ./...
	goimports -w .
	@echo "✓ Code formatted"

# Tidy dependencies
.PHONY: tidy
tidy:
	@echo "Tidying dependencies..."
	go mod tidy
	@echo "✓ Dependencies tidied"

# Download dependencies
.PHONY: deps
deps:
	@echo "Downloading dependencies..."
	go mod download
	@echo "✓ Dependencies downloaded"

# Verify dependencies
.PHONY: verify
verify:
	@echo "Verifying dependencies..."
	go mod verify
	@echo "✓ Dependencies verified"

# Run the CLI tool
.PHONY: run
run: build
	@echo "Running $(APP_NAME)..."
	./$(BUILD_DIR)/$(APP_NAME) $(ARGS)

# Show help for the CLI tool
.PHONY: help-cli
help-cli: build
	@echo "$(APP_NAME) CLI Help:"
	./$(BUILD_DIR)/$(APP_NAME) --help

# Generate a new project using the CLI
.PHONY: demo-new
demo-new: build
	@echo "Creating demo project..."
	./$(BUILD_DIR)/$(APP_NAME) new demo-project --type=api --description="Demo API project"

# Generate components using the CLI
.PHONY: demo-generate
demo-generate: build
	@echo "Generating demo components..."
	./$(BUILD_DIR)/$(APP_NAME) generate controller User --actions=Create,Read,Update,Delete
	./$(BUILD_DIR)/$(APP_NAME) generate service User
	./$(BUILD_DIR)/$(APP_NAME) generate model User --fields="Name:string,Email:string,Age:int"

# Development workflow
.PHONY: dev
dev: clean fmt lint test build
	@echo "✓ Development workflow completed"

# Release workflow
.PHONY: release
release: clean fmt lint test build-all
	@echo "✓ Release workflow completed"

# Show build information
.PHONY: info
info:
	@echo "Build Information:"
	@echo "  App Name:    $(APP_NAME)"
	@echo "  Version:     $(VERSION)"
	@echo "  Commit:      $(COMMIT)"
	@echo "  Build Date:  $(DATE)"
	@echo "  Go Version:  $(GO_VERSION)"
	@echo "  Build Dir:   $(BUILD_DIR)"
	@echo "  Command Dir: $(CMD_DIR)"

# Show available targets
.PHONY: help
help:
	@echo "Available targets:"
	@echo ""
	@echo "Build & Development:"
	@echo "  build        - Build the CLI tool"
	@echo "  build-dev    - Build with debug symbols"
	@echo "  build-all    - Build for multiple platforms"
	@echo "  install      - Install to GOPATH/bin"
	@echo "  clean        - Clean build artifacts"
	@echo "  test         - Run tests"
	@echo "  test-coverage- Run tests with coverage"
	@echo "  lint         - Run linter"
	@echo "  fmt          - Format code"
	@echo "  tidy         - Tidy dependencies"
	@echo "  deps         - Download dependencies"
	@echo "  verify       - Verify dependencies"
	@echo "  run          - Build and run (use ARGS=\"...\" for arguments)"
	@echo "  dev          - Development workflow"
	@echo "  release      - Release workflow"
	@echo "  setup        - Setup development environment"
	@echo ""
	@echo "Kafka Integration Testing:"
	@echo "  kafka-up     - Start Kafka cluster"
	@echo "  kafka-up-ui  - Start Kafka cluster with UI"
	@echo "  kafka-down   - Stop Kafka cluster"
	@echo "  kafka-status - Show Kafka cluster status"
	@echo "  kafka-health - Check Kafka cluster health"
	@echo "  kafka-logs   - Show Kafka logs"
	@echo "  kafka-clean  - Clean up Kafka resources"
	@echo "  kafka-test   - Run full Kafka integration tests"
	@echo "  kafka-test-dev - Run tests (development config)"
	@echo "  kafka-test-prod - Run tests (production config)"
	@echo "  kafka-test-ci - Run tests (CI config)"
	@echo "  kafka-test-all - Run comprehensive tests with UI"
	@echo "  kafka-benchmark - Run Kafka benchmarks"
	@echo "  kafka-dev-setup - Setup Kafka dev environment"
	@echo ""
	@echo "Individual Kafka Tests:"
	@echo "  test-connectivity - Test Kafka connectivity"
	@echo "  test-production - Test message production"
	@echo "  test-consumption - Test message consumption"
	@echo "  test-error-handling - Test error handling"
	@echo "  test-performance - Test performance"
	@echo "  test-integrity - Test data integrity"
	@echo ""
	@echo "CLI & Demo:"
	@echo "  help-cli     - Show CLI help"
	@echo "  demo-new     - Create demo project"
	@echo "  demo-generate- Generate demo components"
	@echo ""
	@echo "Utilities:"
	@echo "  info         - Show build information"
	@echo "  help         - Show this help"

# Check if required tools are installed
.PHONY: check-tools
check-tools:
	@echo "Checking required tools..."
	@command -v go >/dev/null 2>&1 || { echo "Go is required but not installed."; exit 1; }
	@command -v git >/dev/null 2>&1 || { echo "Git is required but not installed."; exit 1; }
	@echo "✓ Required tools are installed"

# Setup development environment
.PHONY: setup
setup: check-tools deps
	@echo "Setting up development environment..."
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi
	@if ! command -v goimports >/dev/null 2>&1; then \
		echo "Installing goimports..."; \
		go install golang.org/x/tools/cmd/goimports@latest; \
	fi
	@echo "✓ Development environment setup completed"

# ============================================================================
# KAFKA INTEGRATION TESTING
# ============================================================================

# Kafka cluster management
.PHONY: kafka-up kafka-down kafka-status kafka-logs kafka-clean kafka-up-ui
kafka-up: ## Start Kafka cluster dengan Docker
	@echo "Starting Kafka cluster..."
	docker-compose -f docker-compose.kafka.yml up -d kafka zookeeper
	@echo "Waiting for Kafka to be ready..."
	@timeout 120 bash -c 'until docker-compose -f docker-compose.kafka.yml exec -T kafka kafka-broker-api-versions --bootstrap-server localhost:9092 >/dev/null 2>&1; do sleep 2; done' || (echo "Timeout waiting for Kafka" && exit 1)
	@echo "✓ Kafka cluster is ready!"

kafka-up-ui: ## Start Kafka cluster dengan UI
	@echo "Starting Kafka cluster with UI..."
	docker-compose -f docker-compose.kafka.yml --profile ui up -d
	@echo "Waiting for Kafka to be ready..."
	@timeout 120 bash -c 'until docker-compose -f docker-compose.kafka.yml exec -T kafka kafka-broker-api-versions --bootstrap-server localhost:9092 >/dev/null 2>&1; do sleep 2; done' || (echo "Timeout waiting for Kafka" && exit 1)
	@echo "✓ Kafka cluster is ready!"
	@echo "Kafka UI available at: http://localhost:8080"

kafka-down: ## Stop Kafka cluster
	@echo "Stopping Kafka cluster..."
	docker-compose -f docker-compose.kafka.yml down -v

kafka-status: ## Show Kafka cluster status
	@echo "Kafka Cluster Status:"
	docker-compose -f docker-compose.kafka.yml ps
	@echo ""
	@echo "Available endpoints:"
	@echo "  - Kafka Broker: localhost:9092"
	@echo "  - Zookeeper: localhost:2181"

kafka-logs: ## Show Kafka logs
	docker-compose -f docker-compose.kafka.yml logs -f kafka

kafka-clean: ## Clean up Kafka data and containers
	@echo "Cleaning up Kafka resources..."
	docker-compose -f docker-compose.kafka.yml down -v --remove-orphans
	docker system prune -f

# Kafka testing commands
.PHONY: kafka-test kafka-test-dev kafka-test-prod kafka-test-ci kafka-test-keep
kafka-test: kafka-up ## Run full Kafka integration tests
	@echo "Running Kafka integration tests..."
	KAFKA_BROKERS=localhost:9092 TEST_ENV=development go test -v ./test -run TestKafkaIntegration -timeout 60s
	@$(MAKE) kafka-down

kafka-test-keep: ## Run Kafka tests without stopping cluster
	@echo "Running Kafka integration tests (keeping cluster running)..."
	KAFKA_BROKERS=localhost:9092 TEST_ENV=development go test -v ./test -run TestKafkaIntegration -timeout 60s

kafka-test-dev: kafka-up ## Run tests dengan development config
	@echo "Running Kafka tests (development environment)..."
	KAFKA_BROKERS=localhost:9092 TEST_ENV=development go test -v ./test -run TestKafkaIntegration -timeout 90s
	@$(MAKE) kafka-down

kafka-test-prod: kafka-up ## Run tests dengan production config
	@echo "Running Kafka tests (production environment)..."
	KAFKA_BROKERS=localhost:9092 TEST_ENV=production go test -v ./test -run TestKafkaIntegration -timeout 45s
	@$(MAKE) kafka-down

kafka-test-ci: kafka-up ## Run tests untuk CI environment
	@echo "Running Kafka tests (CI environment)..."
	KAFKA_BROKERS=localhost:9092 TEST_ENV=ci go test -v ./test -run TestKafkaIntegration -timeout 30s
	@$(MAKE) kafka-down

# Individual test components
.PHONY: test-connectivity test-production test-consumption test-error-handling test-performance test-integrity
test-connectivity: ## Test Kafka connectivity saja
	KAFKA_BROKERS=localhost:9092 go test -v ./test -run TestKafkaIntegration/TestKafkaConnectivity -timeout 30s

test-production: ## Test message production saja
	KAFKA_BROKERS=localhost:9092 go test -v ./test -run TestKafkaIntegration/TestMessageProduction -timeout 30s

test-consumption: ## Test message consumption saja
	KAFKA_BROKERS=localhost:9092 go test -v ./test -run TestKafkaIntegration/TestMessageConsumption -timeout 30s

test-error-handling: ## Test error handling saja
	KAFKA_BROKERS=localhost:9092 go test -v ./test -run TestKafkaIntegration/TestErrorHandlingAndRetry -timeout 30s

test-performance: ## Test performance saja
	KAFKA_BROKERS=localhost:9092 go test -v ./test -run TestKafkaIntegration/TestHighVolumePerformance -timeout 60s

test-integrity: ## Test data integrity saja
	KAFKA_BROKERS=localhost:9092 go test -v ./test -run TestKafkaIntegration/TestDataIntegrityAndMetadata -timeout 30s

# Benchmark tests
.PHONY: kafka-benchmark kafka-benchmark-keep
kafka-benchmark: kafka-up ## Run Kafka benchmarks
	@echo "Running Kafka benchmarks..."
	KAFKA_BROKERS=localhost:9092 TEST_ENV=development go test -v ./test -bench=BenchmarkKafka -benchmem -timeout 60s
	@$(MAKE) kafka-down

kafka-benchmark-keep: ## Run benchmarks without stopping cluster
	@echo "Running Kafka benchmarks (keeping cluster running)..."
	KAFKA_BROKERS=localhost:9092 TEST_ENV=development go test -v ./test -bench=BenchmarkKafka -benchmem -timeout 60s

# Comprehensive testing
.PHONY: kafka-test-all kafka-dev-setup kafka-dev-teardown
kafka-test-all: kafka-up-ui ## Run semua tests dengan monitoring
	@echo "Running comprehensive Kafka tests..."
	@echo "Kafka UI available at: http://localhost:8080"
	@echo ""
	@echo "=== Running Development Tests ==="
	KAFKA_BROKERS=localhost:9092 TEST_ENV=development go test -v ./test -run TestKafkaIntegration -timeout 90s
	@echo ""
	@echo "=== Running Production Tests ==="
	KAFKA_BROKERS=localhost:9092 TEST_ENV=production go test -v ./test -run TestKafkaIntegration -timeout 45s
	@echo ""
	@echo "=== Running Benchmarks ==="
	KAFKA_BROKERS=localhost:9092 TEST_ENV=development go test -v ./test -bench=BenchmarkKafka -benchmem -timeout 60s
	@echo ""
	@echo "✓ All Kafka tests completed"
	@$(MAKE) kafka-down

kafka-dev-setup: kafka-up-ui ## Setup Kafka development environment
	@echo "✓ Kafka development environment ready!"
	@echo "Kafka UI: http://localhost:8080"
	@echo "Run 'make kafka-test-keep' to run tests"

kafka-dev-teardown: kafka-clean ## Teardown Kafka development environment
	@echo "✓ Kafka development environment cleaned up"

# Health checks
.PHONY: kafka-health
kafka-health: ## Check Kafka cluster health
	@echo "Checking Kafka cluster health..."
	@if docker-compose -f docker-compose.kafka.yml exec -T kafka kafka-broker-api-versions --bootstrap-server localhost:9092 >/dev/null 2>&1; then \
		echo "✅ Kafka is healthy"; \
	else \
		echo "❌ Kafka is not responding"; \
		exit 1; \
	fi