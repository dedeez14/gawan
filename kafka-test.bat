@echo off
REM Kafka Integration Testing Script untuk Windows
REM Alternatif untuk Makefile di Windows environment

setlocal enabledelayedexpansion

if "%1"=="" goto :help
if "%1"=="help" goto :help
if "%1"=="kafka-up" goto :kafka_up
if "%1"=="kafka-up-ui" goto :kafka_up_ui
if "%1"=="kafka-down" goto :kafka_down
if "%1"=="kafka-status" goto :kafka_status
if "%1"=="kafka-logs" goto :kafka_logs
if "%1"=="kafka-clean" goto :kafka_clean
if "%1"=="kafka-test" goto :kafka_test
if "%1"=="kafka-test-dev" goto :kafka_test_dev
if "%1"=="kafka-test-prod" goto :kafka_test_prod
if "%1"=="kafka-test-ci" goto :kafka_test_ci
if "%1"=="kafka-benchmark" goto :kafka_benchmark
if "%1"=="test-connectivity" goto :test_connectivity
if "%1"=="test-production" goto :test_production
if "%1"=="test-consumption" goto :test_consumption
if "%1"=="test-error-handling" goto :test_error_handling
if "%1"=="test-performance" goto :test_performance
if "%1"=="test-integrity" goto :test_integrity
if "%1"=="deps" goto :deps
if "%1"=="build-test" goto :build_test
if "%1"=="quick-test" goto :quick_test
goto :help

:help
echo Kafka Integration Testing Commands:
echo.
echo Build ^& Dependencies:
echo   deps             - Install dependencies
echo   build-test       - Build test executable
echo.
echo Kafka Cluster Management:
echo   kafka-up         - Start Kafka cluster
echo   kafka-up-ui      - Start Kafka cluster with UI
echo   kafka-down       - Stop Kafka cluster
echo   kafka-status     - Show Kafka cluster status
echo   kafka-logs       - Show Kafka logs
echo   kafka-clean      - Clean up Kafka resources
echo.
echo Kafka Testing:
echo   kafka-test       - Run full Kafka integration tests
echo   kafka-test-dev   - Run tests (development config)
echo   kafka-test-prod  - Run tests (production config)
echo   kafka-test-ci    - Run tests (CI config)
echo   kafka-benchmark  - Run Kafka benchmarks
echo   quick-test       - Run tests without cluster setup
echo.
echo Individual Tests:
echo   test-connectivity    - Test Kafka connectivity
echo   test-production      - Test message production
echo   test-consumption     - Test message consumption
echo   test-error-handling  - Test error handling
echo   test-performance     - Test performance
echo   test-integrity       - Test data integrity
echo.
echo Examples:
echo   kafka-test.bat kafka-up
echo   kafka-test.bat kafka-test
echo   kafka-test.bat kafka-down
echo.
goto :eof

:deps
echo Installing Go dependencies...
go mod download
go mod tidy
echo Dependencies installed successfully!
goto :eof

:build_test
echo Building test executable...
go test -c ./test -o test_kafka.exe
if %ERRORLEVEL% EQU 0 (
    echo Test executable built successfully!
) else (
    echo Failed to build test executable!
    exit /b 1
)
goto :eof

:kafka_up
echo Starting Kafka cluster...
docker-compose -f docker-compose.kafka.yml up -d kafka zookeeper
echo Waiting for Kafka to be ready...
timeout /t 30 /nobreak >nul
echo Kafka cluster started!
echo.
echo Available endpoints:
echo   - Kafka Broker: localhost:9092
echo   - Zookeeper: localhost:2181
goto :eof

:kafka_up_ui
echo Starting Kafka cluster with UI...
docker-compose -f docker-compose.kafka.yml --profile ui up -d
echo Waiting for Kafka to be ready...
timeout /t 30 /nobreak >nul
echo Kafka cluster with UI started!
echo.
echo Available endpoints:
echo   - Kafka Broker: localhost:9092
echo   - Zookeeper: localhost:2181
echo   - Kafka UI: http://localhost:8080
goto :eof

:kafka_down
echo Stopping Kafka cluster...
docker-compose -f docker-compose.kafka.yml down -v
echo Kafka cluster stopped!
goto :eof

:kafka_status
echo Kafka Cluster Status:
docker-compose -f docker-compose.kafka.yml ps
echo.
echo Available endpoints:
echo   - Kafka Broker: localhost:9092
echo   - Zookeeper: localhost:2181
echo   - Kafka UI: http://localhost:8080 (if UI profile is running)
goto :eof

:kafka_logs
echo Showing Kafka logs...
docker-compose -f docker-compose.kafka.yml logs -f kafka
goto :eof

:kafka_clean
echo Cleaning up Kafka resources...
docker-compose -f docker-compose.kafka.yml down -v --remove-orphans
docker system prune -f
echo Kafka resources cleaned up!
goto :eof

:kafka_test
echo Running full Kafka integration tests...
call :kafka_up
timeout /t 10 /nobreak >nul
set KAFKA_BROKERS=localhost:9092
set TEST_ENV=development
go test -v ./test -run TestKafkaIntegration -timeout 60s
set TEST_RESULT=%ERRORLEVEL%
call :kafka_down
if %TEST_RESULT% EQU 0 (
    echo Tests completed successfully!
) else (
    echo Tests failed!
    exit /b 1
)
goto :eof

:kafka_test_dev
echo Running Kafka tests (development environment)...
call :kafka_up
timeout /t 10 /nobreak >nul
set KAFKA_BROKERS=localhost:9092
set TEST_ENV=development
go test -v ./test -run TestKafkaIntegration -timeout 90s
set TEST_RESULT=%ERRORLEVEL%
call :kafka_down
if %TEST_RESULT% EQU 0 (
    echo Development tests completed successfully!
) else (
    echo Development tests failed!
    exit /b 1
)
goto :eof

:kafka_test_prod
echo Running Kafka tests (production environment)...
call :kafka_up
timeout /t 10 /nobreak >nul
set KAFKA_BROKERS=localhost:9092
set TEST_ENV=production
go test -v ./test -run TestKafkaIntegration -timeout 45s
set TEST_RESULT=%ERRORLEVEL%
call :kafka_down
if %TEST_RESULT% EQU 0 (
    echo Production tests completed successfully!
) else (
    echo Production tests failed!
    exit /b 1
)
goto :eof

:kafka_test_ci
echo Running Kafka tests (CI environment)...
call :kafka_up
timeout /t 10 /nobreak >nul
set KAFKA_BROKERS=localhost:9092
set TEST_ENV=ci
go test -v ./test -run TestKafkaIntegration -timeout 30s
set TEST_RESULT=%ERRORLEVEL%
call :kafka_down
if %TEST_RESULT% EQU 0 (
    echo CI tests completed successfully!
) else (
    echo CI tests failed!
    exit /b 1
)
goto :eof

:kafka_benchmark
echo Running Kafka benchmarks...
call :kafka_up
timeout /t 10 /nobreak >nul
set KAFKA_BROKERS=localhost:9092
set TEST_ENV=development
go test -v ./test -bench=BenchmarkKafka -benchmem -timeout 60s
set TEST_RESULT=%ERRORLEVEL%
call :kafka_down
if %TEST_RESULT% EQU 0 (
    echo Benchmarks completed successfully!
) else (
    echo Benchmarks failed!
    exit /b 1
)
goto :eof

:quick_test
echo Running quick Kafka tests (assuming cluster is running)...
set KAFKA_BROKERS=localhost:9092
set TEST_ENV=development
go test -v ./test -run TestKafkaIntegration -timeout 60s
if %ERRORLEVEL% EQU 0 (
    echo Quick tests completed successfully!
) else (
    echo Quick tests failed!
    exit /b 1
)
goto :eof

:test_connectivity
echo Testing Kafka connectivity...
set KAFKA_BROKERS=localhost:9092
go test -v ./test -run TestKafkaIntegration/TestKafkaConnectivity -timeout 30s
goto :eof

:test_production
echo Testing message production...
set KAFKA_BROKERS=localhost:9092
go test -v ./test -run TestKafkaIntegration/TestMessageProduction -timeout 30s
goto :eof

:test_consumption
echo Testing message consumption...
set KAFKA_BROKERS=localhost:9092
go test -v ./test -run TestKafkaIntegration/TestMessageConsumption -timeout 30s
goto :eof

:test_error_handling
echo Testing error handling...
set KAFKA_BROKERS=localhost:9092
go test -v ./test -run TestKafkaIntegration/TestErrorHandlingAndRetry -timeout 30s
goto :eof

:test_performance
echo Testing performance...
set KAFKA_BROKERS=localhost:9092
go test -v ./test -run TestKafkaIntegration/TestHighVolumePerformance -timeout 60s
goto :eof

:test_integrity
echo Testing data integrity...
set KAFKA_BROKERS=localhost:9092
go test -v ./test -run TestKafkaIntegration/TestDataIntegrityAndMetadata -timeout 30s
goto :eof

:eof
endlocal