# Panduan Pengujian Kafka

Dokumentasi ini menjelaskan cara menjalankan skenario pengujian Kafka yang komprehensif untuk memverifikasi produksi dan konsumsi pesan.

## Fitur Pengujian

### 1. Konektivitas Broker
- Verifikasi koneksi ke broker Kafka
- Validasi metadata cluster
- Pengecekan ketersediaan topic

### 2. Produksi Pesan
- Pengiriman pesan tunggal
- Produksi batch pesan
- Validasi partition dan offset
- Pengujian dengan berbagai format data

### 3. Konsumsi Pesan
- Konsumsi dari multiple partitions
- Validasi integritas data
- Verifikasi metadata pesan
- Pengujian concurrent consumption

### 4. Error Handling & Retry
- Simulasi error scenarios
- Pengujian retry mechanism
- Validasi timeout handling
- Recovery dari connection failures

### 5. Performance Testing
- Pengujian volume tinggi (1000+ pesan)
- Measurement throughput dan latency
- Concurrent producer/consumer
- Benchmark performance

### 6. Data Integrity
- Validasi content dan metadata
- Pengujian dengan berbagai tipe data
- Verifikasi headers dan timestamps
- Consistency checks

## Prerequisites

### 1. Kafka Setup

#### Menggunakan Docker (Recommended)

```bash
# Download docker-compose.yml untuk Kafka
curl -o docker-compose.yml https://raw.githubusercontent.com/confluentinc/cp-all-in-one/7.4.0-post/cp-all-in-one/docker-compose.yml

# Start Kafka cluster
docker-compose up -d

# Verify Kafka is running
docker-compose ps
```

#### Manual Installation

1. Download Kafka dari https://kafka.apache.org/downloads
2. Extract dan navigate ke direktori Kafka
3. Start Zookeeper:
   ```bash
   bin/zookeeper-server-start.sh config/zookeeper.properties
   ```
4. Start Kafka server:
   ```bash
   bin/kafka-server-start.sh config/server.properties
   ```

### 2. Go Dependencies

```bash
# Install required packages
go mod tidy

# Jika belum ada, tambahkan dependencies:
go get github.com/IBM/sarama
go get github.com/stretchr/testify/suite
go get github.com/stretchr/testify/assert
go get github.com/stretchr/testify/require
```

## Environment Configuration

### Environment Variables

```bash
# Kafka brokers (default: localhost:9092)
export KAFKA_BROKERS="localhost:9092,localhost:9093,localhost:9094"

# Test environment (development/production/ci)
export TEST_ENV="development"

# Test timeout (optional)
export KAFKA_TEST_TIMEOUT="30s"
```

### Configuration Files

Test menggunakan konfigurasi yang dapat disesuaikan berdasarkan environment:

- **Development**: Konfigurasi permisif, timeout lebih lama
- **Production**: Konfigurasi ketat, performa tinggi
- **CI**: Konfigurasi optimized untuk continuous integration

## Menjalankan Tests

### 1. Full Test Suite

```bash
# Jalankan semua test Kafka
go test -v ./test -run TestKafkaIntegration

# Dengan timeout custom
go test -v ./test -run TestKafkaIntegration -timeout 60s

# Dengan environment specific config
TEST_ENV=production go test -v ./test -run TestKafkaIntegration
```

### 2. Individual Tests

```bash
# Test konektivitas saja
go test -v ./test -run TestKafkaIntegration/TestKafkaConnectivity

# Test produksi pesan
go test -v ./test -run TestKafkaIntegration/TestMessageProduction

# Test konsumsi pesan
go test -v ./test -run TestKafkaIntegration/TestMessageConsumption

# Test error handling
go test -v ./test -run TestKafkaIntegration/TestErrorHandlingAndRetry

# Test performance
go test -v ./test -run TestKafkaIntegration/TestHighVolumePerformance

# Test data integrity
go test -v ./test -run TestKafkaIntegration/TestDataIntegrityAndMetadata
```

### 3. Benchmark Tests

```bash
# Jalankan benchmark
go test -v ./test -bench=BenchmarkKafkaProduction

# Dengan memory profiling
go test -v ./test -bench=BenchmarkKafkaProduction -memprofile=mem.prof

# Dengan CPU profiling
go test -v ./test -bench=BenchmarkKafkaProduction -cpuprofile=cpu.prof
```

### 4. Short Mode (Skip Integration Tests)

```bash
# Skip integration tests
go test -v ./test -short
```

## Test Configuration

### Custom Configuration

```go
// Contoh penggunaan custom config
func TestWithCustomConfig(t *testing.T) {
    config := DefaultKafkaTestConfig()
    config.Brokers = []string{"localhost:9092"}
    config.TestTimeout = 45 * time.Second
    config.PerformanceThreshold.MinThroughput = 100.0
    
    env, err := NewKafkaTestEnvironment(config)
    require.NoError(t, err)
    defer env.Cleanup()
    
    // Your test logic here
}
```

### Environment-Specific Configs

```go
// Development
config := DevelopmentKafkaTestConfig()

// Production
config := ProductionKafkaTestConfig()

// CI
config := CIKafkaTestConfig()

// Auto-detect from environment
config := GetConfigForEnvironment(os.Getenv("TEST_ENV"))
```

## Troubleshooting

### Common Issues

#### 1. Connection Refused
```
Error: kafka: client has run out of available brokers
```
**Solution**: Pastikan Kafka broker berjalan di port yang benar

#### 2. Topic Creation Failed
```
Error: Topic creation failed
```
**Solution**: Pastikan user memiliki permission untuk membuat topic

#### 3. Test Timeout
```
Error: test timed out
```
**Solution**: Increase timeout atau check Kafka performance

#### 4. Consumer Lag
```
Error: Consumer tidak menerima semua pesan
```
**Solution**: Increase consumer timeout atau check partition assignment

### Debug Mode

```bash
# Enable Kafka client debug logging
export KAFKA_DEBUG=true
go test -v ./test -run TestKafkaIntegration

# Dengan verbose output
go test -v ./test -run TestKafkaIntegration -args -test.v
```

### Health Check

```bash
# Test koneksi Kafka sebelum menjalankan test
go run -c '
package main

import (
    "fmt"
    "github.com/IBM/sarama"
)

func main() {
    config := sarama.NewConfig()
    client, err := sarama.NewClient([]string{"localhost:9092"}, config)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    defer client.Close()
    
    brokers := client.Brokers()
    fmt.Printf("Connected to %d brokers\n", len(brokers))
    for _, broker := range brokers {
        fmt.Printf("- %s\n", broker.Addr())
    }
}
'
```

## Performance Benchmarks

### Expected Performance

| Environment | Min Throughput | Max Latency | Max Error Rate |
|-------------|----------------|-------------|----------------|
| Development| 10 msg/s       | 5s          | 5%             |
| Production  | 100 msg/s      | 500ms       | 0.1%           |
| CI          | 20 msg/s       | 2s          | 2%             |

### Monitoring

Test akan menghasilkan metrics berikut:
- **Throughput**: Pesan per detik
- **Latency**: Waktu end-to-end
- **Error Rate**: Persentase error
- **Resource Usage**: Memory dan CPU

## Integration dengan CI/CD

### GitHub Actions

```yaml
name: Kafka Integration Tests

on: [push, pull_request]

jobs:
  kafka-tests:
    runs-on: ubuntu-latest
    
    services:
      kafka:
        image: confluentinc/cp-kafka:latest
        env:
          KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
          KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092
        ports:
          - 9092:9092
      
      zookeeper:
        image: confluentinc/cp-zookeeper:latest
        env:
          ZOOKEEPER_CLIENT_PORT: 2181
        ports:
          - 2181:2181
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Go
      uses: actions/setup-go@v3
      with:
        go-version: 1.21
    
    - name: Wait for Kafka
      run: |
        timeout 60 bash -c 'until nc -z localhost 9092; do sleep 1; done'
    
    - name: Run Kafka Tests
      env:
        KAFKA_BROKERS: localhost:9092
        TEST_ENV: ci
      run: |
        go test -v ./test -run TestKafkaIntegration -timeout 30s
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    environment {
        KAFKA_BROKERS = 'localhost:9092'
        TEST_ENV = 'ci'
    }
    
    stages {
        stage('Setup Kafka') {
            steps {
                sh 'docker-compose up -d kafka zookeeper'
                sh 'sleep 30' // Wait for Kafka to be ready
            }
        }
        
        stage('Run Tests') {
            steps {
                sh 'go test -v ./test -run TestKafkaIntegration -timeout 30s'
            }
        }
        
        stage('Cleanup') {
            always {
                sh 'docker-compose down'
            }
        }
    }
}
```

## Best Practices

### 1. Test Isolation
- Gunakan unique topic names untuk setiap test
- Cleanup resources setelah test selesai
- Avoid shared state antar test

### 2. Error Handling
- Selalu check error dari Kafka operations
- Implement proper retry logic
- Use context dengan timeout

### 3. Performance
- Monitor resource usage selama test
- Set realistic performance thresholds
- Use connection pooling untuk multiple tests

### 4. Maintenance
- Regular update Kafka client library
- Monitor test execution time
- Review dan update test scenarios

## Contoh Output

```
=== RUN   TestKafkaIntegration
=== RUN   TestKafkaIntegration/TestKafkaConnectivity
--- PASS: TestKafkaIntegration/TestKafkaConnectivity (2.34s)
=== RUN   TestKafkaIntegration/TestMessageProduction
--- PASS: TestKafkaIntegration/TestMessageProduction (1.23s)
=== RUN   TestKafkaIntegration/TestMessageConsumption
--- PASS: TestKafkaIntegration/TestMessageConsumption (3.45s)
=== RUN   TestKafkaIntegration/TestErrorHandlingAndRetry
--- PASS: TestKafkaIntegration/TestErrorHandlingAndRetry (2.67s)
=== RUN   TestKafkaIntegration/TestHighVolumePerformance
    kafka_integration_test.go:XXX: Performa Produksi:
    kafka_integration_test.go:XXX: - Pesan: 1000
    kafka_integration_test.go:XXX: - Durasi: 8.234s
    kafka_integration_test.go:XXX: - Throughput: 121.45 msg/s
    kafka_integration_test.go:XXX: - Error: 0
    kafka_integration_test.go:XXX: Performa Konsumsi:
    kafka_integration_test.go:XXX: - Pesan dikonsumsi: 1000
    kafka_integration_test.go:XXX: - Durasi: 6.789s
    kafka_integration_test.go:XXX: - Throughput: 147.32 msg/s
--- PASS: TestKafkaIntegration/TestHighVolumePerformance (15.67s)
=== RUN   TestKafkaIntegration/TestDataIntegrityAndMetadata
=== RUN   TestKafkaIntegration/TestDataIntegrityAndMetadata/String_content
--- PASS: TestKafkaIntegration/TestDataIntegrityAndMetadata/String_content (0.45s)
=== RUN   TestKafkaIntegration/TestDataIntegrityAndMetadata/JSON_content
--- PASS: TestKafkaIntegration/TestDataIntegrityAndMetadata/JSON_content (0.38s)
=== RUN   TestKafkaIntegration/TestDataIntegrityAndMetadata/Large_content
--- PASS: TestKafkaIntegration/TestDataIntegrityAndMetadata/Large_content (0.52s)
--- PASS: TestKafkaIntegration/TestDataIntegrityAndMetadata (1.35s)
--- PASS: TestKafkaIntegration (25.71s)
PASS
ok      tutorial/test   26.234s
```

## Support

Untuk pertanyaan atau issues:
1. Check troubleshooting section
2. Review Kafka logs
3. Verify network connectivity
4. Check resource constraints

---

**Note**: Pastikan Kafka cluster berjalan sebelum menjalankan tests. Test ini memerlukan koneksi aktif ke Kafka broker.