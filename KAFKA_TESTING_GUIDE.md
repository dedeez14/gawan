# Panduan Kafka Integration Testing

Panduan lengkap untuk menjalankan skenario pengujian Kafka yang mencakup produksi dan konsumsi pesan dengan berbagai validasi.

## 📋 Fitur Testing yang Tersedia

### ✅ Validasi yang Diuji
1. **Konektivitas ke broker Kafka** - Memverifikasi koneksi ke cluster Kafka
2. **Kemampuan memproduksi pesan** - Testing produksi pesan ke topik tertentu
3. **Kemampuan mengonsumsi pesan** - Testing konsumsi pesan dari topik yang sama
4. **Penanganan error dan retry mechanism** - Testing resiliensi dan error handling
5. **Performa dengan volume pesan tinggi** - Benchmark dan load testing
6. **Integritas data dan metadata pesan** - Validasi data integrity dan metadata

### 🧪 Framework Testing
- **Go Testing Framework**: `testing` package bawaan Go
- **Assertion Library**: `github.com/stretchr/testify` untuk assertion yang kaya
- **Kafka Client**: `github.com/IBM/sarama` untuk interaksi dengan Kafka

## 🚀 Quick Start

### 1. Persiapan Environment

```bash
# Install dependencies
make deps

# Setup development environment
make setup
```

### 2. Menjalankan Kafka Cluster

```bash
# Start Kafka cluster dengan UI monitoring
make kafka-up-ui

# Atau start tanpa UI (lebih ringan)
make kafka-up

# Check status cluster
make kafka-status
```

### 3. Menjalankan Tests

```bash
# Run semua integration tests
make kafka-test

# Run tests dengan UI monitoring
make kafka-test-all

# Run tests tanpa stop cluster (untuk development)
make kafka-test-keep
```

## 🔧 Konfigurasi Testing

### Environment Variables

```bash
# Kafka broker addresses
KAFKA_BROKERS=localhost:9092

# Test environment (development/production/ci)
TEST_ENV=development

# Custom timeouts
TEST_TIMEOUT=60s
```

### Test Configurations

- **Development**: Timeout lebih panjang, logging verbose
- **Production**: Timeout ketat, optimized untuk performa
- **CI**: Timeout sangat ketat, minimal logging

## 📊 Jenis Testing yang Tersedia

### 1. Full Integration Tests

```bash
# Development environment
make kafka-test-dev

# Production environment  
make kafka-test-prod

# CI environment
make kafka-test-ci
```

### 2. Individual Component Tests

```bash
# Test konektivitas saja
make test-connectivity

# Test produksi pesan saja
make test-production

# Test konsumsi pesan saja
make test-consumption

# Test error handling saja
make test-error-handling

# Test performa saja
make test-performance

# Test integritas data saja
make test-integrity
```

### 3. Benchmark Tests

```bash
# Run benchmark tests
make kafka-benchmark

# Run benchmark tanpa stop cluster
make kafka-benchmark-keep
```

## 🎯 Detail Skenario Testing

### Test 1: Konektivitas Kafka
- Verifikasi koneksi ke broker
- Test coordinator availability
- Validasi cluster health

### Test 2: Produksi Pesan
- Kirim pesan ke topik test
- Validasi delivery confirmation
- Test dengan berbagai format pesan
- Test batch production

### Test 3: Konsumsi Pesan
- Konsumsi pesan dari topik
- Validasi message ordering
- Test consumer group functionality
- Test offset management

### Test 4: Error Handling & Retry
- Test dengan broker tidak tersedia
- Test retry mechanism
- Test timeout handling
- Test circuit breaker pattern

### Test 5: Performance Testing
- High volume message production
- Concurrent consumer testing
- Throughput measurement
- Latency analysis

### Test 6: Data Integrity
- Message content validation
- Metadata verification
- Checksum validation
- Duplicate detection

## 📈 Monitoring & UI

### Kafka UI (Port 8080)
Ketika menjalankan `make kafka-up-ui`, Anda dapat mengakses:
- **URL**: http://localhost:8080
- **Features**: 
  - Topic management
  - Message browsing
  - Consumer group monitoring
  - Broker metrics

### Test Metrics
```bash
# Generate coverage report
make test-coverage

# CPU profiling
make profile-cpu

# Memory profiling
make profile-mem
```

## 🛠️ Development Workflow

### Setup Development Environment
```bash
# Setup Kafka dengan UI untuk development
make kafka-dev-setup

# Run tests selama development
make quick-test

# Cleanup setelah development
make kafka-dev-teardown
```

### Custom Test Configuration
```go
// Contoh custom config
config := &KafkaTestConfig{
    Brokers: []string{"localhost:9092"},
    TestTimeout: 30 * time.Second,
    ProducerConfig: ProducerTestConfig{
        BatchSize: 100,
        FlushFrequency: time.Second,
    },
    ConsumerConfig: ConsumerTestConfig{
        GroupID: "test-group",
        AutoOffsetReset: "earliest",
    },
}
```

## 🔍 Troubleshooting

### Common Issues

1. **Kafka tidak start**
   ```bash
   # Check Docker status
   docker ps
   
   # Check logs
   make kafka-logs
   
   # Clean dan restart
   make kafka-clean
   make kafka-up
   ```

2. **Test timeout**
   ```bash
   # Increase timeout
   TEST_TIMEOUT=120s make kafka-test
   ```

3. **Port conflict**
   ```bash
   # Check port usage
   netstat -an | findstr :9092
   netstat -an | findstr :8080
   ```

### Health Checks
```bash
# Check Kafka health
make kafka-health

# Check cluster status
make kafka-status

# View logs
make kafka-logs
```

## 📝 Test Output Examples

### Successful Test Run
```
=== RUN   TestKafkaIntegration
=== RUN   TestKafkaIntegration/TestKafkaConnectivity
    kafka_integration_test.go:125: ✓ Berhasil terhubung ke Kafka broker
=== RUN   TestKafkaIntegration/TestMessageProduction
    kafka_integration_test.go:180: ✓ Berhasil memproduksi 100 pesan
=== RUN   TestKafkaIntegration/TestMessageConsumption
    kafka_integration_test.go:245: ✓ Berhasil mengonsumsi 100 pesan
=== RUN   TestKafkaIntegration/TestErrorHandlingAndRetry
    kafka_integration_test.go:320: ✓ Error handling bekerja dengan baik
=== RUN   TestKafkaIntegration/TestHighVolumePerformance
    kafka_integration_test.go:410: ✓ Performance test: 10000 msg/s
=== RUN   TestKafkaIntegration/TestDataIntegrityAndMetadata
    kafka_integration_test.go:480: ✓ Data integrity validated
--- PASS: TestKafkaIntegration (45.23s)
PASS
```

### Benchmark Results
```
BenchmarkKafkaProduction-8         1000    1.2ms/op    1024 B/op    5 allocs/op
BenchmarkKafkaConsumption-8        2000    0.8ms/op     512 B/op    3 allocs/op
BenchmarkKafkaRoundTrip-8           500    2.1ms/op    1536 B/op    8 allocs/op
```

## 🚀 CI/CD Integration

### GitHub Actions Example
```yaml
- name: Run Kafka Tests
  run: |
    make kafka-up
    make kafka-test-ci
    make kafka-down
```

### Jenkins Pipeline
```groovy
stage('Kafka Integration Tests') {
    steps {
        sh 'make kafka-test-ci'
    }
}
```

## 📚 Referensi

- [Sarama Documentation](https://github.com/IBM/sarama)
- [Testify Documentation](https://github.com/stretchr/testify)
- [Kafka Documentation](https://kafka.apache.org/documentation/)
- [Docker Compose Kafka](https://github.com/confluentinc/cp-all-in-one)

## 🤝 Contributing

Untuk menambahkan test case baru:

1. Tambahkan test function di `kafka_integration_test.go`
2. Update konfigurasi di `kafka_test_config.go` jika diperlukan
3. Tambahkan target Makefile jika diperlukan
4. Update dokumentasi ini

---

**Happy Testing! 🎉**