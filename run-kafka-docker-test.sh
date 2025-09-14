#!/bin/bash

# Script untuk menjalankan pengujian Kafka dalam Docker
# Pengujian beban dengan 100 request

set -e

echo "🚀 Memulai Pengujian Kafka dalam Docker Environment"
echo "================================================="

# Fungsi untuk memeriksa koneksi Kafka
check_kafka_connection() {
    echo "🔍 Memeriksa koneksi ke Kafka broker..."
    
    # Coba koneksi ke Kafka menggunakan netcat
    if timeout 10 bash -c "</dev/tcp/kafka/29092"; then
        echo "✅ Kafka broker dapat diakses"
        return 0
    else
        echo "❌ Kafka broker tidak dapat diakses"
        return 1
    fi
}

# Fungsi untuk menunggu Kafka siap
wait_for_kafka() {
    echo "⏳ Menunggu Kafka siap..."
    
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if check_kafka_connection; then
            echo "✅ Kafka siap untuk pengujian"
            return 0
        fi
        
        echo "⏳ Percobaan $attempt/$max_attempts - Menunggu 5 detik..."
        sleep 5
        attempt=$((attempt + 1))
    done
    
    echo "❌ Timeout: Kafka tidak siap setelah $max_attempts percobaan"
    exit 1
}

# Fungsi untuk menjalankan pengujian performa
run_performance_test() {
    echo "🧪 Menjalankan pengujian performa dengan konfigurasi:"
    echo "   - Message Count: ${TEST_MESSAGE_COUNT:-100}"
    echo "   - Batch Size: ${TEST_BATCH_SIZE:-10}"
    echo "   - Concurrency: ${TEST_CONCURRENCY:-5}"
    echo "   - Brokers: ${KAFKA_BROKERS}"
    echo "   - Topic Prefix: ${KAFKA_TOPIC_PREFIX}"
    echo ""
    
    # Set environment variables untuk test
    export KAFKA_BROKERS=${KAFKA_BROKERS:-kafka:29092}
    export KAFKA_TOPIC_PREFIX=${KAFKA_TOPIC_PREFIX:-docker-test}
    export GO_ENV=${GO_ENV:-docker}
    
    # Jalankan test dengan Go
    echo "🏃 Menjalankan pengujian Go..."
    cd /app
    
    # Jalankan test dengan verbose output
    go test -v ./test -run TestKafka100Messages -timeout 10m 2>&1 | tee /app/results/test-output.log
    
    # Simpan exit code
    local test_exit_code=${PIPESTATUS[0]}
    
    if [ $test_exit_code -eq 0 ]; then
        echo "✅ Pengujian berhasil diselesaikan"
    else
        echo "❌ Pengujian gagal dengan exit code: $test_exit_code"
    fi
    
    return $test_exit_code
}

# Fungsi untuk menjalankan benchmark
run_benchmark_test() {
    echo "📊 Menjalankan benchmark test..."
    
    cd /app
    go test -v ./test -bench=BenchmarkKafka100Messages -benchmem -timeout 10m 2>&1 | tee /app/results/benchmark-output.log
    
    local bench_exit_code=${PIPESTATUS[0]}
    
    if [ $bench_exit_code -eq 0 ]; then
        echo "✅ Benchmark berhasil diselesaikan"
    else
        echo "❌ Benchmark gagal dengan exit code: $bench_exit_code"
    fi
    
    return $bench_exit_code
}

# Fungsi untuk mengumpulkan metrik sistem
collect_system_metrics() {
    echo "📈 Mengumpulkan metrik sistem..."
    
    {
        echo "=== SYSTEM METRICS ==="
        echo "Timestamp: $(date)"
        echo "Memory Usage:"
        free -h
        echo ""
        echo "CPU Usage:"
        top -bn1 | grep "Cpu(s)"
        echo ""
        echo "Disk Usage:"
        df -h
        echo ""
        echo "Network Connections:"
        netstat -tuln | grep :29092 || echo "No Kafka connections found"
        echo "=== END METRICS ==="
    } > /app/results/system-metrics.log
}

# Fungsi untuk membuat laporan hasil
generate_report() {
    echo "📋 Membuat laporan hasil pengujian..."
    
    local report_file="/app/results/test-report-$(date +%Y%m%d-%H%M%S).md"
    
    {
        echo "# Laporan Pengujian Kafka Docker"
        echo ""
        echo "**Tanggal:** $(date)"
        echo "**Environment:** Docker"
        echo "**Konfigurasi:**"
        echo "- Message Count: ${TEST_MESSAGE_COUNT:-100}"
        echo "- Batch Size: ${TEST_BATCH_SIZE:-10}"
        echo "- Concurrency: ${TEST_CONCURRENCY:-5}"
        echo "- Kafka Brokers: ${KAFKA_BROKERS}"
        echo "- Topic Prefix: ${KAFKA_TOPIC_PREFIX}"
        echo ""
        echo "## Hasil Pengujian"
        echo ""
        
        if [ -f "/app/results/test-output.log" ]; then
            echo "### Output Test:"
            echo "\`\`\`"
            tail -50 /app/results/test-output.log
            echo "\`\`\`"
            echo ""
        fi
        
        if [ -f "/app/results/benchmark-output.log" ]; then
            echo "### Output Benchmark:"
            echo "\`\`\`"
            tail -30 /app/results/benchmark-output.log
            echo "\`\`\`"
            echo ""
        fi
        
        echo "## Metrik Sistem"
        echo "\`\`\`"
        cat /app/results/system-metrics.log 2>/dev/null || echo "Metrik sistem tidak tersedia"
        echo "\`\`\`"
        
    } > "$report_file"
    
    echo "📄 Laporan disimpan di: $report_file"
}

# Main execution
main() {
    echo "🐳 Docker Kafka Performance Test - 100 Messages"
    echo "==============================================="
    
    # Tunggu Kafka siap
    wait_for_kafka
    
    # Kumpulkan metrik sistem sebelum test
    collect_system_metrics
    
    # Jalankan pengujian performa
    local test_success=true
    
    if ! run_performance_test; then
        test_success=false
        echo "⚠️  Pengujian utama gagal, tetapi melanjutkan dengan benchmark"
    fi
    
    # Jalankan benchmark
    if ! run_benchmark_test; then
        test_success=false
        echo "⚠️  Benchmark gagal"
    fi
    
    # Kumpulkan metrik sistem setelah test
    collect_system_metrics
    
    # Buat laporan
    generate_report
    
    if [ "$test_success" = true ]; then
        echo "🎉 Semua pengujian berhasil diselesaikan!"
        echo "📊 Hasil tersimpan di direktori /app/results/"
        exit 0
    else
        echo "❌ Beberapa pengujian gagal. Periksa log untuk detail."
        echo "📊 Hasil tersimpan di direktori /app/results/"
        exit 1
    fi
}

# Jalankan main function
main "$@"