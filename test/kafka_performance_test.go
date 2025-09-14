package test

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PerformanceTestConfig konfigurasi untuk pengujian performa
type PerformanceTestConfig struct {
	MessageCount    int
	BatchSize      int
	Concurrency    int
	MaxDuration    time.Duration
	Brokers        []string
	TopicName      string
}

// PerformanceMetrics metrik hasil pengujian
type PerformanceMetrics struct {
	TotalMessages       int64
	SuccessfulSent      int64
	FailedSent          int64
	SuccessfulReceived  int64
	FailedReceived      int64
	TotalConsumed       int64
	ProductionTime      time.Duration
	ConsumptionTime     time.Duration
	ThroughputSent      float64
	ThroughputReceived  float64
	ThroughputConsumed  float64
	ErrorRate           float64
	AverageLatency      time.Duration
}

func logResults(t *testing.T, metrics *PerformanceMetrics, config *PerformanceTestConfig) {
	separator := strings.Repeat("=", 60)
	t.Logf("%s", "\n"+separator)
	t.Logf("%s", "HASIL PENGUJIAN PERFORMA KAFKA")
	t.Logf("%s", separator)
	t.Logf("%s", "Konfigurasi:")
	t.Logf("  - Jumlah Message: %d", config.MessageCount)
	t.Logf("  - Batch Size: %d", config.BatchSize)
	t.Logf("  - Concurrency: %d", config.Concurrency)
	t.Logf("  - Brokers: %v", config.Brokers)
	t.Logf("  - Topic: %s", config.TopicName)
	t.Logf("%s", "\nMetrik Produksi:")
	t.Logf("  - Berhasil Dikirim: %d", metrics.SuccessfulSent)
	t.Logf("  - Gagal Dikirim: %d", metrics.FailedSent)
	t.Logf("  - Waktu Produksi: %v", metrics.ProductionTime)
	t.Logf("  - Throughput: %.2f msg/detik", metrics.ThroughputSent)
	t.Logf("  - Error Rate: %.2f%%", metrics.ErrorRate)
	t.Logf("  - Rata-rata Latency: %v", metrics.AverageLatency)
	t.Logf("%s", separator)
}

// checkKafkaConnection memeriksa koneksi ke Kafka brokers
func checkKafkaConnection(brokers []string) bool {
	config := sarama.NewConfig()
	config.Net.DialTimeout = 5 * time.Second
	
	client, err := sarama.NewClient(brokers, config)
	if err != nil {
		return false
	}
	defer client.Close()
	
	return true
}

// Helper functions untuk environment variables
func getEnvString(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvStringSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(value, ",")
	}
	return defaultValue
}

// TestKafka100Messages menguji pengiriman 100 pesan ke Kafka untuk Docker
func TestKafka100Messages(t *testing.T) {
	// Konfigurasi dari environment variables atau default
	messageCount := getEnvInt("TEST_MESSAGE_COUNT", 100)
	batchSize := getEnvInt("TEST_BATCH_SIZE", 10)
	concurrency := getEnvInt("TEST_CONCURRENCY", 5)
	brokers := getEnvStringSlice("KAFKA_BROKERS", []string{"localhost:9092"})
	topicPrefix := getEnvString("KAFKA_TOPIC_PREFIX", "docker-test")
	
	config := &PerformanceTestConfig{
		MessageCount: messageCount,
		BatchSize:    batchSize,
		Concurrency:  concurrency,
		MaxDuration:  2 * time.Minute, // Lebih pendek untuk 100 messages
		Brokers:      brokers,
		TopicName:    fmt.Sprintf("%s-%d", topicPrefix, time.Now().Unix()),
	}

	t.Logf("🚀 Memulai pengujian dengan konfigurasi:")
	t.Logf("   - Message Count: %d", config.MessageCount)
	t.Logf("   - Batch Size: %d", config.BatchSize)
	t.Logf("   - Concurrency: %d", config.Concurrency)
	t.Logf("   - Brokers: %v", config.Brokers)
	t.Logf("   - Topic: %s", config.TopicName)

	// Verifikasi konfigurasi Kafka
	t.Log("🔍 Memverifikasi konfigurasi Kafka...")
	if !checkKafkaConnection(config.Brokers) {
		t.Fatalf("❌ Tidak dapat terhubung ke Kafka brokers: %v", config.Brokers)
	}
	t.Log("✅ Koneksi Kafka berhasil diverifikasi")

	// Setup Kafka clients
	producer, consumer, client := setupKafkaClients(t, config)

	// Buat test topic
	createTestTopic(t, client, config.TopicName)

	// Jalankan pengujian produksi
	t.Log("📤 Memulai pengujian produksi pesan...")
	productionMetrics := runProductionTest(t, producer, config)

	// Tunggu sebentar untuk memastikan pesan tersedia
	time.Sleep(3 * time.Second)

	// Jalankan pengujian konsumsi
	t.Log("📥 Memulai pengujian konsumsi pesan...")
	consumptionMetrics := runConsumptionTest(t, consumer, config)

	// Tunggu sebentar sebelum cleanup untuk memastikan consumer selesai
	time.Sleep(2 * time.Second)

	// Gabungkan metrik
	finalMetrics := &PerformanceMetrics{
		TotalMessages:      int64(config.MessageCount),
		SuccessfulSent:     productionMetrics.SuccessfulSent,
		FailedSent:         productionMetrics.FailedSent,
		TotalConsumed:      consumptionMetrics.TotalConsumed,
		ProductionTime:     productionMetrics.ProductionTime,
		ConsumptionTime:    consumptionMetrics.ConsumptionTime,
		ThroughputSent:     productionMetrics.ThroughputSent,
		ThroughputConsumed: consumptionMetrics.ThroughputConsumed,
		AverageLatency:     productionMetrics.AverageLatency,
		ErrorRate:          productionMetrics.ErrorRate,
	}

	// Log hasil
	logResults(t, finalMetrics, config)

	// Validasi hasil
	validateResults(t, finalMetrics, config)

	// Cleanup resources
	cleanup(producer, consumer, client)

	t.Log("🎉 Pengujian 100 pesan berhasil diselesaikan!")
}

// TestKafka10000Messages menguji pengiriman 10.000 pesan ke Kafka
func TestKafka10000Messages(t *testing.T) {
	config := &PerformanceTestConfig{
		MessageCount: 10000,
		BatchSize:    100,
		Concurrency:  10,
		MaxDuration:  5 * time.Minute,
		Brokers:      []string{"localhost:9092"},
		TopicName:    fmt.Sprintf("perf-test-%d", time.Now().Unix()),
	}

	log.Printf("🚀 Memulai pengujian performa Kafka dengan %d pesan", config.MessageCount)
	log.Printf("📊 Konfigurasi: Batch=%d, Concurrency=%d, Brokers=%v", 
		config.BatchSize, config.Concurrency, config.Brokers)

	// Setup Kafka client dan producer
	producer, consumer, client := setupKafkaClients(t, config)
	defer cleanup(producer, consumer, client)

	// Buat topic untuk pengujian
	createTestTopic(t, client, config.TopicName)

	// Jalankan pengujian produksi
	log.Println("📤 Memulai pengujian produksi pesan...")
	productionMetrics := runProductionTest(t, producer, config)

	// Tunggu sebentar untuk memastikan pesan tersedia
	time.Sleep(2 * time.Second)

	// Jalankan pengujian konsumsi
	log.Println("📥 Memulai pengujian konsumsi pesan...")
	consumptionMetrics := runConsumptionTest(t, consumer, config)

	// Gabungkan metrik
	finalMetrics := &PerformanceMetrics{
		TotalMessages:      int64(config.MessageCount),
		SuccessfulSent:     productionMetrics.SuccessfulSent,
		FailedSent:         productionMetrics.FailedSent,
		TotalConsumed:      consumptionMetrics.TotalConsumed,
		ProductionTime:     productionMetrics.ProductionTime,
		ConsumptionTime:    consumptionMetrics.ConsumptionTime,
		ThroughputSent:     productionMetrics.ThroughputSent,
		ThroughputConsumed: consumptionMetrics.ThroughputConsumed,
		ErrorRate:          productionMetrics.ErrorRate,
		AverageLatency:     productionMetrics.AverageLatency,
	}

	// Tampilkan hasil
	printResults(finalMetrics)

	// Validasi hasil
	validateResults(t, finalMetrics, config)

	log.Println("✅ Pengujian performa selesai!")
}

func setupKafkaClients(t *testing.T, config *PerformanceTestConfig) (sarama.SyncProducer, sarama.Consumer, sarama.Client) {
	// Konfigurasi Kafka yang dioptimalkan untuk performa
	kafkaConfig := sarama.NewConfig()
	kafkaConfig.Producer.Return.Successes = true
	kafkaConfig.Producer.Return.Errors = true
	kafkaConfig.Producer.RequiredAcks = sarama.WaitForAll
	kafkaConfig.Producer.Retry.Max = 3
	kafkaConfig.Producer.Retry.Backoff = 100 * time.Millisecond
	kafkaConfig.Producer.Flush.Frequency = 10 * time.Millisecond
	kafkaConfig.Producer.Flush.Messages = config.BatchSize
	kafkaConfig.Producer.Compression = sarama.CompressionSnappy
	kafkaConfig.Consumer.Return.Errors = true
	kafkaConfig.Consumer.Offsets.Initial = sarama.OffsetOldest
	kafkaConfig.Net.DialTimeout = 10 * time.Second
	kafkaConfig.Net.ReadTimeout = 10 * time.Second
	kafkaConfig.Net.WriteTimeout = 10 * time.Second

	// Buat client
	client, err := sarama.NewClient(config.Brokers, kafkaConfig)
	require.NoError(t, err, "Gagal membuat Kafka client")

	// Buat producer
	producer, err := sarama.NewSyncProducer(config.Brokers, kafkaConfig)
	require.NoError(t, err, "Gagal membuat Kafka producer")

	// Buat consumer dengan client terpisah
	consumer, err := sarama.NewConsumer(config.Brokers, kafkaConfig)
	require.NoError(t, err, "Gagal membuat Kafka consumer")

	return producer, consumer, client
}

func createTestTopic(t *testing.T, client sarama.Client, topicName string) {
	admin, err := sarama.NewClusterAdminFromClient(client)
	require.NoError(t, err, "Gagal membuat cluster admin")
	defer admin.Close()

	topicDetail := &sarama.TopicDetail{
		NumPartitions:     6, // Lebih banyak partisi untuk performa
		ReplicationFactor: 1,
	}

	err = admin.CreateTopic(topicName, topicDetail, false)
	if err != nil && err != sarama.ErrTopicAlreadyExists {
		t.Logf("Peringatan: Gagal membuat topic %s: %v", topicName, err)
	}

	// Tunggu topic tersedia
	time.Sleep(1 * time.Second)
}

func runProductionTest(t *testing.T, producer sarama.SyncProducer, config *PerformanceTestConfig) *PerformanceMetrics {
	var (
		successCount = int64(0)
		failCount    = int64(0)
		totalLatency = int64(0)
	)

	start := time.Now()
	var wg sync.WaitGroup
	errorChan := make(chan error, config.MessageCount)

	// Buat worker pool untuk concurrency
	messageChan := make(chan int, config.MessageCount)
	for i := 0; i < config.MessageCount; i++ {
		messageChan <- i
	}
	close(messageChan)

	// Jalankan worker goroutines
	for w := 0; w < config.Concurrency; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for msgIndex := range messageChan {
				msgStart := time.Now()
				msgID := fmt.Sprintf("perf-msg-%d-%d", workerID, msgIndex)
				
				testMsg := TestMessage{
					ID:        msgID,
					Content:   fmt.Sprintf("Performance test message %s from worker %d", msgID, workerID),
					Timestamp: time.Now(),
					Metadata: map[string]interface{}{
						"worker":      workerID,
						"index":       msgIndex,
						"performance": true,
						"test_type":   "10k_messages",
					},
				}

				msgBytes, err := json.Marshal(testMsg)
				if err != nil {
					errorChan <- err
					atomic.AddInt64(&failCount, 1)
					continue
				}

				msg := &sarama.ProducerMessage{
					Topic:     config.TopicName,
					Key:       sarama.StringEncoder(msgID),
					Value:     sarama.ByteEncoder(msgBytes),
					Timestamp: time.Now(),
				}

				_, _, err = producer.SendMessage(msg)
				latency := time.Since(msgStart)
				atomic.AddInt64(&totalLatency, latency.Nanoseconds())

				if err != nil {
					errorChan <- err
					atomic.AddInt64(&failCount, 1)
				} else {
					atomic.AddInt64(&successCount, 1)
				}

				// Log progress setiap 1000 pesan
				if (msgIndex+1)%1000 == 0 {
					log.Printf("Worker %d: Mengirim pesan ke-%d", workerID, msgIndex+1)
				}
			}
		}(w)
	}

	wg.Wait()
	productionTime := time.Since(start)
	close(errorChan)

	// Hitung metrik
	throughput := float64(successCount) / productionTime.Seconds()
	errorRate := float64(failCount) / float64(config.MessageCount) * 100
	avgLatency := time.Duration(totalLatency / int64(config.MessageCount))

	return &PerformanceMetrics{
		SuccessfulSent:  successCount,
		FailedSent:      failCount,
		ProductionTime:  productionTime,
		ThroughputSent:  throughput,
		ErrorRate:       errorRate,
		AverageLatency:  avgLatency,
	}
}

func runConsumptionTest(t *testing.T, consumer sarama.Consumer, config *PerformanceTestConfig) *PerformanceMetrics {
	start := time.Now()
	consumedCount := int64(0)

	partitions, err := consumer.Partitions(config.TopicName)
	require.NoError(t, err, "Gagal mendapatkan partisi")

	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), config.MaxDuration)
	defer cancel()

	// Konsumsi dari semua partisi secara paralel
	for _, partition := range partitions {
		wg.Add(1)
		go func(partitionID int32) {
			defer wg.Done()

			partitionConsumer, err := consumer.ConsumePartition(config.TopicName, partitionID, sarama.OffsetOldest)
			if err != nil {
				t.Logf("Gagal membuat partition consumer untuk partisi %d: %v", partitionID, err)
				return
			}
			defer partitionConsumer.Close()

			for {
				select {
				case msg := <-partitionConsumer.Messages():
					if msg != nil {
						atomic.AddInt64(&consumedCount, 1)
						// Log progress setiap 1000 pesan
						if consumedCount%1000 == 0 {
							log.Printf("Partisi %d: Mengkonsumsi pesan ke-%d", partitionID, consumedCount)
						}
					}
				case <-ctx.Done():
					return
				}
			}
		}(partition)
	}

	wg.Wait()
	consumptionTime := time.Since(start)
	throughput := float64(consumedCount) / consumptionTime.Seconds()

	return &PerformanceMetrics{
		TotalConsumed:      consumedCount,
		ConsumptionTime:    consumptionTime,
		ThroughputConsumed: throughput,
	}
}

func printResults(metrics *PerformanceMetrics) {
	separator := strings.Repeat("=", 60)
	log.Println("\n" + separator)
	log.Println("📊 HASIL PENGUJIAN PERFORMA KAFKA - 10.000 PESAN")
	log.Println(separator)
	log.Printf("📤 PRODUKSI:")
	log.Printf("   • Total Pesan: %d", metrics.TotalMessages)
	log.Printf("   • Berhasil Dikirim: %d", metrics.SuccessfulSent)
	log.Printf("   • Gagal Dikirim: %d", metrics.FailedSent)
	log.Printf("   • Waktu Produksi: %v", metrics.ProductionTime)
	log.Printf("   • Throughput: %.2f pesan/detik", metrics.ThroughputSent)
	log.Printf("   • Error Rate: %.2f%%", metrics.ErrorRate)
	log.Printf("   • Rata-rata Latency: %v", metrics.AverageLatency)
	log.Printf("\n📥 KONSUMSI:")
	log.Printf("   • Total Dikonsumsi: %d", metrics.TotalConsumed)
	log.Printf("   • Waktu Konsumsi: %v", metrics.ConsumptionTime)
	log.Printf("   • Throughput: %.2f pesan/detik", metrics.ThroughputConsumed)
	log.Printf("\n🎯 RINGKASAN:")
	log.Printf("   • Success Rate: %.2f%%", float64(metrics.SuccessfulSent)/float64(metrics.TotalMessages)*100)
	log.Printf("   • Consumption Rate: %.2f%%", float64(metrics.TotalConsumed)/float64(metrics.SuccessfulSent)*100)
	log.Println(separator)
}

func validateResults(t *testing.T, metrics *PerformanceMetrics, config *PerformanceTestConfig) {
	// Validasi bahwa semua pesan berhasil dikirim
	assert.Equal(t, metrics.TotalMessages, metrics.SuccessfulSent, 
		"Tidak semua pesan berhasil dikirim")

	// Validasi error rate rendah (< 1%)
	assert.Less(t, metrics.ErrorRate, 1.0, 
		"Error rate terlalu tinggi (>1%)")

	// Validasi throughput minimum (> 100 msg/s)
	assert.Greater(t, metrics.ThroughputSent, 100.0, 
		"Throughput produksi terlalu rendah (<100 msg/s)")

	// Validasi konsumsi (minimal 90% dari yang dikirim)
	minConsumed := int64(float64(metrics.SuccessfulSent) * 0.9)
	assert.GreaterOrEqual(t, metrics.TotalConsumed, minConsumed, 
		"Konsumsi terlalu rendah (<90% dari yang dikirim)")

	// Validasi waktu produksi tidak melebihi batas maksimum
	assert.Less(t, metrics.ProductionTime, config.MaxDuration, 
		"Waktu produksi melebihi batas maksimum")

	log.Println("✅ Semua validasi performa berhasil!")
}

func cleanup(producer sarama.SyncProducer, consumer sarama.Consumer, client sarama.Client) {
	if producer != nil {
		producer.Close()
	}
	if consumer != nil {
		consumer.Close()
	}
	if client != nil {
		client.Close()
	}
}



// Fungsi helper untuk benchmark testing
func setupKafkaClientsForBench(b *testing.B, config *PerformanceTestConfig) (sarama.SyncProducer, sarama.Consumer, sarama.Client) {
	// Konfigurasi Kafka yang dioptimalkan untuk performa
	kafkaConfig := sarama.NewConfig()
	kafkaConfig.Producer.Return.Successes = true
	kafkaConfig.Producer.Return.Errors = true
	kafkaConfig.Producer.RequiredAcks = sarama.WaitForAll
	kafkaConfig.Producer.Retry.Max = 3
	kafkaConfig.Producer.Retry.Backoff = 100 * time.Millisecond
	kafkaConfig.Producer.Flush.Frequency = 10 * time.Millisecond
	kafkaConfig.Producer.Flush.Messages = config.BatchSize
	kafkaConfig.Producer.Compression = sarama.CompressionSnappy
	kafkaConfig.Consumer.Return.Errors = true
	kafkaConfig.Consumer.Offsets.Initial = sarama.OffsetOldest
	kafkaConfig.Net.DialTimeout = 10 * time.Second
	kafkaConfig.Net.ReadTimeout = 10 * time.Second
	kafkaConfig.Net.WriteTimeout = 10 * time.Second

	// Buat client
	client, err := sarama.NewClient(config.Brokers, kafkaConfig)
	if err != nil {
		b.Fatalf("Gagal membuat Kafka client: %v", err)
	}

	// Buat producer
	producer, err := sarama.NewSyncProducerFromClient(client)
	if err != nil {
		b.Fatalf("Gagal membuat Kafka producer: %v", err)
	}

	// Buat consumer
	consumer, err := sarama.NewConsumerFromClient(client)
	if err != nil {
		b.Fatalf("Gagal membuat Kafka consumer: %v", err)
	}

	return producer, consumer, client
}

func createTestTopicForBench(b *testing.B, client sarama.Client, topicName string) {
	admin, err := sarama.NewClusterAdminFromClient(client)
	if err != nil {
		b.Fatalf("Gagal membuat cluster admin: %v", err)
	}
	defer admin.Close()

	topicDetail := &sarama.TopicDetail{
		NumPartitions:     6, // Lebih banyak partisi untuk performa
		ReplicationFactor: 1,
	}

	err = admin.CreateTopic(topicName, topicDetail, false)
	if err != nil && err != sarama.ErrTopicAlreadyExists {
		b.Logf("Peringatan: Gagal membuat topic %s: %v", topicName, err)
	}

	// Tunggu topic tersedia
	time.Sleep(1 * time.Second)
}

func runProductionTestForBench(b *testing.B, producer sarama.SyncProducer, config *PerformanceTestConfig) *PerformanceMetrics {
	var (
		successCount = int64(0)
		failCount    = int64(0)
		totalLatency = int64(0)
	)

	start := time.Now()
	var wg sync.WaitGroup
	errorChan := make(chan error, config.MessageCount)

	// Buat worker pool untuk concurrency
	messageChan := make(chan int, config.MessageCount)
	for i := 0; i < config.MessageCount; i++ {
		messageChan <- i
	}
	close(messageChan)

	// Jalankan worker goroutines
	for w := 0; w < config.Concurrency; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for msgIndex := range messageChan {
				msgStart := time.Now()
				msgID := fmt.Sprintf("bench-msg-%d-%d", workerID, msgIndex)
				
				testMsg := TestMessage{
					ID:        msgID,
					Content:   fmt.Sprintf("Benchmark test message %s from worker %d", msgID, workerID),
					Timestamp: time.Now(),
					Metadata: map[string]interface{}{
						"worker":      workerID,
						"index":       msgIndex,
						"performance": true,
						"test_type":   "benchmark",
					},
				}

				msgBytes, err := json.Marshal(testMsg)
				if err != nil {
					errorChan <- err
					atomic.AddInt64(&failCount, 1)
					continue
				}

				msg := &sarama.ProducerMessage{
					Topic:     config.TopicName,
					Key:       sarama.StringEncoder(msgID),
					Value:     sarama.ByteEncoder(msgBytes),
					Timestamp: time.Now(),
				}

				_, _, err = producer.SendMessage(msg)
				latency := time.Since(msgStart)
				atomic.AddInt64(&totalLatency, latency.Nanoseconds())

				if err != nil {
					errorChan <- err
					atomic.AddInt64(&failCount, 1)
				} else {
					atomic.AddInt64(&successCount, 1)
				}
			}
		}(w)
	}

	wg.Wait()
	productionTime := time.Since(start)
	close(errorChan)

	// Hitung metrik
	throughput := float64(successCount) / productionTime.Seconds()
	errorRate := float64(failCount) / float64(config.MessageCount) * 100
	avgLatency := time.Duration(totalLatency / int64(config.MessageCount))

	return &PerformanceMetrics{
		SuccessfulSent:  successCount,
		FailedSent:      failCount,
		ProductionTime:  productionTime,
		ThroughputSent:  throughput,
		ErrorRate:       errorRate,
		AverageLatency:  avgLatency,
	}
}

// BenchmarkKafka100Messages benchmark untuk pengujian performa 100 messages
func BenchmarkKafka100Messages(b *testing.B) {
	// Konfigurasi dari environment variables atau default
	messageCount := getEnvInt("TEST_MESSAGE_COUNT", 100)
	batchSize := getEnvInt("TEST_BATCH_SIZE", 10)
	concurrency := getEnvInt("TEST_CONCURRENCY", 5)
	brokers := getEnvStringSlice("KAFKA_BROKERS", []string{"localhost:9092"})
	topicPrefix := getEnvString("KAFKA_TOPIC_PREFIX", "docker-bench")
	
	config := &PerformanceTestConfig{
		MessageCount: messageCount,
		BatchSize:    batchSize,
		Concurrency:  concurrency,
		MaxDuration:  2 * time.Minute,
		Brokers:      brokers,
		TopicName:    fmt.Sprintf("%s-%d", topicPrefix, time.Now().Unix()),
	}

	// Setup Kafka clients
	producer, consumer, client := setupKafkaClientsForBench(b, config)
	defer cleanup(producer, consumer, client)
	createTestTopicForBench(b, client, config.TopicName)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runProductionTestForBench(b, producer, config)
	}
}

// BenchmarkKafka10000Messages benchmark untuk pengujian performa
func BenchmarkKafka10000Messages(b *testing.B) {
	config := &PerformanceTestConfig{
		MessageCount: 10000,
		BatchSize:    100,
		Concurrency:  10,
		MaxDuration:  5 * time.Minute,
		Brokers:      []string{"localhost:9092"},
		TopicName:    fmt.Sprintf("bench-test-%d", time.Now().Unix()),
	}

	// Convert *testing.B to interface{} that has similar methods
	producer, consumer, client := setupKafkaClientsForBench(b, config)
	defer cleanup(producer, consumer, client)
	createTestTopicForBench(b, client, config.TopicName)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runProductionTestForBench(b, producer, config)
	}
}