package test

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// KafkaTestSuite adalah test suite untuk pengujian integrasi Kafka
type KafkaTestSuite struct {
	suite.Suite
	brokers    []string
	topicName  string
	producer   sarama.SyncProducer
	consumer   sarama.Consumer
	client     sarama.Client
}

// TestMessage adalah struktur pesan untuk pengujian
type TestMessage struct {
	ID        string    `json:"id"`
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// SetupSuite dijalankan sekali sebelum semua test
func (suite *KafkaTestSuite) SetupSuite() {
	// Konfigurasi broker Kafka (sesuaikan dengan environment Anda)
	suite.brokers = []string{"localhost:9092"}
	suite.topicName = "test-topic-" + strconv.FormatInt(time.Now().Unix(), 10)

	// Konfigurasi Kafka client
	config := sarama.NewConfig()
	config.Producer.Return.Successes = true
	config.Producer.Return.Errors = true
	config.Producer.RequiredAcks = sarama.WaitForAll
	config.Producer.Retry.Max = 5
	config.Producer.Retry.Backoff = 100 * time.Millisecond
	config.Consumer.Return.Errors = true
	config.Consumer.Group.Rebalance.Strategy = sarama.BalanceStrategyRoundRobin
	config.Consumer.Offsets.Initial = sarama.OffsetOldest

	// Membuat client
	client, err := sarama.NewClient(suite.brokers, config)
	require.NoError(suite.T(), err, "Gagal membuat Kafka client")
	suite.client = client

	// Membuat producer
	producer, err := sarama.NewSyncProducerFromClient(client)
	require.NoError(suite.T(), err, "Gagal membuat Kafka producer")
	suite.producer = producer

	// Membuat consumer
	consumer, err := sarama.NewConsumerFromClient(client)
	require.NoError(suite.T(), err, "Gagal membuat Kafka consumer")
	suite.consumer = consumer

	// Membuat topic untuk pengujian
	suite.createTestTopic()
}

// TearDownSuite dijalankan sekali setelah semua test
func (suite *KafkaTestSuite) TearDownSuite() {
	if suite.producer != nil {
		suite.producer.Close()
	}
	if suite.consumer != nil {
		suite.consumer.Close()
	}
	if suite.client != nil {
		suite.client.Close()
	}

	// Hapus topic test (opsional)
	suite.deleteTestTopic()
}

// createTestTopic membuat topic untuk pengujian
func (suite *KafkaTestSuite) createTestTopic() {
	admin, err := sarama.NewClusterAdminFromClient(suite.client)
	require.NoError(suite.T(), err, "Gagal membuat cluster admin")
	defer admin.Close()

	topicDetail := &sarama.TopicDetail{
		NumPartitions:     3,
		ReplicationFactor: 1,
	}

	err = admin.CreateTopic(suite.topicName, topicDetail, false)
	if err != nil && err != sarama.ErrTopicAlreadyExists {
		require.NoError(suite.T(), err, "Gagal membuat topic")
	}

	// Tunggu topic tersedia
	time.Sleep(2 * time.Second)
}

// deleteTestTopic menghapus topic setelah pengujian
func (suite *KafkaTestSuite) deleteTestTopic() {
	admin, err := sarama.NewClusterAdminFromClient(suite.client)
	if err != nil {
		return
	}
	defer admin.Close()

	admin.DeleteTopic(suite.topicName)
}

// TestKafkaConnectivity menguji konektivitas ke broker Kafka
func (suite *KafkaTestSuite) TestKafkaConnectivity() {
	// Test 1: Verifikasi koneksi ke broker
	brokers := suite.client.Brokers()
	assert.NotEmpty(suite.T(), brokers, "Tidak ada broker yang tersedia")

	// Test 2: Verifikasi broker dapat diakses
	for _, broker := range brokers {
		connected, err := broker.Connected()
		assert.NoError(suite.T(), err, "Error saat mengecek koneksi broker")
		assert.True(suite.T(), connected, fmt.Sprintf("Broker %s tidak terhubung", broker.Addr()))
	}

	// Test 3: Verifikasi broker connectivity
	_, err := suite.client.Coordinator("__consumer_offsets")
	assert.NoError(suite.T(), err, "Gagal mendapatkan coordinator dari broker")

	// Test 4: Verifikasi topic tersedia
	topics, err := suite.client.Topics()
	assert.NoError(suite.T(), err, "Gagal mendapatkan daftar topic")
	assert.Contains(suite.T(), topics, suite.topicName, "Topic test tidak ditemukan")
}

// TestMessageProduction menguji kemampuan memproduksi pesan
func (suite *KafkaTestSuite) TestMessageProduction() {
	// Test 1: Produksi pesan tunggal
	testMsg := TestMessage{
		ID:        "test-001",
		Content:   "Hello Kafka!",
		Timestamp: time.Now(),
		Metadata: map[string]interface{}{
			"source": "unit-test",
			"version": "1.0",
		},
	}

	msgBytes, err := json.Marshal(testMsg)
	require.NoError(suite.T(), err, "Gagal marshal pesan")

	msg := &sarama.ProducerMessage{
		Topic: suite.topicName,
		Key:   sarama.StringEncoder(testMsg.ID),
		Value: sarama.ByteEncoder(msgBytes),
		Headers: []sarama.RecordHeader{
			{Key: []byte("content-type"), Value: []byte("application/json")},
			{Key: []byte("producer"), Value: []byte("kafka-test-suite")},
		},
		Timestamp: time.Now(),
	}

	partition, offset, err := suite.producer.SendMessage(msg)
	assert.NoError(suite.T(), err, "Gagal mengirim pesan")
	assert.GreaterOrEqual(suite.T(), partition, int32(0), "Partition tidak valid")
	assert.GreaterOrEqual(suite.T(), offset, int64(0), "Offset tidak valid")

	// Test 2: Produksi batch pesan
	batchSize := 10
	var wg sync.WaitGroup
	errorChan := make(chan error, batchSize)

	for i := 0; i < batchSize; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			batchMsg := TestMessage{
				ID:        fmt.Sprintf("batch-%03d", index),
				Content:   fmt.Sprintf("Batch message %d", index),
				Timestamp: time.Now(),
				Metadata: map[string]interface{}{
					"batch_id": "batch-001",
					"index":    index,
				},
			}

			msgBytes, err := json.Marshal(batchMsg)
			if err != nil {
				errorChan <- err
				return
			}

			msg := &sarama.ProducerMessage{
				Topic:     suite.topicName,
				Key:       sarama.StringEncoder(batchMsg.ID),
				Value:     sarama.ByteEncoder(msgBytes),
				Timestamp: time.Now(),
			}

			_, _, err = suite.producer.SendMessage(msg)
			if err != nil {
				errorChan <- err
			}
		}(i)
	}

	wg.Wait()
	close(errorChan)

	// Verifikasi tidak ada error dalam batch
	for err := range errorChan {
		assert.NoError(suite.T(), err, "Error dalam produksi batch")
	}
}

// TestMessageConsumption menguji kemampuan mengonsumsi pesan
func (suite *KafkaTestSuite) TestMessageConsumption() {
	// Produksi pesan untuk dikonsumsi
	testMessages := []TestMessage{
		{
			ID:        "consume-001",
			Content:   "Message for consumption test 1",
			Timestamp: time.Now(),
			Metadata:  map[string]interface{}{"test": "consumption"},
		},
		{
			ID:        "consume-002",
			Content:   "Message for consumption test 2",
			Timestamp: time.Now(),
			Metadata:  map[string]interface{}{"test": "consumption"},
		},
	}

	// Kirim pesan
	for _, testMsg := range testMessages {
		msgBytes, err := json.Marshal(testMsg)
		require.NoError(suite.T(), err)

		msg := &sarama.ProducerMessage{
			Topic:     suite.topicName,
			Key:       sarama.StringEncoder(testMsg.ID),
			Value:     sarama.ByteEncoder(msgBytes),
			Timestamp: time.Now(),
		}

		_, _, err = suite.producer.SendMessage(msg)
		require.NoError(suite.T(), err)
	}

	// Konsumsi pesan
	partitions, err := suite.consumer.Partitions(suite.topicName)
	require.NoError(suite.T(), err, "Gagal mendapatkan partisi")

	consumedMessages := make([]TestMessage, 0)
	var mu sync.Mutex
	var wg sync.WaitGroup

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, partition := range partitions {
		wg.Add(1)
		go func(partitionID int32) {
			defer wg.Done()

			partitionConsumer, err := suite.consumer.ConsumePartition(suite.topicName, partitionID, sarama.OffsetOldest)
			if err != nil {
				assert.NoError(suite.T(), err, "Gagal membuat partition consumer")
				return
			}
			defer partitionConsumer.Close()

			for {
				select {
				case msg := <-partitionConsumer.Messages():
					if msg != nil {
						var testMsg TestMessage
						err := json.Unmarshal(msg.Value, &testMsg)
						if err == nil {
							mu.Lock()
							consumedMessages = append(consumedMessages, testMsg)
							mu.Unlock()

							// Validasi metadata pesan
							assert.Equal(suite.T(), suite.topicName, msg.Topic)
							assert.GreaterOrEqual(suite.T(), msg.Partition, int32(0))
							assert.GreaterOrEqual(suite.T(), msg.Offset, int64(0))
							assert.NotEmpty(suite.T(), msg.Key)
						}
					}
				case err := <-partitionConsumer.Errors():
					if err != nil {
						assert.NoError(suite.T(), err, "Error dalam konsumsi pesan")
					}
				case <-ctx.Done():
					return
				}
			}
		}(partition)
	}

	wg.Wait()

	// Validasi pesan yang dikonsumsi
	assert.GreaterOrEqual(suite.T(), len(consumedMessages), len(testMessages), "Jumlah pesan yang dikonsumsi kurang")

	// Validasi integritas data
	for _, originalMsg := range testMessages {
		found := false
		for _, consumedMsg := range consumedMessages {
			if consumedMsg.ID == originalMsg.ID {
				assert.Equal(suite.T(), originalMsg.Content, consumedMsg.Content, "Content pesan tidak sama")
				assert.Equal(suite.T(), originalMsg.Metadata, consumedMsg.Metadata, "Metadata pesan tidak sama")
				found = true
				break
			}
		}
		assert.True(suite.T(), found, fmt.Sprintf("Pesan dengan ID %s tidak ditemukan", originalMsg.ID))
	}
}

// TestErrorHandlingAndRetry menguji penanganan error dan retry mechanism
func (suite *KafkaTestSuite) TestErrorHandlingAndRetry() {
	// Test 1: Simulasi error dengan topic yang tidak ada
	invalidTopic := "non-existent-topic-" + strconv.FormatInt(time.Now().Unix(), 10)
	msg := &sarama.ProducerMessage{
		Topic: invalidTopic,
		Key:   sarama.StringEncoder("test-key"),
		Value: sarama.StringEncoder("test-value"),
	}

	_, _, err := suite.producer.SendMessage(msg)
	assert.Error(suite.T(), err, "Seharusnya ada error untuk topic yang tidak ada")

	// Test 2: Test retry mechanism dengan konfigurasi producer
	config := sarama.NewConfig()
	config.Producer.Return.Successes = true
	config.Producer.Return.Errors = true
	config.Producer.RequiredAcks = sarama.WaitForAll
	config.Producer.Retry.Max = 3
	config.Producer.Retry.Backoff = 100 * time.Millisecond
	config.Producer.Timeout = 1 * time.Second

	retryProducer, err := sarama.NewSyncProducer(suite.brokers, config)
	require.NoError(suite.T(), err)
	defer retryProducer.Close()

	// Test dengan pesan yang valid untuk memastikan retry bekerja
	validMsg := &sarama.ProducerMessage{
		Topic: suite.topicName,
		Key:   sarama.StringEncoder("retry-test"),
		Value: sarama.StringEncoder("retry test message"),
	}

	start := time.Now()
	_, _, err = retryProducer.SendMessage(validMsg)
	duration := time.Since(start)

	assert.NoError(suite.T(), err, "Pesan valid seharusnya berhasil dikirim")
	assert.Less(suite.T(), duration, 5*time.Second, "Retry tidak boleh terlalu lama")

	// Test 3: Consumer error handling
	_, err = suite.consumer.ConsumePartition(invalidTopic, 0, sarama.OffsetOldest)
	assert.Error(suite.T(), err, "Seharusnya ada error untuk topic yang tidak ada")
}

// TestHighVolumePerformance menguji performa dengan volume pesan tinggi
func (suite *KafkaTestSuite) TestHighVolumePerformance() {
	messageCount := 1000
	batchSize := 100
	maxDuration := 30 * time.Second

	// Test produksi volume tinggi
	start := time.Now()
	var wg sync.WaitGroup
	errorChan := make(chan error, messageCount)
	successCount := int64(0)
	var successMutex sync.Mutex

	for batch := 0; batch < messageCount/batchSize; batch++ {
		wg.Add(1)
		go func(batchNum int) {
			defer wg.Done()
			for i := 0; i < batchSize; i++ {
				msgID := fmt.Sprintf("perf-%d-%d", batchNum, i)
				testMsg := TestMessage{
					ID:        msgID,
					Content:   fmt.Sprintf("Performance test message %s", msgID),
					Timestamp: time.Now(),
					Metadata: map[string]interface{}{
						"batch":       batchNum,
						"index":       i,
						"performance": true,
					},
				}

				msgBytes, err := json.Marshal(testMsg)
				if err != nil {
					errorChan <- err
					continue
				}

				msg := &sarama.ProducerMessage{
					Topic:     suite.topicName,
					Key:       sarama.StringEncoder(msgID),
					Value:     sarama.ByteEncoder(msgBytes),
					Timestamp: time.Now(),
				}

				_, _, err = suite.producer.SendMessage(msg)
				if err != nil {
					errorChan <- err
				} else {
					successMutex.Lock()
					successCount++
					successMutex.Unlock()
				}
			}
		}(batch)
	}

	wg.Wait()
	productionDuration := time.Since(start)
	close(errorChan)

	// Hitung error rate
	errorCount := 0
	for range errorChan {
		errorCount++
	}

	// Validasi performa produksi
	assert.Less(suite.T(), productionDuration, maxDuration, "Produksi terlalu lambat")
	assert.Equal(suite.T(), int64(messageCount), successCount, "Tidak semua pesan berhasil dikirim")
	assert.Equal(suite.T(), 0, errorCount, "Ada error dalam produksi volume tinggi")

	// Hitung throughput
	throughput := float64(messageCount) / productionDuration.Seconds()
	assert.Greater(suite.T(), throughput, 50.0, "Throughput terlalu rendah (< 50 msg/s)")

	suite.T().Logf("Performa Produksi:")
	suite.T().Logf("- Pesan: %d", messageCount)
	suite.T().Logf("- Durasi: %v", productionDuration)
	suite.T().Logf("- Throughput: %.2f msg/s", throughput)
	suite.T().Logf("- Error: %d", errorCount)

	// Test konsumsi volume tinggi
	time.Sleep(2 * time.Second) // Tunggu pesan tersedia

	consumeStart := time.Now()
	consumedCount := 0
	partitions, err := suite.consumer.Partitions(suite.topicName)
	require.NoError(suite.T(), err)

	var consumeWg sync.WaitGroup
	var consumeMutex sync.Mutex
	ctx, cancel := context.WithTimeout(context.Background(), maxDuration)
	defer cancel()

	for _, partition := range partitions {
		consumeWg.Add(1)
		go func(partitionID int32) {
			defer consumeWg.Done()

			partitionConsumer, err := suite.consumer.ConsumePartition(suite.topicName, partitionID, sarama.OffsetOldest)
			if err != nil {
				return
			}
			defer partitionConsumer.Close()

			for {
				select {
				case msg := <-partitionConsumer.Messages():
					if msg != nil {
						consumeMutex.Lock()
						consumedCount++
						consumeMutex.Unlock()
					}
				case <-ctx.Done():
					return
				}
			}
		}(partition)
	}

	consumeWg.Wait()
	consumptionDuration := time.Since(consumeStart)

	// Validasi performa konsumsi
	assert.GreaterOrEqual(suite.T(), consumedCount, messageCount/2, "Konsumsi terlalu sedikit")
	assert.Less(suite.T(), consumptionDuration, maxDuration, "Konsumsi terlalu lambat")

	consumeThroughput := float64(consumedCount) / consumptionDuration.Seconds()

	suite.T().Logf("Performa Konsumsi:")
	suite.T().Logf("- Pesan dikonsumsi: %d", consumedCount)
	suite.T().Logf("- Durasi: %v", consumptionDuration)
	suite.T().Logf("- Throughput: %.2f msg/s", consumeThroughput)
}

// TestDataIntegrityAndMetadata menguji integritas data dan metadata
func (suite *KafkaTestSuite) TestDataIntegrityAndMetadata() {
	// Pesan dengan berbagai tipe data
	testCases := []struct {
		name    string
		message TestMessage
	}{
		{
			name: "String content",
			message: TestMessage{
				ID:        "integrity-001",
				Content:   "Test string with special chars: àáâãäåæçèéêë",
				Timestamp: time.Now(),
				Metadata:  map[string]interface{}{"type": "string"},
			},
		},
		{
			name: "JSON content",
			message: TestMessage{
				ID:        "integrity-002",
				Content:   `{"nested": {"value": 123, "array": [1,2,3]}}`,
				Timestamp: time.Now(),
				Metadata:  map[string]interface{}{"type": "json", "nested": map[string]interface{}{"level": 2}},
			},
		},
		{
			name: "Large content",
			message: TestMessage{
				ID:        "integrity-003",
				Content:   string(make([]byte, 10000)), // 10KB content
				Timestamp: time.Now(),
				Metadata:  map[string]interface{}{"type": "large", "size": 10000},
			},
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			// Produksi pesan
			msgBytes, err := json.Marshal(tc.message)
			require.NoError(t, err)

			headers := []sarama.RecordHeader{
				{Key: []byte("content-type"), Value: []byte("application/json")},
				{Key: []byte("test-case"), Value: []byte(tc.name)},
				{Key: []byte("timestamp"), Value: []byte(tc.message.Timestamp.Format(time.RFC3339))},
			}

			msg := &sarama.ProducerMessage{
				Topic:     suite.topicName,
				Key:       sarama.StringEncoder(tc.message.ID),
				Value:     sarama.ByteEncoder(msgBytes),
				Headers:   headers,
				Timestamp: tc.message.Timestamp,
			}

			partition, offset, err := suite.producer.SendMessage(msg)
			require.NoError(t, err)

			// Konsumsi dan validasi pesan
			partitionConsumer, err := suite.consumer.ConsumePartition(suite.topicName, partition, offset)
			require.NoError(t, err)
			defer partitionConsumer.Close()

			select {
			case consumedMsg := <-partitionConsumer.Messages():
				// Validasi metadata Kafka
				assert.Equal(t, suite.topicName, consumedMsg.Topic)
				assert.Equal(t, partition, consumedMsg.Partition)
				assert.Equal(t, offset, consumedMsg.Offset)
				assert.Equal(t, string(tc.message.ID), string(consumedMsg.Key))

				// Validasi headers
				assert.Len(t, consumedMsg.Headers, len(headers))
				for _, expectedHeader := range headers {
					found := false
					for _, actualHeader := range consumedMsg.Headers {
						if string(actualHeader.Key) == string(expectedHeader.Key) {
							assert.Equal(t, expectedHeader.Value, actualHeader.Value)
							found = true
							break
						}
					}
					assert.True(t, found, fmt.Sprintf("Header %s tidak ditemukan", string(expectedHeader.Key)))
				}

				// Validasi integritas data
				var consumedTestMsg TestMessage
				err = json.Unmarshal(consumedMsg.Value, &consumedTestMsg)
				require.NoError(t, err)

				assert.Equal(t, tc.message.ID, consumedTestMsg.ID)
				assert.Equal(t, tc.message.Content, consumedTestMsg.Content)
				assert.Equal(t, tc.message.Metadata, consumedTestMsg.Metadata)
				
				// Validasi timestamp (dengan toleransi)
				timeDiff := tc.message.Timestamp.Sub(consumedTestMsg.Timestamp)
				assert.Less(t, timeDiff.Abs(), time.Second, "Timestamp tidak akurat")

			case <-time.After(5 * time.Second):
				t.Fatal("Timeout menunggu pesan")
			}
		})
	}
}

// TestKafkaIntegration menjalankan semua test dalam suite
func TestKafkaIntegration(t *testing.T) {
	// Skip test jika Kafka tidak tersedia
	if testing.Short() {
		t.Skip("Skipping Kafka integration tests in short mode")
	}

	suite.Run(t, new(KafkaTestSuite))
}

// BenchmarkKafkaProduction benchmark untuk produksi pesan
func BenchmarkKafkaProduction(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping Kafka benchmark in short mode")
	}

	brokers := []string{"localhost:9092"}
	config := sarama.NewConfig()
	config.Producer.Return.Successes = true
	config.Producer.RequiredAcks = sarama.WaitForAll

	producer, err := sarama.NewSyncProducer(brokers, config)
	if err != nil {
		b.Fatalf("Gagal membuat producer: %v", err)
	}
	defer producer.Close()

	topicName := "benchmark-topic"
	msg := &sarama.ProducerMessage{
		Topic: topicName,
		Value: sarama.StringEncoder("benchmark message"),
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, err := producer.SendMessage(msg)
			if err != nil {
				b.Errorf("Error sending message: %v", err)
			}
		}
	})
}