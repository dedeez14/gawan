package test

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/IBM/sarama"
)

// KafkaTestConfig menyediakan konfigurasi untuk pengujian Kafka
type KafkaTestConfig struct {
	Brokers              []string
	TopicPrefix          string
	Partitions           int32
	ReplicationFactor    int16
	ProducerConfig       *sarama.Config
	ConsumerConfig       *sarama.Config
	TestTimeout          time.Duration
	RetryAttempts        int
	RetryBackoff         time.Duration
	PerformanceThreshold struct {
		MinThroughput    float64 // msg/s
		MaxLatency       time.Duration
		MaxErrorRate     float64 // percentage
	}
}

// DefaultKafkaTestConfig mengembalikan konfigurasi default untuk pengujian
func DefaultKafkaTestConfig() *KafkaTestConfig {
	config := &KafkaTestConfig{
		Brokers:           getBrokersFromEnv(),
		TopicPrefix:       "test-",
		Partitions:        3,
		ReplicationFactor: 1,
		TestTimeout:       30 * time.Second,
		RetryAttempts:     3,
		RetryBackoff:      100 * time.Millisecond,
	}

	// Konfigurasi producer
	config.ProducerConfig = sarama.NewConfig()
	config.ProducerConfig.Producer.Return.Successes = true
	config.ProducerConfig.Producer.Return.Errors = true
	config.ProducerConfig.Producer.RequiredAcks = sarama.WaitForAll
	config.ProducerConfig.Producer.Retry.Max = config.RetryAttempts
	config.ProducerConfig.Producer.Retry.Backoff = config.RetryBackoff
	config.ProducerConfig.Producer.Timeout = 10 * time.Second
	config.ProducerConfig.Producer.Compression = sarama.CompressionSnappy
	config.ProducerConfig.Producer.Flush.Frequency = 100 * time.Millisecond
	config.ProducerConfig.Producer.Flush.Messages = 100

	// Konfigurasi consumer
	config.ConsumerConfig = sarama.NewConfig()
	config.ConsumerConfig.Consumer.Return.Errors = true
	config.ConsumerConfig.Consumer.Group.Rebalance.Strategy = sarama.BalanceStrategyRoundRobin
	config.ConsumerConfig.Consumer.Offsets.Initial = sarama.OffsetOldest
	config.ConsumerConfig.Consumer.Group.Session.Timeout = 10 * time.Second
	config.ConsumerConfig.Consumer.Group.Heartbeat.Interval = 3 * time.Second
	config.ConsumerConfig.Consumer.MaxProcessingTime = 1 * time.Second

	// Threshold performa
	config.PerformanceThreshold.MinThroughput = 50.0
	config.PerformanceThreshold.MaxLatency = 1 * time.Second
	config.PerformanceThreshold.MaxErrorRate = 1.0

	return config
}

// DevelopmentKafkaTestConfig konfigurasi untuk environment development
func DevelopmentKafkaTestConfig() *KafkaTestConfig {
	config := DefaultKafkaTestConfig()
	
	// Konfigurasi lebih permisif untuk development
	config.TestTimeout = 60 * time.Second
	config.RetryAttempts = 5
	config.PerformanceThreshold.MinThroughput = 10.0
	config.PerformanceThreshold.MaxLatency = 5 * time.Second
	config.PerformanceThreshold.MaxErrorRate = 5.0

	// Producer config untuk development
	config.ProducerConfig.Producer.RequiredAcks = sarama.WaitForLocal
	config.ProducerConfig.Producer.Compression = sarama.CompressionNone
	config.ProducerConfig.Producer.Flush.Frequency = 500 * time.Millisecond

	return config
}

// ProductionKafkaTestConfig konfigurasi untuk environment production
func ProductionKafkaTestConfig() *KafkaTestConfig {
	config := DefaultKafkaTestConfig()
	
	// Konfigurasi ketat untuk production
	config.ReplicationFactor = 3
	config.TestTimeout = 15 * time.Second
	config.RetryAttempts = 2
	config.PerformanceThreshold.MinThroughput = 100.0
	config.PerformanceThreshold.MaxLatency = 500 * time.Millisecond
	config.PerformanceThreshold.MaxErrorRate = 0.1

	// Producer config untuk production
	config.ProducerConfig.Producer.RequiredAcks = sarama.WaitForAll
	config.ProducerConfig.Producer.Compression = sarama.CompressionLZ4
	config.ProducerConfig.Producer.Flush.Frequency = 50 * time.Millisecond
	config.ProducerConfig.Producer.Flush.Messages = 50
	config.ProducerConfig.Producer.Idempotent = true
	config.ProducerConfig.Net.MaxOpenRequests = 1

	// Consumer config untuk production
	config.ConsumerConfig.Consumer.Group.Session.Timeout = 6 * time.Second
	config.ConsumerConfig.Consumer.Group.Heartbeat.Interval = 2 * time.Second
	config.ConsumerConfig.Consumer.MaxProcessingTime = 500 * time.Millisecond

	return config
}

// CIKafkaTestConfig konfigurasi untuk Continuous Integration
func CIKafkaTestConfig() *KafkaTestConfig {
	config := DefaultKafkaTestConfig()
	
	// Konfigurasi cepat untuk CI
	config.TestTimeout = 20 * time.Second
	config.RetryAttempts = 2
	config.PerformanceThreshold.MinThroughput = 20.0
	config.PerformanceThreshold.MaxLatency = 2 * time.Second
	config.PerformanceThreshold.MaxErrorRate = 2.0

	// Optimasi untuk CI environment
	config.ProducerConfig.Producer.Flush.Frequency = 200 * time.Millisecond
	config.ProducerConfig.Producer.Flush.Messages = 50
	config.ConsumerConfig.Consumer.MaxProcessingTime = 2 * time.Second

	return config
}

// getBrokersFromEnv mendapatkan daftar broker dari environment variable
func getBrokersFromEnv() []string {
	brokers := os.Getenv("KAFKA_BROKERS")
	if brokers == "" {
		// Default ke localhost jika tidak ada environment variable
		return []string{"localhost:9092"}
	}
	return strings.Split(brokers, ",")
}

// GetConfigForEnvironment mengembalikan konfigurasi berdasarkan environment
func GetConfigForEnvironment(env string) *KafkaTestConfig {
	switch strings.ToLower(env) {
	case "development", "dev":
		return DevelopmentKafkaTestConfig()
	case "production", "prod":
		return ProductionKafkaTestConfig()
	case "ci", "continuous-integration":
		return CIKafkaTestConfig()
	default:
		return DefaultKafkaTestConfig()
	}
}

// ValidateConfig memvalidasi konfigurasi test
func (c *KafkaTestConfig) ValidateConfig() error {
	if len(c.Brokers) == 0 {
		return fmt.Errorf("tidak ada broker yang dikonfigurasi")
	}

	if c.Partitions <= 0 {
		return fmt.Errorf("jumlah partisi harus lebih dari 0")
	}

	if c.ReplicationFactor <= 0 {
		return fmt.Errorf("replication factor harus lebih dari 0")
	}

	if c.TestTimeout <= 0 {
		return fmt.Errorf("test timeout harus lebih dari 0")
	}

	if c.RetryAttempts < 0 {
		return fmt.Errorf("retry attempts tidak boleh negatif")
	}

	if c.PerformanceThreshold.MinThroughput < 0 {
		return fmt.Errorf("minimum throughput tidak boleh negatif")
	}

	if c.PerformanceThreshold.MaxErrorRate < 0 || c.PerformanceThreshold.MaxErrorRate > 100 {
		return fmt.Errorf("max error rate harus antara 0-100")
	}

	return nil
}

// GetTopicName menghasilkan nama topic dengan prefix
func (c *KafkaTestConfig) GetTopicName(suffix string) string {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	return c.TopicPrefix + suffix + "-" + timestamp
}

// IsPerformanceAcceptable mengecek apakah performa memenuhi threshold
func (c *KafkaTestConfig) IsPerformanceAcceptable(throughput float64, latency time.Duration, errorRate float64) bool {
	if throughput < c.PerformanceThreshold.MinThroughput {
		return false
	}

	if latency > c.PerformanceThreshold.MaxLatency {
		return false
	}

	if errorRate > c.PerformanceThreshold.MaxErrorRate {
		return false
	}

	return true
}

// KafkaTestEnvironment menyediakan environment untuk pengujian
type KafkaTestEnvironment struct {
	Config   *KafkaTestConfig
	Client   sarama.Client
	Producer sarama.SyncProducer
	Consumer sarama.Consumer
	Admin    sarama.ClusterAdmin
	Topics   []string
}

// NewKafkaTestEnvironment membuat environment pengujian baru
func NewKafkaTestEnvironment(config *KafkaTestConfig) (*KafkaTestEnvironment, error) {
	if err := config.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("konfigurasi tidak valid: %w", err)
	}

	env := &KafkaTestEnvironment{
		Config: config,
		Topics: make([]string, 0),
	}

	// Buat client
	client, err := sarama.NewClient(config.Brokers, config.ProducerConfig)
	if err != nil {
		return nil, fmt.Errorf("gagal membuat client: %w", err)
	}
	env.Client = client

	// Buat producer
	producer, err := sarama.NewSyncProducerFromClient(client)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("gagal membuat producer: %w", err)
	}
	env.Producer = producer

	// Buat consumer
	consumer, err := sarama.NewConsumerFromClient(client)
	if err != nil {
		producer.Close()
		client.Close()
		return nil, fmt.Errorf("gagal membuat consumer: %w", err)
	}
	env.Consumer = consumer

	// Buat admin
	admin, err := sarama.NewClusterAdminFromClient(client)
	if err != nil {
		consumer.Close()
		producer.Close()
		client.Close()
		return nil, fmt.Errorf("gagal membuat admin: %w", err)
	}
	env.Admin = admin

	return env, nil
}

// CreateTopic membuat topic untuk pengujian
func (e *KafkaTestEnvironment) CreateTopic(topicName string) error {
	topicDetail := &sarama.TopicDetail{
		NumPartitions:     e.Config.Partitions,
		ReplicationFactor: e.Config.ReplicationFactor,
	}

	err := e.Admin.CreateTopic(topicName, topicDetail, false)
	if err != nil && err != sarama.ErrTopicAlreadyExists {
		return fmt.Errorf("gagal membuat topic %s: %w", topicName, err)
	}

	e.Topics = append(e.Topics, topicName)
	
	// Tunggu topic tersedia
	time.Sleep(2 * time.Second)
	return nil
}

// Cleanup membersihkan resources
func (e *KafkaTestEnvironment) Cleanup() {
	// Hapus topics yang dibuat
	for _, topic := range e.Topics {
		e.Admin.DeleteTopic(topic)
	}

	// Tutup connections
	if e.Admin != nil {
		e.Admin.Close()
	}
	if e.Consumer != nil {
		e.Consumer.Close()
	}
	if e.Producer != nil {
		e.Producer.Close()
	}
	if e.Client != nil {
		e.Client.Close()
	}
}

// HealthCheck mengecek kesehatan koneksi Kafka
func (e *KafkaTestEnvironment) HealthCheck() error {
	// Cek broker connectivity
	brokers := e.Client.Brokers()
	if len(brokers) == 0 {
		return fmt.Errorf("tidak ada broker yang tersedia")
	}

	for _, broker := range brokers {
		connected, err := broker.Connected()
		if err != nil {
			return fmt.Errorf("error mengecek koneksi broker %s: %w", broker.Addr(), err)
		}
		if !connected {
			return fmt.Errorf("broker %s tidak terhubung", broker.Addr())
		}
	}

	// Test broker connectivity by getting coordinator
	_, err := e.Client.Coordinator("__consumer_offsets")
	if err != nil {
		return fmt.Errorf("failed to get coordinator: %w", err)
	}

	return nil
}