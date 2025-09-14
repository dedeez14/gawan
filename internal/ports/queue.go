package ports

import (
	"context"
	"time"
)

// QueuePort defines the interface for queue operations
type QueuePort interface {
	// Publish publishes a message to a queue
	Publish(ctx context.Context, queueName string, message *Message) error

	// PublishBatch publishes multiple messages to a queue
	PublishBatch(ctx context.Context, queueName string, messages []*Message) error

	// Subscribe subscribes to a queue and processes messages
	Subscribe(ctx context.Context, queueName string, handler MessageHandler) error

	// SubscribeWithWorkers subscribes to a queue with multiple workers
	SubscribeWithWorkers(ctx context.Context, queueName string, handler MessageHandler, workerCount int) error

	// Acknowledge acknowledges a message as processed
	Acknowledge(ctx context.Context, messageID string) error

	// Reject rejects a message and optionally requeues it
	Reject(ctx context.Context, messageID string, requeue bool) error

	// GetQueueInfo gets information about a queue
	GetQueueInfo(ctx context.Context, queueName string) (*QueueInfo, error)

	// PurgeQueue removes all messages from a queue
	PurgeQueue(ctx context.Context, queueName string) error

	// Close closes the queue connection
	Close() error
}

// Message represents a queue message
type Message struct {
	ID          string            `json:"id"`
	Body        []byte            `json:"body"`
	Headers     map[string]string `json:"headers,omitempty"`
	Priority    int               `json:"priority,omitempty"`
	Delay       time.Duration     `json:"delay,omitempty"`
	TTL         time.Duration     `json:"ttl,omitempty"`
	RetryCount  int               `json:"retry_count,omitempty"`
	MaxRetries  int               `json:"max_retries,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	ScheduledAt *time.Time        `json:"scheduled_at,omitempty"`
}

// MessageHandler defines the function signature for message handlers
type MessageHandler func(ctx context.Context, message *Message) error

// QueueInfo represents information about a queue
type QueueInfo struct {
	Name            string `json:"name"`
	MessageCount    int64  `json:"message_count"`
	ConsumerCount   int    `json:"consumer_count"`
	PendingMessages int64  `json:"pending_messages"`
	ProcessedTotal  int64  `json:"processed_total"`
	FailedTotal     int64  `json:"failed_total"`
}

// QueueConfig holds queue configuration
type QueueConfig struct {
	BrokerURL       string        `json:"broker_url"`
	DefaultQueue    string        `json:"default_queue"`
	PrefetchCount   int           `json:"prefetch_count"`
	ReconnectDelay  time.Duration `json:"reconnect_delay"`
	MaxReconnects   int           `json:"max_reconnects"`
	Heartbeat       time.Duration `json:"heartbeat"`
	ConnectionTimeout time.Duration `json:"connection_timeout"`
}

// JobPort defines the interface for job queue operations
type JobPort interface {
	// EnqueueJob enqueues a job for processing
	EnqueueJob(ctx context.Context, job *Job) error

	// EnqueueDelayedJob enqueues a job to be processed after a delay
	EnqueueDelayedJob(ctx context.Context, job *Job, delay time.Duration) error

	// EnqueueScheduledJob enqueues a job to be processed at a specific time
	EnqueueScheduledJob(ctx context.Context, job *Job, scheduledAt time.Time) error

	// ProcessJobs starts processing jobs from the queue
	ProcessJobs(ctx context.Context, jobType string, handler JobHandler) error

	// GetJobStatus gets the status of a job
	GetJobStatus(ctx context.Context, jobID string) (*JobStatus, error)

	// CancelJob cancels a pending job
	CancelJob(ctx context.Context, jobID string) error

	// RetryJob retries a failed job
	RetryJob(ctx context.Context, jobID string) error
}

// Job represents a background job
type Job struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Payload  map[string]interface{} `json:"payload"`
	Priority int                    `json:"priority,omitempty"`
	Retries  int                    `json:"retries,omitempty"`
	MaxRetries int                  `json:"max_retries,omitempty"`
	Timeout  time.Duration          `json:"timeout,omitempty"`
	CreatedAt time.Time             `json:"created_at"`
}

// JobHandler defines the function signature for job handlers
type JobHandler func(ctx context.Context, job *Job) error

// JobStatus represents the status of a job
type JobStatus struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Status      JobState  `json:"status"`
	Progress    int       `json:"progress,omitempty"`
	Result      string    `json:"result,omitempty"`
	Error       string    `json:"error,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	RetryCount  int       `json:"retry_count"`
}

// JobState represents the state of a job
type JobState string

const (
	JobStatePending   JobState = "pending"
	JobStateRunning   JobState = "running"
	JobStateCompleted JobState = "completed"
	JobStateFailed    JobState = "failed"
	JobStateCancelled JobState = "cancelled"
)