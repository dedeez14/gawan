package metrics

import (
	"context"
	"time"
)

// Counter represents a monotonically increasing counter metric
type Counter interface {
	// Inc increments the counter by 1
	Inc(ctx context.Context, labels ...Label)
	// Add increments the counter by the given value
	Add(ctx context.Context, value float64, labels ...Label)
}

// Histogram represents a histogram metric for measuring distributions
type Histogram interface {
	// Observe records a value in the histogram
	Observe(ctx context.Context, value float64, labels ...Label)
	// Time records the duration of a function execution
	Time(ctx context.Context, labels ...Label) func()
}

// Gauge represents a gauge metric that can go up and down
type Gauge interface {
	// Set sets the gauge to the given value
	Set(ctx context.Context, value float64, labels ...Label)
	// Inc increments the gauge by 1
	Inc(ctx context.Context, labels ...Label)
	// Dec decrements the gauge by 1
	Dec(ctx context.Context, labels ...Label)
	// Add adds the given value to the gauge
	Add(ctx context.Context, value float64, labels ...Label)
	// Sub subtracts the given value from the gauge
	Sub(ctx context.Context, value float64, labels ...Label)
}

// Label represents a key-value pair for metric labels
type Label struct {
	Key   string
	Value string
}

// Labels creates a slice of labels from key-value pairs
func Labels(keyValues ...string) []Label {
	if len(keyValues)%2 != 0 {
		panic("labels must be provided in key-value pairs")
	}
	
	labels := make([]Label, 0, len(keyValues)/2)
	for i := 0; i < len(keyValues); i += 2 {
		labels = append(labels, Label{
			Key:   keyValues[i],
			Value: keyValues[i+1],
		})
	}
	return labels
}

// MetricsProvider defines the interface for creating metrics
type MetricsProvider interface {
	// NewCounter creates a new counter metric
	NewCounter(name, help string) Counter
	// NewHistogram creates a new histogram metric
	NewHistogram(name, help string, buckets []float64) Histogram
	// NewGauge creates a new gauge metric
	NewGauge(name, help string) Gauge
	// Start initializes the metrics provider
	Start(ctx context.Context) error
	// Stop gracefully shuts down the metrics provider
	Stop(ctx context.Context) error
}

// Config holds configuration for metrics
type Config struct {
	// Enabled determines if metrics collection is enabled
	Enabled bool `json:"enabled" yaml:"enabled" env:"METRICS_ENABLED" default:"true"`
	// Provider specifies the metrics provider (prometheus, otel, noop)
	Provider string `json:"provider" yaml:"provider" env:"METRICS_PROVIDER" default:"prometheus"`
	// Namespace is the metrics namespace/prefix
	Namespace string `json:"namespace" yaml:"namespace" env:"METRICS_NAMESPACE" default:"gawan"`
	// Address is the metrics server address
	Address string `json:"address" yaml:"address" env:"METRICS_ADDRESS" default:":9090"`
	// Path is the metrics endpoint path
	Path string `json:"path" yaml:"path" env:"METRICS_PATH" default:"/metrics"`
}

// DefaultBuckets provides default histogram buckets for HTTP request durations
var DefaultBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// HTTPBuckets provides histogram buckets optimized for HTTP request durations
var HTTPBuckets = []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}

// Timer is a helper for timing operations
type Timer struct {
	start time.Time
	hist  Histogram
	ctx   context.Context
	labels []Label
}

// NewTimer creates a new timer for the given histogram
func NewTimer(ctx context.Context, hist Histogram, labels ...Label) *Timer {
	return &Timer{
		start:  time.Now(),
		hist:   hist,
		ctx:    ctx,
		labels: labels,
	}
}

// Stop stops the timer and records the duration
func (t *Timer) Stop() {
	duration := time.Since(t.start).Seconds()
	t.hist.Observe(t.ctx, duration, t.labels...)
}

// ObserveDuration is a helper to time a function execution
func ObserveDuration(ctx context.Context, hist Histogram, labels []Label, fn func()) {
	timer := NewTimer(ctx, hist, labels...)
	defer timer.Stop()
	fn()
}