package metrics

import "context"

// NoopProvider implements MetricsProvider with no-op operations
type NoopProvider struct{}

// NewNoopProvider creates a new no-op metrics provider
func NewNoopProvider() *NoopProvider {
	return &NoopProvider{}
}

// Start is a no-op
func (n *NoopProvider) Start(ctx context.Context) error {
	return nil
}

// Stop is a no-op
func (n *NoopProvider) Stop(ctx context.Context) error {
	return nil
}

// NewCounter creates a no-op counter
func (n *NoopProvider) NewCounter(name, help string) Counter {
	return &noopCounter{}
}

// NewHistogram creates a no-op histogram
func (n *NoopProvider) NewHistogram(name, help string, buckets []float64) Histogram {
	return &noopHistogram{}
}

// NewGauge creates a no-op gauge
func (n *NoopProvider) NewGauge(name, help string) Gauge {
	return &noopGauge{}
}

// noopCounter implements Counter interface with no-op operations
type noopCounter struct{}

func (c *noopCounter) Inc(ctx context.Context, labels ...Label) {}

func (c *noopCounter) Add(ctx context.Context, value float64, labels ...Label) {}

// noopHistogram implements Histogram interface with no-op operations
type noopHistogram struct{}

func (h *noopHistogram) Observe(ctx context.Context, value float64, labels ...Label) {}

func (h *noopHistogram) Time(ctx context.Context, labels ...Label) func() {
	return func() {} // Return a no-op function
}

// noopGauge implements Gauge interface with no-op operations
type noopGauge struct{}

func (g *noopGauge) Set(ctx context.Context, value float64, labels ...Label) {}

func (g *noopGauge) Inc(ctx context.Context, labels ...Label) {}

func (g *noopGauge) Dec(ctx context.Context, labels ...Label) {}

func (g *noopGauge) Add(ctx context.Context, value float64, labels ...Label) {}

func (g *noopGauge) Sub(ctx context.Context, value float64, labels ...Label) {}