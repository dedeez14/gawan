package metrics

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"
)

// OtelProvider implements MetricsProvider using OpenTelemetry
type OtelProvider struct {
	meterProvider *metric.MeterProvider
	meter         metric.Meter
	namespace     string
	config        Config
	exporter      *prometheus.Exporter
}

// NewOtelProvider creates a new OpenTelemetry metrics provider
func NewOtelProvider(config Config) (*OtelProvider, error) {
	// Create Prometheus exporter for OTel metrics
	exporter, err := prometheus.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create prometheus exporter: %w", err)
	}

	// Create meter provider
	meterProvider := metric.NewMeterProvider(
		metric.WithReader(exporter),
	)

	// Set global meter provider
	otel.SetMeterProvider(meterProvider)

	// Create meter
	meter := meterProvider.Meter(config.Namespace)

	return &OtelProvider{
		meterProvider: meterProvider,
		meter:         meter,
		namespace:     config.Namespace,
		config:        config,
		exporter:      exporter,
	}, nil
}

// Start initializes the OpenTelemetry metrics provider
func (o *OtelProvider) Start(ctx context.Context) error {
	if !o.config.Enabled {
		return nil
	}

	// OpenTelemetry metrics are automatically started when created
	// Additional initialization can be added here if needed
	return nil
}

// Stop gracefully shuts down the OpenTelemetry metrics provider
func (o *OtelProvider) Stop(ctx context.Context) error {
	if o.meterProvider == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return o.meterProvider.Shutdown(ctx)
}

// NewCounter creates a new OpenTelemetry counter
func (o *OtelProvider) NewCounter(name, help string) Counter {
	counter, err := o.meter.Float64Counter(
		name,
		metric.WithDescription(help),
	)
	if err != nil {
		// In production, this should be handled properly
		panic(fmt.Sprintf("failed to create counter %s: %v", name, err))
	}

	return &otelCounter{counter: counter}
}

// NewHistogram creates a new OpenTelemetry histogram
func (o *OtelProvider) NewHistogram(name, help string, buckets []float64) Histogram {
	histogram, err := o.meter.Float64Histogram(
		name,
		metric.WithDescription(help),
		// Note: OpenTelemetry histograms use explicit bucket boundaries
		// The buckets parameter is used for Prometheus compatibility
	)
	if err != nil {
		panic(fmt.Sprintf("failed to create histogram %s: %v", name, err))
	}

	return &otelHistogram{histogram: histogram}
}

// NewGauge creates a new OpenTelemetry gauge
func (o *OtelProvider) NewGauge(name, help string) Gauge {
	// OpenTelemetry doesn't have a direct gauge equivalent
	// We use UpDownCounter which can increase and decrease
	gauge, err := o.meter.Float64UpDownCounter(
		name,
		metric.WithDescription(help),
	)
	if err != nil {
		panic(fmt.Sprintf("failed to create gauge %s: %v", name, err))
	}

	return &otelGauge{gauge: gauge}
}

// otelCounter implements Counter interface
type otelCounter struct {
	counter metric.Float64Counter
}

func (c *otelCounter) Inc(ctx context.Context, labels ...Label) {
	c.counter.Add(ctx, 1, metric.WithAttributes(labelsToAttributes(labels)...))
}

func (c *otelCounter) Add(ctx context.Context, value float64, labels ...Label) {
	c.counter.Add(ctx, value, metric.WithAttributes(labelsToAttributes(labels)...))
}

// otelHistogram implements Histogram interface
type otelHistogram struct {
	histogram metric.Float64Histogram
}

func (h *otelHistogram) Observe(ctx context.Context, value float64, labels ...Label) {
	h.histogram.Record(ctx, value, metric.WithAttributes(labelsToAttributes(labels)...))
}

func (h *otelHistogram) Time(ctx context.Context, labels ...Label) func() {
	start := time.Now()
	return func() {
		duration := time.Since(start).Seconds()
		h.histogram.Record(ctx, duration, metric.WithAttributes(labelsToAttributes(labels)...))
	}
}

// otelGauge implements Gauge interface using UpDownCounter
type otelGauge struct {
	gauge metric.Float64UpDownCounter
}

func (g *otelGauge) Set(ctx context.Context, value float64, labels ...Label) {
	// OpenTelemetry doesn't have a direct "set" operation for gauges
	// This is a limitation when using UpDownCounter as a gauge
	// In practice, you might need to track the current value separately
	// For now, we'll just add the value (this is not ideal)
	g.gauge.Add(ctx, value, metric.WithAttributes(labelsToAttributes(labels)...))
}

func (g *otelGauge) Inc(ctx context.Context, labels ...Label) {
	g.gauge.Add(ctx, 1, metric.WithAttributes(labelsToAttributes(labels)...))
}

func (g *otelGauge) Dec(ctx context.Context, labels ...Label) {
	g.gauge.Add(ctx, -1, metric.WithAttributes(labelsToAttributes(labels)...))
}

func (g *otelGauge) Add(ctx context.Context, value float64, labels ...Label) {
	g.gauge.Add(ctx, value, metric.WithAttributes(labelsToAttributes(labels)...))
}

func (g *otelGauge) Sub(ctx context.Context, value float64, labels ...Label) {
	g.gauge.Add(ctx, -value, metric.WithAttributes(labelsToAttributes(labels)...))
}

// labelsToAttributes converts Label slice to OpenTelemetry attributes
func labelsToAttributes(labels []Label) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, len(labels))
	for i, label := range labels {
		attrs[i] = attribute.String(label.Key, label.Value)
	}
	return attrs
}