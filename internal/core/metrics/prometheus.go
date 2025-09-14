package metrics

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// PrometheusProvider implements MetricsProvider using Prometheus
type PrometheusProvider struct {
	registry  *prometheus.Registry
	server    *http.Server
	namespace string
	config    Config
}

// NewPrometheusProvider creates a new Prometheus metrics provider
func NewPrometheusProvider(config Config) *PrometheusProvider {
	return &PrometheusProvider{
		registry:  prometheus.NewRegistry(),
		namespace: config.Namespace,
		config:    config,
	}
}

// Start initializes the Prometheus metrics server
func (p *PrometheusProvider) Start(ctx context.Context) error {
	if !p.config.Enabled {
		return nil
	}

	// Register default collectors
	p.registry.MustRegister(prometheus.NewGoCollector())
	p.registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

	// Create HTTP server for metrics endpoint
	mux := http.NewServeMux()
	mux.Handle(p.config.Path, promhttp.HandlerFor(p.registry, promhttp.HandlerOpts{
		Registry: p.registry,
	}))

	p.server = &http.Server{
		Addr:    p.config.Address,
		Handler: mux,
	}

	// Start server in goroutine
	go func() {
		if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// Log error (would use logger in real implementation)
			fmt.Printf("Prometheus metrics server error: %v\n", err)
		}
	}()

	return nil
}

// Stop gracefully shuts down the Prometheus metrics server
func (p *PrometheusProvider) Stop(ctx context.Context) error {
	if p.server == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return p.server.Shutdown(ctx)
}

// NewCounter creates a new Prometheus counter
func (p *PrometheusProvider) NewCounter(name, help string) Counter {
	counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: p.namespace,
			Name:      name,
			Help:      help,
		},
		[]string{}, // Will be populated dynamically
	)
	p.registry.MustRegister(counter)
	return &prometheusCounter{counter: counter}
}

// NewHistogram creates a new Prometheus histogram
func (p *PrometheusProvider) NewHistogram(name, help string, buckets []float64) Histogram {
	if buckets == nil {
		buckets = DefaultBuckets
	}

	histogram := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: p.namespace,
			Name:      name,
			Help:      help,
			Buckets:   buckets,
		},
		[]string{}, // Will be populated dynamically
	)
	p.registry.MustRegister(histogram)
	return &prometheusHistogram{histogram: histogram}
}

// NewGauge creates a new Prometheus gauge
func (p *PrometheusProvider) NewGauge(name, help string) Gauge {
	gauge := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: p.namespace,
			Name:      name,
			Help:      help,
		},
		[]string{}, // Will be populated dynamically
	)
	p.registry.MustRegister(gauge)
	return &prometheusGauge{gauge: gauge}
}

// prometheusCounter implements Counter interface
type prometheusCounter struct {
	counter *prometheus.CounterVec
}

func (c *prometheusCounter) Inc(ctx context.Context, labels ...Label) {
	c.counter.With(labelsToMap(labels)).Inc()
}

func (c *prometheusCounter) Add(ctx context.Context, value float64, labels ...Label) {
	c.counter.With(labelsToMap(labels)).Add(value)
}

// prometheusHistogram implements Histogram interface
type prometheusHistogram struct {
	histogram *prometheus.HistogramVec
}

func (h *prometheusHistogram) Observe(ctx context.Context, value float64, labels ...Label) {
	h.histogram.With(labelsToMap(labels)).Observe(value)
}

func (h *prometheusHistogram) Time(ctx context.Context, labels ...Label) func() {
	timer := prometheus.NewTimer(h.histogram.With(labelsToMap(labels)))
	return timer.ObserveDuration
}

// prometheusGauge implements Gauge interface
type prometheusGauge struct {
	gauge *prometheus.GaugeVec
}

func (g *prometheusGauge) Set(ctx context.Context, value float64, labels ...Label) {
	g.gauge.With(labelsToMap(labels)).Set(value)
}

func (g *prometheusGauge) Inc(ctx context.Context, labels ...Label) {
	g.gauge.With(labelsToMap(labels)).Inc()
}

func (g *prometheusGauge) Dec(ctx context.Context, labels ...Label) {
	g.gauge.With(labelsToMap(labels)).Dec()
}

func (g *prometheusGauge) Add(ctx context.Context, value float64, labels ...Label) {
	g.gauge.With(labelsToMap(labels)).Add(value)
}

func (g *prometheusGauge) Sub(ctx context.Context, value float64, labels ...Label) {
	g.gauge.With(labelsToMap(labels)).Sub(value)
}

// labelsToMap converts Label slice to prometheus.Labels map
func labelsToMap(labels []Label) prometheus.Labels {
	m := make(prometheus.Labels, len(labels))
	for _, label := range labels {
		m[label.Key] = label.Value
	}
	return m
}