package httpx

import (
	"net/http"
	"strconv"
	"time"

	"Gawan/internal/core/metrics"
)

// MetricsConfig holds configuration for metrics middleware
type MetricsConfig struct {
	// Provider is the metrics provider instance
	Provider metrics.MetricsProvider
	// RequestsTotal counter name
	RequestsTotal string
	// RequestDuration histogram name
	RequestDuration string
	// RequestsInFlight gauge name
	RequestsInFlight string
	// ResponseSize histogram name
	ResponseSize string
	// IncludeMethod includes HTTP method in labels
	IncludeMethod bool
	// IncludePath includes request path in labels (be careful with high cardinality)
	IncludePath bool
	// IncludeStatusCode includes HTTP status code in labels
	IncludeStatusCode bool
}

// DefaultMetricsConfig returns default metrics middleware configuration
func DefaultMetricsConfig(provider metrics.MetricsProvider) MetricsConfig {
	return MetricsConfig{
		Provider:          provider,
		RequestsTotal:     "http_requests_total",
		RequestDuration:   "http_request_duration_seconds",
		RequestsInFlight:  "http_requests_in_flight",
		ResponseSize:      "http_response_size_bytes",
		IncludeMethod:     true,
		IncludePath:       false, // Disabled by default to avoid high cardinality
		IncludeStatusCode: true,
	}
}

// MetricsMiddleware creates HTTP metrics collection middleware
func MetricsMiddleware(config MetricsConfig) Middleware {
	// Create metrics
	requestsTotal := config.Provider.NewCounter(
		config.RequestsTotal,
		"Total number of HTTP requests",
	)

	requestDuration := config.Provider.NewHistogram(
		config.RequestDuration,
		"HTTP request duration in seconds",
		metrics.HTTPBuckets,
	)

	requestsInFlight := config.Provider.NewGauge(
		config.RequestsInFlight,
		"Number of HTTP requests currently being processed",
	)

	responseSize := config.Provider.NewHistogram(
		config.ResponseSize,
		"HTTP response size in bytes",
		[]float64{100, 1000, 10000, 100000, 1000000, 10000000},
	)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			start := time.Now()

			// Increment in-flight requests
			requestsInFlight.Inc(ctx)
			defer requestsInFlight.Dec(ctx)

			// Wrap response writer to capture metrics
			mw := &metricsResponseWriter{
				ResponseWriter: w,
				statusCode:     200, // Default status code
			}

			// Process request
			next.ServeHTTP(mw, r)

			// Calculate duration
			duration := time.Since(start).Seconds()

			// Build labels
			labels := buildMetricsLabels(config, r, mw.statusCode)

			// Record metrics
			requestsTotal.Inc(ctx, labels...)
			requestDuration.Observe(ctx, duration, labels...)
			responseSize.Observe(ctx, float64(mw.bytesWritten), labels...)
		})
	}
}

// metricsResponseWriter wraps http.ResponseWriter to capture metrics
type metricsResponseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

func (m *metricsResponseWriter) WriteHeader(statusCode int) {
	m.statusCode = statusCode
	m.ResponseWriter.WriteHeader(statusCode)
}

func (m *metricsResponseWriter) Write(data []byte) (int, error) {
	n, err := m.ResponseWriter.Write(data)
	m.bytesWritten += int64(n)
	return n, err
}

// buildMetricsLabels builds metric labels based on configuration
func buildMetricsLabels(config MetricsConfig, r *http.Request, statusCode int) []metrics.Label {
	var labels []metrics.Label

	if config.IncludeMethod {
		labels = append(labels, metrics.Label{
			Key:   "method",
			Value: r.Method,
		})
	}

	if config.IncludePath {
		labels = append(labels, metrics.Label{
			Key:   "path",
			Value: r.URL.Path,
		})
	}

	if config.IncludeStatusCode {
		labels = append(labels, metrics.Label{
			Key:   "status_code",
			Value: strconv.Itoa(statusCode),
		})
	}

	return labels
}

// SimpleMetricsMiddleware creates a simple metrics middleware with default configuration
func SimpleMetricsMiddleware(provider metrics.MetricsProvider) Middleware {
	return MetricsMiddleware(DefaultMetricsConfig(provider))
}

// MetricsMiddlewareWithConfig creates metrics middleware with custom configuration
func MetricsMiddlewareWithConfig(provider metrics.MetricsProvider, customizer func(*MetricsConfig)) Middleware {
	config := DefaultMetricsConfig(provider)
	if customizer != nil {
		customizer(&config)
	}
	return MetricsMiddleware(config)
}