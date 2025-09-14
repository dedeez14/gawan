package metrics

import (
	"fmt"
	"strings"
)

// NewProvider creates a new metrics provider based on the configuration
func NewProvider(config Config) (MetricsProvider, error) {
	if !config.Enabled {
		return NewNoopProvider(), nil
	}

	switch strings.ToLower(config.Provider) {
	case "prometheus":
		return NewPrometheusProvider(config), nil
	case "otel", "opentelemetry":
		return NewOtelProvider(config)
	case "noop", "disabled":
		return NewNoopProvider(), nil
	default:
		return nil, fmt.Errorf("unsupported metrics provider: %s", config.Provider)
	}
}

// DefaultConfig returns a default metrics configuration
func DefaultConfig() Config {
	return Config{
		Enabled:   true,
		Provider:  "prometheus",
		Namespace: "gawan",
		Address:   ":9090",
		Path:      "/metrics",
	}
}

// MustNewProvider creates a new metrics provider and panics on error
func MustNewProvider(config Config) MetricsProvider {
	provider, err := NewProvider(config)
	if err != nil {
		panic(fmt.Sprintf("failed to create metrics provider: %v", err))
	}
	return provider
}