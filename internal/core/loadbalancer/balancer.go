package loadbalancer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// LoadBalancerType represents different load balancing algorithms
type LoadBalancerType string

const (
	RoundRobin    LoadBalancerType = "round_robin"
	WeightedRound LoadBalancerType = "weighted_round"
	LeastConn     LoadBalancerType = "least_conn"
	IPHash        LoadBalancerType = "ip_hash"
	Random        LoadBalancerType = "random"
)

// Config holds load balancer configuration
type Config struct {
	Type                LoadBalancerType `json:"type" yaml:"type" env:"LB_TYPE" default:"round_robin"`
	HealthCheckEnabled  bool             `json:"health_check_enabled" yaml:"health_check_enabled" env:"LB_HEALTH_CHECK_ENABLED" default:"true"`
	HealthCheckInterval time.Duration    `json:"health_check_interval" yaml:"health_check_interval" env:"LB_HEALTH_CHECK_INTERVAL" default:"30s"`
	HealthCheckTimeout  time.Duration    `json:"health_check_timeout" yaml:"health_check_timeout" env:"LB_HEALTH_CHECK_TIMEOUT" default:"5s"`
	HealthCheckPath     string           `json:"health_check_path" yaml:"health_check_path" env:"LB_HEALTH_CHECK_PATH" default:"/health"`
	MaxRetries          int              `json:"max_retries" yaml:"max_retries" env:"LB_MAX_RETRIES" default:"3"`
	RetryDelay          time.Duration    `json:"retry_delay" yaml:"retry_delay" env:"LB_RETRY_DELAY" default:"1s"`
}

// Backend represents a backend server
type Backend struct {
	ID       string    `json:"id"`
	URL      *url.URL  `json:"url"`
	Weight   int       `json:"weight"`
	Healthy  bool      `json:"healthy"`
	Proxy    *httputil.ReverseProxy
	mu       sync.RWMutex
	conns    int64     // Active connections
	lastSeen time.Time
	stats    BackendStats
}

// BackendStats holds backend statistics
type BackendStats struct {
	TotalRequests   int64         `json:"total_requests"`
	FailedRequests  int64         `json:"failed_requests"`
	AverageLatency  time.Duration `json:"average_latency"`
	LastRequestTime time.Time     `json:"last_request_time"`
}

// NewBackend creates a new backend instance
func NewBackend(id string, targetURL *url.URL, weight int) *Backend {
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	
	// Customize proxy behavior
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, "Backend unavailable", http.StatusBadGateway)
	}

	return &Backend{
		ID:      id,
		URL:     targetURL,
		Weight:  weight,
		Healthy: true,
		Proxy:   proxy,
	}
}

// IsHealthy returns the health status of the backend
func (b *Backend) IsHealthy() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.Healthy
}

// SetHealthy sets the health status of the backend
func (b *Backend) SetHealthy(healthy bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.Healthy = healthy
	b.lastSeen = time.Now()
}

// IncrementConnections increments active connection count
func (b *Backend) IncrementConnections() {
	atomic.AddInt64(&b.conns, 1)
}

// DecrementConnections decrements active connection count
func (b *Backend) DecrementConnections() {
	atomic.AddInt64(&b.conns, -1)
}

// GetConnections returns current active connection count
func (b *Backend) GetConnections() int64 {
	return atomic.LoadInt64(&b.conns)
}

// UpdateStats updates backend statistics
func (b *Backend) UpdateStats(latency time.Duration, failed bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	
	b.stats.TotalRequests++
	if failed {
		b.stats.FailedRequests++
	}
	
	// Update average latency (simple moving average)
	if b.stats.TotalRequests == 1 {
		b.stats.AverageLatency = latency
	} else {
		b.stats.AverageLatency = (b.stats.AverageLatency + latency) / 2
	}
	
	b.stats.LastRequestTime = time.Now()
}

// LoadBalancer represents a load balancer instance
type LoadBalancer struct {
	config   Config
	backends []*Backend
	mu       sync.RWMutex
	counter  uint64 // For round-robin
	stopCh   chan struct{}
}

// NewLoadBalancer creates a new load balancer
func NewLoadBalancer(config Config) *LoadBalancer {
	lb := &LoadBalancer{
		config:   config,
		backends: make([]*Backend, 0),
		stopCh:   make(chan struct{}),
	}
	
	// Start health check if enabled
	if config.HealthCheckEnabled {
		go lb.healthCheckLoop()
	}
	
	return lb
}

// AddBackend adds a backend to the load balancer
func (lb *LoadBalancer) AddBackend(backend *Backend) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.backends = append(lb.backends, backend)
}

// RemoveBackend removes a backend from the load balancer
func (lb *LoadBalancer) RemoveBackend(backendID string) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	
	for i, backend := range lb.backends {
		if backend.ID == backendID {
			lb.backends = append(lb.backends[:i], lb.backends[i+1:]...)
			return nil
		}
	}
	
	return errors.New("backend not found")
}

// GetBackend selects a backend based on the load balancing algorithm
func (lb *LoadBalancer) GetBackend(r *http.Request) (*Backend, error) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	
	// Filter healthy backends
	healthyBackends := make([]*Backend, 0)
	for _, backend := range lb.backends {
		if backend.IsHealthy() {
			healthyBackends = append(healthyBackends, backend)
		}
	}
	
	if len(healthyBackends) == 0 {
		return nil, errors.New("no healthy backends available")
	}
	
	switch lb.config.Type {
	case RoundRobin:
		return lb.roundRobin(healthyBackends), nil
	case WeightedRound:
		return lb.weightedRoundRobin(healthyBackends), nil
	case LeastConn:
		return lb.leastConnections(healthyBackends), nil
	case IPHash:
		return lb.ipHash(healthyBackends, r), nil
	case Random:
		return lb.random(healthyBackends), nil
	default:
		return lb.roundRobin(healthyBackends), nil
	}
}

// roundRobin implements round-robin load balancing
func (lb *LoadBalancer) roundRobin(backends []*Backend) *Backend {
	index := atomic.AddUint64(&lb.counter, 1) % uint64(len(backends))
	return backends[index]
}

// weightedRoundRobin implements weighted round-robin load balancing
func (lb *LoadBalancer) weightedRoundRobin(backends []*Backend) *Backend {
	totalWeight := 0
	for _, backend := range backends {
		totalWeight += backend.Weight
	}
	
	if totalWeight == 0 {
		return lb.roundRobin(backends)
	}
	
	index := int(atomic.AddUint64(&lb.counter, 1)) % totalWeight
	currentWeight := 0
	
	for _, backend := range backends {
		currentWeight += backend.Weight
		if index < currentWeight {
			return backend
		}
	}
	
	return backends[0]
}

// leastConnections implements least connections load balancing
func (lb *LoadBalancer) leastConnections(backends []*Backend) *Backend {
	var selected *Backend
	minConns := int64(-1)
	
	for _, backend := range backends {
		conns := backend.GetConnections()
		if minConns == -1 || conns < minConns {
			minConns = conns
			selected = backend
		}
	}
	
	return selected
}

// ipHash implements IP hash load balancing
func (lb *LoadBalancer) ipHash(backends []*Backend, r *http.Request) *Backend {
	clientIP := getClientIP(r)
	hash := simpleHash(clientIP)
	index := hash % uint32(len(backends))
	return backends[index]
}

// random implements random load balancing
func (lb *LoadBalancer) random(backends []*Backend) *Backend {
	index := time.Now().UnixNano() % int64(len(backends))
	return backends[index]
}

// ServeHTTP implements http.Handler interface
func (lb *LoadBalancer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	
	backend, err := lb.GetBackend(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	
	// Track connection
	backend.IncrementConnections()
	defer backend.DecrementConnections()
	
	// Attempt request with retries
	var lastErr error
	for attempt := 0; attempt <= lb.config.MaxRetries; attempt++ {
		if attempt > 0 {
			// Get a new backend for retry
			if newBackend, err := lb.GetBackend(r); err == nil {
				backend.DecrementConnections()
				backend = newBackend
				backend.IncrementConnections()
			}
			
			time.Sleep(lb.config.RetryDelay * time.Duration(attempt))
		}
		
		// Create a custom response writer to capture errors
		cw := &captureWriter{ResponseWriter: w}
		backend.Proxy.ServeHTTP(cw, r)
		
		if !cw.hasError {
			// Success
			backend.UpdateStats(time.Since(start), false)
			return
		}
		
		lastErr = fmt.Errorf("backend error: status %d", cw.statusCode)
		
		// Mark backend as unhealthy if it's consistently failing
		if cw.statusCode >= 500 {
			backend.SetHealthy(false)
		}
	}
	
	// All retries failed
	backend.UpdateStats(time.Since(start), true)
	if lastErr != nil {
		http.Error(w, lastErr.Error(), http.StatusBadGateway)
	}
}

// captureWriter captures response status for error handling
type captureWriter struct {
	http.ResponseWriter
	statusCode int
	hasError   bool
}

func (cw *captureWriter) WriteHeader(code int) {
	cw.statusCode = code
	cw.hasError = code >= 400
	cw.ResponseWriter.WriteHeader(code)
}

// healthCheckLoop performs periodic health checks on backends
func (lb *LoadBalancer) healthCheckLoop() {
	ticker := time.NewTicker(lb.config.HealthCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			lb.performHealthChecks()
		case <-lb.stopCh:
			return
		}
	}
}

// performHealthChecks checks the health of all backends
func (lb *LoadBalancer) performHealthChecks() {
	lb.mu.RLock()
	backends := make([]*Backend, len(lb.backends))
	copy(backends, lb.backends)
	lb.mu.RUnlock()
	
	for _, backend := range backends {
		go lb.checkBackendHealth(backend)
	}
}

// checkBackendHealth checks the health of a single backend
func (lb *LoadBalancer) checkBackendHealth(backend *Backend) {
	ctx, cancel := context.WithTimeout(context.Background(), lb.config.HealthCheckTimeout)
	defer cancel()
	
	healthURL := *backend.URL
	healthURL.Path = lb.config.HealthCheckPath
	
	req, err := http.NewRequestWithContext(ctx, "GET", healthURL.String(), nil)
	if err != nil {
		backend.SetHealthy(false)
		return
	}
	
	client := &http.Client{
		Timeout: lb.config.HealthCheckTimeout,
	}
	
	resp, err := client.Do(req)
	if err != nil {
		backend.SetHealthy(false)
		return
	}
	defer resp.Body.Close()
	
	// Consider 2xx status codes as healthy
	backend.SetHealthy(resp.StatusCode >= 200 && resp.StatusCode < 300)
}

// Stop stops the load balancer
func (lb *LoadBalancer) Stop() {
	close(lb.stopCh)
}

// GetStats returns load balancer statistics
func (lb *LoadBalancer) GetStats() map[string]interface{} {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	
	stats := map[string]interface{}{
		"total_backends":   len(lb.backends),
		"healthy_backends": 0,
		"backends":         make([]map[string]interface{}, 0),
	}
	
	for _, backend := range lb.backends {
		if backend.IsHealthy() {
			stats["healthy_backends"] = stats["healthy_backends"].(int) + 1
		}
		
		backendStats := map[string]interface{}{
			"id":               backend.ID,
			"url":              backend.URL.String(),
			"healthy":          backend.IsHealthy(),
			"weight":           backend.Weight,
			"connections":      backend.GetConnections(),
			"total_requests":   backend.stats.TotalRequests,
			"failed_requests":  backend.stats.FailedRequests,
			"average_latency":  backend.stats.AverageLatency.String(),
		}
		
		stats["backends"] = append(stats["backends"].([]map[string]interface{}), backendStats)
	}
	
	return stats
}

// getClientIP extracts client IP from request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	
	// Use remote address
	return r.RemoteAddr
}

// simpleHash implements a simple hash function
func simpleHash(s string) uint32 {
	hash := uint32(0)
	for _, c := range s {
		hash = hash*31 + uint32(c)
	}
	return hash
}