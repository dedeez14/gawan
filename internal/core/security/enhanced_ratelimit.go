package security

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"Gawan/internal/core/logx"
)

// EnhancedRateLimitConfig holds enhanced rate limiting configuration
type EnhancedRateLimitConfig struct {
	// Enabled enables rate limiting
	Enabled bool `json:"enabled" yaml:"enabled" env:"ENHANCED_RATE_LIMIT_ENABLED" default:"true"`
	// RequestsPerWindow is the number of requests allowed per time window
	RequestsPerWindow int `json:"requests_per_window" yaml:"requests_per_window" env:"RATE_LIMIT_REQUESTS_PER_WINDOW" default:"100"`
	// WindowDuration is the time window duration
	WindowDuration time.Duration `json:"window_duration" yaml:"window_duration" env:"RATE_LIMIT_WINDOW_DURATION" default:"10s"`
	// KeyExtractor extracts the key for rate limiting
	KeyExtractor KeyExtractor `json:"-" yaml:"-"`
	// SkipFunc determines if rate limiting should be skipped
	SkipFunc SkipFunc `json:"-" yaml:"-"`
	// OnLimitExceeded is called when rate limit is exceeded
	OnLimitExceeded EnhancedLimitExceededHandler `json:"-" yaml:"-"`
	// Logger for audit events
	Logger *logx.Logger `json:"-" yaml:"-"`
}

// EnhancedLimitExceededHandler handles rate limit exceeded scenarios with audit logging
type EnhancedLimitExceededHandler func(w http.ResponseWriter, r *http.Request, retryAfter time.Duration, logger *logx.Logger)

// WindowedRateLimiter implements sliding window rate limiting
type WindowedRateLimiter struct {
	mu           sync.RWMutex
	requestCounts map[string]*WindowCounter
	requestsPerWindow int
	windowDuration   time.Duration
	cleanupTicker    *time.Ticker
	stop             chan struct{}
}

// WindowCounter tracks requests in a sliding window
type WindowCounter struct {
	requests  []time.Time
	lastClean time.Time
	mu        sync.RWMutex
}

// NewWindowedRateLimiter creates a new windowed rate limiter
func NewWindowedRateLimiter(requestsPerWindow int, windowDuration time.Duration) *WindowedRateLimiter {
	limiter := &WindowedRateLimiter{
		requestCounts:     make(map[string]*WindowCounter),
		requestsPerWindow: requestsPerWindow,
		windowDuration:    windowDuration,
		cleanupTicker:     time.NewTicker(windowDuration),
		stop:              make(chan struct{}),
	}

	// Start cleanup goroutine
	go limiter.cleanupRoutine()
	return limiter
}

// Allow checks if a request is allowed within the rate limit
func (wrl *WindowedRateLimiter) Allow(key string) bool {
	wrl.mu.Lock()
	defer wrl.mu.Unlock()

	counter, exists := wrl.requestCounts[key]
	if !exists {
		counter = &WindowCounter{
			requests:  make([]time.Time, 0),
			lastClean: time.Now(),
		}
		wrl.requestCounts[key] = counter
	}

	now := time.Now()
	counter.mu.Lock()
	defer counter.mu.Unlock()

	// Clean old requests outside the window
	cutoff := now.Add(-wrl.windowDuration)
	validRequests := make([]time.Time, 0, len(counter.requests))
	for _, reqTime := range counter.requests {
		if reqTime.After(cutoff) {
			validRequests = append(validRequests, reqTime)
		}
	}
	counter.requests = validRequests

	// Check if we can allow this request
	if len(counter.requests) >= wrl.requestsPerWindow {
		return false
	}

	// Add current request
	counter.requests = append(counter.requests, now)
	return true
}

// GetCurrentCount returns the current request count for a key
func (wrl *WindowedRateLimiter) GetCurrentCount(key string) int {
	wrl.mu.RLock()
	defer wrl.mu.RUnlock()

	counter, exists := wrl.requestCounts[key]
	if !exists {
		return 0
	}

	counter.mu.RLock()
	defer counter.mu.RUnlock()

	now := time.Now()
	cutoff := now.Add(-wrl.windowDuration)
	count := 0
	for _, reqTime := range counter.requests {
		if reqTime.After(cutoff) {
			count++
		}
	}
	return count
}

// cleanupRoutine removes expired counters
func (wrl *WindowedRateLimiter) cleanupRoutine() {
	for {
		select {
		case <-wrl.cleanupTicker.C:
			wrl.cleanupExpired()
		case <-wrl.stop:
			return
		}
	}
}

// cleanupExpired removes expired request counters
func (wrl *WindowedRateLimiter) cleanupExpired() {
	wrl.mu.Lock()
	defer wrl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-wrl.windowDuration * 2) // Keep some buffer

	for key, counter := range wrl.requestCounts {
		counter.mu.Lock()
		if counter.lastClean.Before(cutoff) && len(counter.requests) == 0 {
			delete(wrl.requestCounts, key)
		}
		counter.mu.Unlock()
	}
}

// Stop stops the cleanup routine
func (wrl *WindowedRateLimiter) Stop() {
	close(wrl.stop)
	wrl.cleanupTicker.Stop()
}

// DefaultEnhancedRateLimitConfig returns default enhanced rate limiting configuration
func DefaultEnhancedRateLimitConfig() EnhancedRateLimitConfig {
	return EnhancedRateLimitConfig{
		Enabled:           true,
		RequestsPerWindow: 100,
		WindowDuration:    10 * time.Second,
		KeyExtractor:      IPKeyExtractor,
		SkipFunc:          nil,
		OnLimitExceeded:   DefaultEnhancedLimitExceededHandler,
	}
}

// DefaultEnhancedLimitExceededHandler is the default handler for enhanced rate limit exceeded
func DefaultEnhancedLimitExceededHandler(w http.ResponseWriter, r *http.Request, retryAfter time.Duration, logger *logx.Logger) {
	// Audit log the rate limit hit
	if logger != nil {
		logger.Warn("RATE_LIMIT_HIT",
			"event", "RATE_LIMIT_HIT",
			"ip", IPKeyExtractor(r),
			"user_agent", r.UserAgent(),
			"path", r.URL.Path,
			"method", r.Method,
			"timestamp", time.Now().UTC(),
		)
	}

	w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
	w.Header().Set("X-RateLimit-Limit", "100")
	w.Header().Set("X-RateLimit-Window", "10s")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	w.Write([]byte(`{"error":"rate_limit_exceeded","message":"Batasan laju terlampaui: 100 permintaan per 10 detik","code":429}`))
}

// EnhancedRateLimitMiddleware creates an enhanced rate limiting middleware
func EnhancedRateLimitMiddleware(config EnhancedRateLimitConfig) func(http.Handler) http.Handler {
	if !config.Enabled {
		return func(next http.Handler) http.Handler {
			return next // Pass through if disabled
		}
	}

	// Set defaults
	if config.KeyExtractor == nil {
		config.KeyExtractor = IPKeyExtractor
	}
	if config.OnLimitExceeded == nil {
		config.OnLimitExceeded = DefaultEnhancedLimitExceededHandler
	}
	if config.RequestsPerWindow <= 0 {
		config.RequestsPerWindow = 100
	}
	if config.WindowDuration <= 0 {
		config.WindowDuration = 10 * time.Second
	}

	limiter := NewWindowedRateLimiter(config.RequestsPerWindow, config.WindowDuration)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip rate limiting if skip function returns true
			if config.SkipFunc != nil && config.SkipFunc(r) {
				next.ServeHTTP(w, r)
				return
			}

			key := config.KeyExtractor(r)
			if !limiter.Allow(key) {
				// Calculate retry after based on window duration
				retryAfter := config.WindowDuration
				config.OnLimitExceeded(w, r, retryAfter, config.Logger)
				return
			}

			// Add rate limit headers
			currentCount := limiter.GetCurrentCount(key)
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(config.RequestsPerWindow))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(config.RequestsPerWindow-currentCount))
			w.Header().Set("X-RateLimit-Window", config.WindowDuration.String())
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(config.WindowDuration).Unix(), 10))

			next.ServeHTTP(w, r)
		})
	}
}