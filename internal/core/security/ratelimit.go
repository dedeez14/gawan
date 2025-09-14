package security

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter defines the interface for rate limiting
type RateLimiter interface {
	Allow(key string) bool
	AllowN(key string, n int) bool
	Wait(ctx context.Context, key string) error
	WaitN(ctx context.Context, key string, n int) error
	Reset(key string)
	Cleanup()
}

// TokenBucketLimiter implements rate limiting using token bucket algorithm
type TokenBucketLimiter struct {
	mu       sync.RWMutex
	limiters map[string]*rate.Limiter
	rate     rate.Limit
	burst    int
	ttl      time.Duration
	lastSeen map[string]time.Time
	cleanup  *time.Ticker
	stop     chan struct{}
}

// NewTokenBucketLimiter creates a new token bucket rate limiter
func NewTokenBucketLimiter(rps float64, burst int, ttl time.Duration) *TokenBucketLimiter {
	limiter := &TokenBucketLimiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     rate.Limit(rps),
		burst:    burst,
		ttl:      ttl,
		lastSeen: make(map[string]time.Time),
		cleanup:  time.NewTicker(ttl),
		stop:     make(chan struct{}),
	}

	// Start cleanup goroutine
	go limiter.cleanupRoutine()
	return limiter
}

// getLimiter gets or creates a limiter for the given key
func (tbl *TokenBucketLimiter) getLimiter(key string) *rate.Limiter {
	tbl.mu.Lock()
	defer tbl.mu.Unlock()

	limiter, exists := tbl.limiters[key]
	if !exists {
		limiter = rate.NewLimiter(tbl.rate, tbl.burst)
		tbl.limiters[key] = limiter
	}
	tbl.lastSeen[key] = time.Now()
	return limiter
}

// Allow checks if a request is allowed
func (tbl *TokenBucketLimiter) Allow(key string) bool {
	return tbl.getLimiter(key).Allow()
}

// AllowN checks if n requests are allowed
func (tbl *TokenBucketLimiter) AllowN(key string, n int) bool {
	return tbl.getLimiter(key).AllowN(time.Now(), n)
}

// Wait waits until a request is allowed
func (tbl *TokenBucketLimiter) Wait(ctx context.Context, key string) error {
	return tbl.getLimiter(key).Wait(ctx)
}

// WaitN waits until n requests are allowed
func (tbl *TokenBucketLimiter) WaitN(ctx context.Context, key string, n int) error {
	return tbl.getLimiter(key).WaitN(ctx, n)
}

// Reset resets the limiter for the given key
func (tbl *TokenBucketLimiter) Reset(key string) {
	tbl.mu.Lock()
	defer tbl.mu.Unlock()
	delete(tbl.limiters, key)
	delete(tbl.lastSeen, key)
}

// Cleanup stops the cleanup routine
func (tbl *TokenBucketLimiter) Cleanup() {
	close(tbl.stop)
	tbl.cleanup.Stop()
}

// cleanupRoutine removes expired limiters
func (tbl *TokenBucketLimiter) cleanupRoutine() {
	for {
		select {
		case <-tbl.cleanup.C:
			tbl.cleanupExpired()
		case <-tbl.stop:
			return
		}
	}
}

// cleanupExpired removes expired limiters
func (tbl *TokenBucketLimiter) cleanupExpired() {
	tbl.mu.Lock()
	defer tbl.mu.Unlock()

	now := time.Now()
	for key, lastSeen := range tbl.lastSeen {
		if now.Sub(lastSeen) > tbl.ttl {
			delete(tbl.limiters, key)
			delete(tbl.lastSeen, key)
		}
	}
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	// Enabled enables rate limiting
	Enabled bool `json:"enabled" yaml:"enabled" env:"RATE_LIMIT_ENABLED" default:"true"`
	// RPS is requests per second allowed
	RPS float64 `json:"rps" yaml:"rps" env:"RATE_LIMIT_RPS" default:"100"`
	// Burst is the maximum burst size
	Burst int `json:"burst" yaml:"burst" env:"RATE_LIMIT_BURST" default:"200"`
	// TTL is the time to live for rate limiters
	TTL time.Duration `json:"ttl" yaml:"ttl" env:"RATE_LIMIT_TTL" default:"1h"`
	// KeyFunc extracts the key for rate limiting
	KeyFunc KeyExtractor `json:"-" yaml:"-"`
	// SkipFunc determines if rate limiting should be skipped
	SkipFunc SkipFunc `json:"-" yaml:"-"`
	// OnLimitExceeded is called when rate limit is exceeded
	OnLimitExceeded LimitExceededHandler `json:"-" yaml:"-"`
}

// KeyExtractor extracts a key from the request for rate limiting
type KeyExtractor func(r *http.Request) string

// SkipFunc determines if rate limiting should be skipped for a request
type SkipFunc func(r *http.Request) bool

// LimitExceededHandler handles rate limit exceeded scenarios
type LimitExceededHandler func(w http.ResponseWriter, r *http.Request, retryAfter time.Duration)

// DefaultRateLimitConfig returns default rate limiting configuration
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Enabled:         true,
		RPS:             100,
		Burst:           200,
		TTL:             time.Hour,
		KeyFunc:         IPKeyExtractor,
		SkipFunc:        nil,
		OnLimitExceeded: DefaultLimitExceededHandler,
	}
}

// IPKeyExtractor extracts IP address as the key
func IPKeyExtractor(r *http.Request) string {
	// Try to get real IP from headers
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		if idx := len(ip); idx > 0 {
			for i, char := range ip {
				if char == ',' {
					idx = i
					break
				}
			}
			return ip[:idx]
		}
	}

	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}

	if ip := r.Header.Get("X-Forwarded-Host"); ip != "" {
		return ip
	}

	// Fallback to remote address
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// UserKeyExtractor extracts user ID as the key (requires authentication)
func UserKeyExtractor(r *http.Request) string {
	// This would typically extract user ID from JWT token or session
	// For now, return a placeholder
	if userID := r.Header.Get("X-User-ID"); userID != "" {
		return "user:" + userID
	}
	return IPKeyExtractor(r) // Fallback to IP
}

// APIKeyExtractor extracts API key as the key
func APIKeyExtractor(r *http.Request) string {
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		return "api:" + apiKey
	}
	if apiKey := r.URL.Query().Get("api_key"); apiKey != "" {
		return "api:" + apiKey
	}
	return IPKeyExtractor(r) // Fallback to IP
}

// DefaultLimitExceededHandler is the default handler for rate limit exceeded
func DefaultLimitExceededHandler(w http.ResponseWriter, r *http.Request, retryAfter time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
	w.Header().Set("X-RateLimit-Limit", "exceeded")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	w.Write([]byte(`{"error":"rate limit exceeded","message":"too many requests"}`))
}

// RateLimitMiddleware creates a rate limiting middleware
func RateLimitMiddleware(config RateLimitConfig) func(http.Handler) http.Handler {
	if !config.Enabled {
		return func(next http.Handler) http.Handler {
			return next // Pass through if disabled
		}
	}

	// Set defaults
	if config.KeyFunc == nil {
		config.KeyFunc = IPKeyExtractor
	}
	if config.OnLimitExceeded == nil {
		config.OnLimitExceeded = DefaultLimitExceededHandler
	}

	limiter := NewTokenBucketLimiter(config.RPS, config.Burst, config.TTL)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip rate limiting if skip function returns true
			if config.SkipFunc != nil && config.SkipFunc(r) {
				next.ServeHTTP(w, r)
				return
			}

			key := config.KeyFunc(r)
			if !limiter.Allow(key) {
				// Calculate retry after based on rate
				retryAfter := time.Duration(float64(time.Second) / float64(config.RPS))
				config.OnLimitExceeded(w, r, retryAfter)
				return
			}

			// Add rate limit headers
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%.0f", config.RPS))
			w.Header().Set("X-RateLimit-Burst", strconv.Itoa(config.Burst))

			next.ServeHTTP(w, r)
		})
	}
}

// PerEndpointRateLimitConfig holds per-endpoint rate limiting configuration
type PerEndpointRateLimitConfig struct {
	Endpoints map[string]RateLimitConfig `json:"endpoints" yaml:"endpoints"`
	Default   RateLimitConfig            `json:"default" yaml:"default"`
}

// PerEndpointRateLimitMiddleware creates a per-endpoint rate limiting middleware
func PerEndpointRateLimitMiddleware(config PerEndpointRateLimitConfig) func(http.Handler) http.Handler {
	limiters := make(map[string]func(http.Handler) http.Handler)

	// Create limiters for each endpoint
	for endpoint, endpointConfig := range config.Endpoints {
		limiters[endpoint] = RateLimitMiddleware(endpointConfig)
	}

	// Create default limiter
	defaultLimiter := RateLimitMiddleware(config.Default)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			endpoint := r.Method + " " + r.URL.Path

			// Use endpoint-specific limiter if available
			if limiter, exists := limiters[endpoint]; exists {
				limiter(next).ServeHTTP(w, r)
				return
			}

			// Use default limiter
			defaultLimiter(next).ServeHTTP(w, r)
		})
	}
}