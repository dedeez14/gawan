package middleware

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"Gawan/internal/ports"
)

// CompressionConfig holds compression middleware configuration
type CompressionConfig struct {
	Enabled     bool     `json:"enabled" yaml:"enabled" env:"COMPRESSION_ENABLED" default:"true"`
	Level       int      `json:"level" yaml:"level" env:"COMPRESSION_LEVEL" default:"6"`
	MinSize     int      `json:"min_size" yaml:"min_size" env:"COMPRESSION_MIN_SIZE" default:"1024"`
	Types       []string `json:"types" yaml:"types"`
	ExcludePaths []string `json:"exclude_paths" yaml:"exclude_paths"`
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	Enabled    bool          `json:"enabled" yaml:"enabled" env:"RATE_LIMIT_ENABLED" default:"true"`
	RPS        float64       `json:"rps" yaml:"rps" env:"RATE_LIMIT_RPS" default:"100"`
	Burst      int           `json:"burst" yaml:"burst" env:"RATE_LIMIT_BURST" default:"200"`
	WindowSize time.Duration `json:"window_size" yaml:"window_size" env:"RATE_LIMIT_WINDOW" default:"1m"`
	ByIP       bool          `json:"by_ip" yaml:"by_ip" env:"RATE_LIMIT_BY_IP" default:"true"`
	ByUser     bool          `json:"by_user" yaml:"by_user" env:"RATE_LIMIT_BY_USER" default:"false"`
}

// CacheConfig holds HTTP caching configuration
type CacheConfig struct {
	Enabled        bool          `json:"enabled" yaml:"enabled" env:"HTTP_CACHE_ENABLED" default:"true"`
	DefaultTTL     time.Duration `json:"default_ttl" yaml:"default_ttl" env:"HTTP_CACHE_DEFAULT_TTL" default:"5m"`
	MaxSize        int           `json:"max_size" yaml:"max_size" env:"HTTP_CACHE_MAX_SIZE" default:"1000"`
	CacheableTypes []string      `json:"cacheable_types" yaml:"cacheable_types"`
	ExcludePaths   []string      `json:"exclude_paths" yaml:"exclude_paths"`
	VaryHeaders    []string      `json:"vary_headers" yaml:"vary_headers"`
}

// CompressionMiddleware provides HTTP response compression
func CompressionMiddleware(config CompressionConfig) func(http.Handler) http.Handler {
	if !config.Enabled {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	// Default compressible types
	if len(config.Types) == 0 {
		config.Types = []string{
			"text/html",
			"text/css",
			"text/javascript",
			"application/javascript",
			"application/json",
			"application/xml",
			"text/xml",
			"text/plain",
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if path should be excluded
			for _, path := range config.ExcludePaths {
				if strings.HasPrefix(r.URL.Path, path) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Check if client accepts gzip
			if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				next.ServeHTTP(w, r)
				return
			}

			// Create gzip writer
			gzWriter, err := gzip.NewWriterLevel(w, config.Level)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			defer gzWriter.Close()

			// Create compressed response writer
			cw := &compressedWriter{
				ResponseWriter: w,
				gzWriter:       gzWriter,
				config:         config,
			}

			next.ServeHTTP(cw, r)
		})
	}
}

// compressedWriter wraps http.ResponseWriter to provide compression
type compressedWriter struct {
	http.ResponseWriter
	gzWriter       *gzip.Writer
	config         CompressionConfig
	headerWritten  bool
	contentLength  int
	contentType    string
	shouldCompress bool
}

func (cw *compressedWriter) WriteHeader(code int) {
	if cw.headerWritten {
		return
	}

	cw.contentType = cw.Header().Get("Content-Type")
	cw.shouldCompress = cw.isCompressible()

	if cw.shouldCompress {
		cw.Header().Set("Content-Encoding", "gzip")
		cw.Header().Del("Content-Length")
		cw.Header().Set("Vary", "Accept-Encoding")
	}

	cw.headerWritten = true
	cw.ResponseWriter.WriteHeader(code)
}

func (cw *compressedWriter) Write(data []byte) (int, error) {
	if !cw.headerWritten {
		cw.WriteHeader(http.StatusOK)
	}

	cw.contentLength += len(data)

	// Check minimum size requirement
	if cw.contentLength < cw.config.MinSize {
		cw.shouldCompress = false
	}

	if cw.shouldCompress {
		return cw.gzWriter.Write(data)
	}

	return cw.ResponseWriter.Write(data)
}

func (cw *compressedWriter) isCompressible() bool {
	for _, contentType := range cw.config.Types {
		if strings.Contains(cw.contentType, contentType) {
			return true
		}
	}
	return false
}

// RateLimitMiddleware provides rate limiting functionality
func RateLimitMiddleware(config RateLimitConfig) func(http.Handler) http.Handler {
	if !config.Enabled {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	limiters := &rateLimiters{
		limiters: make(map[string]*rate.Limiter),
		config:   config,
	}

	// Cleanup expired limiters
	go limiters.cleanup()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := limiters.getKey(r)
			limiter := limiters.getLimiter(key)

			if !limiter.Allow() {
				w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%.0f", config.RPS))
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(config.WindowSize).Unix()))
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// rateLimiters manages rate limiters for different keys
type rateLimiters struct {
	mu       sync.RWMutex
	limiters map[string]*rateLimiterEntry
	config   RateLimitConfig
}

type rateLimiterEntry struct {
	limiter   *rate.Limiter
	lastSeen  time.Time
}

func (rl *rateLimiters) getKey(r *http.Request) string {
	if rl.config.ByIP {
		return getClientIP(r)
	}
	if rl.config.ByUser {
		// Extract user ID from context or headers
		if userID := r.Header.Get("X-User-ID"); userID != "" {
			return "user:" + userID
		}
	}
	return "global"
}

func (rl *rateLimiters) getLimiter(key string) *rate.Limiter {
	rl.mu.RLock()
	entry, exists := rl.limiters[key]
	rl.mu.RUnlock()

	if exists {
		entry.lastSeen = time.Now()
		return entry.limiter
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Double-check after acquiring write lock
	if entry, exists := rl.limiters[key]; exists {
		entry.lastSeen = time.Now()
		return entry.limiter
	}

	limiter := rate.NewLimiter(rate.Limit(rl.config.RPS), rl.config.Burst)
	rl.limiters[key] = &rateLimiterEntry{
		limiter:  limiter,
		lastSeen: time.Now(),
	}

	return limiter
}

func (rl *rateLimiters) cleanup() {
	ticker := time.NewTicker(rl.config.WindowSize)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for key, entry := range rl.limiters {
			if now.Sub(entry.lastSeen) > rl.config.WindowSize*2 {
				delete(rl.limiters, key)
			}
		}
		rl.mu.Unlock()
	}
}

// HTTPCacheMiddleware provides HTTP response caching
func HTTPCacheMiddleware(cache ports.CachePort, config CacheConfig) func(http.Handler) http.Handler {
	if !config.Enabled || cache == nil {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	// Default cacheable types
	if len(config.CacheableTypes) == 0 {
		config.CacheableTypes = []string{
			"application/json",
			"text/html",
			"text/css",
			"application/javascript",
			"text/javascript",
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only cache GET requests
			if r.Method != http.MethodGet {
				next.ServeHTTP(w, r)
				return
			}

			// Check if path should be excluded
			for _, path := range config.ExcludePaths {
				if strings.HasPrefix(r.URL.Path, path) {
					next.ServeHTTP(w, r)
					return
				}
			}

			cacheKey := generateCacheKey(r, config.VaryHeaders)

			// Try to get from cache
			if cachedData, err := cache.Get(r.Context(), cacheKey); err == nil {
				var cachedResponse CachedResponse
				if err := cachedResponse.Unmarshal(cachedData); err == nil {
					// Set cached headers
					for key, values := range cachedResponse.Headers {
						for _, value := range values {
							w.Header().Add(key, value)
						}
					}
					w.Header().Set("X-Cache", "HIT")
					w.WriteHeader(cachedResponse.StatusCode)
					w.Write(cachedResponse.Body)
					return
				}
			}

			// Create caching response writer
			cw := &cachingWriter{
				ResponseWriter: w,
				cache:          cache,
				cacheKey:       cacheKey,
				config:         config,
				context:        r.Context(),
			}

			w.Header().Set("X-Cache", "MISS")
			next.ServeHTTP(cw, r)
		})
	}
}

// CachedResponse represents a cached HTTP response
type CachedResponse struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers"`
	Body       []byte              `json:"body"`
	Timestamp  time.Time           `json:"timestamp"`
}

// Marshal serializes the cached response
func (cr *CachedResponse) Marshal() ([]byte, error) {
	return []byte(fmt.Sprintf("%d|%v|%s|%d", cr.StatusCode, cr.Headers, cr.Body, cr.Timestamp.Unix())), nil
}

// Unmarshal deserializes the cached response
func (cr *CachedResponse) Unmarshal(data []byte) error {
	// Simple unmarshaling - in production, use proper serialization
	parts := strings.SplitN(string(data), "|", 4)
	if len(parts) != 4 {
		return fmt.Errorf("invalid cached response format")
	}

	statusCode, err := strconv.Atoi(parts[0])
	if err != nil {
		return err
	}
	cr.StatusCode = statusCode

	// For simplicity, we'll skip header parsing in this example
	cr.Headers = make(map[string][]string)
	cr.Body = []byte(parts[2])

	timestamp, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		return err
	}
	cr.Timestamp = time.Unix(timestamp, 0)

	return nil
}

// cachingWriter wraps http.ResponseWriter to cache responses
type cachingWriter struct {
	http.ResponseWriter
	cache      ports.CachePort
	cacheKey   string
	config     CacheConfig
	context    context.Context
	statusCode int
	body       []byte
	headers    map[string][]string
}

func (cw *cachingWriter) WriteHeader(code int) {
	cw.statusCode = code
	cw.headers = make(map[string][]string)
	for key, values := range cw.Header() {
		cw.headers[key] = values
	}
	cw.ResponseWriter.WriteHeader(code)
}

func (cw *cachingWriter) Write(data []byte) (int, error) {
	if cw.statusCode == 0 {
		cw.WriteHeader(http.StatusOK)
	}

	cw.body = append(cw.body, data...)
	n, err := cw.ResponseWriter.Write(data)

	// Cache successful responses
	if cw.statusCode == http.StatusOK && cw.isCacheable() {
		cachedResponse := CachedResponse{
			StatusCode: cw.statusCode,
			Headers:    cw.headers,
			Body:       cw.body,
			Timestamp:  time.Now(),
		}

		if data, err := cachedResponse.Marshal(); err == nil {
			_ = cw.cache.Set(cw.context, cw.cacheKey, data, cw.config.DefaultTTL)
		}
	}

	return n, err
}

func (cw *cachingWriter) isCacheable() bool {
	contentType := cw.Header().Get("Content-Type")
	for _, cacheableType := range cw.config.CacheableTypes {
		if strings.Contains(contentType, cacheableType) {
			return true
		}
	}
	return false
}

// generateCacheKey generates a cache key based on request and vary headers
func generateCacheKey(r *http.Request, varyHeaders []string) string {
	h := sha256.New()
	h.Write([]byte(r.Method))
	h.Write([]byte(r.URL.Path))
	h.Write([]byte(r.URL.RawQuery))

	// Include vary headers in cache key
	for _, header := range varyHeaders {
		h.Write([]byte(header))
		h.Write([]byte(r.Header.Get(header)))
	}

	return fmt.Sprintf("http_cache:%x", h.Sum(nil))
}

// getClientIP extracts client IP from request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Use remote address
	parts := strings.Split(r.RemoteAddr, ":")
	if len(parts) > 0 {
		return parts[0]
	}

	return r.RemoteAddr
}