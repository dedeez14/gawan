package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"Gawan/internal/core/logx"
)

// TimeoutConfig holds timeout configuration
type TimeoutConfig struct {
	// Enabled enables timeout middleware
	Enabled bool `json:"enabled" yaml:"enabled" env:"TIMEOUT_ENABLED" default:"true"`
	
	// ReadTimeout is the maximum duration for reading the entire request
	ReadTimeout time.Duration `json:"read_timeout" yaml:"read_timeout" env:"TIMEOUT_READ" default:"30s"`
	
	// WriteTimeout is the maximum duration before timing out writes of the response
	WriteTimeout time.Duration `json:"write_timeout" yaml:"write_timeout" env:"TIMEOUT_WRITE" default:"30s"`
	
	// IdleTimeout is the maximum amount of time to wait for the next request when keep-alives are enabled
	IdleTimeout time.Duration `json:"idle_timeout" yaml:"idle_timeout" env:"TIMEOUT_IDLE" default:"120s"`
	
	// HandlerTimeout is the maximum duration for handler execution
	HandlerTimeout time.Duration `json:"handler_timeout" yaml:"handler_timeout" env:"TIMEOUT_HANDLER" default:"60s"`
	
	// SlowRequestThreshold defines what constitutes a slow request
	SlowRequestThreshold time.Duration `json:"slow_request_threshold" yaml:"slow_request_threshold" env:"TIMEOUT_SLOW_THRESHOLD" default:"10s"`
	
	// OnTimeout is called when a timeout occurs
	OnTimeout TimeoutHandler `json:"-" yaml:"-"`
	
	// OnSlowRequest is called when a slow request is detected
	OnSlowRequest SlowRequestHandler `json:"-" yaml:"-"`
	
	// Logger for timeout events
	Logger *logx.Logger `json:"-" yaml:"-"`
	
	// AuditLogger for security events
	AuditLogger *AuditLogger `json:"-" yaml:"-"`
	
	// SkipPaths are paths to skip timeout checking
	SkipPaths []string `json:"skip_paths" yaml:"skip_paths" env:"TIMEOUT_SKIP_PATHS"`
	
	// LongRunningPaths are paths that are allowed longer execution times
	LongRunningPaths map[string]time.Duration `json:"long_running_paths" yaml:"long_running_paths"`
}

// TimeoutHandler handles timeout scenarios
type TimeoutHandler func(w http.ResponseWriter, r *http.Request, timeoutType string, duration time.Duration, logger *logx.Logger, auditLogger *AuditLogger)

// SlowRequestHandler handles slow request scenarios
type SlowRequestHandler func(r *http.Request, duration time.Duration, logger *logx.Logger)

// TimeoutType represents different types of timeouts
type TimeoutType string

const (
	TimeoutTypeHandler TimeoutType = "HANDLER_TIMEOUT"
	TimeoutTypeRead    TimeoutType = "READ_TIMEOUT"
	TimeoutTypeWrite   TimeoutType = "WRITE_TIMEOUT"
	TimeoutTypeIdle    TimeoutType = "IDLE_TIMEOUT"
)

// DefaultTimeoutConfig returns default timeout configuration
func DefaultTimeoutConfig() TimeoutConfig {
	return TimeoutConfig{
		Enabled:              true,
		ReadTimeout:          30 * time.Second,
		WriteTimeout:         30 * time.Second,
		IdleTimeout:          120 * time.Second,
		HandlerTimeout:       60 * time.Second,
		SlowRequestThreshold: 10 * time.Second,
		OnTimeout:            DefaultTimeoutHandler,
		OnSlowRequest:        DefaultSlowRequestHandler,
		SkipPaths:            []string{"/health", "/metrics", "/ping"},
		LongRunningPaths:     make(map[string]time.Duration),
	}
}

// StrictTimeoutConfig returns a strict timeout configuration
func StrictTimeoutConfig() TimeoutConfig {
	config := DefaultTimeoutConfig()
	config.ReadTimeout = 15 * time.Second
	config.WriteTimeout = 15 * time.Second
	config.IdleTimeout = 60 * time.Second
	config.HandlerTimeout = 30 * time.Second
	config.SlowRequestThreshold = 5 * time.Second
	return config
}

// LenientTimeoutConfig returns a lenient timeout configuration
func LenientTimeoutConfig() TimeoutConfig {
	config := DefaultTimeoutConfig()
	config.ReadTimeout = 60 * time.Second
	config.WriteTimeout = 60 * time.Second
	config.IdleTimeout = 300 * time.Second
	config.HandlerTimeout = 120 * time.Second
	config.SlowRequestThreshold = 30 * time.Second
	return config
}

// DefaultTimeoutHandler is the default handler for timeouts
func DefaultTimeoutHandler(w http.ResponseWriter, r *http.Request, timeoutType string, duration time.Duration, logger *logx.Logger, auditLogger *AuditLogger) {
	// Audit log the timeout
	if auditLogger != nil {
		metadata := map[string]interface{}{
			"timeout_type": timeoutType,
			"duration":     duration.String(),
			"user_agent":   r.UserAgent(),
			"content_type": r.Header.Get("Content-Type"),
		}
		auditLogger.LogSecurityViolation(r, "TIMEOUT_EXCEEDED", 
			fmt.Sprintf("Request timeout: %s after %s", timeoutType, duration),
			AuditSeverityMedium, metadata)
	}
	
	// Log the timeout
	if logger != nil {
		logger.Warn("TIMEOUT_EXCEEDED",
			"event", "TIMEOUT_EXCEEDED",
			"ip", GetClientIP(r),
			"user_agent", r.UserAgent(),
			"path", r.URL.Path,
			"method", r.Method,
			"timeout_type", timeoutType,
			"duration", duration.String(),
		)
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusRequestTimeout)
	
	response := map[string]interface{}{
		"error":   "request_timeout",
		"message": "Permintaan melebihi batas waktu yang diizinkan",
		"code":    408,
		"details": map[string]interface{}{
			"timeout_type": timeoutType,
			"duration":     duration.String(),
		},
	}
	
	jsonResponse, _ := json.Marshal(response)
	w.Write(jsonResponse)
}

// DefaultSlowRequestHandler is the default handler for slow requests
func DefaultSlowRequestHandler(r *http.Request, duration time.Duration, logger *logx.Logger) {
	if logger != nil {
		logger.Warn("SLOW_REQUEST",
			"event", "SLOW_REQUEST",
			"ip", GetClientIP(r),
			"user_agent", r.UserAgent(),
			"path", r.URL.Path,
			"method", r.Method,
			"duration", duration.String(),
		)
	}
}

// shouldSkipTimeout checks if timeout should be skipped for this path
func shouldSkipTimeout(path string, skipPaths []string) bool {
	for _, skipPath := range skipPaths {
		if path == skipPath {
			return true
		}
		// Simple wildcard matching
		if len(skipPath) > 0 && skipPath[len(skipPath)-1] == '*' {
			prefix := skipPath[:len(skipPath)-1]
			if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
				return true
			}
		}
	}
	return false
}

// getTimeoutForPath gets the timeout duration for a specific path
func getTimeoutForPath(path string, defaultTimeout time.Duration, longRunningPaths map[string]time.Duration) time.Duration {
	if timeout, exists := longRunningPaths[path]; exists {
		return timeout
	}
	
	// Check for wildcard matches
	for pathPattern, timeout := range longRunningPaths {
		if len(pathPattern) > 0 && pathPattern[len(pathPattern)-1] == '*' {
			prefix := pathPattern[:len(pathPattern)-1]
			if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
				return timeout
			}
		}
	}
	
	return defaultTimeout
}

// timeoutResponseWriter wraps http.ResponseWriter to track write timeouts
type timeoutResponseWriter struct {
	http.ResponseWriter
	writeTimeout time.Duration
	written      bool
}

// Write implements http.ResponseWriter with timeout tracking
func (trw *timeoutResponseWriter) Write(data []byte) (int, error) {
	trw.written = true
	return trw.ResponseWriter.Write(data)
}

// WriteHeader implements http.ResponseWriter with timeout tracking
func (trw *timeoutResponseWriter) WriteHeader(code int) {
	trw.written = true
	rw.ResponseWriter.WriteHeader(code)
}

// TimeoutMiddleware creates a timeout handling middleware
func TimeoutMiddleware(config TimeoutConfig) func(http.Handler) http.Handler {
	if !config.Enabled {
		return func(next http.Handler) http.Handler {
			return next // Pass through if disabled
		}
	}
	
	// Set defaults
	if config.OnTimeout == nil {
		config.OnTimeout = DefaultTimeoutHandler
	}
	if config.OnSlowRequest == nil {
		config.OnSlowRequest = DefaultSlowRequestHandler
	}
	if config.HandlerTimeout <= 0 {
		config.HandlerTimeout = 60 * time.Second
	}
	if config.SlowRequestThreshold <= 0 {
		config.SlowRequestThreshold = 10 * time.Second
	}
	
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip timeout for certain paths
			if shouldSkipTimeout(r.URL.Path, config.SkipPaths) {
				next.ServeHTTP(w, r)
				return
			}
			
			// Get timeout for this specific path
			handlerTimeout := getTimeoutForPath(r.URL.Path, config.HandlerTimeout, config.LongRunningPaths)
			
			// Create context with timeout
			ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
			defer cancel()
			
			// Update request with timeout context
			r = r.WithContext(ctx)
			
			// Track request start time
			startTime := time.Now()
			
			// Create a channel to signal completion
			done := make(chan struct{})
			var handlerPanic interface{}
			
			// Wrap response writer for timeout tracking
			timeoutWriter := &timeoutResponseWriter{
				ResponseWriter: w,
				writeTimeout:   config.WriteTimeout,
			}
			
			// Run handler in goroutine
			go func() {
				defer func() {
					if p := recover(); p != nil {
						handlerPanic = p
					}
					close(done)
				}()
				
				next.ServeHTTP(timeoutWriter, r)
			}()
			
			// Wait for completion or timeout
			select {
			case <-done:
				// Handler completed
				duration := time.Since(startTime)
				
				// Check if it was a slow request
				if duration > config.SlowRequestThreshold {
					config.OnSlowRequest(r, duration, config.Logger)
				}
				
				// Re-panic if handler panicked
				if handlerPanic != nil {
					panic(handlerPanic)
				}
				
			case <-ctx.Done():
				// Timeout occurred
				duration := time.Since(startTime)
				
				// Only send timeout response if nothing was written yet
				if !timeoutWriter.written {
					config.OnTimeout(w, r, string(TimeoutTypeHandler), duration, config.Logger, config.AuditLogger)
				}
			}
		})
	}
}

// ConfigureServerTimeouts configures server-level timeouts
func ConfigureServerTimeouts(server *http.Server, config TimeoutConfig) {
	if !config.Enabled {
		return
	}
	
	if config.ReadTimeout > 0 {
		server.ReadTimeout = config.ReadTimeout
	}
	if config.WriteTimeout > 0 {
		server.WriteTimeout = config.WriteTimeout
	}
	if config.IdleTimeout > 0 {
		server.IdleTimeout = config.IdleTimeout
	}
}

// TimeoutListener wraps a net.Listener to enforce connection timeouts
type TimeoutListener struct {
	net.Listener
	readTimeout  time.Duration
	writeTimeout time.Duration
}

// NewTimeoutListener creates a new timeout listener
func NewTimeoutListener(listener net.Listener, readTimeout, writeTimeout time.Duration) *TimeoutListener {
	return &TimeoutListener{
		Listener:     listener,
		readTimeout:  readTimeout,
		writeTimeout: writeTimeout,
	}
}

// Accept accepts connections with timeout configuration
func (tl *TimeoutListener) Accept() (net.Conn, error) {
	conn, err := tl.Listener.Accept()
	if err != nil {
		return nil, err
	}
	
	return &timeoutConn{
		Conn:         conn,
		readTimeout:  tl.readTimeout,
		writeTimeout: tl.writeTimeout,
	}, nil
}

// timeoutConn wraps net.Conn to enforce read/write timeouts
type timeoutConn struct {
	net.Conn
	readTimeout  time.Duration
	writeTimeout time.Duration
}

// Read implements net.Conn with read timeout
func (tc *timeoutConn) Read(b []byte) (int, error) {
	if tc.readTimeout > 0 {
		tc.Conn.SetReadDeadline(time.Now().Add(tc.readTimeout))
	}
	return tc.Conn.Read(b)
}

// Write implements net.Conn with write timeout
func (tc *timeoutConn) Write(b []byte) (int, error) {
	if tc.writeTimeout > 0 {
		tc.Conn.SetWriteDeadline(time.Now().Add(tc.writeTimeout))
	}
	return tc.Conn.Write(b)
}

// ValidateTimeoutConfig validates timeout configuration
func ValidateTimeoutConfig(config TimeoutConfig) error {
	if !config.Enabled {
		return nil
	}
	
	if config.ReadTimeout < 0 {
		return fmt.Errorf("read timeout cannot be negative")
	}
	if config.WriteTimeout < 0 {
		return fmt.Errorf("write timeout cannot be negative")
	}
	if config.IdleTimeout < 0 {
		return fmt.Errorf("idle timeout cannot be negative")
	}
	if config.HandlerTimeout <= 0 {
		return fmt.Errorf("handler timeout must be positive")
	}
	if config.SlowRequestThreshold < 0 {
		return fmt.Errorf("slow request threshold cannot be negative")
	}
	
	// Validate that handler timeout is reasonable compared to read/write timeouts
	if config.ReadTimeout > 0 && config.HandlerTimeout > config.ReadTimeout*2 {
		return fmt.Errorf("handler timeout should not be much larger than read timeout")
	}
	
	return nil
}