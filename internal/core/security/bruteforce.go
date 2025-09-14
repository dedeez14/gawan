package security

import (
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"Gawan/internal/core/logx"
)

// BruteForceConfig holds brute force protection configuration
type BruteForceConfig struct {
	// Enabled enables brute force protection
	Enabled bool `json:"enabled" yaml:"enabled" env:"BRUTE_FORCE_ENABLED" default:"true"`
	// MaxAttempts is the maximum number of failed attempts allowed
	MaxAttempts int `json:"max_attempts" yaml:"max_attempts" env:"BRUTE_FORCE_MAX_ATTEMPTS" default:"6"`
	// WindowDuration is the time window for counting attempts
	WindowDuration time.Duration `json:"window_duration" yaml:"window_duration" env:"BRUTE_FORCE_WINDOW" default:"60s"`
	// LockoutDuration is how long to lock out after max attempts
	LockoutDuration time.Duration `json:"lockout_duration" yaml:"lockout_duration" env:"BRUTE_FORCE_LOCKOUT" default:"5m"`
	// KeyExtractor extracts the key for tracking attempts (usually IP)
	KeyExtractor KeyExtractor `json:"-" yaml:"-"`
	// LoginPathPatterns are the paths to monitor for login attempts
	LoginPathPatterns []string `json:"login_paths" yaml:"login_paths" env:"BRUTE_FORCE_LOGIN_PATHS"`
	// OnLockout is called when an IP is locked out
	OnLockout BruteForceLockoutHandler `json:"-" yaml:"-"`
	// Logger for audit events
	Logger *logx.Logger `json:"-" yaml:"-"`
}

// BruteForceLockoutHandler handles brute force lockout scenarios
type BruteForceLockoutHandler func(w http.ResponseWriter, r *http.Request, lockoutUntil time.Time, logger *logx.Logger)

// LoginAttemptTracker tracks login attempts and lockouts
type LoginAttemptTracker struct {
	mu           sync.RWMutex
	attempts     map[string]*AttemptRecord
	maxAttempts  int
	windowDuration time.Duration
	lockoutDuration time.Duration
	cleanupTicker *time.Ticker
	stop         chan struct{}
}

// AttemptRecord tracks failed login attempts for a key
type AttemptRecord struct {
	FailedAttempts []time.Time `json:"failed_attempts"`
	LockoutUntil   time.Time   `json:"lockout_until"`
	LastAttempt    time.Time   `json:"last_attempt"`
	mu             sync.RWMutex
}

// NewLoginAttemptTracker creates a new login attempt tracker
func NewLoginAttemptTracker(maxAttempts int, windowDuration, lockoutDuration time.Duration) *LoginAttemptTracker {
	tracker := &LoginAttemptTracker{
		attempts:        make(map[string]*AttemptRecord),
		maxAttempts:     maxAttempts,
		windowDuration:  windowDuration,
		lockoutDuration: lockoutDuration,
		cleanupTicker:   time.NewTicker(windowDuration),
		stop:            make(chan struct{}),
	}

	// Start cleanup goroutine
	go tracker.cleanupRoutine()
	return tracker
}

// IsLockedOut checks if a key is currently locked out
func (lat *LoginAttemptTracker) IsLockedOut(key string) (bool, time.Time) {
	lat.mu.RLock()
	defer lat.mu.RUnlock()

	record, exists := lat.attempts[key]
	if !exists {
		return false, time.Time{}
	}

	record.mu.RLock()
	defer record.mu.RUnlock()

	if record.LockoutUntil.After(time.Now()) {
		return true, record.LockoutUntil
	}
	return false, time.Time{}
}

// RecordFailedAttempt records a failed login attempt
func (lat *LoginAttemptTracker) RecordFailedAttempt(key string) bool {
	lat.mu.Lock()
	defer lat.mu.Unlock()

	record, exists := lat.attempts[key]
	if !exists {
		record = &AttemptRecord{
			FailedAttempts: make([]time.Time, 0),
		}
		lat.attempts[key] = record
	}

	record.mu.Lock()
	defer record.mu.Unlock()

	now := time.Now()
	record.LastAttempt = now

	// Clean old attempts outside the window
	cutoff := now.Add(-lat.windowDuration)
	validAttempts := make([]time.Time, 0)
	for _, attemptTime := range record.FailedAttempts {
		if attemptTime.After(cutoff) {
			validAttempts = append(validAttempts, attemptTime)
		}
	}

	// Add current attempt
	validAttempts = append(validAttempts, now)
	record.FailedAttempts = validAttempts

	// Check if we should lock out
	if len(record.FailedAttempts) >= lat.maxAttempts {
		record.LockoutUntil = now.Add(lat.lockoutDuration)
		return true // Lockout triggered
	}

	return false // No lockout yet
}

// RecordSuccessfulLogin clears failed attempts for a key
func (lat *LoginAttemptTracker) RecordSuccessfulLogin(key string) {
	lat.mu.Lock()
	defer lat.mu.Unlock()

	record, exists := lat.attempts[key]
	if !exists {
		return
	}

	record.mu.Lock()
	defer record.mu.Unlock()

	// Clear failed attempts and lockout
	record.FailedAttempts = make([]time.Time, 0)
	record.LockoutUntil = time.Time{}
}

// GetAttemptCount returns the current number of failed attempts in the window
func (lat *LoginAttemptTracker) GetAttemptCount(key string) int {
	lat.mu.RLock()
	defer lat.mu.RUnlock()

	record, exists := lat.attempts[key]
	if !exists {
		return 0
	}

	record.mu.RLock()
	defer record.mu.RUnlock()

	now := time.Now()
	cutoff := now.Add(-lat.windowDuration)
	count := 0
	for _, attemptTime := range record.FailedAttempts {
		if attemptTime.After(cutoff) {
			count++
		}
	}
	return count
}

// cleanupRoutine removes expired records
func (lat *LoginAttemptTracker) cleanupRoutine() {
	for {
		select {
		case <-lat.cleanupTicker.C:
			lat.cleanupExpired()
		case <-lat.stop:
			return
		}
	}
}

// cleanupExpired removes expired attempt records
func (lat *LoginAttemptTracker) cleanupExpired() {
	lat.mu.Lock()
	defer lat.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-lat.windowDuration * 2) // Keep some buffer

	for key, record := range lat.attempts {
		record.mu.Lock()
		// Remove if no recent activity and not locked out
		if record.LastAttempt.Before(cutoff) && record.LockoutUntil.Before(now) {
			delete(lat.attempts, key)
		}
		record.mu.Unlock()
	}
}

// Stop stops the cleanup routine
func (lat *LoginAttemptTracker) Stop() {
	close(lat.stop)
	lat.cleanupTicker.Stop()
}

// DefaultBruteForceConfig returns default brute force protection configuration
func DefaultBruteForceConfig() BruteForceConfig {
	return BruteForceConfig{
		Enabled:           true,
		MaxAttempts:       6,
		WindowDuration:    60 * time.Second,
		LockoutDuration:   5 * time.Minute,
		KeyExtractor:      IPKeyExtractor,
		LoginPathPatterns: []string{"/login", "/auth", "/signin", "/api/auth/login"},
		OnLockout:         DefaultBruteForceLockoutHandler,
	}
}

// DefaultBruteForceLockoutHandler is the default handler for brute force lockout
func DefaultBruteForceLockoutHandler(w http.ResponseWriter, r *http.Request, lockoutUntil time.Time, logger *logx.Logger) {
	// Audit log the brute force attempt
	if logger != nil {
		logger.Warn("LOGIN_FAIL",
			"event", "LOGIN_FAIL",
			"ip", IPKeyExtractor(r),
			"user_agent", r.UserAgent(),
			"path", r.URL.Path,
			"method", r.Method,
			"lockout_until", lockoutUntil.UTC(),
			"timestamp", time.Now().UTC(),
		)
	}

	retryAfter := int(time.Until(lockoutUntil).Seconds())
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)

	response := map[string]interface{}{
		"error":   "brute_force_protection",
		"message": "Terlalu banyak percobaan login gagal. Akses diblokir selama 5 menit.",
		"code":    429,
		"lockout_until": lockoutUntil.UTC(),
		"retry_after_seconds": retryAfter,
	}

	jsonResponse, _ := json.Marshal(response)
	w.Write(jsonResponse)
}

// matchesLoginPath checks if the request path matches any login path pattern
func matchesLoginPath(path string, patterns []string) bool {
	for _, pattern := range patterns {
		if path == pattern {
			return true
		}
		// Simple wildcard matching
		if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
			prefix := pattern[:len(pattern)-1]
			if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
				return true
			}
		}
	}
	return false
}

// BruteForceProtectionMiddleware creates a brute force protection middleware
func BruteForceProtectionMiddleware(config BruteForceConfig) func(http.Handler) http.Handler {
	if !config.Enabled {
		return func(next http.Handler) http.Handler {
			return next // Pass through if disabled
		}
	}

	// Set defaults
	if config.KeyExtractor == nil {
		config.KeyExtractor = IPKeyExtractor
	}
	if config.OnLockout == nil {
		config.OnLockout = DefaultBruteForceLockoutHandler
	}
	if config.MaxAttempts <= 0 {
		config.MaxAttempts = 6
	}
	if config.WindowDuration <= 0 {
		config.WindowDuration = 60 * time.Second
	}
	if config.LockoutDuration <= 0 {
		config.LockoutDuration = 5 * time.Minute
	}
	if len(config.LoginPathPatterns) == 0 {
		config.LoginPathPatterns = []string{"/login", "/auth", "/signin", "/api/auth/login"}
	}

	tracker := NewLoginAttemptTracker(config.MaxAttempts, config.WindowDuration, config.LockoutDuration)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only apply to login paths
			if !matchesLoginPath(r.URL.Path, config.LoginPathPatterns) {
				next.ServeHTTP(w, r)
				return
			}

			key := config.KeyExtractor(r)
			
			// Check if currently locked out
			if isLocked, lockoutUntil := tracker.IsLockedOut(key); isLocked {
				config.OnLockout(w, r, lockoutUntil, config.Logger)
				return
			}

			// Create a response writer wrapper to capture status code
			wrapped := &bruteForceResponseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
				tracker:        tracker,
				key:            key,
				config:         config,
				request:        r,
			}

			next.ServeHTTP(wrapped, r)
		})
	}
}

// bruteForceResponseWriter wraps http.ResponseWriter to track login failures
type bruteForceResponseWriter struct {
	http.ResponseWriter
	statusCode int
	tracker    *LoginAttemptTracker
	key        string
	config     BruteForceConfig
	request    *http.Request
}

// WriteHeader captures the status code and handles login success/failure
func (bfrw *bruteForceResponseWriter) WriteHeader(code int) {
	bfrw.statusCode = code

	// Handle login success (2xx status codes)
	if code >= 200 && code < 300 {
		bfrw.tracker.RecordSuccessfulLogin(bfrw.key)
	} else if code == http.StatusUnauthorized || code == http.StatusForbidden {
		// Handle login failure
		lockoutTriggered := bfrw.tracker.RecordFailedAttempt(bfrw.key)
		
		// Log the failed attempt
		if bfrw.config.Logger != nil {
			attemptCount := bfrw.tracker.GetAttemptCount(bfrw.key)
			bfrw.config.Logger.Warn("LOGIN_FAIL",
				"event", "LOGIN_FAIL",
				"ip", bfrw.key,
				"user_agent", bfrw.request.UserAgent(),
				"path", bfrw.request.URL.Path,
				"method", bfrw.request.Method,
				"attempt_count", attemptCount,
				"lockout_triggered", lockoutTriggered,
				"timestamp", time.Now().UTC(),
			)
		}
	}

	bfrw.ResponseWriter.WriteHeader(code)
}