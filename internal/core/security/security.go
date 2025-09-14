package security

import (
	"net/http"
	"time"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

// SkipFunc is a function that determines if middleware should be skipped
type SkipFunc func(r *http.Request) bool

// SecurityConfig holds all security configurations
type SecurityConfig struct {
	// CORS configuration
	CORS CORSConfig `json:"cors" yaml:"cors"`
	// Enhanced CORS configuration
	EnhancedCORS EnhancedCORSConfig `json:"enhanced_cors" yaml:"enhanced_cors"`
	// Rate limiting configuration
	RateLimit RateLimitConfig `json:"rate_limit" yaml:"rate_limit"`
	// Enhanced rate limiting configuration
	EnhancedRateLimit EnhancedRateLimitConfig `json:"enhanced_rate_limit" yaml:"enhanced_rate_limit"`
	// Brute force protection configuration
	BruteForce BruteForceConfig `json:"brute_force" yaml:"brute_force"`
	// Security headers configuration
	SecurityHeaders SecurityHeadersConfig `json:"security_headers" yaml:"security_headers"`
	// Payload size limit configuration
	PayloadLimit PayloadLimitConfig `json:"payload_limit" yaml:"payload_limit"`
	// Timeout configuration
	Timeout TimeoutConfig `json:"timeout" yaml:"timeout"`
	// Audit logging configuration
	Audit AuditConfig `json:"audit" yaml:"audit"`
	// JWT configuration
	JWT JWTConfig `json:"jwt" yaml:"jwt"`
	// Session configuration
	Session SessionConfig `json:"session" yaml:"session"`
	// RBAC configuration
	RBAC RBACConfig `json:"rbac" yaml:"rbac"`
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	// Enabled enables rate limiting
	Enabled bool `json:"enabled" yaml:"enabled" env:"RATE_LIMIT_ENABLED" default:"true"`
	// RequestsPerMinute is the number of requests allowed per minute
	RequestsPerMinute int `json:"requests_per_minute" yaml:"requests_per_minute" env:"RATE_LIMIT_RPM" default:"60"`
	// BurstSize is the burst size for the token bucket
	BurstSize int `json:"burst_size" yaml:"burst_size" env:"RATE_LIMIT_BURST" default:"10"`
	// KeyExtractor extracts the key for rate limiting
	KeyExtractor KeyExtractor `json:"-" yaml:"-"`
	// SkipFunc determines if rate limiting should be skipped
	SkipFunc SkipFunc `json:"-" yaml:"-"`
	// ErrorHandler handles rate limit errors
	ErrorHandler RateLimitErrorHandler `json:"-" yaml:"-"`
}

// DefaultSecurityConfig returns default security configuration
func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		CORS:              DefaultCORSConfig(),
		EnhancedCORS:      DefaultEnhancedCORSConfig(),
		RateLimit:         DefaultRateLimitConfig(),
		EnhancedRateLimit: DefaultEnhancedRateLimitConfig(),
		BruteForce:        DefaultBruteForceConfig(),
		SecurityHeaders:   DefaultSecurityHeadersConfig(),
		PayloadLimit:      DefaultPayloadLimitConfig(),
		Timeout:           DefaultTimeoutConfig(),
		Audit:             DefaultAuditConfig(),
		JWT:               DefaultJWTConfig(),
		Session:           DefaultSessionConfig(),
		RBAC:              DefaultRBACConfig(),
	}
}

// DefaultRateLimitConfig returns default rate limit configuration
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Enabled:           true,
		RequestsPerMinute: 60,
		BurstSize:         10,
		KeyExtractor:      IPKeyExtractor,
		ErrorHandler:      DefaultRateLimitErrorHandler,
	}
}

// SecurityMiddleware creates a comprehensive security middleware stack
type SecurityMiddleware struct {
	config               SecurityConfig
	sessionManager       *SessionManager
	rateLimiter          *TokenBucketLimiter
	enhancedRateLimiter  *EnhancedRateLimiter
	bruteForceProtector  *BruteForceProtector
	auditLogger          *AuditLogger
	jwtService           *JWTService
}

// NewSecurityMiddleware creates a new security middleware
func NewSecurityMiddleware(config SecurityConfig) *SecurityMiddleware {
	sm := &SecurityMiddleware{
		config: config,
	}

	// Initialize audit logger
	if config.Audit.Enabled {
		sm.auditLogger = NewAuditLogger(config.Audit)
	}

	// Initialize session manager if enabled
	if config.Session.Store != nil {
		sm.sessionManager = NewSessionManager(config.Session)
	}

	// Initialize rate limiter if enabled
	if config.RateLimit.Enabled {
		sm.rateLimiter = NewTokenBucketLimiter(
			config.RateLimit.RequestsPerMinute,
			config.RateLimit.BurstSize,
			time.Minute,
		)
	}

	// Initialize enhanced rate limiter if enabled
	if config.EnhancedRateLimit.Enabled {
		enhancedConfig := config.EnhancedRateLimit
		enhancedConfig.AuditLogger = sm.auditLogger
		sm.enhancedRateLimiter = NewEnhancedRateLimiter(enhancedConfig)
	}

	// Initialize brute force protector if enabled
	if config.BruteForce.Enabled {
		bruteForceConfig := config.BruteForce
		bruteForceConfig.AuditLogger = sm.auditLogger
		sm.bruteForceProtector = NewBruteForceProtector(bruteForceConfig)
	}

	// Initialize JWT service if enabled
	if config.JWT.Enabled {
		sm.jwtService = NewJWTService(config.JWT)
	}

	return sm
}

// Handler returns the complete security middleware stack
func (sm *SecurityMiddleware) Handler() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := next

		// Apply RBAC middleware (innermost)
		if sm.config.RBAC.Enabled {
			handler = RBACMiddleware(sm.config.RBAC)(handler)
		}

		// Apply JWT middleware
		if sm.config.JWT.Enabled && sm.jwtService != nil {
			handler = JWTMiddleware(sm.config.JWT)(handler)
		}

		// Apply session middleware
		if sm.sessionManager != nil {
			handler = SessionMiddleware(sm.sessionManager)(handler)
		}

		// Apply brute force protection middleware
		if sm.config.BruteForce.Enabled && sm.bruteForceProtector != nil {
			handler = BruteForceMiddleware(sm.config.BruteForce)(handler)
		}

		// Apply enhanced rate limiting middleware (takes precedence over basic rate limiting)
		if sm.config.EnhancedRateLimit.Enabled && sm.enhancedRateLimiter != nil {
			handler = EnhancedRateLimitMiddleware(sm.config.EnhancedRateLimit)(handler)
		} else if sm.config.RateLimit.Enabled && sm.rateLimiter != nil {
			// Apply basic rate limiting middleware if enhanced is not enabled
			handler = RateLimitMiddleware(
				sm.rateLimiter,
				sm.config.RateLimit.KeyExtractor,
				sm.config.RateLimit.SkipFunc,
				sm.config.RateLimit.ErrorHandler,
			)(handler)
		}

		// Apply payload size limit middleware
		if sm.config.PayloadLimit.Enabled {
			handler = PayloadLimitMiddleware(sm.config.PayloadLimit)(handler)
		}

		// Apply timeout middleware
		if sm.config.Timeout.Enabled {
			handler = TimeoutMiddleware(sm.config.Timeout)(handler)
		}

		// Apply security headers middleware
		if sm.config.SecurityHeaders.Enabled {
			handler = SecurityHeadersMiddleware(sm.config.SecurityHeaders)(handler)
		}

		// Apply enhanced CORS middleware (takes precedence over basic CORS)
		if sm.config.EnhancedCORS.Enabled {
			handler = EnhancedCORSMiddleware(sm.config.EnhancedCORS)(handler)
		} else {
			// Apply basic CORS middleware (outermost)
			handler = CORSMiddleware(sm.config.CORS)(handler)
		}

		return handler
	}
}

// CORSHandler returns only CORS middleware
func (sm *SecurityMiddleware) CORSHandler() func(http.Handler) http.Handler {
	return CORSMiddleware(sm.config.CORS)
}

// RateLimitHandler returns only rate limiting middleware
func (sm *SecurityMiddleware) RateLimitHandler() func(http.Handler) http.Handler {
	if !sm.config.RateLimit.Enabled || sm.rateLimiter == nil {
		return func(next http.Handler) http.Handler {
			return next
		}
	}
	return RateLimitMiddleware(
		sm.rateLimiter,
		sm.config.RateLimit.KeyExtractor,
		sm.config.RateLimit.SkipFunc,
		sm.config.RateLimit.ErrorHandler,
	)
}

// JWTHandler returns only JWT middleware
func (sm *SecurityMiddleware) JWTHandler() func(http.Handler) http.Handler {
	if !sm.config.JWT.Enabled {
		return func(next http.Handler) http.Handler {
			return next
		}
	}
	return JWTMiddleware(sm.config.JWT)
}

// SessionHandler returns only session middleware
func (sm *SecurityMiddleware) SessionHandler() func(http.Handler) http.Handler {
	if sm.sessionManager == nil {
		return func(next http.Handler) http.Handler {
			return next
		}
	}
	return SessionMiddleware(sm.sessionManager)
}

// RBACHandler returns only RBAC middleware
func (sm *SecurityMiddleware) RBACHandler() func(http.Handler) http.Handler {
	if !sm.config.RBAC.Enabled {
		return func(next http.Handler) http.Handler {
			return next
		}
	}
	return RBACMiddleware(sm.config.RBAC)
}

// GetSessionManager returns the session manager
func (sm *SecurityMiddleware) GetSessionManager() *SessionManager {
	return sm.sessionManager
}

// GetJWTService returns the JWT service
func (sm *SecurityMiddleware) GetJWTService() *JWTService {
	return sm.jwtService
}

// GetRateLimiter returns the rate limiter
func (sm *SecurityMiddleware) GetRateLimiter() *TokenBucketLimiter {
	return sm.rateLimiter
}

// GetEnhancedRateLimiter returns the enhanced rate limiter
func (sm *SecurityMiddleware) GetEnhancedRateLimiter() *EnhancedRateLimiter {
	return sm.enhancedRateLimiter
}

// GetBruteForceProtector returns the brute force protector
func (sm *SecurityMiddleware) GetBruteForceProtector() *BruteForceProtector {
	return sm.bruteForceProtector
}

// GetAuditLogger returns the audit logger
func (sm *SecurityMiddleware) GetAuditLogger() *AuditLogger {
	return sm.auditLogger
}

// EnhancedRateLimitHandler returns only enhanced rate limiting middleware
func (sm *SecurityMiddleware) EnhancedRateLimitHandler() func(http.Handler) http.Handler {
	if !sm.config.EnhancedRateLimit.Enabled || sm.enhancedRateLimiter == nil {
		return func(next http.Handler) http.Handler {
			return next
		}
	}
	return EnhancedRateLimitMiddleware(sm.config.EnhancedRateLimit)
}

// BruteForceHandler returns only brute force protection middleware
func (sm *SecurityMiddleware) BruteForceHandler() func(http.Handler) http.Handler {
	if !sm.config.BruteForce.Enabled || sm.bruteForceProtector == nil {
		return func(next http.Handler) http.Handler {
			return next
		}
	}
	return BruteForceMiddleware(sm.config.BruteForce)
}

// SecurityHeadersHandler returns only security headers middleware
func (sm *SecurityMiddleware) SecurityHeadersHandler() func(http.Handler) http.Handler {
	if !sm.config.SecurityHeaders.Enabled {
		return func(next http.Handler) http.Handler {
			return next
		}
	}
	return SecurityHeadersMiddleware(sm.config.SecurityHeaders)
}

// PayloadLimitHandler returns only payload limit middleware
func (sm *SecurityMiddleware) PayloadLimitHandler() func(http.Handler) http.Handler {
	if !sm.config.PayloadLimit.Enabled {
		return func(next http.Handler) http.Handler {
			return next
		}
	}
	return PayloadLimitMiddleware(sm.config.PayloadLimit)
}

// TimeoutHandler returns only timeout middleware
func (sm *SecurityMiddleware) TimeoutHandler() func(http.Handler) http.Handler {
	if !sm.config.Timeout.Enabled {
		return func(next http.Handler) http.Handler {
			return next
		}
	}
	return TimeoutMiddleware(sm.config.Timeout)
}

// EnhancedCORSHandler returns only enhanced CORS middleware
func (sm *SecurityMiddleware) EnhancedCORSHandler() func(http.Handler) http.Handler {
	if !sm.config.EnhancedCORS.Enabled {
		return func(next http.Handler) http.Handler {
			return next
		}
	}
	return EnhancedCORSMiddleware(sm.config.EnhancedCORS)
}

// Stop stops all security services
func (sm *SecurityMiddleware) Stop() {
	if sm.sessionManager != nil {
		sm.sessionManager.Stop()
	}
	if sm.rateLimiter != nil {
		sm.rateLimiter.Stop()
	}
	if sm.enhancedRateLimiter != nil {
		sm.enhancedRateLimiter.Stop()
	}
	if sm.bruteForceProtector != nil {
		sm.bruteForceProtector.Stop()
	}
}

// Common skip functions

// SkipHealthCheck skips middleware for health check endpoints
func SkipHealthCheck(r *http.Request) bool {
	return r.URL.Path == "/health" || r.URL.Path == "/healthz" || r.URL.Path == "/ping"
}

// SkipStatic skips middleware for static file requests
func SkipStatic(r *http.Request) bool {
	path := r.URL.Path
	return len(path) > 4 && (
		path[len(path)-4:] == ".css" ||
		path[len(path)-3:] == ".js" ||
		path[len(path)-4:] == ".png" ||
		path[len(path)-4:] == ".jpg" ||
		path[len(path)-5:] == ".jpeg" ||
		path[len(path)-4:] == ".gif" ||
		path[len(path)-4:] == ".svg" ||
		path[len(path)-4:] == ".ico")
}

// SkipPublicEndpoints skips middleware for public endpoints
func SkipPublicEndpoints(r *http.Request) bool {
	path := r.URL.Path
	return path == "/" ||
		path == "/login" ||
		path == "/register" ||
		path == "/forgot-password" ||
		path == "/reset-password" ||
		path == "/public" ||
		len(path) > 7 && path[:8] == "/public/"
}

// CombineSkipFuncs combines multiple skip functions with OR logic
func CombineSkipFuncs(funcs ...SkipFunc) SkipFunc {
	return func(r *http.Request) bool {
		for _, fn := range funcs {
			if fn != nil && fn(r) {
				return true
			}
		}
		return false
	}
}

// SecurityBuilder helps build security middleware with fluent API
type SecurityBuilder struct {
	config SecurityConfig
}

// NewSecurityBuilder creates a new security builder
func NewSecurityBuilder() *SecurityBuilder {
	return &SecurityBuilder{
		config: DefaultSecurityConfig(),
	}
}

// WithCORS configures CORS
func (sb *SecurityBuilder) WithCORS(config CORSConfig) *SecurityBuilder {
	sb.config.CORS = config
	return sb
}

// WithRateLimit configures rate limiting
func (sb *SecurityBuilder) WithRateLimit(config RateLimitConfig) *SecurityBuilder {
	sb.config.RateLimit = config
	return sb
}

// WithJWT configures JWT authentication
func (sb *SecurityBuilder) WithJWT(config JWTConfig) *SecurityBuilder {
	sb.config.JWT = config
	return sb
}

// WithSession configures session management
func (sb *SecurityBuilder) WithSession(config SessionConfig) *SecurityBuilder {
	sb.config.Session = config
	return sb
}

// WithRBAC configures RBAC
func (sb *SecurityBuilder) WithRBAC(config RBACConfig) *SecurityBuilder {
	sb.config.RBAC = config
	return sb
}

// WithEnhancedCORS configures enhanced CORS
func (sb *SecurityBuilder) WithEnhancedCORS(config EnhancedCORSConfig) *SecurityBuilder {
	sb.config.EnhancedCORS = config
	return sb
}

// WithEnhancedRateLimit configures enhanced rate limiting
func (sb *SecurityBuilder) WithEnhancedRateLimit(config EnhancedRateLimitConfig) *SecurityBuilder {
	sb.config.EnhancedRateLimit = config
	return sb
}

// WithBruteForce configures brute force protection
func (sb *SecurityBuilder) WithBruteForce(config BruteForceConfig) *SecurityBuilder {
	sb.config.BruteForce = config
	return sb
}

// WithSecurityHeaders configures security headers
func (sb *SecurityBuilder) WithSecurityHeaders(config SecurityHeadersConfig) *SecurityBuilder {
	sb.config.SecurityHeaders = config
	return sb
}

// WithPayloadLimit configures payload size limits
func (sb *SecurityBuilder) WithPayloadLimit(config PayloadLimitConfig) *SecurityBuilder {
	sb.config.PayloadLimit = config
	return sb
}

// WithTimeout configures timeout handling
func (sb *SecurityBuilder) WithTimeout(config TimeoutConfig) *SecurityBuilder {
	sb.config.Timeout = config
	return sb
}

// WithAudit configures audit logging
func (sb *SecurityBuilder) WithAudit(config AuditConfig) *SecurityBuilder {
	sb.config.Audit = config
	return sb
}

// DisableCORS disables CORS
func (sb *SecurityBuilder) DisableCORS() *SecurityBuilder {
	sb.config.CORS.Enabled = false
	return sb
}

// DisableRateLimit disables rate limiting
func (sb *SecurityBuilder) DisableRateLimit() *SecurityBuilder {
	sb.config.RateLimit.Enabled = false
	return sb
}

// DisableJWT disables JWT authentication
func (sb *SecurityBuilder) DisableJWT() *SecurityBuilder {
	sb.config.JWT.Enabled = false
	return sb
}

// DisableRBAC disables RBAC
func (sb *SecurityBuilder) DisableRBAC() *SecurityBuilder {
	sb.config.RBAC.Enabled = false
	return sb
}

// DisableEnhancedCORS disables enhanced CORS
func (sb *SecurityBuilder) DisableEnhancedCORS() *SecurityBuilder {
	sb.config.EnhancedCORS.Enabled = false
	return sb
}

// DisableEnhancedRateLimit disables enhanced rate limiting
func (sb *SecurityBuilder) DisableEnhancedRateLimit() *SecurityBuilder {
	sb.config.EnhancedRateLimit.Enabled = false
	return sb
}

// DisableBruteForce disables brute force protection
func (sb *SecurityBuilder) DisableBruteForce() *SecurityBuilder {
	sb.config.BruteForce.Enabled = false
	return sb
}

// DisableSecurityHeaders disables security headers
func (sb *SecurityBuilder) DisableSecurityHeaders() *SecurityBuilder {
	sb.config.SecurityHeaders.Enabled = false
	return sb
}

// DisablePayloadLimit disables payload size limits
func (sb *SecurityBuilder) DisablePayloadLimit() *SecurityBuilder {
	sb.config.PayloadLimit.Enabled = false
	return sb
}

// DisableTimeout disables timeout handling
func (sb *SecurityBuilder) DisableTimeout() *SecurityBuilder {
	sb.config.Timeout.Enabled = false
	return sb
}

// DisableAudit disables audit logging
func (sb *SecurityBuilder) DisableAudit() *SecurityBuilder {
	sb.config.Audit.Enabled = false
	return sb
}

// Build creates the security middleware
func (sb *SecurityBuilder) Build() *SecurityMiddleware {
	return NewSecurityMiddleware(sb.config)
}

// Preset configurations

// DevelopmentSecurity returns security configuration for development
func DevelopmentSecurity() SecurityConfig {
	config := DefaultSecurityConfig()
	
	// Relaxed CORS for development
	config.CORS = DevelopmentCORSConfig()
	config.EnhancedCORS = DevelopmentEnhancedCORSConfig()
	
	// Higher rate limits for development
	config.RateLimit.RequestsPerMinute = 300
	config.RateLimit.BurstSize = 50
	config.EnhancedRateLimit = LenientEnhancedRateLimitConfig()
	
	// Relaxed brute force protection for development
	config.BruteForce = LenientBruteForceConfig()
	
	// Development-friendly security headers
	config.SecurityHeaders = DevelopmentSecurityHeadersConfig()
	
	// Higher payload limits for development
	config.PayloadLimit = LenientPayloadLimitConfig()
	
	// Lenient timeouts for development
	config.Timeout = LenientTimeoutConfig()
	
	// Enable audit logging for development
	config.Audit.Enabled = true
	
	// Shorter JWT expiration for testing
	config.JWT.AccessTokenExpiry = 15 * time.Minute
	config.JWT.RefreshTokenExpiry = 24 * time.Hour
	
	// Shorter session timeout
	config.Session.MaxAge = 1800 // 30 minutes
	
	return config
}

// ProductionSecurity returns security configuration for production
func ProductionSecurity() SecurityConfig {
	config := DefaultSecurityConfig()
	
	// Strict CORS for production
	config.CORS = StrictCORSConfig()
	config.EnhancedCORS = StrictEnhancedCORSConfig()
	
	// Indonesian compliance: 100 requests per 10 seconds
	config.RateLimit.RequestsPerMinute = 60
	config.RateLimit.BurstSize = 10
	config.EnhancedRateLimit = DefaultEnhancedRateLimitConfig() // 100 req/10s
	
	// Indonesian compliance: 6 failures/60s → 5min lockout
	config.BruteForce = DefaultBruteForceConfig()
	
	// Strict security headers for production
	config.SecurityHeaders = StrictSecurityHeadersConfig()
	
	// Indonesian compliance: >1MB → 413/400
	config.PayloadLimit = DefaultPayloadLimitConfig()
	
	// Strict timeouts for production
	config.Timeout = StrictTimeoutConfig()
	
	// Enable audit logging for production
	config.Audit.Enabled = true
	
	// Longer JWT expiration for production
	config.JWT.AccessTokenExpiry = 1 * time.Hour
	config.JWT.RefreshTokenExpiry = 7 * 24 * time.Hour
	
	// Standard session timeout
	config.Session.MaxAge = 3600 // 1 hour
	config.Session.CookieSecure = true
	
	return config
}

// APIOnlySecurity returns security configuration for API-only services
func APIOnlySecurity() SecurityConfig {
	config := DefaultSecurityConfig()
	
	// API-friendly CORS
	config.CORS.AllowCredentials = false
	config.CORS.AllowedHeaders = []string{"Authorization", "Content-Type", "X-API-Key"}
	config.EnhancedCORS.AllowCredentials = false
	config.EnhancedCORS.AllowedHeaders = []string{"Authorization", "Content-Type", "X-API-Key"}
	
	// JWT only, no sessions
	config.Session.Store = nil
	
	// API key based rate limiting
	config.RateLimit.KeyExtractor = APIKeyExtractor
	config.EnhancedRateLimit.KeyExtractor = APIKeyExtractor
	
	// API-specific brute force protection
	config.BruteForce.KeyExtractor = APIKeyExtractor
	
	// API-friendly security headers
	config.SecurityHeaders = APISecurityHeadersConfig()
	
	// Standard payload limits for APIs
	config.PayloadLimit = DefaultPayloadLimitConfig()
	
	// API-appropriate timeouts
	config.Timeout = DefaultTimeoutConfig()
	
	// Enable audit logging for APIs
	config.Audit.Enabled = true
	
	return config
}

// IndonesianComplianceSecurity returns security configuration compliant with Indonesian requirements
func IndonesianComplianceSecurity() SecurityConfig {
	config := ProductionSecurity()
	
	// Indonesian specific requirements
	// Rate limiting: 100 requests/10 seconds → 429 when quota exhausted
	config.EnhancedRateLimit.Enabled = true
	config.EnhancedRateLimit.RequestsPerWindow = 100
	config.EnhancedRateLimit.WindowDuration = 10 * time.Second
	
	// Brute force: 6 failed login attempts in 60s → 429 + 5min wait
	config.BruteForce.Enabled = true
	config.BruteForce.MaxAttempts = 6
	config.BruteForce.WindowDuration = 60 * time.Second
	config.BruteForce.LockoutDuration = 5 * time.Minute
	
	// Security headers: all security headers must be available
	config.SecurityHeaders.Enabled = true
	config.SecurityHeaders = StrictSecurityHeadersConfig()
	
	// Payload size: >1MB → 413 or 400
	config.PayloadLimit.Enabled = true
	config.PayloadLimit.MaxSize = 1024 * 1024 // 1MB
	
	// CORS: only whitelisted origins allowed for cookies/authorization
	config.EnhancedCORS.Enabled = true
	config.EnhancedCORS.StrictOriginCheck = true
	
	// Timeout: idle/slow connections closed per configuration
	config.Timeout.Enabled = true
	
	// Audit: LOGIN_FAIL/RATE_LIMIT_HIT events must be logged
	config.Audit.Enabled = true
	
	return config
}