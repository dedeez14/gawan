package security

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"Gawan/internal/core/logx"
)

// EnhancedCORSConfig holds enhanced CORS configuration with strict security
type EnhancedCORSConfig struct {
	// Enabled enables CORS middleware
	Enabled bool `json:"enabled" yaml:"enabled" env:"CORS_ENABLED" default:"true"`
	
	// AllowedOrigins is a whitelist of allowed origins
	AllowedOrigins []string `json:"allowed_origins" yaml:"allowed_origins" env:"CORS_ALLOWED_ORIGINS"`
	
	// AllowedMethods specifies allowed HTTP methods
	AllowedMethods []string `json:"allowed_methods" yaml:"allowed_methods" env:"CORS_ALLOWED_METHODS"`
	
	// AllowedHeaders specifies allowed request headers
	AllowedHeaders []string `json:"allowed_headers" yaml:"allowed_headers" env:"CORS_ALLOWED_HEADERS"`
	
	// ExposedHeaders specifies headers exposed to the client
	ExposedHeaders []string `json:"exposed_headers" yaml:"exposed_headers" env:"CORS_EXPOSED_HEADERS"`
	
	// AllowCredentials allows cookies and authorization headers (STRICT: only for whitelisted origins)
	AllowCredentials bool `json:"allow_credentials" yaml:"allow_credentials" env:"CORS_ALLOW_CREDENTIALS" default:"false"`
	
	// MaxAge specifies how long preflight requests can be cached
	MaxAge int `json:"max_age" yaml:"max_age" env:"CORS_MAX_AGE" default:"86400"`
	
	// StrictOriginCheck enforces exact origin matching (no wildcards)
	StrictOriginCheck bool `json:"strict_origin_check" yaml:"strict_origin_check" env:"CORS_STRICT_ORIGIN_CHECK" default:"true"`
	
	// RequireOriginForCredentials requires Origin header when credentials are allowed
	RequireOriginForCredentials bool `json:"require_origin_for_credentials" yaml:"require_origin_for_credentials" env:"CORS_REQUIRE_ORIGIN_FOR_CREDENTIALS" default:"true"`
	
	// BlockNullOrigin blocks requests with null origin
	BlockNullOrigin bool `json:"block_null_origin" yaml:"block_null_origin" env:"CORS_BLOCK_NULL_ORIGIN" default:"true"`
	
	// OnViolation is called when CORS policy is violated
	OnViolation CORSViolationHandler `json:"-" yaml:"-"`
	
	// Logger for audit events
	Logger *logx.Logger `json:"-" yaml:"-"`
	
	// AuditLogger for security events
	AuditLogger *AuditLogger `json:"-" yaml:"-"`
	
	// DevelopmentMode allows more permissive CORS for development
	DevelopmentMode bool `json:"development_mode" yaml:"development_mode" env:"CORS_DEVELOPMENT_MODE" default:"false"`
}

// CORSViolationHandler handles CORS policy violations
type CORSViolationHandler func(w http.ResponseWriter, r *http.Request, violation string, logger *logx.Logger, auditLogger *AuditLogger)

// CORSViolationType represents different types of CORS violations
type CORSViolationType string

const (
	CORSViolationOriginNotAllowed     CORSViolationType = "ORIGIN_NOT_ALLOWED"
	CORSViolationMethodNotAllowed     CORSViolationType = "METHOD_NOT_ALLOWED"
	CORSViolationHeaderNotAllowed     CORSViolationType = "HEADER_NOT_ALLOWED"
	CORSViolationCredentialsNotAllowed CORSViolationType = "CREDENTIALS_NOT_ALLOWED"
	CORSViolationNullOriginBlocked    CORSViolationType = "NULL_ORIGIN_BLOCKED"
	CORSViolationMissingOrigin        CORSViolationType = "MISSING_ORIGIN"
)

// DefaultEnhancedCORSConfig returns default enhanced CORS configuration
func DefaultEnhancedCORSConfig() EnhancedCORSConfig {
	return EnhancedCORSConfig{
		Enabled:                     true,
		AllowedOrigins:              []string{}, // Empty by default - must be explicitly configured
		AllowedMethods:              []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:              []string{"Content-Type", "Accept", "X-Requested-With"},
		ExposedHeaders:              []string{},
		AllowCredentials:            false, // Strict default
		MaxAge:                      86400, // 24 hours
		StrictOriginCheck:           true,
		RequireOriginForCredentials: true,
		BlockNullOrigin:             true,
		OnViolation:                 DefaultCORSViolationHandler,
		DevelopmentMode:             false,
	}
}

// ProductionCORSConfig returns a production-ready CORS configuration
func ProductionCORSConfig(allowedOrigins []string) EnhancedCORSConfig {
	config := DefaultEnhancedCORSConfig()
	config.AllowedOrigins = allowedOrigins
	config.AllowCredentials = true // Allow credentials only for whitelisted origins
	config.AllowedHeaders = []string{
		"Content-Type",
		"Accept",
		"Authorization",
		"X-Requested-With",
		"X-CSRF-Token",
	}
	config.ExposedHeaders = []string{
		"X-Total-Count",
		"X-Page-Count",
	}
	return config
}

// DevelopmentCORSConfig returns a development-friendly CORS configuration
func DevelopmentCORSConfig() EnhancedCORSConfig {
	config := DefaultEnhancedCORSConfig()
	config.DevelopmentMode = true
	config.AllowedOrigins = []string{
		"http://localhost:3000",
		"http://localhost:3001",
		"http://localhost:8080",
		"http://127.0.0.1:3000",
		"http://127.0.0.1:3001",
		"http://127.0.0.1:8080",
	}
	config.AllowCredentials = true
	config.AllowedHeaders = []string{
		"*", // More permissive for development
	}
	config.StrictOriginCheck = false
	config.BlockNullOrigin = false
	return config
}

// DefaultCORSViolationHandler is the default handler for CORS violations
func DefaultCORSViolationHandler(w http.ResponseWriter, r *http.Request, violation string, logger *logx.Logger, auditLogger *AuditLogger) {
	// Audit log the CORS violation
	if auditLogger != nil {
		metadata := map[string]interface{}{
			"violation_type": violation,
			"origin":         r.Header.Get("Origin"),
			"referer":        r.Header.Get("Referer"),
			"user_agent":     r.UserAgent(),
		}
		auditLogger.LogSecurityViolation(r, "CORS_VIOLATION", 
			fmt.Sprintf("CORS policy violation: %s", violation),
			AuditSeverityMedium, metadata)
	}
	
	// Log the violation
	if logger != nil {
		logger.Warn("CORS_VIOLATION",
			"event", "CORS_VIOLATION",
			"ip", GetClientIP(r),
			"origin", r.Header.Get("Origin"),
			"referer", r.Header.Get("Referer"),
			"user_agent", r.UserAgent(),
			"path", r.URL.Path,
			"method", r.Method,
			"violation", violation,
		)
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	
	response := map[string]interface{}{
		"error":   "cors_violation",
		"message": "Akses ditolak: pelanggaran kebijakan CORS",
		"code":    403,
		"details": map[string]interface{}{
			"violation": violation,
			"origin":    r.Header.Get("Origin"),
		},
	}
	
	jsonResponse, _ := json.Marshal(response)
	w.Write(jsonResponse)
}

// isOriginAllowed checks if the origin is in the allowed list
func (config *EnhancedCORSConfig) isOriginAllowed(origin string) bool {
	if origin == "" {
		return false
	}
	
	// Block null origin if configured
	if config.BlockNullOrigin && origin == "null" {
		return false
	}
	
	// In development mode, be more permissive
	if config.DevelopmentMode {
		// Allow localhost and 127.0.0.1 with any port
		if strings.Contains(origin, "localhost") || strings.Contains(origin, "127.0.0.1") {
			return true
		}
	}
	
	for _, allowedOrigin := range config.AllowedOrigins {
		if config.StrictOriginCheck {
			// Exact match only
			if origin == allowedOrigin {
				return true
			}
		} else {
			// Allow wildcard matching
			if allowedOrigin == "*" {
				return true
			}
			if matchesWildcard(origin, allowedOrigin) {
				return true
			}
		}
	}
	
	return false
}

// matchesWildcard checks if origin matches wildcard pattern
func matchesWildcard(origin, pattern string) bool {
	if pattern == "*" {
		return true
	}
	
	// Simple subdomain wildcard matching (e.g., *.example.com)
	if strings.HasPrefix(pattern, "*.") {
		domain := pattern[2:]
		if strings.HasSuffix(origin, "."+domain) || origin == domain {
			return true
		}
	}
	
	return origin == pattern
}

// isMethodAllowed checks if the method is allowed
func (config *EnhancedCORSConfig) isMethodAllowed(method string) bool {
	for _, allowedMethod := range config.AllowedMethods {
		if strings.EqualFold(method, allowedMethod) {
			return true
		}
	}
	return false
}

// areHeadersAllowed checks if all requested headers are allowed
func (config *EnhancedCORSConfig) areHeadersAllowed(headers []string) bool {
	if len(config.AllowedHeaders) == 1 && config.AllowedHeaders[0] == "*" {
		return true // Allow all headers
	}
	
	allowedHeadersMap := make(map[string]bool)
	for _, header := range config.AllowedHeaders {
		allowedHeadersMap[strings.ToLower(header)] = true
	}
	
	for _, header := range headers {
		if !allowedHeadersMap[strings.ToLower(header)] {
			return false
		}
	}
	return true
}

// parseHeaderList parses comma-separated header list
func parseHeaderList(headerValue string) []string {
	if headerValue == "" {
		return nil
	}
	
	headers := strings.Split(headerValue, ",")
	for i, header := range headers {
		headers[i] = strings.TrimSpace(header)
	}
	return headers
}

// EnhancedCORSMiddleware creates an enhanced CORS middleware with strict security
func EnhancedCORSMiddleware(config EnhancedCORSConfig) func(http.Handler) http.Handler {
	if !config.Enabled {
		return func(next http.Handler) http.Handler {
			return next // Pass through if disabled
		}
	}
	
	// Set defaults
	if config.OnViolation == nil {
		config.OnViolation = DefaultCORSViolationHandler
	}
	if len(config.AllowedMethods) == 0 {
		config.AllowedMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	}
	if len(config.AllowedHeaders) == 0 {
		config.AllowedHeaders = []string{"Content-Type", "Accept", "X-Requested-With"}
	}
	
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			
			// Check if origin is required for credentials
			if config.AllowCredentials && config.RequireOriginForCredentials && origin == "" {
				config.OnViolation(w, r, string(CORSViolationMissingOrigin), config.Logger, config.AuditLogger)
				return
			}
			
			// Check if origin is allowed (only if origin is present)
			if origin != "" {
				if !config.isOriginAllowed(origin) {
					config.OnViolation(w, r, string(CORSViolationOriginNotAllowed), config.Logger, config.AuditLogger)
					return
				}
				
				// Set CORS headers for allowed origin
				w.Header().Set("Access-Control-Allow-Origin", origin)
			} else if len(config.AllowedOrigins) > 0 && !config.AllowCredentials {
				// If no origin header and we have allowed origins, set the first one
				w.Header().Set("Access-Control-Allow-Origin", config.AllowedOrigins[0])
			}
			
			// Handle preflight requests
			if r.Method == "OPTIONS" {
				// Check requested method
				requestedMethod := r.Header.Get("Access-Control-Request-Method")
				if requestedMethod != "" && !config.isMethodAllowed(requestedMethod) {
					config.OnViolation(w, r, string(CORSViolationMethodNotAllowed), config.Logger, config.AuditLogger)
					return
				}
				
				// Check requested headers
				requestedHeaders := parseHeaderList(r.Header.Get("Access-Control-Request-Headers"))
				if len(requestedHeaders) > 0 && !config.areHeadersAllowed(requestedHeaders) {
					config.OnViolation(w, r, string(CORSViolationHeaderNotAllowed), config.Logger, config.AuditLogger)
					return
				}
				
				// Set preflight response headers
				w.Header().Set("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
				w.Header().Set("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))
				w.Header().Set("Access-Control-Max-Age", strconv.Itoa(config.MaxAge))
				
				if config.AllowCredentials && origin != "" && config.isOriginAllowed(origin) {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
				
				w.WriteHeader(http.StatusNoContent)
				return
			}
			
			// For actual requests, set CORS headers
			if len(config.ExposedHeaders) > 0 {
				w.Header().Set("Access-Control-Expose-Headers", strings.Join(config.ExposedHeaders, ", "))
			}
			
			// Only allow credentials for whitelisted origins
			if config.AllowCredentials && origin != "" && config.isOriginAllowed(origin) {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			} else if config.AllowCredentials && (origin == "" || !config.isOriginAllowed(origin)) {
				// Block credentials for non-whitelisted origins
				config.OnViolation(w, r, string(CORSViolationCredentialsNotAllowed), config.Logger, config.AuditLogger)
				return
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// ValidateOrigin validates if an origin URL is properly formatted
func ValidateOrigin(origin string) error {
	if origin == "" {
		return fmt.Errorf("origin cannot be empty")
	}
	
	if origin == "null" {
		return nil // null is a valid origin value
	}
	
	_, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("invalid origin URL: %v", err)
	}
	
	return nil
}

// ValidateCORSConfig validates the CORS configuration
func ValidateCORSConfig(config EnhancedCORSConfig) error {
	if !config.Enabled {
		return nil
	}
	
	// Validate origins
	for _, origin := range config.AllowedOrigins {
		if origin != "*" && !strings.HasPrefix(origin, "*.") {
			if err := ValidateOrigin(origin); err != nil {
				return fmt.Errorf("invalid allowed origin '%s': %v", origin, err)
			}
		}
	}
	
	// Validate that credentials are only allowed with specific origins
	if config.AllowCredentials && config.StrictOriginCheck {
		for _, origin := range config.AllowedOrigins {
			if origin == "*" {
				return fmt.Errorf("cannot allow credentials with wildcard origin '*'")
			}
		}
	}
	
	return nil
}