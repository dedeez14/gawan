package security

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// CORSConfig holds CORS configuration
type CORSConfig struct {
	// Enabled enables CORS middleware
	Enabled bool `json:"enabled" yaml:"enabled" env:"CORS_ENABLED" default:"true"`
	// AllowedOrigins is a list of allowed origins
	AllowedOrigins []string `json:"allowed_origins" yaml:"allowed_origins" env:"CORS_ALLOWED_ORIGINS"`
	// AllowedMethods is a list of allowed HTTP methods
	AllowedMethods []string `json:"allowed_methods" yaml:"allowed_methods" env:"CORS_ALLOWED_METHODS"`
	// AllowedHeaders is a list of allowed headers
	AllowedHeaders []string `json:"allowed_headers" yaml:"allowed_headers" env:"CORS_ALLOWED_HEADERS"`
	// ExposedHeaders is a list of headers exposed to the client
	ExposedHeaders []string `json:"exposed_headers" yaml:"exposed_headers" env:"CORS_EXPOSED_HEADERS"`
	// AllowCredentials indicates whether credentials are allowed
	AllowCredentials bool `json:"allow_credentials" yaml:"allow_credentials" env:"CORS_ALLOW_CREDENTIALS" default:"false"`
	// MaxAge is the maximum age for preflight requests
	MaxAge time.Duration `json:"max_age" yaml:"max_age" env:"CORS_MAX_AGE" default:"12h"`
	// AllowAllOrigins allows all origins (overrides AllowedOrigins)
	AllowAllOrigins bool `json:"allow_all_origins" yaml:"allow_all_origins" env:"CORS_ALLOW_ALL_ORIGINS" default:"false"`
	// AllowOriginFunc is a custom function to determine allowed origins
	AllowOriginFunc func(origin string) bool `json:"-" yaml:"-"`
}

// DefaultCORSConfig returns default CORS configuration
func DefaultCORSConfig() CORSConfig {
	return CORSConfig{
		Enabled: true,
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodHead,
			http.MethodOptions,
		},
		AllowedHeaders: []string{
			"Accept",
			"Authorization",
			"Content-Type",
			"X-CSRF-Token",
			"X-Requested-With",
			"X-API-Key",
		},
		ExposedHeaders:   []string{},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
		AllowAllOrigins:  false,
	}
}

// StrictCORSConfig returns a strict CORS configuration
func StrictCORSConfig(allowedOrigins []string) CORSConfig {
	return CORSConfig{
		Enabled:        true,
		AllowedOrigins: allowedOrigins,
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodOptions,
		},
		AllowedHeaders: []string{
			"Accept",
			"Authorization",
			"Content-Type",
			"X-CSRF-Token",
		},
		ExposedHeaders:   []string{},
		AllowCredentials: true,
		MaxAge:           1 * time.Hour,
		AllowAllOrigins:  false,
	}
}

// CORSMiddleware creates a CORS middleware
func CORSMiddleware(config CORSConfig) func(http.Handler) http.Handler {
	if !config.Enabled {
		return func(next http.Handler) http.Handler {
			return next // Pass through if disabled
		}
	}

	// Normalize configuration
	allowedOriginMap := make(map[string]bool)
	for _, origin := range config.AllowedOrigins {
		allowedOriginMap[strings.ToLower(origin)] = true
	}

	allowedMethodMap := make(map[string]bool)
	for _, method := range config.AllowedMethods {
		allowedMethodMap[strings.ToUpper(method)] = true
	}

	allowedHeaderMap := make(map[string]bool)
	for _, header := range config.AllowedHeaders {
		allowedHeaderMap[strings.ToLower(header)] = true
	}

	// Pre-compute header values
	allowedMethodsHeader := strings.Join(config.AllowedMethods, ", ")
	allowedHeadersHeader := strings.Join(config.AllowedHeaders, ", ")
	exposedHeadersHeader := strings.Join(config.ExposedHeaders, ", ")
	maxAgeHeader := strconv.Itoa(int(config.MaxAge.Seconds()))

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Determine if origin is allowed
			allowOrigin := false
			if config.AllowAllOrigins {
				allowOrigin = true
			} else if config.AllowOriginFunc != nil {
				allowOrigin = config.AllowOriginFunc(origin)
			} else if origin != "" {
				// Check against allowed origins
				if allowedOriginMap["*"] {
					allowOrigin = true
				} else {
					allowOrigin = allowedOriginMap[strings.ToLower(origin)]
				}
			}

			// Set CORS headers
			if allowOrigin {
				if config.AllowAllOrigins || allowedOriginMap["*"] {
					w.Header().Set("Access-Control-Allow-Origin", "*")
				} else {
					w.Header().Set("Access-Control-Allow-Origin", origin)
				}

				if config.AllowCredentials {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}

				if len(config.ExposedHeaders) > 0 {
					w.Header().Set("Access-Control-Expose-Headers", exposedHeadersHeader)
				}
			}

			// Handle preflight requests
			if r.Method == http.MethodOptions {
				if !allowOrigin {
					w.WriteHeader(http.StatusForbidden)
					return
				}

				// Check requested method
				requestedMethod := r.Header.Get("Access-Control-Request-Method")
				if requestedMethod != "" && !allowedMethodMap[strings.ToUpper(requestedMethod)] {
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}

				// Check requested headers
				requestedHeaders := r.Header.Get("Access-Control-Request-Headers")
				if requestedHeaders != "" {
					headers := strings.Split(requestedHeaders, ",")
					for _, header := range headers {
						header = strings.TrimSpace(strings.ToLower(header))
						if !allowedHeaderMap[header] {
							w.WriteHeader(http.StatusForbidden)
							return
						}
					}
				}

				// Set preflight response headers
				w.Header().Set("Access-Control-Allow-Methods", allowedMethodsHeader)
				w.Header().Set("Access-Control-Allow-Headers", allowedHeadersHeader)
				w.Header().Set("Access-Control-Max-Age", maxAgeHeader)

				w.WriteHeader(http.StatusNoContent)
				return
			}

			// Continue with the request
			next.ServeHTTP(w, r)
		})
	}
}

// CORSWithOriginValidator creates CORS middleware with custom origin validation
func CORSWithOriginValidator(validator func(origin string) bool) func(http.Handler) http.Handler {
	config := DefaultCORSConfig()
	config.AllowOriginFunc = validator
	config.AllowAllOrigins = false
	return CORSMiddleware(config)
}

// CORSForDevelopment creates permissive CORS middleware for development
func CORSForDevelopment() func(http.Handler) http.Handler {
	config := CORSConfig{
		Enabled:         true,
		AllowAllOrigins: true,
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodHead,
			http.MethodOptions,
		},
		AllowedHeaders: []string{"*"},
		ExposedHeaders: []string{"*"},
		AllowCredentials: true,
		MaxAge:           24 * time.Hour,
	}
	return CORSMiddleware(config)
}

// CORSForProduction creates strict CORS middleware for production
func CORSForProduction(allowedOrigins []string) func(http.Handler) http.Handler {
	config := StrictCORSConfig(allowedOrigins)
	return CORSMiddleware(config)
}

// ValidateOrigin validates if an origin is allowed based on patterns
func ValidateOrigin(origin string, patterns []string) bool {
	if origin == "" {
		return false
	}

	for _, pattern := range patterns {
		if pattern == "*" {
			return true
		}

		// Exact match
		if pattern == origin {
			return true
		}

		// Wildcard subdomain matching (e.g., *.example.com)
		if strings.HasPrefix(pattern, "*.") {
			domain := pattern[2:]
			if strings.HasSuffix(origin, "."+domain) || origin == domain {
				return true
			}
		}

		// Protocol wildcard (e.g., *://example.com)
		if strings.HasPrefix(pattern, "*://") {
			host := pattern[4:]
			if strings.Contains(origin, "://"+host) {
				return true
			}
		}
	}

	return false
}

// OriginValidatorFromPatterns creates an origin validator from patterns
func OriginValidatorFromPatterns(patterns []string) func(string) bool {
	return func(origin string) bool {
		return ValidateOrigin(origin, patterns)
	}
}

// DynamicCORSConfig allows dynamic CORS configuration
type DynamicCORSConfig struct {
	GetConfig func(r *http.Request) CORSConfig
}

// DynamicCORSMiddleware creates a dynamic CORS middleware
func DynamicCORSMiddleware(config DynamicCORSConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			corsConfig := config.GetConfig(r)
			middleware := CORSMiddleware(corsConfig)
			middleware(next).ServeHTTP(w, r)
		})
	}
}