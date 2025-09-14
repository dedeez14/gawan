package security

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// SecurityHeadersConfig holds security headers configuration
type SecurityHeadersConfig struct {
	// Enabled enables security headers middleware
	Enabled bool `json:"enabled" yaml:"enabled" env:"SECURITY_HEADERS_ENABLED" default:"true"`
	
	// HSTS Configuration
	HSTS HSSTConfig `json:"hsts" yaml:"hsts"`
	
	// Content Security Policy
	CSP CSPConfig `json:"csp" yaml:"csp"`
	
	// X-Frame-Options
	FrameOptions string `json:"frame_options" yaml:"frame_options" env:"X_FRAME_OPTIONS" default:"DENY"`
	
	// X-Content-Type-Options
	ContentTypeOptions string `json:"content_type_options" yaml:"content_type_options" env:"X_CONTENT_TYPE_OPTIONS" default:"nosniff"`
	
	// X-XSS-Protection
	XSSProtection string `json:"xss_protection" yaml:"xss_protection" env:"X_XSS_PROTECTION" default:"1; mode=block"`
	
	// Referrer-Policy
	ReferrerPolicy string `json:"referrer_policy" yaml:"referrer_policy" env:"REFERRER_POLICY" default:"strict-origin-when-cross-origin"`
	
	// Permissions-Policy
	PermissionsPolicy string `json:"permissions_policy" yaml:"permissions_policy" env:"PERMISSIONS_POLICY"`
	
	// X-Permitted-Cross-Domain-Policies
	CrossDomainPolicy string `json:"cross_domain_policy" yaml:"cross_domain_policy" env:"X_PERMITTED_CROSS_DOMAIN_POLICIES" default:"none"`
	
	// Custom headers
	CustomHeaders map[string]string `json:"custom_headers" yaml:"custom_headers"`
	
	// Remove server header
	RemoveServerHeader bool `json:"remove_server_header" yaml:"remove_server_header" env:"REMOVE_SERVER_HEADER" default:"true"`
	
	// Remove X-Powered-By header
	RemovePoweredBy bool `json:"remove_powered_by" yaml:"remove_powered_by" env:"REMOVE_POWERED_BY" default:"true"`
}

// HSSTConfig holds HSTS configuration
type HSSTConfig struct {
	// Enabled enables HSTS (only applies to HTTPS connections)
	Enabled bool `json:"enabled" yaml:"enabled" env:"HSTS_ENABLED" default:"true"`
	// MaxAge in seconds
	MaxAge int `json:"max_age" yaml:"max_age" env:"HSTS_MAX_AGE" default:"31536000"`
	// IncludeSubDomains includes subdomains
	IncludeSubDomains bool `json:"include_subdomains" yaml:"include_subdomains" env:"HSTS_INCLUDE_SUBDOMAINS" default:"true"`
	// Preload enables HSTS preload
	Preload bool `json:"preload" yaml:"preload" env:"HSTS_PRELOAD" default:"false"`
}

// CSPConfig holds Content Security Policy configuration
type CSPConfig struct {
	// Enabled enables CSP
	Enabled bool `json:"enabled" yaml:"enabled" env:"CSP_ENABLED" default:"true"`
	// DefaultSrc sets default-src directive
	DefaultSrc []string `json:"default_src" yaml:"default_src" env:"CSP_DEFAULT_SRC"`
	// ScriptSrc sets script-src directive
	ScriptSrc []string `json:"script_src" yaml:"script_src" env:"CSP_SCRIPT_SRC"`
	// StyleSrc sets style-src directive
	StyleSrc []string `json:"style_src" yaml:"style_src" env:"CSP_STYLE_SRC"`
	// ImgSrc sets img-src directive
	ImgSrc []string `json:"img_src" yaml:"img_src" env:"CSP_IMG_SRC"`
	// ConnectSrc sets connect-src directive
	ConnectSrc []string `json:"connect_src" yaml:"connect_src" env:"CSP_CONNECT_SRC"`
	// FontSrc sets font-src directive
	FontSrc []string `json:"font_src" yaml:"font_src" env:"CSP_FONT_SRC"`
	// ObjectSrc sets object-src directive
	ObjectSrc []string `json:"object_src" yaml:"object_src" env:"CSP_OBJECT_SRC"`
	// MediaSrc sets media-src directive
	MediaSrc []string `json:"media_src" yaml:"media_src" env:"CSP_MEDIA_SRC"`
	// FrameSrc sets frame-src directive
	FrameSrc []string `json:"frame_src" yaml:"frame_src" env:"CSP_FRAME_SRC"`
	// ReportURI sets report-uri directive
	ReportURI string `json:"report_uri" yaml:"report_uri" env:"CSP_REPORT_URI"`
	// ReportOnly enables CSP report-only mode
	ReportOnly bool `json:"report_only" yaml:"report_only" env:"CSP_REPORT_ONLY" default:"false"`
	// Custom CSP policy (overrides individual directives if set)
	CustomPolicy string `json:"custom_policy" yaml:"custom_policy" env:"CSP_CUSTOM_POLICY"`
}

// DefaultSecurityHeadersConfig returns default security headers configuration
func DefaultSecurityHeadersConfig() SecurityHeadersConfig {
	return SecurityHeadersConfig{
		Enabled: true,
		HSTS: HSSTConfig{
			Enabled:           true,
			MaxAge:            31536000, // 1 year
			IncludeSubDomains: true,
			Preload:           false,
		},
		CSP: CSPConfig{
			Enabled:      true,
			DefaultSrc:   []string{"'self'"},
			ScriptSrc:    []string{"'self'", "'unsafe-inline'"},
			StyleSrc:     []string{"'self'", "'unsafe-inline'"},
			ImgSrc:       []string{"'self'", "data:", "https:"},
			ConnectSrc:   []string{"'self'"},
			FontSrc:      []string{"'self'", "https:"},
			ObjectSrc:    []string{"'none'"},
			MediaSrc:     []string{"'self'"},
			FrameSrc:     []string{"'none'"},
			ReportOnly:   false,
		},
		FrameOptions:       "DENY",
		ContentTypeOptions: "nosniff",
		XSSProtection:      "1; mode=block",
		ReferrerPolicy:     "strict-origin-when-cross-origin",
		PermissionsPolicy:  "geolocation=(), microphone=(), camera=()",
		CrossDomainPolicy:  "none",
		RemoveServerHeader: true,
		RemovePoweredBy:    true,
		CustomHeaders:      make(map[string]string),
	}
}

// buildCSPHeader builds the Content Security Policy header value
func (c *CSPConfig) buildCSPHeader() string {
	if !c.Enabled {
		return ""
	}
	
	// Use custom policy if provided
	if c.CustomPolicy != "" {
		return c.CustomPolicy
	}
	
	var directives []string
	
	if len(c.DefaultSrc) > 0 {
		directives = append(directives, "default-src "+strings.Join(c.DefaultSrc, " "))
	}
	if len(c.ScriptSrc) > 0 {
		directives = append(directives, "script-src "+strings.Join(c.ScriptSrc, " "))
	}
	if len(c.StyleSrc) > 0 {
		directives = append(directives, "style-src "+strings.Join(c.StyleSrc, " "))
	}
	if len(c.ImgSrc) > 0 {
		directives = append(directives, "img-src "+strings.Join(c.ImgSrc, " "))
	}
	if len(c.ConnectSrc) > 0 {
		directives = append(directives, "connect-src "+strings.Join(c.ConnectSrc, " "))
	}
	if len(c.FontSrc) > 0 {
		directives = append(directives, "font-src "+strings.Join(c.FontSrc, " "))
	}
	if len(c.ObjectSrc) > 0 {
		directives = append(directives, "object-src "+strings.Join(c.ObjectSrc, " "))
	}
	if len(c.MediaSrc) > 0 {
		directives = append(directives, "media-src "+strings.Join(c.MediaSrc, " "))
	}
	if len(c.FrameSrc) > 0 {
		directives = append(directives, "frame-src "+strings.Join(c.FrameSrc, " "))
	}
	if c.ReportURI != "" {
		directives = append(directives, "report-uri "+c.ReportURI)
	}
	
	return strings.Join(directives, "; ")
}

// buildHSTSHeader builds the HSTS header value
func (h *HSSTConfig) buildHSTSHeader() string {
	if !h.Enabled {
		return ""
	}
	
	var parts []string
	parts = append(parts, "max-age="+strconv.Itoa(h.MaxAge))
	
	if h.IncludeSubDomains {
		parts = append(parts, "includeSubDomains")
	}
	
	if h.Preload {
		parts = append(parts, "preload")
	}
	
	return strings.Join(parts, "; ")
}

// isHTTPS checks if the request is over HTTPS
func isHTTPS(r *http.Request) bool {
	// Check the request scheme
	if r.TLS != nil {
		return true
	}
	
	// Check X-Forwarded-Proto header (for reverse proxies)
	if proto := r.Header.Get("X-Forwarded-Proto"); proto == "https" {
		return true
	}
	
	// Check X-Forwarded-SSL header
	if ssl := r.Header.Get("X-Forwarded-SSL"); ssl == "on" {
		return true
	}
	
	// Check if URL scheme is https
	if r.URL.Scheme == "https" {
		return true
	}
	
	return false
}

// SecurityHeadersMiddleware creates a security headers middleware
func SecurityHeadersMiddleware(config SecurityHeadersConfig) func(http.Handler) http.Handler {
	if !config.Enabled {
		return func(next http.Handler) http.Handler {
			return next // Pass through if disabled
		}
	}
	
	// Pre-build headers for performance
	cspHeader := config.CSP.buildCSPHeader()
	hstsHeader := config.HSTS.buildHSTSHeader()
	
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := w.Header()
			
			// Remove server identification headers
			if config.RemoveServerHeader {
				header.Del("Server")
			}
			if config.RemovePoweredBy {
				header.Del("X-Powered-By")
			}
			
			// HSTS - only for HTTPS connections
			if hstsHeader != "" && isHTTPS(r) {
				header.Set("Strict-Transport-Security", hstsHeader)
			}
			
			// Content Security Policy
			if cspHeader != "" {
				headerName := "Content-Security-Policy"
				if config.CSP.ReportOnly {
					headerName = "Content-Security-Policy-Report-Only"
				}
				header.Set(headerName, cspHeader)
			}
			
			// X-Frame-Options
			if config.FrameOptions != "" {
				header.Set("X-Frame-Options", config.FrameOptions)
			}
			
			// X-Content-Type-Options
			if config.ContentTypeOptions != "" {
				header.Set("X-Content-Type-Options", config.ContentTypeOptions)
			}
			
			// X-XSS-Protection
			if config.XSSProtection != "" {
				header.Set("X-XSS-Protection", config.XSSProtection)
			}
			
			// Referrer-Policy
			if config.ReferrerPolicy != "" {
				header.Set("Referrer-Policy", config.ReferrerPolicy)
			}
			
			// Permissions-Policy
			if config.PermissionsPolicy != "" {
				header.Set("Permissions-Policy", config.PermissionsPolicy)
			}
			
			// X-Permitted-Cross-Domain-Policies
			if config.CrossDomainPolicy != "" {
				header.Set("X-Permitted-Cross-Domain-Policies", config.CrossDomainPolicy)
			}
			
			// Custom headers
			for name, value := range config.CustomHeaders {
				header.Set(name, value)
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// StrictSecurityHeadersConfig returns a strict security headers configuration
func StrictSecurityHeadersConfig() SecurityHeadersConfig {
	config := DefaultSecurityHeadersConfig()
	
	// Stricter CSP
	config.CSP.DefaultSrc = []string{"'self'"}
	config.CSP.ScriptSrc = []string{"'self'"}
	config.CSP.StyleSrc = []string{"'self'"}
	config.CSP.ImgSrc = []string{"'self'", "data:"}
	config.CSP.ConnectSrc = []string{"'self'"}
	config.CSP.FontSrc = []string{"'self'"}
	config.CSP.ObjectSrc = []string{"'none'"}
	config.CSP.MediaSrc = []string{"'none'"}
	config.CSP.FrameSrc = []string{"'none'"}
	
	// Stricter referrer policy
	config.ReferrerPolicy = "no-referrer"
	
	// More restrictive permissions policy
	config.PermissionsPolicy = "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), speaker=()"
	
	return config
}

// DevelopmentSecurityHeadersConfig returns a development-friendly security headers configuration
func DevelopmentSecurityHeadersConfig() SecurityHeadersConfig {
	config := DefaultSecurityHeadersConfig()
	
	// More permissive CSP for development
	config.CSP.DefaultSrc = []string{"'self'", "'unsafe-inline'", "'unsafe-eval'"}
	config.CSP.ScriptSrc = []string{"'self'", "'unsafe-inline'", "'unsafe-eval'", "localhost:*", "127.0.0.1:*"}
	config.CSP.StyleSrc = []string{"'self'", "'unsafe-inline'", "localhost:*", "127.0.0.1:*"}
	config.CSP.ConnectSrc = []string{"'self'", "localhost:*", "127.0.0.1:*", "ws:", "wss:"}
	
	// Disable HSTS in development
	config.HSTS.Enabled = false
	
	return config
}