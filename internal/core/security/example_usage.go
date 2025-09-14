package security

import (
	"log"
	"net/http"
	"time"

	"Gawan/internal/core/logx"
)

// ExampleBasicUsage demonstrates basic security middleware usage
func ExampleBasicUsage() {
	// Create security middleware with default configuration
	securityMiddleware := NewSecurityMiddleware(DefaultSecurityConfig())
	defer securityMiddleware.Stop()

	// Create your HTTP handler
	mux := http.NewServeMux()
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "Hello, World!"}`))
	})

	// Apply security middleware
	protectedHandler := securityMiddleware.Handler()(mux)

	// Start server
	log.Println("Server starting on :8080 with basic security")
	log.Fatal(http.ListenAndServe(":8080", protectedHandler))
}

// ExampleIndonesianCompliance demonstrates Indonesian compliance configuration
func ExampleIndonesianCompliance() {
	// Use Indonesian compliance configuration
	config := IndonesianComplianceSecurity()
	
	// Initialize logger
	logger := logx.New()
	
	// Configure audit logger
	config.Audit.Logger = logger
	config.EnhancedRateLimit.Logger = logger
	config.BruteForce.Logger = logger
	config.PayloadLimit.Logger = logger
	config.Timeout.Logger = logger
	config.EnhancedCORS.Logger = logger
	
	// Create security middleware
	securityMiddleware := NewSecurityMiddleware(config)
	defer securityMiddleware.Stop()

	// Create your HTTP handler
	mux := http.NewServeMux()
	
	// Login endpoint with brute force protection
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		// Your login logic here
		// If login fails, the brute force middleware will track it
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "Login successful"}`))
	})
	
	// Protected API endpoint
	mux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data": "sensitive information"}`))
	})

	// Apply security middleware
	protectedHandler := securityMiddleware.Handler()(mux)

	// Configure server with timeouts
	server := &http.Server{
		Addr:    ":8080",
		Handler: protectedHandler,
	}
	
	// Apply server-level timeouts
	ConfigureServerTimeouts(server, config.Timeout)

	// Start server
	log.Println("Server starting on :8080 with Indonesian compliance")
	log.Fatal(server.ListenAndServe())
}

// ExampleCustomConfiguration demonstrates custom security configuration
func ExampleCustomConfiguration() {
	// Build custom security configuration
	config := NewSecurityBuilder().
		// Enhanced rate limiting: 50 requests per 5 seconds
		WithEnhancedRateLimit(EnhancedRateLimitConfig{
			Enabled:           true,
			RequestsPerWindow: 50,
			WindowDuration:    5 * time.Second,
			KeyExtractor:      IPKeyExtractor,
		}).
		// Strict brute force protection: 3 attempts, 10 minute lockout
		WithBruteForce(BruteForceConfig{
			Enabled:         true,
			MaxAttempts:     3,
			WindowDuration:  60 * time.Second,
			LockoutDuration: 10 * time.Minute,
			KeyExtractor:    IPKeyExtractor,
		}).
		// Strict security headers
		WithSecurityHeaders(StrictSecurityHeadersConfig()).
		// Small payload limit: 512KB
		WithPayloadLimit(PayloadLimitConfig{
			Enabled: true,
			MaxSize: 512 * 1024, // 512KB
		}).
		// Strict timeouts
		WithTimeout(StrictTimeoutConfig()).
		// Enhanced CORS with specific origins
		WithEnhancedCORS(EnhancedCORSConfig{
			Enabled:           true,
			AllowedOrigins:    []string{"https://myapp.com", "https://admin.myapp.com"},
			AllowCredentials:  true,
			StrictOriginCheck: true,
		}).
		// Enable audit logging
		WithAudit(AuditConfig{
			Enabled: true,
		}).
		// Disable basic CORS (use enhanced instead)
		DisableCORS().
		// Disable basic rate limiting (use enhanced instead)
		DisableRateLimit().
		Build()

	// Create security middleware
	securityMiddleware := config
	defer securityMiddleware.Stop()

	// Your application logic here
	log.Println("Custom security configuration applied")
}

// ExampleDevelopmentSetup demonstrates development-friendly configuration
func ExampleDevelopmentSetup() {
	// Use development configuration
	config := DevelopmentSecurity()
	
	// Create security middleware
	securityMiddleware := NewSecurityMiddleware(config)
	defer securityMiddleware.Stop()

	// Create your HTTP handler
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "Development server running"}`))
	})

	// Apply security middleware
	protectedHandler := securityMiddleware.Handler()(mux)

	// Start server
	log.Println("Development server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", protectedHandler))
}

// ExampleAPIOnlySetup demonstrates API-only configuration
func ExampleAPIOnlySetup() {
	// Use API-only configuration
	config := APIOnlySecurity()
	
	// Create security middleware
	securityMiddleware := NewSecurityMiddleware(config)
	defer securityMiddleware.Stop()

	// Create your API handler
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok", "version": "1.0.0"}`))
	})

	// Apply security middleware
	protectedHandler := securityMiddleware.Handler()(mux)

	// Start server
	log.Println("API server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", protectedHandler))
}

// ExampleSelectiveMiddleware demonstrates using individual middleware components
func ExampleSelectiveMiddleware() {
	// Create security middleware
	config := DefaultSecurityConfig()
	securityMiddleware := NewSecurityMiddleware(config)
	defer securityMiddleware.Stop()

	// Create your HTTP handler
	mux := http.NewServeMux()
	mux.HandleFunc("/api/public", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "Public endpoint"}`))
	})
	mux.HandleFunc("/api/protected", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "Protected endpoint"}`))
	})

	// Apply different middleware to different routes
	publicHandler := securityMiddleware.CORSHandler()(
		securityMiddleware.SecurityHeadersHandler()(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/public" {
					mux.ServeHTTP(w, r)
				} else {
					http.NotFound(w, r)
				}
			}),
		),
	)

	protectedHandler := securityMiddleware.Handler()(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/protected" {
				mux.ServeHTTP(w, r)
			} else {
				http.NotFound(w, r)
			}
		}),
	)

	// Route requests
	mainHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/public" {
			publicHandler.ServeHTTP(w, r)
		} else if r.URL.Path == "/api/protected" {
			protectedHandler.ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}
	})

	// Start server
	log.Println("Selective middleware server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", mainHandler))
}

// ExampleWithHTTPS demonstrates HTTPS configuration with security headers
func ExampleWithHTTPS() {
	// Use production configuration with HTTPS-specific settings
	config := ProductionSecurity()
	
	// Configure security headers for HTTPS
	config.SecurityHeaders.HSTS.Enabled = true
	config.SecurityHeaders.HSTS.MaxAge = 31536000 // 1 year
	config.SecurityHeaders.HSTS.IncludeSubdomains = true
	config.SecurityHeaders.HSTS.Preload = true
	
	// Create security middleware
	securityMiddleware := NewSecurityMiddleware(config)
	defer securityMiddleware.Stop()

	// Create your HTTP handler
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "Secure HTTPS server"}`))
	})

	// Apply security middleware
	protectedHandler := securityMiddleware.Handler()(mux)

	// Configure HTTPS server
	server := &http.Server{
		Addr:    ":8443",
		Handler: protectedHandler,
	}
	
	// Apply server-level timeouts
	ConfigureServerTimeouts(server, config.Timeout)

	// Start HTTPS server (you'll need cert.pem and key.pem files)
	log.Println("HTTPS server starting on :8443")
	log.Fatal(server.ListenAndServeTLS("cert.pem", "key.pem"))
}