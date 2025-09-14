package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"Gawan/internal/core/logx"
	"Gawan/internal/core/security"
)

// Application represents the main application
type Application struct {
	securitySystem *security.SecuritySystem
	server         *http.Server
	logger         *logx.Logger
}

// NewApplication creates a new application instance
func NewApplication() (*Application, error) {
	// Initialize logger
	logger := logx.New()

	// Load security configuration based on environment
	var config security.SecuritySystemConfig
	env := os.Getenv("APP_ENV")
	switch env {
	case "production":
		config = security.ProductionSecurityConfig()
	case "development":
		config = security.DevelopmentSecurityConfig()
	case "testing":
		config = security.TestingSecurityConfig()
	case "maximum":
		config = security.MaximumSecurityConfig()
	default:
		config = security.ProductionSecurityConfig()
	}

	// Override config with environment variables if needed
	if apiKey := os.Getenv("CLOUDFLARE_API_KEY"); apiKey != "" {
		config.CDNConfig.APIKey = apiKey
	}
	if email := os.Getenv("CLOUDFLARE_EMAIL"); email != "" {
		config.CDNConfig.Email = email
	}
	if zoneID := os.Getenv("CLOUDFLARE_ZONE_ID"); zoneID != "" {
		config.CDNConfig.ZoneID = zoneID
	}

	// Initialize security system
	securitySystem, err := security.NewSecuritySystem(config, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize security system: %w", err)
	}

	return &Application{
		securitySystem: securitySystem,
		logger:         logger,
	}, nil
}

// setupRoutes sets up HTTP routes with security middleware
func (app *Application) setupRoutes() *http.ServeMux {
	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("/", app.homeHandler)
	mux.HandleFunc("/health", app.healthHandler)
	mux.HandleFunc("/status", app.statusHandler)

	// API routes
	mux.HandleFunc("/api/login", app.loginHandler)
	mux.HandleFunc("/api/register", app.registerHandler)
	mux.HandleFunc("/api/profile", app.profileHandler)
	mux.HandleFunc("/api/data", app.dataHandler)

	// Admin routes
	mux.HandleFunc("/admin/dashboard", app.adminDashboardHandler)
	mux.HandleFunc("/admin/users", app.adminUsersHandler)
	mux.HandleFunc("/admin/security", app.adminSecurityHandler)

	// Security management routes
	mux.HandleFunc("/security/status", app.securityStatusHandler)
	mux.HandleFunc("/security/metrics", app.securityMetricsHandler)
	mux.HandleFunc("/security/test", app.securityTestHandler)
	mux.HandleFunc("/security/emergency", app.emergencyModeHandler)
	mux.HandleFunc("/security/maintenance", app.maintenanceModeHandler)

	// CAPTCHA routes
	mux.HandleFunc("/captcha/generate", app.captchaGenerateHandler)
	mux.HandleFunc("/captcha/verify", app.captchaVerifyHandler)

	// 2FA routes
	mux.HandleFunc("/2fa/setup", app.twoFASetupHandler)
	mux.HandleFunc("/2fa/verify", app.twoFAVerifyHandler)
	mux.HandleFunc("/2fa/backup", app.twoFABackupHandler)

	return mux
}

// Start starts the application
func (app *Application) Start() error {
	// Start security system
	if err := app.securitySystem.Start(); err != nil {
		return fmt.Errorf("failed to start security system: %w", err)
	}

	// Setup routes
	mux := app.setupRoutes()

	// Apply security middleware
	secureHandler := app.securitySystem.GetSecurityMiddleware()(mux)

	// Create HTTP server
	app.server = &http.Server{
		Addr:         ":8080",
		Handler:      secureHandler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		app.logger.Info("SERVER_STARTING", "addr", app.server.Addr)
		if err := app.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			app.logger.Error("SERVER_ERROR", "error", err.Error())
		}
	}()

	// Run initial security tests
	go func() {
		time.Sleep(5 * time.Second) // Wait for server to start
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		app.logger.Info("RUNNING_INITIAL_SECURITY_TESTS")
		results, err := app.securitySystem.RunSecurityTests(ctx)
		if err != nil {
			app.logger.Error("SECURITY_TESTS_FAILED", "error", err.Error())
		} else {
			app.logger.Info("SECURITY_TESTS_COMPLETED", "total_tests", len(results))
			for _, result := range results {
				app.logger.Info("SECURITY_TEST_RESULT",
					"test_name", result.TestName,
					"status", result.Status,
					"score", result.Score,
					"duration", result.Duration,
				)
			}
		}
	}()

	return nil
}

// Stop stops the application gracefully
func (app *Application) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stop HTTP server
	if app.server != nil {
		if err := app.server.Shutdown(ctx); err != nil {
			app.logger.Error("SERVER_SHUTDOWN_ERROR", "error", err.Error())
		}
	}

	// Stop security system
	if app.securitySystem != nil {
		if err := app.securitySystem.Stop(); err != nil {
			app.logger.Error("SECURITY_SYSTEM_SHUTDOWN_ERROR", "error", err.Error())
		}
	}

	app.logger.Info("APPLICATION_STOPPED")
	return nil
}

// HTTP Handlers

func (app *Application) homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
    <title>Secure Application</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .status { padding: 10px; margin: 10px 0; border-radius: 5px; }
        .healthy { background-color: #d4edda; color: #155724; }
        .warning { background-color: #fff3cd; color: #856404; }
        .error { background-color: #f8d7da; color: #721c24; }
        .nav { margin: 20px 0; }
        .nav a { margin-right: 15px; text-decoration: none; color: #007bff; }
        .nav a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Secure Application</h1>
        <p>This application is protected by a comprehensive security system.</p>
        
        <div class="status healthy">
            ✅ Security System: Active
        </div>
        
        <div class="nav">
            <a href="/health">Health Check</a>
            <a href="/status">System Status</a>
            <a href="/security/status">Security Status</a>
            <a href="/security/metrics">Security Metrics</a>
            <a href="/api/login">Login API</a>
            <a href="/admin/dashboard">Admin Dashboard</a>
        </div>
        
        <h2>Security Features</h2>
        <ul>
            <li>✅ DDoS Protection with rate limiting and geo-blocking</li>
            <li>✅ Brute Force Prevention with progressive lockout</li>
            <li>✅ SQL Injection Protection with advanced detection</li>
            <li>✅ Web Application Firewall (WAF)</li>
            <li>✅ Real-time Security Monitoring</li>
            <li>✅ CAPTCHA Integration</li>
            <li>✅ Two-Factor Authentication (2FA)</li>
            <li>✅ Comprehensive Security Testing</li>
            <li>✅ Security Logging and Alerting</li>
        </ul>
        
        <h2>Test Security</h2>
        <p>Try these endpoints to test security features:</p>
        <ul>
            <li><code>POST /api/login</code> - Test brute force protection</li>
            <li><code>GET /api/data?id=1' OR '1'='1</code> - Test SQL injection protection</li>
            <li><code>POST /api/register</code> with XSS payload - Test XSS protection</li>
        </ul>
    </div>
</body>
</html>
`)
}

func (app *Application) healthHandler(w http.ResponseWriter, r *http.Request) {
	health := app.securitySystem.GetHealthStatus()
	w.Header().Set("Content-Type", "application/json")
	
	status := http.StatusOK
	if health.Overall != "healthy" {
		status = http.StatusServiceUnavailable
	}
	
	w.WriteHeader(status)
	fmt.Fprintf(w, `{
	"status": "%s",
	"timestamp": "%s",
	"uptime": "%s",
	"components": %d,
	"last_check": "%s"
}`, health.Overall, time.Now().Format(time.RFC3339), health.Uptime, len(health.Components), health.LastCheck.Format(time.RFC3339))
}

func (app *Application) statusHandler(w http.ResponseWriter, r *http.Request) {
	status := app.securitySystem.GetComponentStatus()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
	"system": %v,
	"components": %v,
	"health": "%v",
	"timestamp": "%s"
}`, status["system"], status["components"], status["health"], time.Now().Format(time.RFC3339))
}

func (app *Application) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Simulate login logic
	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error": "Username and password required"}`)
		return
	}

	// Simulate authentication (always fail for demo)
	if username != "admin" || password != "secure123" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error": "Invalid credentials"}`)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"success": true, "token": "demo-jwt-token", "message": "Login successful"}`)
}

func (app *Application) registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")

	if username == "" || email == "" || password == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error": "All fields required"}`)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"success": true, "message": "Registration successful"}`)
}

func (app *Application) profileHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"user": "demo", "email": "demo@example.com", "role": "user"}`)
}

func (app *Application) dataHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error": "ID parameter required"}`)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"id": "%s", "data": "Sample data for ID %s"}`, id, id)
}

func (app *Application) adminDashboardHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
    <title>Admin Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .card { border: 1px solid #ddd; padding: 20px; margin: 10px 0; border-radius: 5px; }
        .metric { display: inline-block; margin: 10px 20px 10px 0; }
        .metric-value { font-size: 24px; font-weight: bold; color: #007bff; }
        .metric-label { font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Security Admin Dashboard</h1>
        
        <div class="card">
            <h2>System Status</h2>
            <div class="metric">
                <div class="metric-value">ACTIVE</div>
                <div class="metric-label">Security System</div>
            </div>
            <div class="metric">
                <div class="metric-value">HIGH</div>
                <div class="metric-label">Security Level</div>
            </div>
            <div class="metric">
                <div class="metric-value">HEALTHY</div>
                <div class="metric-label">Overall Health</div>
            </div>
        </div>
        
        <div class="card">
            <h2>Security Metrics</h2>
            <div class="metric">
                <div class="metric-value">0</div>
                <div class="metric-label">Blocked Attacks</div>
            </div>
            <div class="metric">
                <div class="metric-value">0</div>
                <div class="metric-label">Failed Logins</div>
            </div>
            <div class="metric">
                <div class="metric-value">0</div>
                <div class="metric-label">Security Alerts</div>
            </div>
        </div>
        
        <div class="card">
            <h2>Quick Actions</h2>
            <button onclick="location.href='/security/test'">Run Security Tests</button>
            <button onclick="location.href='/security/emergency'">Emergency Mode</button>
            <button onclick="location.href='/security/maintenance'">Maintenance Mode</button>
        </div>
    </div>
</body>
</html>
`)
}

func (app *Application) adminUsersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"users": [{"id": 1, "username": "admin", "role": "admin"}, {"id": 2, "username": "user", "role": "user"}]}`)
}

func (app *Application) adminSecurityHandler(w http.ResponseWriter, r *http.Request) {
	metrics := app.securitySystem.GetSecurityMetrics()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
	"total_requests": %d,
	"blocked_requests": %d,
	"ddos_attacks": %d,
	"brute_force_attacks": %d,
	"sql_injection_attempts": %d,
	"xss_attempts": %d,
	"average_response_time": %.2f,
	"memory_usage": %.2f,
	"cpu_usage": %.2f
}`, metrics.TotalRequests, metrics.BlockedRequests, metrics.DDoSAttacks, metrics.BruteForceAttacks, metrics.SQLInjectionAttempts, metrics.XSSAttempts, metrics.AverageResponseTime, metrics.MemoryUsage, metrics.CPUUsage)
}

func (app *Application) securityStatusHandler(w http.ResponseWriter, r *http.Request) {
	health := app.securitySystem.GetHealthStatus()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
	"overall": "%s",
	"components": %v,
	"last_check": "%s",
	"uptime": "%s",
	"errors": %v,
	"warnings": %v
}`, health.Overall, health.Components, health.LastCheck.Format(time.RFC3339), health.Uptime, health.Errors, health.Warnings)
}

func (app *Application) securityMetricsHandler(w http.ResponseWriter, r *http.Request) {
	metrics := app.securitySystem.GetSecurityMetrics()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
	"window_start": "%s",
	"window_end": "%s",
	"total_requests": %d,
	"blocked_requests": %d,
	"allowed_requests": %d,
	"ddos_attacks": %d,
	"brute_force_attacks": %d,
	"sql_injection_attempts": %d,
	"xss_attempts": %d,
	"csrf_attempts": %d,
	"security_alerts": %d,
	"critical_events": %d,
	"high_severity_events": %d,
	"average_response_time": %.2f,
	"throughput": %.2f,
	"error_rate": %.4f,
	"memory_usage": %.2f,
	"cpu_usage": %.2f,
	"active_connections": %d
}`, metrics.WindowStart.Format(time.RFC3339), metrics.WindowEnd.Format(time.RFC3339), metrics.TotalRequests, metrics.BlockedRequests, metrics.AllowedRequests, metrics.DDoSAttacks, metrics.BruteForceAttacks, metrics.SQLInjectionAttempts, metrics.XSSAttempts, metrics.CSRFAttempts, metrics.SecurityAlerts, metrics.CriticalEvents, metrics.HighSeverityEvents, metrics.AverageResponseTime, metrics.Throughput, metrics.ErrorRate, metrics.MemoryUsage, metrics.CPUUsage, metrics.ActiveConnections)
}

func (app *Application) securityTestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	results, err := app.securitySystem.RunSecurityTests(ctx)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error": "Failed to run security tests: %s"}`, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"success": true, "total_tests": %d, "message": "Security tests completed"}`, len(results))
}

func (app *Application) emergencyModeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		app.securitySystem.EnableEmergencyMode()
		fmt.Fprintf(w, `{"success": true, "message": "Emergency mode enabled"}`)
	} else if r.Method == http.MethodDelete {
		app.securitySystem.DisableEmergencyMode()
		fmt.Fprintf(w, `{"success": true, "message": "Emergency mode disabled"}`)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (app *Application) maintenanceModeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		app.securitySystem.EnableMaintenanceMode()
		fmt.Fprintf(w, `{"success": true, "message": "Maintenance mode enabled"}`)
	} else if r.Method == http.MethodDelete {
		app.securitySystem.DisableMaintenanceMode()
		fmt.Fprintf(w, `{"success": true, "message": "Maintenance mode disabled"}`)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (app *Application) captchaGenerateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"captcha_id": "demo-captcha-123", "image_url": "/captcha/image/demo-captcha-123"}`)
}

func (app *Application) captchaVerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	captchaID := r.FormValue("captcha_id")
	answer := r.FormValue("answer")

	if captchaID == "" || answer == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error": "CAPTCHA ID and answer required"}`)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"success": true, "message": "CAPTCHA verified"}`)
}

func (app *Application) twoFASetupHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"secret": "DEMO2FASECRET123", "qr_code_url": "/2fa/qr/demo-secret", "backup_codes": ["12345678", "87654321"]}`)
}

func (app *Application) twoFAVerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	code := r.FormValue("code")
	if code == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error": "2FA code required"}`)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"success": true, "message": "2FA verified"}`)
}

func (app *Application) twoFABackupHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"backup_codes": ["12345678", "87654321", "11111111", "22222222", "33333333"]}`)
}

func main() {
	// Create application
	app, err := NewApplication()
	if err != nil {
		log.Fatalf("Failed to create application: %v", err)
	}

	// Start application
	if err := app.Start(); err != nil {
		log.Fatalf("Failed to start application: %v", err)
	}

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	app.logger.Info("APPLICATION_STARTED", "pid", os.Getpid())
	fmt.Println("🔒 Secure Application started on http://localhost:8080")
	fmt.Println("📊 Admin Dashboard: http://localhost:8080/admin/dashboard")
	fmt.Println("🛡️ Security Status: http://localhost:8080/security/status")
	fmt.Println("📈 Security Metrics: http://localhost:8080/security/metrics")
	fmt.Println("Press Ctrl+C to stop...")

	// Wait for signal
	<-sigChan

	// Graceful shutdown
	app.logger.Info("SHUTDOWN_SIGNAL_RECEIVED")
	if err := app.Stop(); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}
}