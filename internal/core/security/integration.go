package security

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"Gawan/internal/core/logx"
)

// SecuritySystemConfig comprehensive security system configuration
type SecuritySystemConfig struct {
	Enabled                bool                    `json:"enabled"`
	DDoSProtectionConfig   DDoSProtectionConfig    `json:"ddos_protection_config"`
	BruteForceConfig       EnhancedBruteForceConfig `json:"brute_force_config"`
	SQLInjectionConfig     SQLInjectionConfig      `json:"sql_injection_config"`
	WAFConfig              WAFConfig               `json:"waf_config"`
	MonitoringConfig       SecurityMonitorConfig   `json:"monitoring_config"`
	LoggingConfig          SecurityLoggerConfig    `json:"logging_config"`
	TestingConfig          SecurityTestConfig      `json:"testing_config"`
	CaptchaConfig          CaptchaConfig           `json:"captcha_config"`
	TwoFAConfig            TwoFAConfig             `json:"twofa_config"`
	GeoIPConfig            GeoIPConfig             `json:"geoip_config"`
	CDNConfig              CDNConfig               `json:"cdn_config"`
	GlobalSettings         GlobalSecuritySettings `json:"global_settings"`
}

// GlobalSecuritySettings global security settings
type GlobalSecuritySettings struct {
	SecurityLevel          string        `json:"security_level"` // low, medium, high, maximum
	StrictMode             bool          `json:"strict_mode"`
	MaintenanceMode        bool          `json:"maintenance_mode"`
	EmergencyMode          bool          `json:"emergency_mode"`
	DebugMode              bool          `json:"debug_mode"`
	HealthCheckInterval    time.Duration `json:"health_check_interval"`
	MetricsRetention       time.Duration `json:"metrics_retention"`
	AutoUpdate             bool          `json:"auto_update"`
	FailsafeMode           bool          `json:"failsafe_mode"`
	PerformanceMode        bool          `json:"performance_mode"`
}

// GeoIPConfig configuration for GeoIP services
type GeoIPConfig struct {
	Enabled        bool   `json:"enabled"`
	Provider       string `json:"provider"` // maxmind, ipapi, simple
	DatabasePath   string `json:"database_path"`
	APIKey         string `json:"api_key"`
	CacheEnabled   bool   `json:"cache_enabled"`
	CacheTTL       time.Duration `json:"cache_ttl"`
	UpdateInterval time.Duration `json:"update_interval"`
}

// SecuritySystem main integrated security system
type SecuritySystem struct {
	config              SecuritySystemConfig
	logger              *logx.Logger
	
	// Core components
	ddosProtector       *DDoSProtector
	bruteForceManager   *EnhancedBruteForceManager
	sqlInjectionDetector *SQLInjectionDetector
	waf                 *WAF
	monitor             *SecurityMonitor
	securityLogger      *SecurityLogger
	tester              *SecurityTester
	captchaManager      *CaptchaManager
	twoFAManager        *TwoFAManager
	geoIPResolver       GeoIPResolver
	cdnManager          *CDNManager
	
	// Middleware chain
	middlewareChain     []func(http.Handler) http.Handler
	
	// System state
	isInitialized       bool
	isRunning           bool
	healthStatus        HealthStatus
	mu                  sync.RWMutex
	stop                chan struct{}
	wg                  sync.WaitGroup
	
	// Metrics and monitoring
	metrics             *SecurityMetrics
	lastHealthCheck     time.Time
	healthCheckTicker   *time.Ticker
}

// HealthStatus represents system health status
type HealthStatus struct {
	Overall             string                 `json:"overall"` // healthy, degraded, unhealthy
	Components          map[string]string      `json:"components"`
	LastCheck           time.Time              `json:"last_check"`
	Uptime              time.Duration          `json:"uptime"`
	Errors              []string               `json:"errors,omitempty"`
	Warnings            []string               `json:"warnings,omitempty"`
	PerformanceMetrics  map[string]interface{} `json:"performance_metrics"`
}

// SecurityMetrics comprehensive security metrics
type SecurityMetrics struct {
	// Request metrics
	TotalRequests          int64 `json:"total_requests"`
	BlockedRequests        int64 `json:"blocked_requests"`
	AllowedRequests        int64 `json:"allowed_requests"`
	
	// Attack metrics
	DDoSAttacks            int64 `json:"ddos_attacks"`
	BruteForceAttacks      int64 `json:"brute_force_attacks"`
	SQLInjectionAttempts   int64 `json:"sql_injection_attempts"`
	XSSAttempts            int64 `json:"xss_attempts"`
	CSRFAttempts           int64 `json:"csrf_attempts"`
	
	// Security events
	SecurityAlerts         int64 `json:"security_alerts"`
	CriticalEvents         int64 `json:"critical_events"`
	HighSeverityEvents     int64 `json:"high_severity_events"`
	
	// Performance metrics
	AverageResponseTime    float64 `json:"average_response_time"`
	Throughput             float64 `json:"throughput"`
	ErrorRate              float64 `json:"error_rate"`
	
	// System metrics
	MemoryUsage            float64 `json:"memory_usage"`
	CPUUsage               float64 `json:"cpu_usage"`
	ActiveConnections      int64   `json:"active_connections"`
	
	// Time window
	WindowStart            time.Time `json:"window_start"`
	WindowEnd              time.Time `json:"window_end"`
}

// NewSecuritySystem creates a new integrated security system
func NewSecuritySystem(config SecuritySystemConfig, logger *logx.Logger) (*SecuritySystem, error) {
	if !config.Enabled {
		return nil, fmt.Errorf("security system is disabled")
	}

	// Set default global settings
	if config.GlobalSettings.SecurityLevel == "" {
		config.GlobalSettings.SecurityLevel = "high"
	}
	if config.GlobalSettings.HealthCheckInterval <= 0 {
		config.GlobalSettings.HealthCheckInterval = 30 * time.Second
	}
	if config.GlobalSettings.MetricsRetention <= 0 {
		config.GlobalSettings.MetricsRetention = 24 * time.Hour
	}

	ss := &SecuritySystem{
		config:            config,
		logger:            logger,
		middlewareChain:   make([]func(http.Handler) http.Handler, 0),
		stop:              make(chan struct{}),
		metrics:           &SecurityMetrics{},
		healthStatus: HealthStatus{
			Overall:    "initializing",
			Components: make(map[string]string),
			LastCheck:  time.Now(),
			PerformanceMetrics: make(map[string]interface{}),
		},
	}

	// Initialize components
	if err := ss.initializeComponents(); err != nil {
		return nil, fmt.Errorf("failed to initialize security components: %w", err)
	}

	// Build middleware chain
	ss.buildMiddlewareChain()

	// Start health monitoring
	ss.startHealthMonitoring()

	ss.isInitialized = true
	ss.healthStatus.Overall = "healthy"

	if logger != nil {
		logger.Info("SECURITY_SYSTEM_INITIALIZED",
			"security_level", config.GlobalSettings.SecurityLevel,
			"strict_mode", config.GlobalSettings.StrictMode,
			"components", len(ss.healthStatus.Components),
		)
	}

	return ss, nil
}

// initializeComponents initializes all security components
func (ss *SecuritySystem) initializeComponents() error {
	var err error

	// Initialize GeoIP resolver
	if ss.config.GeoIPConfig.Enabled {
		switch ss.config.GeoIPConfig.Provider {
		case "enhanced":
			ss.geoIPResolver = NewEnhancedGeoIPResolver(ss.config.GeoIPConfig.DatabasePath, ss.config.GeoIPConfig.APIKey)
		case "simple":
			ss.geoIPResolver = NewSimpleGeoIPResolver(ss.config.GeoIPConfig.DatabasePath, ss.config.GeoIPConfig.APIKey)
		default:
			ss.geoIPResolver = NewMockGeoIPResolver()
		}
		ss.healthStatus.Components["geoip"] = "healthy"
	}

	// Initialize security logger
	if ss.config.LoggingConfig.Enabled {
		ss.securityLogger, err = NewSecurityLogger(ss.config.LoggingConfig, ss.logger)
		if err != nil {
			return fmt.Errorf("failed to initialize security logger: %w", err)
		}
		ss.healthStatus.Components["logger"] = "healthy"
	}

	// Initialize security monitor
	if ss.config.MonitoringConfig.Enabled {
		ss.monitor = NewSecurityMonitor(ss.config.MonitoringConfig, ss.geoIPResolver, ss.logger)
		ss.healthStatus.Components["monitor"] = "healthy"
	}

	// Initialize DDoS protector
	if ss.config.DDoSProtectionConfig.Enabled {
		ss.ddosProtector = NewDDoSProtector(ss.config.DDoSProtectionConfig, ss.geoIPResolver, ss.logger)
		ss.healthStatus.Components["ddos_protector"] = "healthy"
	}

	// Initialize brute force manager
	if ss.config.BruteForceConfig.Enabled {
		ss.bruteForceManager = NewEnhancedBruteForceManager(ss.config.BruteForceConfig, ss.logger)
		ss.healthStatus.Components["brute_force_manager"] = "healthy"
	}

	// Initialize SQL injection detector
	if ss.config.SQLInjectionConfig.Enabled {
		ss.sqlInjectionDetector = NewSQLInjectionDetector(ss.config.SQLInjectionConfig, ss.logger)
		ss.healthStatus.Components["sql_injection_detector"] = "healthy"
	}

	// Initialize WAF
	if ss.config.WAFConfig.Enabled {
		ss.waf = NewWAF(ss.config.WAFConfig, ss.geoIPResolver, ss.logger)
		ss.healthStatus.Components["waf"] = "healthy"
	}

	// Initialize CAPTCHA manager
	if ss.config.CaptchaConfig.Enabled {
		ss.captchaManager = NewCaptchaManager(ss.config.CaptchaConfig, ss.logger)
		ss.healthStatus.Components["captcha_manager"] = "healthy"
	}

	// Initialize 2FA manager
	if ss.config.TwoFAConfig.Enabled {
		ss.twoFAManager = NewTwoFAManager(ss.config.TwoFAConfig, ss.logger)
		ss.healthStatus.Components["twofa_manager"] = "healthy"
	}

	// Initialize CDN manager
	if ss.config.CDNConfig.Enabled {
		ss.cdnManager = NewCDNManager(ss.config.CDNConfig, ss.logger)
		ss.healthStatus.Components["cdn_manager"] = "healthy"
	}

	// Initialize security tester
	if ss.config.TestingConfig.Enabled {
		ss.tester = NewSecurityTester(ss.config.TestingConfig, ss.logger)
		ss.healthStatus.Components["tester"] = "healthy"
	}

	return nil
}

// buildMiddlewareChain builds the security middleware chain
func (ss *SecuritySystem) buildMiddlewareChain() {
	// Clear existing chain
	ss.middlewareChain = make([]func(http.Handler) http.Handler, 0)

	// Add middleware in order of execution

	// 1. Security logging (first to capture all requests)
	if ss.securityLogger != nil {
		ss.middlewareChain = append(ss.middlewareChain, SecurityLoggingMiddleware(ss.securityLogger))
	}

	// 2. Security monitoring
	if ss.monitor != nil {
		ss.middlewareChain = append(ss.middlewareChain, SecurityMonitoringMiddleware(ss.monitor))
	}

	// 3. DDoS protection (early filtering)
	if ss.ddosProtector != nil {
		ss.middlewareChain = append(ss.middlewareChain, DDoSProtectionMiddleware(ss.ddosProtector))
	}

	// 4. WAF (comprehensive filtering)
	if ss.waf != nil {
		ss.middlewareChain = append(ss.middlewareChain, WAFMiddleware(ss.waf))
	}

	// 5. SQL injection protection
	if ss.sqlInjectionDetector != nil {
		ss.middlewareChain = append(ss.middlewareChain, SQLInjectionMiddleware(ss.sqlInjectionDetector))
	}

	// 6. Brute force protection
	if ss.bruteForceManager != nil {
		ss.middlewareChain = append(ss.middlewareChain, EnhancedBruteForceMiddleware(ss.bruteForceManager))
	}

	// 7. CAPTCHA validation (when needed)
	if ss.captchaManager != nil {
		ss.middlewareChain = append(ss.middlewareChain, CaptchaMiddleware(ss.captchaManager))
	}

	// 8. 2FA validation (when needed)
	if ss.twoFAManager != nil {
		ss.middlewareChain = append(ss.middlewareChain, TwoFAMiddleware(ss.twoFAManager))
	}

	if ss.logger != nil {
		ss.logger.Info("MIDDLEWARE_CHAIN_BUILT", "middleware_count", len(ss.middlewareChain))
	}
}

// GetSecurityMiddleware returns the complete security middleware chain
func (ss *SecuritySystem) GetSecurityMiddleware() func(http.Handler) http.Handler {
	if !ss.isInitialized {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "Security system not initialized", http.StatusServiceUnavailable)
			})
		}
	}

	return func(next http.Handler) http.Handler {
		// Apply middleware chain in reverse order
		handler := next
		for i := len(ss.middlewareChain) - 1; i >= 0; i-- {
			handler = ss.middlewareChain[i](handler)
		}

		// Add emergency mode check
		if ss.config.GlobalSettings.EmergencyMode {
			handler = ss.emergencyModeMiddleware(handler)
		}

		// Add maintenance mode check
		if ss.config.GlobalSettings.MaintenanceMode {
			handler = ss.maintenanceModeMiddleware(handler)
		}

		return handler
	}
}

// emergencyModeMiddleware handles emergency mode
func (ss *SecuritySystem) emergencyModeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// In emergency mode, block all non-essential requests
		if !ss.isEssentialRequest(r) {
			http.Error(w, "Service temporarily unavailable - Emergency mode active", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// maintenanceModeMiddleware handles maintenance mode
func (ss *SecuritySystem) maintenanceModeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// In maintenance mode, show maintenance page
		if !ss.isMaintenanceExempt(r) {
			w.Header().Set("Retry-After", "3600") // 1 hour
			http.Error(w, "Service temporarily unavailable for maintenance", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isEssentialRequest checks if a request is essential during emergency mode
func (ss *SecuritySystem) isEssentialRequest(r *http.Request) bool {
	essentialPaths := []string{
		"/health",
		"/status",
		"/api/security/status",
		"/admin/emergency",
	}

	for _, path := range essentialPaths {
		if r.URL.Path == path {
			return true
		}
	}
	return false
}

// isMaintenanceExempt checks if a request is exempt from maintenance mode
func (ss *SecuritySystem) isMaintenanceExempt(r *http.Request) bool {
	exemptPaths := []string{
		"/health",
		"/status",
		"/maintenance",
		"/admin",
	}

	for _, path := range exemptPaths {
		if len(r.URL.Path) >= len(path) && r.URL.Path[:len(path)] == path {
			return true
		}
	}
	return false
}

// Start starts the security system
func (ss *SecuritySystem) Start() error {
	if !ss.isInitialized {
		return fmt.Errorf("security system not initialized")
	}

	if ss.isRunning {
		return fmt.Errorf("security system already running")
	}

	ss.isRunning = true

	// Start health monitoring
	ss.startHealthMonitoring()

	// Start automatic testing if configured
	if ss.config.TestingConfig.ScheduleConfig.RunOnStart && ss.tester != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), ss.config.TestingConfig.TestTimeout)
			defer cancel()
			
			if _, err := ss.tester.RunAllTests(ctx); err != nil && ss.logger != nil {
				ss.logger.Error("STARTUP_SECURITY_TEST_FAILED", "error", err.Error())
			}
		}()
	}

	if ss.logger != nil {
		ss.logger.Info("SECURITY_SYSTEM_STARTED",
			"security_level", ss.config.GlobalSettings.SecurityLevel,
			"components", len(ss.healthStatus.Components),
		)
	}

	return nil
}

// Stop stops the security system
func (ss *SecuritySystem) Stop() error {
	if !ss.isRunning {
		return nil
	}

	ss.isRunning = false

	// Stop health monitoring
	if ss.healthCheckTicker != nil {
		ss.healthCheckTicker.Stop()
	}

	// Stop all components
	close(ss.stop)
	ss.wg.Wait()

	// Stop individual components
	if ss.monitor != nil {
		ss.monitor.Stop()
	}
	if ss.securityLogger != nil {
		ss.securityLogger.Close()
	}
	if ss.tester != nil {
		ss.tester.Stop()
	}

	if ss.logger != nil {
		ss.logger.Info("SECURITY_SYSTEM_STOPPED")
	}

	return nil
}

// startHealthMonitoring starts the health monitoring routine
func (ss *SecuritySystem) startHealthMonitoring() {
	if ss.healthCheckTicker != nil {
		ss.healthCheckTicker.Stop()
	}

	ss.healthCheckTicker = time.NewTicker(ss.config.GlobalSettings.HealthCheckInterval)

	ss.wg.Add(1)
	go func() {
		defer ss.wg.Done()
		for {
			select {
			case <-ss.healthCheckTicker.C:
				ss.performHealthCheck()
			case <-ss.stop:
				return
			}
		}
	}()
}

// performHealthCheck performs a comprehensive health check
func (ss *SecuritySystem) performHealthCheck() {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.lastHealthCheck = time.Now()
	ss.healthStatus.LastCheck = ss.lastHealthCheck
	ss.healthStatus.Errors = make([]string, 0)
	ss.healthStatus.Warnings = make([]string, 0)

	// Check each component
	healthyComponents := 0
	totalComponents := len(ss.healthStatus.Components)

	for component, status := range ss.healthStatus.Components {
		if ss.checkComponentHealth(component) {
			ss.healthStatus.Components[component] = "healthy"
			healthyComponents++
		} else {
			ss.healthStatus.Components[component] = "unhealthy"
			ss.healthStatus.Errors = append(ss.healthStatus.Errors, fmt.Sprintf("Component %s is unhealthy", component))
		}
	}

	// Determine overall health
	if healthyComponents == totalComponents {
		ss.healthStatus.Overall = "healthy"
	} else if healthyComponents > totalComponents/2 {
		ss.healthStatus.Overall = "degraded"
	} else {
		ss.healthStatus.Overall = "unhealthy"
	}

	// Update performance metrics
	ss.updatePerformanceMetrics()

	// Log health status if degraded or unhealthy
	if ss.healthStatus.Overall != "healthy" && ss.logger != nil {
		ss.logger.Warn("SECURITY_SYSTEM_HEALTH_DEGRADED",
			"overall_status", ss.healthStatus.Overall,
			"healthy_components", healthyComponents,
			"total_components", totalComponents,
			"errors", ss.healthStatus.Errors,
		)
	}
}

// checkComponentHealth checks the health of a specific component
func (ss *SecuritySystem) checkComponentHealth(component string) bool {
	// Basic health checks for each component
	switch component {
	case "geoip":
		return ss.geoIPResolver != nil
	case "logger":
		return ss.securityLogger != nil
	case "monitor":
		return ss.monitor != nil
	case "ddos_protector":
		return ss.ddosProtector != nil
	case "brute_force_manager":
		return ss.bruteForceManager != nil
	case "sql_injection_detector":
		return ss.sqlInjectionDetector != nil
	case "waf":
		return ss.waf != nil
	case "captcha_manager":
		return ss.captchaManager != nil
	case "twofa_manager":
		return ss.twoFAManager != nil
	case "cdn_manager":
		return ss.cdnManager != nil
	case "tester":
		return ss.tester != nil
	default:
		return false
	}
}

// updatePerformanceMetrics updates performance metrics
func (ss *SecuritySystem) updatePerformanceMetrics() {
	// Get metrics from monitor if available
	if ss.monitor != nil {
		monitorMetrics := ss.monitor.GetMetrics()
		ss.healthStatus.PerformanceMetrics["total_requests"] = monitorMetrics.TotalRequests
		ss.healthStatus.PerformanceMetrics["blocked_requests"] = monitorMetrics.BlockedRequests
		ss.healthStatus.PerformanceMetrics["average_response_time"] = monitorMetrics.AverageResponseTime
		ss.healthStatus.PerformanceMetrics["memory_usage"] = monitorMetrics.MemoryUsage
		ss.healthStatus.PerformanceMetrics["cpu_usage"] = monitorMetrics.CPUUsage
	}
}

// GetHealthStatus returns the current health status
func (ss *SecuritySystem) GetHealthStatus() HealthStatus {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	// Calculate uptime
	if ss.isRunning {
		ss.healthStatus.Uptime = time.Since(ss.lastHealthCheck)
	}

	return ss.healthStatus
}

// GetSecurityMetrics returns comprehensive security metrics
func (ss *SecuritySystem) GetSecurityMetrics() *SecurityMetrics {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	// Aggregate metrics from all components
	metrics := &SecurityMetrics{
		WindowStart: time.Now().Add(-time.Hour),
		WindowEnd:   time.Now(),
	}

	if ss.monitor != nil {
		monitorMetrics := ss.monitor.GetMetrics()
		metrics.TotalRequests = monitorMetrics.TotalRequests
		metrics.BlockedRequests = monitorMetrics.BlockedRequests
		metrics.AllowedRequests = monitorMetrics.TotalRequests - monitorMetrics.BlockedRequests
		metrics.SQLInjectionAttempts = monitorMetrics.SQLInjectionAttempts
		metrics.XSSAttempts = monitorMetrics.XSSAttempts
		metrics.BruteForceAttacks = monitorMetrics.BruteForceAttempts
		metrics.DDoSAttacks = monitorMetrics.DDoSAttempts
		metrics.AverageResponseTime = monitorMetrics.AverageResponseTime
		metrics.MemoryUsage = monitorMetrics.MemoryUsage
		metrics.CPUUsage = monitorMetrics.CPUUsage
	}

	return metrics
}

// RunSecurityTests runs comprehensive security tests
func (ss *SecuritySystem) RunSecurityTests(ctx context.Context) ([]TestResult, error) {
	if ss.tester == nil {
		return nil, fmt.Errorf("security tester not initialized")
	}

	return ss.tester.RunAllTests(ctx)
}

// SetSecurityLevel dynamically adjusts security level
func (ss *SecuritySystem) SetSecurityLevel(level string) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	validLevels := []string{"low", "medium", "high", "maximum"}
	valid := false
	for _, validLevel := range validLevels {
		if level == validLevel {
			valid = true
			break
		}
	}

	if !valid {
		return fmt.Errorf("invalid security level: %s", level)
	}

	ss.config.GlobalSettings.SecurityLevel = level

	// Adjust component configurations based on security level
	ss.adjustSecurityLevel(level)

	if ss.logger != nil {
		ss.logger.Info("SECURITY_LEVEL_CHANGED", "new_level", level)
	}

	return nil
}

// adjustSecurityLevel adjusts component configurations based on security level
func (ss *SecuritySystem) adjustSecurityLevel(level string) {
	switch level {
	case "low":
		// Relaxed settings
		if ss.ddosProtector != nil {
			// Adjust DDoS thresholds
		}
		if ss.waf != nil {
			// Reduce WAF strictness
		}
	case "medium":
		// Balanced settings
	case "high":
		// Strict settings
	case "maximum":
		// Maximum security settings
		ss.config.GlobalSettings.StrictMode = true
	}
}

// EnableEmergencyMode enables emergency mode
func (ss *SecuritySystem) EnableEmergencyMode() {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.config.GlobalSettings.EmergencyMode = true

	if ss.logger != nil {
		ss.logger.Error("EMERGENCY_MODE_ENABLED")
	}

	// Notify all components
	if ss.monitor != nil {
		ss.monitor.LogSecurityEvent(SecurityEvent{
			EventType: "emergency_mode_enabled",
			Severity:  "critical",
			Source:    "security_system",
			Message:   "Emergency mode has been enabled",
			Timestamp: time.Now(),
		})
	}
}

// DisableEmergencyMode disables emergency mode
func (ss *SecuritySystem) DisableEmergencyMode() {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.config.GlobalSettings.EmergencyMode = false

	if ss.logger != nil {
		ss.logger.Info("EMERGENCY_MODE_DISABLED")
	}
}

// EnableMaintenanceMode enables maintenance mode
func (ss *SecuritySystem) EnableMaintenanceMode() {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.config.GlobalSettings.MaintenanceMode = true

	if ss.logger != nil {
		ss.logger.Info("MAINTENANCE_MODE_ENABLED")
	}
}

// DisableMaintenanceMode disables maintenance mode
func (ss *SecuritySystem) DisableMaintenanceMode() {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.config.GlobalSettings.MaintenanceMode = false

	if ss.logger != nil {
		ss.logger.Info("MAINTENANCE_MODE_DISABLED")
	}
}

// GetComponentStatus returns the status of all components
func (ss *SecuritySystem) GetComponentStatus() map[string]interface{} {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	status := make(map[string]interface{})

	status["system"] = map[string]interface{}{
		"initialized":     ss.isInitialized,
		"running":         ss.isRunning,
		"security_level":  ss.config.GlobalSettings.SecurityLevel,
		"strict_mode":     ss.config.GlobalSettings.StrictMode,
		"emergency_mode":  ss.config.GlobalSettings.EmergencyMode,
		"maintenance_mode": ss.config.GlobalSettings.MaintenanceMode,
	}

	status["components"] = ss.healthStatus.Components
	status["health"] = ss.healthStatus.Overall
	status["last_check"] = ss.healthStatus.LastCheck
	status["uptime"] = ss.healthStatus.Uptime

	return status
}

// DefaultSecuritySystemConfig returns default security system configuration
func DefaultSecuritySystemConfig() SecuritySystemConfig {
	return SecuritySystemConfig{
		Enabled:                true,
		DDoSProtectionConfig:   DefaultDDoSProtectionConfig(),
		BruteForceConfig:       DefaultEnhancedBruteForceConfig(),
		SQLInjectionConfig:     DefaultSQLInjectionConfig(),
		WAFConfig:              DefaultWAFConfig(),
		MonitoringConfig:       DefaultSecurityMonitorConfig(),
		LoggingConfig:          DefaultSecurityLoggerConfig(),
		TestingConfig:          DefaultSecurityTestConfig(),
		CaptchaConfig:          DefaultCaptchaConfig(),
		TwoFAConfig:            DefaultTwoFAConfig(),
		GeoIPConfig: GeoIPConfig{
			Enabled:        true,
			Provider:       "simple",
			DatabasePath:   "./data/geoip.db",
			CacheEnabled:   true,
			CacheTTL:       24 * time.Hour,
			UpdateInterval: 7 * 24 * time.Hour,
		},
		CDNConfig: DefaultCDNConfig(),
		GlobalSettings: GlobalSecuritySettings{
			SecurityLevel:       "high",
			StrictMode:          false,
			MaintenanceMode:     false,
			EmergencyMode:       false,
			DebugMode:           false,
			HealthCheckInterval: 30 * time.Second,
			MetricsRetention:    24 * time.Hour,
			AutoUpdate:          false,
			FailsafeMode:        true,
			PerformanceMode:     false,
		},
	}
}