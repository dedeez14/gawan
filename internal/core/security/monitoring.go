package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"Gawan/internal/core/logx"
)

// SecurityMonitorConfig configuration for security monitoring
type SecurityMonitorConfig struct {
	Enabled                bool          `json:"enabled"`
	RealTimeAlerts         bool          `json:"real_time_alerts"`
	MetricsInterval        time.Duration `json:"metrics_interval"`
	AlertThresholds        AlertThresholds `json:"alert_thresholds"`
	RetentionPeriod        time.Duration `json:"retention_period"`
	MaxEventsInMemory      int           `json:"max_events_in_memory"`
	EnablePerformanceStats bool          `json:"enable_performance_stats"`
	EnableGeoTracking      bool          `json:"enable_geo_tracking"`
	EnableUserTracking     bool          `json:"enable_user_tracking"`
	WebhookURL             string        `json:"webhook_url"`
	SlackWebhook           string        `json:"slack_webhook"`
	EmailAlerts            EmailConfig   `json:"email_alerts"`
}

// AlertThresholds defines thresholds for various security alerts
type AlertThresholds struct {
	FailedLoginsPerMinute    int `json:"failed_logins_per_minute"`
	SQLInjectionPerHour      int `json:"sql_injection_per_hour"`
	XSSAttemptsPerHour       int `json:"xss_attempts_per_hour"`
	BruteForceAttemptsPerMin int `json:"brute_force_attempts_per_min"`
	DDoSRequestsPerSecond    int `json:"ddos_requests_per_second"`
	SuspiciousIPsPerHour     int `json:"suspicious_ips_per_hour"`
	HighSeverityEventsPerMin int `json:"high_severity_events_per_min"`
	CriticalEventsPerMin     int `json:"critical_events_per_min"`
	UnauthorizedAccessPerMin int `json:"unauthorized_access_per_min"`
	AnomalousTrafficPerMin   int `json:"anomalous_traffic_per_min"`
}

// EmailConfig configuration for email alerts
type EmailConfig struct {
	Enabled    bool     `json:"enabled"`
	SMTPServer string   `json:"smtp_server"`
	SMTPPort   int      `json:"smtp_port"`
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	FromEmail  string   `json:"from_email"`
	ToEmails   []string `json:"to_emails"`
	UseTLS     bool     `json:"use_tls"`
}

// SecurityEvent represents a security event
type SecurityEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"`
	Severity    string                 `json:"severity"`
	Source      string                 `json:"source"`
	ClientIP    string                 `json:"client_ip"`
	UserID      string                 `json:"user_id,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	URL         string                 `json:"url,omitempty"`
	Method      string                 `json:"method,omitempty"`
	StatusCode  int                    `json:"status_code,omitempty"`
	Message     string                 `json:"message"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Country     string                 `json:"country,omitempty"`
	ASN         string                 `json:"asn,omitempty"`
	Blocked     bool                   `json:"blocked"`
	RuleID      string                 `json:"rule_id,omitempty"`
	Score       int                    `json:"score,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
}

// SecurityMetrics holds security metrics
type SecurityMetrics struct {
	// Request metrics
	TotalRequests          int64 `json:"total_requests"`
	BlockedRequests        int64 `json:"blocked_requests"`
	SuspiciousRequests     int64 `json:"suspicious_requests"`
	MaliciousRequests      int64 `json:"malicious_requests"`
	
	// Attack metrics
	SQLInjectionAttempts   int64 `json:"sql_injection_attempts"`
	XSSAttempts            int64 `json:"xss_attempts"`
	BruteForceAttempts     int64 `json:"brute_force_attempts"`
	DDoSAttempts           int64 `json:"ddos_attempts"`
	CSRFAttempts           int64 `json:"csrf_attempts"`
	
	// Authentication metrics
	FailedLogins           int64 `json:"failed_logins"`
	SuccessfulLogins       int64 `json:"successful_logins"`
	AccountLockouts        int64 `json:"account_lockouts"`
	PasswordResets         int64 `json:"password_resets"`
	
	// Geographic metrics
	UniqueCountries        int64 `json:"unique_countries"`
	BlockedCountries       int64 `json:"blocked_countries"`
	
	// Performance metrics
	AverageResponseTime    float64 `json:"average_response_time"`
	MaxResponseTime        float64 `json:"max_response_time"`
	MinResponseTime        float64 `json:"min_response_time"`
	
	// System metrics
	MemoryUsage            float64 `json:"memory_usage"`
	CPUUsage               float64 `json:"cpu_usage"`
	Goroutines             int     `json:"goroutines"`
	
	// Time window
	WindowStart            time.Time `json:"window_start"`
	WindowEnd              time.Time `json:"window_end"`
}

// SecurityAlert represents a security alert
type SecurityAlert struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	AlertType   string                 `json:"alert_type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Source      string                 `json:"source"`
	AffectedIPs []string               `json:"affected_ips,omitempty"`
	EventCount  int                    `json:"event_count"`
	TimeWindow  string                 `json:"time_window"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Resolved    bool                   `json:"resolved"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty"`
	Actions     []string               `json:"actions,omitempty"`
}

// SecurityMonitor main security monitoring system
type SecurityMonitor struct {
	config          SecurityMonitorConfig
	events          []SecurityEvent
	alerts          []SecurityAlert
	metrics         SecurityMetrics
	eventCounters   map[string]*EventCounter
	geoIPResolver   GeoIPResolver
	logger          *logx.Logger
	mu              sync.RWMutex
	metricsTimer    *time.Ticker
	cleanupTimer    *time.Ticker
	stop            chan struct{}
	alertHandlers   []AlertHandler
	notificationCh  chan SecurityAlert
}

// EventCounter tracks event counts for alerting
type EventCounter struct {
	Count       int64
	LastReset   time.Time
	Window      time.Duration
	mu          sync.RWMutex
}

// AlertHandler interface for handling alerts
type AlertHandler interface {
	HandleAlert(alert SecurityAlert) error
}

// WebhookAlertHandler sends alerts to webhook
type WebhookAlertHandler struct {
	URL    string
	client *http.Client
}

// SlackAlertHandler sends alerts to Slack
type SlackAlertHandler struct {
	WebhookURL string
	client     *http.Client
}

// EmailAlertHandler sends alerts via email
type EmailAlertHandler struct {
	Config EmailConfig
}

// NewSecurityMonitor creates a new security monitor
func NewSecurityMonitor(config SecurityMonitorConfig, geoIPResolver GeoIPResolver, logger *logx.Logger) *SecurityMonitor {
	// Set defaults
	if config.MetricsInterval <= 0 {
		config.MetricsInterval = time.Minute
	}
	if config.RetentionPeriod <= 0 {
		config.RetentionPeriod = 24 * time.Hour
	}
	if config.MaxEventsInMemory <= 0 {
		config.MaxEventsInMemory = 10000
	}

	sm := &SecurityMonitor{
		config:         config,
		events:         make([]SecurityEvent, 0),
		alerts:         make([]SecurityAlert, 0),
		eventCounters:  make(map[string]*EventCounter),
		geoIPResolver:  geoIPResolver,
		logger:         logger,
		metricsTimer:   time.NewTicker(config.MetricsInterval),
		cleanupTimer:   time.NewTicker(time.Hour),
		stop:           make(chan struct{}),
		alertHandlers:  make([]AlertHandler, 0),
		notificationCh: make(chan SecurityAlert, 1000),
	}

	// Initialize event counters
	sm.initializeEventCounters()

	// Initialize alert handlers
	sm.initializeAlertHandlers()

	// Start background routines
	go sm.metricsRoutine()
	go sm.cleanupRoutine()
	go sm.alertRoutine()

	return sm
}

// initializeEventCounters initializes event counters for alerting
func (sm *SecurityMonitor) initializeEventCounters() {
	counters := map[string]time.Duration{
		"failed_logins":         time.Minute,
		"sql_injection":         time.Hour,
		"xss_attempts":          time.Hour,
		"brute_force":           time.Minute,
		"ddos_requests":         time.Second,
		"suspicious_ips":        time.Hour,
		"high_severity_events":  time.Minute,
		"critical_events":       time.Minute,
		"unauthorized_access":   time.Minute,
		"anomalous_traffic":     time.Minute,
	}

	for name, window := range counters {
		sm.eventCounters[name] = &EventCounter{
			Window:    window,
			LastReset: time.Now(),
		}
	}
}

// initializeAlertHandlers initializes alert handlers
func (sm *SecurityMonitor) initializeAlertHandlers() {
	// Webhook handler
	if sm.config.WebhookURL != "" {
		sm.alertHandlers = append(sm.alertHandlers, &WebhookAlertHandler{
			URL:    sm.config.WebhookURL,
			client: &http.Client{Timeout: 10 * time.Second},
		})
	}

	// Slack handler
	if sm.config.SlackWebhook != "" {
		sm.alertHandlers = append(sm.alertHandlers, &SlackAlertHandler{
			WebhookURL: sm.config.SlackWebhook,
			client:     &http.Client{Timeout: 10 * time.Second},
		})
	}

	// Email handler
	if sm.config.EmailAlerts.Enabled {
		sm.alertHandlers = append(sm.alertHandlers, &EmailAlertHandler{
			Config: sm.config.EmailAlerts,
		})
	}
}

// LogSecurityEvent logs a security event
func (sm *SecurityMonitor) LogSecurityEvent(event SecurityEvent) {
	if !sm.config.Enabled {
		return
	}

	// Set timestamp if not provided
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Generate ID if not provided
	if event.ID == "" {
		event.ID = fmt.Sprintf("%d-%s", event.Timestamp.UnixNano(), event.EventType)
	}

	// Enrich with geo data
	if sm.config.EnableGeoTracking && event.ClientIP != "" && sm.geoIPResolver != nil {
		if country, err := sm.geoIPResolver.GetCountryCode(event.ClientIP); err == nil {
			event.Country = country
		}
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Add to events list
	sm.events = append(sm.events, event)

	// Trim events if exceeding max
	if len(sm.events) > sm.config.MaxEventsInMemory {
		sm.events = sm.events[len(sm.events)-sm.config.MaxEventsInMemory:]
	}

	// Update metrics
	sm.updateMetrics(event)

	// Update event counters
	sm.updateEventCounters(event)

	// Check for alerts
	if sm.config.RealTimeAlerts {
		go sm.checkAlerts(event)
	}

	// Log to structured logger
	if sm.logger != nil {
		sm.logEventToLogger(event)
	}
}

// updateMetrics updates security metrics based on event
func (sm *SecurityMonitor) updateMetrics(event SecurityEvent) {
	atomic.AddInt64(&sm.metrics.TotalRequests, 1)

	switch event.EventType {
	case "request_blocked":
		atomic.AddInt64(&sm.metrics.BlockedRequests, 1)
	case "suspicious_request":
		atomic.AddInt64(&sm.metrics.SuspiciousRequests, 1)
	case "malicious_request":
		atomic.AddInt64(&sm.metrics.MaliciousRequests, 1)
	case "sql_injection":
		atomic.AddInt64(&sm.metrics.SQLInjectionAttempts, 1)
	case "xss_attempt":
		atomic.AddInt64(&sm.metrics.XSSAttempts, 1)
	case "brute_force":
		atomic.AddInt64(&sm.metrics.BruteForceAttempts, 1)
	case "ddos_attempt":
		atomic.AddInt64(&sm.metrics.DDoSAttempts, 1)
	case "csrf_attempt":
		atomic.AddInt64(&sm.metrics.CSRFAttempts, 1)
	case "login_failure":
		atomic.AddInt64(&sm.metrics.FailedLogins, 1)
	case "login_success":
		atomic.AddInt64(&sm.metrics.SuccessfulLogins, 1)
	case "account_lockout":
		atomic.AddInt64(&sm.metrics.AccountLockouts, 1)
	case "password_reset":
		atomic.AddInt64(&sm.metrics.PasswordResets, 1)
	}
}

// updateEventCounters updates event counters for alerting
func (sm *SecurityMonitor) updateEventCounters(event SecurityEvent) {
	counterMap := map[string]string{
		"login_failure":        "failed_logins",
		"sql_injection":        "sql_injection",
		"xss_attempt":          "xss_attempts",
		"brute_force":          "brute_force",
		"ddos_attempt":         "ddos_requests",
		"unauthorized_access":  "unauthorized_access",
		"anomalous_traffic":    "anomalous_traffic",
	}

	if counterName, exists := counterMap[event.EventType]; exists {
		if counter, exists := sm.eventCounters[counterName]; exists {
			counter.mu.Lock()
			
			// Reset counter if window expired
			if time.Since(counter.LastReset) > counter.Window {
				counter.Count = 0
				counter.LastReset = time.Now()
			}
			
			atomic.AddInt64(&counter.Count, 1)
			counter.mu.Unlock()
		}
	}

	// Check severity-based counters
	if event.Severity == "high" {
		if counter, exists := sm.eventCounters["high_severity_events"]; exists {
			counter.mu.Lock()
			if time.Since(counter.LastReset) > counter.Window {
				counter.Count = 0
				counter.LastReset = time.Now()
			}
			atomic.AddInt64(&counter.Count, 1)
			counter.mu.Unlock()
		}
	}

	if event.Severity == "critical" {
		if counter, exists := sm.eventCounters["critical_events"]; exists {
			counter.mu.Lock()
			if time.Since(counter.LastReset) > counter.Window {
				counter.Count = 0
				counter.LastReset = time.Now()
			}
			atomic.AddInt64(&counter.Count, 1)
			counter.mu.Unlock()
		}
	}
}

// checkAlerts checks if any alert thresholds are exceeded
func (sm *SecurityMonitor) checkAlerts(event SecurityEvent) {
	thresholds := map[string]int{
		"failed_logins":         sm.config.AlertThresholds.FailedLoginsPerMinute,
		"sql_injection":         sm.config.AlertThresholds.SQLInjectionPerHour,
		"xss_attempts":          sm.config.AlertThresholds.XSSAttemptsPerHour,
		"brute_force":           sm.config.AlertThresholds.BruteForceAttemptsPerMin,
		"ddos_requests":         sm.config.AlertThresholds.DDoSRequestsPerSecond,
		"high_severity_events":  sm.config.AlertThresholds.HighSeverityEventsPerMin,
		"critical_events":       sm.config.AlertThresholds.CriticalEventsPerMin,
		"unauthorized_access":   sm.config.AlertThresholds.UnauthorizedAccessPerMin,
		"anomalous_traffic":     sm.config.AlertThresholds.AnomalousTrafficPerMin,
	}

	for counterName, threshold := range thresholds {
		if threshold <= 0 {
			continue
		}

		if counter, exists := sm.eventCounters[counterName]; exists {
			counter.mu.RLock()
			count := atomic.LoadInt64(&counter.Count)
			counter.mu.RUnlock()

			if int(count) >= threshold {
				alert := sm.createAlert(counterName, int(count), threshold, event)
				select {
				case sm.notificationCh <- alert:
				default:
					// Channel full, skip alert
				}
			}
		}
	}
}

// createAlert creates a security alert
func (sm *SecurityMonitor) createAlert(alertType string, count, threshold int, triggerEvent SecurityEvent) SecurityAlert {
	alert := SecurityAlert{
		ID:          fmt.Sprintf("%s-%d", alertType, time.Now().UnixNano()),
		Timestamp:   time.Now(),
		AlertType:   alertType,
		EventCount:  count,
		Source:      "security_monitor",
		AffectedIPs: []string{triggerEvent.ClientIP},
		Resolved:    false,
	}

	// Set alert details based on type
	switch alertType {
	case "failed_logins":
		alert.Severity = "medium"
		alert.Title = "High Failed Login Rate Detected"
		alert.Description = fmt.Sprintf("Detected %d failed login attempts in the last minute (threshold: %d)", count, threshold)
		alert.TimeWindow = "1 minute"
	case "sql_injection":
		alert.Severity = "high"
		alert.Title = "SQL Injection Attack Detected"
		alert.Description = fmt.Sprintf("Detected %d SQL injection attempts in the last hour (threshold: %d)", count, threshold)
		alert.TimeWindow = "1 hour"
	case "xss_attempts":
		alert.Severity = "high"
		alert.Title = "XSS Attack Detected"
		alert.Description = fmt.Sprintf("Detected %d XSS attempts in the last hour (threshold: %d)", count, threshold)
		alert.TimeWindow = "1 hour"
	case "brute_force":
		alert.Severity = "high"
		alert.Title = "Brute Force Attack Detected"
		alert.Description = fmt.Sprintf("Detected %d brute force attempts in the last minute (threshold: %d)", count, threshold)
		alert.TimeWindow = "1 minute"
	case "ddos_requests":
		alert.Severity = "critical"
		alert.Title = "DDoS Attack Detected"
		alert.Description = fmt.Sprintf("Detected %d requests per second (threshold: %d)", count, threshold)
		alert.TimeWindow = "1 second"
	case "critical_events":
		alert.Severity = "critical"
		alert.Title = "Critical Security Events Detected"
		alert.Description = fmt.Sprintf("Detected %d critical security events in the last minute (threshold: %d)", count, threshold)
		alert.TimeWindow = "1 minute"
	default:
		alert.Severity = "medium"
		alert.Title = "Security Threshold Exceeded"
		alert.Description = fmt.Sprintf("Detected %d %s events (threshold: %d)", count, alertType, threshold)
	}

	// Add metadata
	alert.Metadata = map[string]interface{}{
		"trigger_event": triggerEvent,
		"threshold":     threshold,
		"actual_count":  count,
	}

	return alert
}

// logEventToLogger logs event to structured logger
func (sm *SecurityMonitor) logEventToLogger(event SecurityEvent) {
	logLevel := "INFO"
	switch event.Severity {
	case "low":
		logLevel = "INFO"
	case "medium":
		logLevel = "WARN"
	case "high":
		logLevel = "ERROR"
	case "critical":
		logLevel = "ERROR"
	}

	fields := []interface{}{
		"event_id", event.ID,
		"event_type", event.EventType,
		"severity", event.Severity,
		"source", event.Source,
		"client_ip", event.ClientIP,
		"message", event.Message,
		"blocked", event.Blocked,
		"timestamp", event.Timestamp.UTC(),
	}

	if event.UserID != "" {
		fields = append(fields, "user_id", event.UserID)
	}
	if event.URL != "" {
		fields = append(fields, "url", event.URL)
	}
	if event.Country != "" {
		fields = append(fields, "country", event.Country)
	}
	if event.RuleID != "" {
		fields = append(fields, "rule_id", event.RuleID)
	}

	switch logLevel {
	case "INFO":
		sm.logger.Info("SECURITY_EVENT", fields...)
	case "WARN":
		sm.logger.Warn("SECURITY_EVENT", fields...)
	case "ERROR":
		sm.logger.Error("SECURITY_EVENT", fields...)
	}
}

// metricsRoutine periodically updates system metrics
func (sm *SecurityMonitor) metricsRoutine() {
	for {
		select {
		case <-sm.metricsTimer.C:
			if sm.config.EnablePerformanceStats {
				sm.updateSystemMetrics()
			}
		case <-sm.stop:
			return
		}
	}
}

// updateSystemMetrics updates system performance metrics
func (sm *SecurityMonitor) updateSystemMetrics() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	sm.mu.Lock()
	sm.metrics.MemoryUsage = float64(m.Alloc) / 1024 / 1024 // MB
	sm.metrics.Goroutines = runtime.NumGoroutine()
	sm.mu.Unlock()
}

// cleanupRoutine periodically cleans up old events and alerts
func (sm *SecurityMonitor) cleanupRoutine() {
	for {
		select {
		case <-sm.cleanupTimer.C:
			sm.cleanupOldData()
		case <-sm.stop:
			return
		}
	}
}

// cleanupOldData removes old events and alerts
func (sm *SecurityMonitor) cleanupOldData() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	cutoff := time.Now().Add(-sm.config.RetentionPeriod)

	// Clean up events
	validEvents := make([]SecurityEvent, 0)
	for _, event := range sm.events {
		if event.Timestamp.After(cutoff) {
			validEvents = append(validEvents, event)
		}
	}
	sm.events = validEvents

	// Clean up alerts
	validAlerts := make([]SecurityAlert, 0)
	for _, alert := range sm.alerts {
		if alert.Timestamp.After(cutoff) {
			validAlerts = append(validAlerts, alert)
		}
	}
	sm.alerts = validAlerts
}

// alertRoutine processes alerts
func (sm *SecurityMonitor) alertRoutine() {
	for {
		select {
		case alert := <-sm.notificationCh:
			sm.processAlert(alert)
		case <-sm.stop:
			return
		}
	}
}

// processAlert processes and sends alerts
func (sm *SecurityMonitor) processAlert(alert SecurityAlert) {
	sm.mu.Lock()
	sm.alerts = append(sm.alerts, alert)
	sm.mu.Unlock()

	// Send to all alert handlers
	for _, handler := range sm.alertHandlers {
		go func(h AlertHandler) {
			if err := h.HandleAlert(alert); err != nil && sm.logger != nil {
				sm.logger.Error("ALERT_HANDLER_ERROR",
					"handler", fmt.Sprintf("%T", h),
					"alert_id", alert.ID,
					"error", err.Error(),
				)
			}
		}(handler)
	}

	// Log alert
	if sm.logger != nil {
		sm.logger.Error("SECURITY_ALERT",
			"alert_id", alert.ID,
			"alert_type", alert.AlertType,
			"severity", alert.Severity,
			"title", alert.Title,
			"description", alert.Description,
			"event_count", alert.EventCount,
			"affected_ips", alert.AffectedIPs,
			"timestamp", alert.Timestamp.UTC(),
		)
	}
}

// GetMetrics returns current security metrics
func (sm *SecurityMonitor) GetMetrics() SecurityMetrics {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// Create a copy with current values
	metrics := sm.metrics
	metrics.WindowStart = time.Now().Add(-sm.config.MetricsInterval)
	metrics.WindowEnd = time.Now()

	return metrics
}

// GetRecentEvents returns recent security events
func (sm *SecurityMonitor) GetRecentEvents(limit int) []SecurityEvent {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if limit <= 0 || limit > len(sm.events) {
		limit = len(sm.events)
	}

	// Return most recent events
	start := len(sm.events) - limit
	if start < 0 {
		start = 0
	}

	return sm.events[start:]
}

// GetRecentAlerts returns recent security alerts
func (sm *SecurityMonitor) GetRecentAlerts(limit int) []SecurityAlert {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if limit <= 0 || limit > len(sm.alerts) {
		limit = len(sm.alerts)
	}

	// Return most recent alerts
	start := len(sm.alerts) - limit
	if start < 0 {
		start = 0
	}

	return sm.alerts[start:]
}

// Stop stops the security monitor
func (sm *SecurityMonitor) Stop() {
	close(sm.stop)
	sm.metricsTimer.Stop()
	sm.cleanupTimer.Stop()
}

// Alert handler implementations

// HandleAlert implements AlertHandler for WebhookAlertHandler
func (wah *WebhookAlertHandler) HandleAlert(alert SecurityAlert) error {
	payload, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("failed to marshal alert: %w", err)
	}

	resp, err := wah.client.Post(wah.URL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// HandleAlert implements AlertHandler for SlackAlertHandler
func (sah *SlackAlertHandler) HandleAlert(alert SecurityAlert) error {
	color := "warning"
	switch alert.Severity {
	case "low":
		color = "good"
	case "medium":
		color = "warning"
	case "high", "critical":
		color = "danger"
	}

	payload := map[string]interface{}{
		"text": fmt.Sprintf("🚨 Security Alert: %s", alert.Title),
		"attachments": []map[string]interface{}{
			{
				"color":       color,
				"title":       alert.Title,
				"text":        alert.Description,
				"fields": []map[string]interface{}{
					{"title": "Severity", "value": alert.Severity, "short": true},
					{"title": "Event Count", "value": alert.EventCount, "short": true},
					{"title": "Time Window", "value": alert.TimeWindow, "short": true},
					{"title": "Affected IPs", "value": strings.Join(alert.AffectedIPs, ", "), "short": true},
				},
				"timestamp": alert.Timestamp.Unix(),
			},
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal Slack payload: %w", err)
	}

	resp, err := sah.client.Post(sah.WebhookURL, "application/json", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to send Slack alert: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("Slack webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// HandleAlert implements AlertHandler for EmailAlertHandler
func (eah *EmailAlertHandler) HandleAlert(alert SecurityAlert) error {
	// Email implementation would go here
	// For now, just return nil as email sending requires additional dependencies
	return nil
}

// SecurityMonitoringMiddleware creates middleware for security monitoring
func SecurityMonitoringMiddleware(monitor *SecurityMonitor) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			clientIP := getClientIP(r)

			// Wrap response writer to capture status
			wrapped := &monitoringResponseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			next.ServeHTTP(wrapped, r)

			duration := time.Since(start)

			// Log request event
			event := SecurityEvent{
				Timestamp:  start,
				EventType:  "http_request",
				Severity:   "low",
				Source:     "http_middleware",
				ClientIP:   clientIP,
				UserAgent:  r.UserAgent(),
				URL:        r.URL.String(),
				Method:     r.Method,
				StatusCode: wrapped.statusCode,
				Message:    fmt.Sprintf("%s %s - %d", r.Method, r.URL.Path, wrapped.statusCode),
				Details: map[string]interface{}{
					"response_time_ms": duration.Milliseconds(),
					"content_length":   r.ContentLength,
					"referer":          r.Header.Get("Referer"),
				},
			}

			// Adjust severity based on status code
			if wrapped.statusCode >= 400 && wrapped.statusCode < 500 {
				event.Severity = "medium"
				event.EventType = "client_error"
			} else if wrapped.statusCode >= 500 {
				event.Severity = "high"
				event.EventType = "server_error"
			}

			monitor.LogSecurityEvent(event)
		})
	}
}

// monitoringResponseWriter wraps http.ResponseWriter to capture status code
type monitoringResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (mrw *monitoringResponseWriter) WriteHeader(code int) {
	mrw.statusCode = code
	mrw.ResponseWriter.WriteHeader(code)
}

// DefaultSecurityMonitorConfig returns default security monitoring configuration
func DefaultSecurityMonitorConfig() SecurityMonitorConfig {
	return SecurityMonitorConfig{
		Enabled:                true,
		RealTimeAlerts:         true,
		MetricsInterval:        time.Minute,
		RetentionPeriod:        24 * time.Hour,
		MaxEventsInMemory:      10000,
		EnablePerformanceStats: true,
		EnableGeoTracking:      true,
		EnableUserTracking:     true,
		AlertThresholds: AlertThresholds{
			FailedLoginsPerMinute:    10,
			SQLInjectionPerHour:      5,
			XSSAttemptsPerHour:       5,
			BruteForceAttemptsPerMin: 20,
			DDoSRequestsPerSecond:    100,
			SuspiciousIPsPerHour:     50,
			HighSeverityEventsPerMin: 5,
			CriticalEventsPerMin:     1,
			UnauthorizedAccessPerMin: 10,
			AnomalousTrafficPerMin:   50,
		},
		EmailAlerts: EmailConfig{
			Enabled: false,
		},
	}
}