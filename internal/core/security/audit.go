package security

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"Gawan/internal/core/logx"
)

// AuditEventType represents the type of audit event
type AuditEventType string

const (
	// LOGIN_FAIL represents failed login attempts
	AuditEventLoginFail AuditEventType = "LOGIN_FAIL"
	// RATE_LIMIT_HIT represents rate limit violations
	AuditEventRateLimitHit AuditEventType = "RATE_LIMIT_HIT"
	// BRUTE_FORCE_DETECTED represents brute force attack detection
	AuditEventBruteForceDetected AuditEventType = "BRUTE_FORCE_DETECTED"
	// LOGIN_SUCCESS represents successful login
	AuditEventLoginSuccess AuditEventType = "LOGIN_SUCCESS"
	// SECURITY_VIOLATION represents general security violations
	AuditEventSecurityViolation AuditEventType = "SECURITY_VIOLATION"
	// PAYLOAD_SIZE_EXCEEDED represents payload size limit violations
	AuditEventPayloadSizeExceeded AuditEventType = "PAYLOAD_SIZE_EXCEEDED"
	// CORS_VIOLATION represents CORS policy violations
	AuditEventCORSViolation AuditEventType = "CORS_VIOLATION"
	// TIMEOUT_EXCEEDED represents connection timeout violations
	AuditEventTimeoutExceeded AuditEventType = "TIMEOUT_EXCEEDED"
)

// AuditEvent represents a security audit event
type AuditEvent struct {
	// Event type
	EventType AuditEventType `json:"event_type"`
	// Timestamp of the event
	Timestamp time.Time `json:"timestamp"`
	// Client IP address
	ClientIP string `json:"client_ip"`
	// User agent
	UserAgent string `json:"user_agent"`
	// Request method
	Method string `json:"method"`
	// Request path
	Path string `json:"path"`
	// User ID (if available)
	UserID string `json:"user_id,omitempty"`
	// Username (if available)
	Username string `json:"username,omitempty"`
	// Session ID (if available)
	SessionID string `json:"session_id,omitempty"`
	// Additional event-specific data
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	// Severity level
	Severity AuditSeverity `json:"severity"`
	// Description of the event
	Description string `json:"description"`
	// Response status code
	StatusCode int `json:"status_code,omitempty"`
}

// AuditSeverity represents the severity level of an audit event
type AuditSeverity string

const (
	AuditSeverityLow      AuditSeverity = "LOW"
	AuditSeverityMedium   AuditSeverity = "MEDIUM"
	AuditSeverityHigh     AuditSeverity = "HIGH"
	AuditSeverityCritical AuditSeverity = "CRITICAL"
)

// AuditLogger handles security audit logging
type AuditLogger struct {
	logger   *logx.Logger
	enabled  bool
	filters  []AuditFilter
	handlers []AuditHandler
}

// AuditFilter determines if an event should be logged
type AuditFilter func(event *AuditEvent) bool

// AuditHandler processes audit events
type AuditHandler func(event *AuditEvent, logger *logx.Logger)

// AuditConfig holds audit logging configuration
type AuditConfig struct {
	// Enabled enables audit logging
	Enabled bool `json:"enabled" yaml:"enabled" env:"AUDIT_ENABLED" default:"true"`
	// LogLevel sets the minimum log level for audit events
	LogLevel string `json:"log_level" yaml:"log_level" env:"AUDIT_LOG_LEVEL" default:"info"`
	// IncludeUserAgent includes user agent in audit logs
	IncludeUserAgent bool `json:"include_user_agent" yaml:"include_user_agent" env:"AUDIT_INCLUDE_USER_AGENT" default:"true"`
	// IncludeHeaders includes request headers in audit logs
	IncludeHeaders bool `json:"include_headers" yaml:"include_headers" env:"AUDIT_INCLUDE_HEADERS" default:"false"`
	// MaxMetadataSize limits the size of metadata in bytes
	MaxMetadataSize int `json:"max_metadata_size" yaml:"max_metadata_size" env:"AUDIT_MAX_METADATA_SIZE" default:"1024"`
	// AsyncLogging enables asynchronous logging
	AsyncLogging bool `json:"async_logging" yaml:"async_logging" env:"AUDIT_ASYNC_LOGGING" default:"true"`
	// BufferSize for async logging
	BufferSize int `json:"buffer_size" yaml:"buffer_size" env:"AUDIT_BUFFER_SIZE" default:"1000"`
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(logger *logx.Logger, config AuditConfig) *AuditLogger {
	auditLogger := &AuditLogger{
		logger:   logger,
		enabled:  config.Enabled,
		filters:  make([]AuditFilter, 0),
		handlers: make([]AuditHandler, 0),
	}
	
	// Add default handler
	auditLogger.AddHandler(DefaultAuditHandler)
	
	return auditLogger
}

// AddFilter adds an audit filter
func (al *AuditLogger) AddFilter(filter AuditFilter) {
	al.filters = append(al.filters, filter)
}

// AddHandler adds an audit handler
func (al *AuditLogger) AddHandler(handler AuditHandler) {
	al.handlers = append(al.handlers, handler)
}

// LogEvent logs an audit event
func (al *AuditLogger) LogEvent(event *AuditEvent) {
	if !al.enabled || al.logger == nil {
		return
	}
	
	// Apply filters
	for _, filter := range al.filters {
		if !filter(event) {
			return // Event filtered out
		}
	}
	
	// Process with handlers
	for _, handler := range al.handlers {
		handler(event, al.logger)
	}
}

// LogLoginFail logs a failed login attempt
func (al *AuditLogger) LogLoginFail(r *http.Request, username string, reason string, metadata map[string]interface{}) {
	event := &AuditEvent{
		EventType:   AuditEventLoginFail,
		Timestamp:   time.Now().UTC(),
		ClientIP:    GetClientIP(r),
		UserAgent:   r.UserAgent(),
		Method:      r.Method,
		Path:        r.URL.Path,
		Username:    username,
		Severity:    AuditSeverityMedium,
		Description: fmt.Sprintf("Login failed for user '%s': %s", username, reason),
		StatusCode:  http.StatusUnauthorized,
		Metadata:    metadata,
	}
	
	if sessionID := GetSessionID(r); sessionID != "" {
		event.SessionID = sessionID
	}
	
	al.LogEvent(event)
}

// LogRateLimitHit logs a rate limit violation
func (al *AuditLogger) LogRateLimitHit(r *http.Request, limitType string, metadata map[string]interface{}) {
	event := &AuditEvent{
		EventType:   AuditEventRateLimitHit,
		Timestamp:   time.Now().UTC(),
		ClientIP:    GetClientIP(r),
		UserAgent:   r.UserAgent(),
		Method:      r.Method,
		Path:        r.URL.Path,
		Severity:    AuditSeverityHigh,
		Description: fmt.Sprintf("Rate limit exceeded: %s", limitType),
		StatusCode:  http.StatusTooManyRequests,
		Metadata:    metadata,
	}
	
	if sessionID := GetSessionID(r); sessionID != "" {
		event.SessionID = sessionID
	}
	
	al.LogEvent(event)
}

// LogBruteForceDetected logs brute force attack detection
func (al *AuditLogger) LogBruteForceDetected(r *http.Request, attemptCount int, lockoutUntil time.Time, metadata map[string]interface{}) {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	metadata["attempt_count"] = attemptCount
	metadata["lockout_until"] = lockoutUntil.UTC()
	
	event := &AuditEvent{
		EventType:   AuditEventBruteForceDetected,
		Timestamp:   time.Now().UTC(),
		ClientIP:    GetClientIP(r),
		UserAgent:   r.UserAgent(),
		Method:      r.Method,
		Path:        r.URL.Path,
		Severity:    AuditSeverityCritical,
		Description: fmt.Sprintf("Brute force attack detected: %d failed attempts, locked until %s", attemptCount, lockoutUntil.Format(time.RFC3339)),
		StatusCode:  http.StatusTooManyRequests,
		Metadata:    metadata,
	}
	
	al.LogEvent(event)
}

// LogSecurityViolation logs a general security violation
func (al *AuditLogger) LogSecurityViolation(r *http.Request, violationType string, description string, severity AuditSeverity, metadata map[string]interface{}) {
	event := &AuditEvent{
		EventType:   AuditEventSecurityViolation,
		Timestamp:   time.Now().UTC(),
		ClientIP:    GetClientIP(r),
		UserAgent:   r.UserAgent(),
		Method:      r.Method,
		Path:        r.URL.Path,
		Severity:    severity,
		Description: fmt.Sprintf("%s: %s", violationType, description),
		Metadata:    metadata,
	}
	
	al.LogEvent(event)
}

// DefaultAuditHandler is the default audit event handler
func DefaultAuditHandler(event *AuditEvent, logger *logx.Logger) {
	if logger == nil {
		return
	}
	
	// Convert event to structured log fields
	fields := []interface{}{
		"event_type", event.EventType,
		"timestamp", event.Timestamp,
		"client_ip", event.ClientIP,
		"method", event.Method,
		"path", event.Path,
		"severity", event.Severity,
		"description", event.Description,
	}
	
	if event.UserAgent != "" {
		fields = append(fields, "user_agent", event.UserAgent)
	}
	if event.UserID != "" {
		fields = append(fields, "user_id", event.UserID)
	}
	if event.Username != "" {
		fields = append(fields, "username", event.Username)
	}
	if event.SessionID != "" {
		fields = append(fields, "session_id", event.SessionID)
	}
	if event.StatusCode > 0 {
		fields = append(fields, "status_code", event.StatusCode)
	}
	
	// Add metadata
	if event.Metadata != nil {
		for key, value := range event.Metadata {
			fields = append(fields, "meta_"+key, value)
		}
	}
	
	// Log based on severity
	switch event.Severity {
	case AuditSeverityLow:
		logger.Info("AUDIT", fields...)
	case AuditSeverityMedium:
		logger.Warn("AUDIT", fields...)
	case AuditSeverityHigh:
		logger.Error("AUDIT", fields...)
	case AuditSeverityCritical:
		logger.Error("AUDIT_CRITICAL", fields...)
	default:
		logger.Info("AUDIT", fields...)
	}
}

// GetClientIP extracts the client IP from the request
func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	
	// Check X-Forwarded header
	if xf := r.Header.Get("X-Forwarded"); xf != "" {
		return strings.TrimSpace(xf)
	}
	
	// Fall back to RemoteAddr
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}
	return r.RemoteAddr
}

// GetSessionID extracts session ID from request (customize based on your session implementation)
func GetSessionID(r *http.Request) string {
	// Try to get from cookie
	if cookie, err := r.Cookie("session_id"); err == nil {
		return cookie.Value
	}
	
	// Try to get from Authorization header
	if auth := r.Header.Get("Authorization"); auth != "" {
		// This is a simplified example - customize based on your auth implementation
		if len(auth) > 20 {
			return auth[:20] // Return first 20 chars as session identifier
		}
	}
	
	return ""
}

// SeverityFilter creates a filter that only allows events of certain severity levels
func SeverityFilter(minSeverity AuditSeverity) AuditFilter {
	severityLevels := map[AuditSeverity]int{
		AuditSeverityLow:      1,
		AuditSeverityMedium:   2,
		AuditSeverityHigh:     3,
		AuditSeverityCritical: 4,
	}
	
	minLevel := severityLevels[minSeverity]
	
	return func(event *AuditEvent) bool {
		return severityLevels[event.Severity] >= minLevel
	}
}

// EventTypeFilter creates a filter that only allows specific event types
func EventTypeFilter(allowedTypes ...AuditEventType) AuditFilter {
	allowed := make(map[AuditEventType]bool)
	for _, eventType := range allowedTypes {
		allowed[eventType] = true
	}
	
	return func(event *AuditEvent) bool {
		return allowed[event.EventType]
	}
}

// JSONAuditHandler logs audit events as JSON
func JSONAuditHandler(event *AuditEvent, logger *logx.Logger) {
	if logger == nil {
		return
	}
	
	jsonData, err := json.Marshal(event)
	if err != nil {
		logger.Error("Failed to marshal audit event", "error", err)
		return
	}
	
	logger.Info("AUDIT_JSON", "data", string(jsonData))
}

// DefaultAuditConfig returns default audit configuration
func DefaultAuditConfig() AuditConfig {
	return AuditConfig{
		Enabled:          true,
		LogLevel:         "info",
		IncludeUserAgent: true,
		IncludeHeaders:   false,
		MaxMetadataSize:  1024,
		AsyncLogging:     true,
		BufferSize:       1000,
	}
}