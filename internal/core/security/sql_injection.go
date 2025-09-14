package security

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"Gawan/internal/core/logx"
)

// SQLInjectionConfig configuration for SQL injection protection
type SQLInjectionConfig struct {
	Enabled                bool     `json:"enabled"`
	StrictMode             bool     `json:"strict_mode"`             // Reject any suspicious patterns
	LogSuspiciousQueries   bool     `json:"log_suspicious_queries"`
	BlockSuspiciousQueries bool     `json:"block_suspicious_queries"`
	MaxQueryLength         int      `json:"max_query_length"`
	AllowedTables          []string `json:"allowed_tables"`          // Whitelist of allowed table names
	AllowedColumns         []string `json:"allowed_columns"`         // Whitelist of allowed column names
	BlockedPatterns        []string `json:"blocked_patterns"`        // Custom blocked patterns
	SensitiveFields        []string `json:"sensitive_fields"`        // Fields that require extra validation
	RateLimitEnabled       bool     `json:"rate_limit_enabled"`      // Rate limit suspicious queries
	RateLimitWindow        int      `json:"rate_limit_window"`       // Window in seconds
	RateLimitMaxQueries    int      `json:"rate_limit_max_queries"`  // Max queries per window
}

// SQLInjectionDetector detects and prevents SQL injection attacks
type SQLInjectionDetector struct {
	config          SQLInjectionConfig
	sqlPatterns     []*regexp.Regexp
	dangerousWords  []string
	queryTracker    map[string]*QueryTracker
	mu              sync.RWMutex
	logger          *logx.Logger
	cleanup         *time.Ticker
	stop            chan struct{}
}

// QueryTracker tracks queries from specific IPs
type QueryTracker struct {
	Queries     []time.Time `json:"queries"`
	Suspicious  int         `json:"suspicious"`
	Blocked     int         `json:"blocked"`
	LastQuery   time.Time   `json:"last_query"`
	LastPattern string      `json:"last_pattern"`
}

// SQLValidationResult represents validation result
type SQLValidationResult struct {
	Valid           bool     `json:"valid"`
	Reason          string   `json:"reason,omitempty"`
	SuspiciousLevel int      `json:"suspicious_level"` // 0-100
	DetectedPattern string   `json:"detected_pattern,omitempty"`
	Suggestion      string   `json:"suggestion,omitempty"`
	BlockedWords    []string `json:"blocked_words,omitempty"`
}

// PreparedStatementManager manages prepared statements safely
type PreparedStatementManager struct {
	db         *sql.DB
	statements map[string]*sql.Stmt
	mu         sync.RWMutex
	logger     *logx.Logger
}

// NewSQLInjectionDetector creates a new SQL injection detector
func NewSQLInjectionDetector(config SQLInjectionConfig, logger *logx.Logger) *SQLInjectionDetector {
	// Set defaults
	if config.MaxQueryLength <= 0 {
		config.MaxQueryLength = 10000
	}
	if config.RateLimitWindow <= 0 {
		config.RateLimitWindow = 60
	}
	if config.RateLimitMaxQueries <= 0 {
		config.RateLimitMaxQueries = 100
	}

	detector := &SQLInjectionDetector{
		config:       config,
		queryTracker: make(map[string]*QueryTracker),
		logger:       logger,
		cleanup:      time.NewTicker(5 * time.Minute),
		stop:         make(chan struct{}),
	}

	// Initialize SQL injection patterns
	detector.initializePatterns()

	// Start cleanup routine
	go detector.cleanupRoutine()

	return detector
}

// initializePatterns initializes SQL injection detection patterns
func (sid *SQLInjectionDetector) initializePatterns() {
	// Common SQL injection patterns
	patterns := []string{
		// Union-based attacks
		`(?i)\bunion\s+(all\s+)?select\b`,
		`(?i)\bunion\s+.*\bselect\b`,
		
		// Boolean-based blind attacks
		`(?i)\b(and|or)\s+\d+\s*=\s*\d+`,
		`(?i)\b(and|or)\s+['"]\w+['"]\s*=\s*['"]\w+['"]`,
		`(?i)\b(and|or)\s+\d+\s*(>|<|>=|<=)\s*\d+`,
		
		// Time-based blind attacks
		`(?i)\bwaitfor\s+delay\b`,
		`(?i)\bsleep\s*\(`,
		`(?i)\bbenchmark\s*\(`,
		`(?i)\bpg_sleep\s*\(`,
		
		// Error-based attacks
		`(?i)\bconvert\s*\(`,
		`(?i)\bcast\s*\(`,
		`(?i)\bextractvalue\s*\(`,
		`(?i)\bupdatexml\s*\(`,
		
		// Stacked queries
		`(?i);\s*(drop|delete|insert|update|create|alter)\b`,
		`(?i);\s*exec\s*\(`,
		`(?i);\s*execute\s+`,
		
		// Information schema attacks
		`(?i)\binformation_schema\b`,
		`(?i)\bsys\.tables\b`,
		`(?i)\bsys\.columns\b`,
		`(?i)\bsysobjects\b`,
		`(?i)\bsyscolumns\b`,
		
		// Comment-based evasion
		`(?i)/\*.*\*/`,
		`(?i)--\s*`,
		`(?i)#.*$`,
		
		// Function-based attacks
		`(?i)\bload_file\s*\(`,
		`(?i)\binto\s+outfile\b`,
		`(?i)\binto\s+dumpfile\b`,
		`(?i)\buser\s*\(\s*\)`,
		`(?i)\bversion\s*\(\s*\)`,
		`(?i)\bdatabase\s*\(\s*\)`,
		
		// Hex encoding attacks
		`(?i)0x[0-9a-f]+`,
		`(?i)\bchar\s*\(`,
		`(?i)\bunhex\s*\(`,
		
		// Conditional attacks
		`(?i)\bif\s*\(.*,.*,.*\)`,
		`(?i)\bcase\s+when\b`,
		`(?i)\biif\s*\(`,
		
		// Subquery attacks
		`(?i)\bselect\s+.*\bfrom\s*\(\s*select\b`,
		`(?i)\bexists\s*\(\s*select\b`,
		
		// Custom blocked patterns from config
	}

	// Add custom patterns from config
	patterns = append(patterns, sid.config.BlockedPatterns...)

	// Compile patterns
	for _, pattern := range patterns {
		if compiled, err := regexp.Compile(pattern); err == nil {
			sid.sqlPatterns = append(sid.sqlPatterns, compiled)
		} else if sid.logger != nil {
			sid.logger.Error("PATTERN_COMPILE_ERROR",
				"pattern", pattern,
				"error", err.Error(),
			)
		}
	}

	// Dangerous SQL keywords
	sid.dangerousWords = []string{
		"drop", "delete", "truncate", "alter", "create", "insert", "update",
		"exec", "execute", "sp_", "xp_", "cmdshell", "openrowset", "opendatasource",
		"bulk", "shutdown", "grant", "revoke", "deny", "backup", "restore",
		"load_file", "into outfile", "into dumpfile", "script", "javascript",
		"vbscript", "onload", "onerror", "eval", "expression", "applet",
		"object", "embed", "form", "iframe", "frameset", "meta", "link",
	}
}

// ValidateInput validates input for SQL injection patterns
func (sid *SQLInjectionDetector) ValidateInput(input string, fieldName string, clientIP string) *SQLValidationResult {
	if !sid.config.Enabled {
		return &SQLValidationResult{Valid: true}
	}

	result := &SQLValidationResult{
		Valid:           true,
		SuspiciousLevel: 0,
	}

	// Check input length
	if len(input) > sid.config.MaxQueryLength {
		result.Valid = false
		result.Reason = "Input too long"
		result.SuspiciousLevel = 90
		result.Suggestion = fmt.Sprintf("Input length %d exceeds maximum %d", len(input), sid.config.MaxQueryLength)
		return result
	}

	// Rate limiting check
	if sid.config.RateLimitEnabled {
		if !sid.checkRateLimit(clientIP) {
			result.Valid = false
			result.Reason = "Rate limit exceeded"
			result.SuspiciousLevel = 80
			return result
		}
	}

	// Check against SQL injection patterns
	for _, pattern := range sid.sqlPatterns {
		if pattern.MatchString(input) {
			result.SuspiciousLevel += 30
			result.DetectedPattern = pattern.String()
			
			if sid.config.StrictMode || sid.config.BlockSuspiciousQueries {
				result.Valid = false
				result.Reason = "SQL injection pattern detected"
			}
			break
		}
	}

	// Check for dangerous words
	lowerInput := strings.ToLower(input)
	for _, word := range sid.dangerousWords {
		if strings.Contains(lowerInput, strings.ToLower(word)) {
			result.SuspiciousLevel += 20
			result.BlockedWords = append(result.BlockedWords, word)
			
			if sid.config.StrictMode {
				result.Valid = false
				result.Reason = fmt.Sprintf("Dangerous keyword detected: %s", word)
			}
		}
	}

	// Extra validation for sensitive fields
	for _, sensitiveField := range sid.config.SensitiveFields {
		if strings.EqualFold(fieldName, sensitiveField) {
			result.SuspiciousLevel += 10
			// Apply stricter validation for sensitive fields
			if result.SuspiciousLevel > 30 {
				result.Valid = false
				result.Reason = "Suspicious input in sensitive field"
			}
			break
		}
	}

	// Check for encoding attacks
	if sid.detectEncodingAttacks(input) {
		result.SuspiciousLevel += 25
		if sid.config.StrictMode {
			result.Valid = false
			result.Reason = "Encoding-based attack detected"
		}
	}

	// Final decision
	if result.SuspiciousLevel >= 70 && sid.config.BlockSuspiciousQueries {
		result.Valid = false
		if result.Reason == "" {
			result.Reason = "High suspicious score"
		}
	}

	// Log suspicious activity
	if result.SuspiciousLevel > 30 && sid.config.LogSuspiciousQueries && sid.logger != nil {
		sid.logSuspiciousActivity(input, fieldName, clientIP, result)
	}

	// Track query
	sid.trackQuery(clientIP, result.SuspiciousLevel > 50, !result.Valid)

	return result
}

// detectEncodingAttacks detects various encoding-based attacks
func (sid *SQLInjectionDetector) detectEncodingAttacks(input string) bool {
	// URL encoding attacks
	if strings.Contains(input, "%27") || strings.Contains(input, "%22") || // ' and "
	   strings.Contains(input, "%3B") || strings.Contains(input, "%2D") || // ; and -
	   strings.Contains(input, "%2F") || strings.Contains(input, "%2A") {   // / and *
		return true
	}

	// HTML entity encoding
	if strings.Contains(input, "&#") || strings.Contains(input, "&lt;") || strings.Contains(input, "&gt;") {
		return true
	}

	// Unicode encoding
	if strings.Contains(input, "\\u") || strings.Contains(input, "\\x") {
		return true
	}

	// Base64 patterns (potential)
	if matched, _ := regexp.MatchString(`[A-Za-z0-9+/]{20,}={0,2}`, input); matched {
		return true
	}

	return false
}

// checkRateLimit checks if the client IP is within rate limits
func (sid *SQLInjectionDetector) checkRateLimit(clientIP string) bool {
	sid.mu.Lock()
	defer sid.mu.Unlock()

	tracker, exists := sid.queryTracker[clientIP]
	if !exists {
		tracker = &QueryTracker{
			Queries: make([]time.Time, 0),
		}
		sid.queryTracker[clientIP] = tracker
	}

	now := time.Now()
	windowStart := now.Add(-time.Duration(sid.config.RateLimitWindow) * time.Second)

	// Clean old queries
	validQueries := make([]time.Time, 0)
	for _, queryTime := range tracker.Queries {
		if queryTime.After(windowStart) {
			validQueries = append(validQueries, queryTime)
		}
	}
	tracker.Queries = validQueries

	// Check limit
	if len(tracker.Queries) >= sid.config.RateLimitMaxQueries {
		return false
	}

	// Add current query
	tracker.Queries = append(tracker.Queries, now)
	tracker.LastQuery = now

	return true
}

// trackQuery tracks query statistics
func (sid *SQLInjectionDetector) trackQuery(clientIP string, suspicious, blocked bool) {
	sid.mu.Lock()
	defer sid.mu.Unlock()

	tracker, exists := sid.queryTracker[clientIP]
	if !exists {
		tracker = &QueryTracker{}
		sid.queryTracker[clientIP] = tracker
	}

	if suspicious {
		tracker.Suspicious++
	}
	if blocked {
		tracker.Blocked++
	}
	tracker.LastQuery = time.Now()
}

// logSuspiciousActivity logs suspicious SQL injection attempts
func (sid *SQLInjectionDetector) logSuspiciousActivity(input, fieldName, clientIP string, result *SQLValidationResult) {
	sid.logger.Warn("SQL_INJECTION_ATTEMPT",
		"event", "SQL_INJECTION_ATTEMPT",
		"client_ip", clientIP,
		"field_name", fieldName,
		"input_length", len(input),
		"input_preview", truncateString(input, 100),
		"suspicious_level", result.SuspiciousLevel,
		"detected_pattern", result.DetectedPattern,
		"blocked_words", result.BlockedWords,
		"blocked", !result.Valid,
		"timestamp", time.Now().UTC(),
	)
}

// cleanupRoutine cleans up old tracking data
func (sid *SQLInjectionDetector) cleanupRoutine() {
	for {
		select {
		case <-sid.cleanup.C:
			sid.cleanupOldTrackers()
		case <-sid.stop:
			return
		}
	}
}

// cleanupOldTrackers removes old query trackers
func (sid *SQLInjectionDetector) cleanupOldTrackers() {
	sid.mu.Lock()
	defer sid.mu.Unlock()

	cutoff := time.Now().Add(-time.Hour)
	for ip, tracker := range sid.queryTracker {
		if tracker.LastQuery.Before(cutoff) {
			delete(sid.queryTracker, ip)
		}
	}
}

// Stop stops the SQL injection detector
func (sid *SQLInjectionDetector) Stop() {
	close(sid.stop)
	sid.cleanup.Stop()
}

// GetStats returns SQL injection protection statistics
func (sid *SQLInjectionDetector) GetStats() map[string]interface{} {
	sid.mu.RLock()
	defer sid.mu.RUnlock()

	totalSuspicious := 0
	totalBlocked := 0
	activeIPs := len(sid.queryTracker)

	for _, tracker := range sid.queryTracker {
		totalSuspicious += tracker.Suspicious
		totalBlocked += tracker.Blocked
	}

	return map[string]interface{}{
		"active_ips":       activeIPs,
		"total_suspicious": totalSuspicious,
		"total_blocked":    totalBlocked,
		"patterns_loaded":  len(sid.sqlPatterns),
		"config":           sid.config,
	}
}

// NewPreparedStatementManager creates a new prepared statement manager
func NewPreparedStatementManager(db *sql.DB, logger *logx.Logger) *PreparedStatementManager {
	return &PreparedStatementManager{
		db:         db,
		statements: make(map[string]*sql.Stmt),
		logger:     logger,
	}
}

// PrepareStatement prepares and caches a SQL statement
func (psm *PreparedStatementManager) PrepareStatement(name, query string) error {
	psm.mu.Lock()
	defer psm.mu.Unlock()

	// Check if already prepared
	if _, exists := psm.statements[name]; exists {
		return nil
	}

	stmt, err := psm.db.Prepare(query)
	if err != nil {
		if psm.logger != nil {
			psm.logger.Error("PREPARE_STATEMENT_ERROR",
				"name", name,
				"query", query,
				"error", err.Error(),
			)
		}
		return fmt.Errorf("failed to prepare statement %s: %w", name, err)
	}

	psm.statements[name] = stmt
	return nil
}

// ExecuteQuery executes a prepared statement with parameters
func (psm *PreparedStatementManager) ExecuteQuery(ctx context.Context, name string, args ...interface{}) (*sql.Rows, error) {
	psm.mu.RLock()
	stmt, exists := psm.statements[name]
	psm.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("prepared statement %s not found", name)
	}

	return stmt.QueryContext(ctx, args...)
}

// ExecuteNonQuery executes a prepared statement that doesn't return rows
func (psm *PreparedStatementManager) ExecuteNonQuery(ctx context.Context, name string, args ...interface{}) (sql.Result, error) {
	psm.mu.RLock()
	stmt, exists := psm.statements[name]
	psm.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("prepared statement %s not found", name)
	}

	return stmt.ExecContext(ctx, args...)
}

// Close closes all prepared statements
func (psm *PreparedStatementManager) Close() error {
	psm.mu.Lock()
	defer psm.mu.Unlock()

	for name, stmt := range psm.statements {
		if err := stmt.Close(); err != nil && psm.logger != nil {
			psm.logger.Error("CLOSE_STATEMENT_ERROR",
				"name", name,
				"error", err.Error(),
			)
		}
	}

	psm.statements = make(map[string]*sql.Stmt)
	return nil
}

// SQLInjectionMiddleware creates middleware for SQL injection protection
func SQLInjectionMiddleware(detector *SQLInjectionDetector) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !detector.config.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			clientIP := getClientIP(r)

			// Validate query parameters
			for key, values := range r.URL.Query() {
				for _, value := range values {
					result := detector.ValidateInput(value, key, clientIP)
					if !result.Valid {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusBadRequest)
						json.NewEncoder(w).Encode(map[string]interface{}{
							"error":   "Invalid input detected",
							"reason":  result.Reason,
							"field":   key,
							"blocked": true,
						})
						return
					}
				}
			}

			// Validate form data
			if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
				if err := r.ParseForm(); err == nil {
					for key, values := range r.PostForm {
						for _, value := range values {
							result := detector.ValidateInput(value, key, clientIP)
							if !result.Valid {
								w.Header().Set("Content-Type", "application/json")
								w.WriteHeader(http.StatusBadRequest)
								json.NewEncoder(w).Encode(map[string]interface{}{
									"error":   "Invalid input detected",
									"reason":  result.Reason,
									"field":   key,
									"blocked": true,
								})
								return
							}
						}
					}
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// InputSanitizer provides input sanitization functions
type InputSanitizer struct {
	allowedTables  map[string]bool
	allowedColumns map[string]bool
}

// NewInputSanitizer creates a new input sanitizer
func NewInputSanitizer(allowedTables, allowedColumns []string) *InputSanitizer {
	tables := make(map[string]bool)
	for _, table := range allowedTables {
		tables[strings.ToLower(table)] = true
	}

	columns := make(map[string]bool)
	for _, column := range allowedColumns {
		columns[strings.ToLower(column)] = true
	}

	return &InputSanitizer{
		allowedTables:  tables,
		allowedColumns: columns,
	}
}

// SanitizeTableName validates and sanitizes table names
func (is *InputSanitizer) SanitizeTableName(tableName string) (string, error) {
	// Remove dangerous characters
	sanitized := regexp.MustCompile(`[^a-zA-Z0-9_]`).ReplaceAllString(tableName, "")
	
	// Check against whitelist
	if len(is.allowedTables) > 0 {
		if !is.allowedTables[strings.ToLower(sanitized)] {
			return "", fmt.Errorf("table name not allowed: %s", tableName)
		}
	}

	return sanitized, nil
}

// SanitizeColumnName validates and sanitizes column names
func (is *InputSanitizer) SanitizeColumnName(columnName string) (string, error) {
	// Remove dangerous characters
	sanitized := regexp.MustCompile(`[^a-zA-Z0-9_]`).ReplaceAllString(columnName, "")
	
	// Check against whitelist
	if len(is.allowedColumns) > 0 {
		if !is.allowedColumns[strings.ToLower(sanitized)] {
			return "", fmt.Errorf("column name not allowed: %s", columnName)
		}
	}

	return sanitized, nil
}

// SanitizeStringValue sanitizes string values for SQL
func (is *InputSanitizer) SanitizeStringValue(value string) string {
	// Escape single quotes
	value = strings.ReplaceAll(value, "'", "''")
	// Remove null bytes
	value = strings.ReplaceAll(value, "\x00", "")
	// Remove other control characters
	value = regexp.MustCompile(`[\x00-\x1f\x7f]`).ReplaceAllString(value, "")
	return value
}

// ValidateAndSanitizeInput validates and sanitizes input based on expected type
func (is *InputSanitizer) ValidateAndSanitizeInput(value interface{}, expectedType string) (interface{}, error) {
	switch expectedType {
	case "int", "integer":
		if str, ok := value.(string); ok {
			return strconv.Atoi(str)
		}
		return value, nil
	
	case "float", "decimal":
		if str, ok := value.(string); ok {
			return strconv.ParseFloat(str, 64)
		}
		return value, nil
	
	case "string", "varchar", "text":
		if str, ok := value.(string); ok {
			return is.SanitizeStringValue(str), nil
		}
		return fmt.Sprintf("%v", value), nil
	
	case "bool", "boolean":
		if str, ok := value.(string); ok {
			return strconv.ParseBool(str)
		}
		return value, nil
	
	default:
		return value, nil
	}
}

// DefaultSQLInjectionConfig returns default SQL injection protection configuration
func DefaultSQLInjectionConfig() SQLInjectionConfig {
	return SQLInjectionConfig{
		Enabled:                true,
		StrictMode:             false,
		LogSuspiciousQueries:   true,
		BlockSuspiciousQueries: true,
		MaxQueryLength:         10000,
		AllowedTables:          []string{}, // Empty means all allowed
		AllowedColumns:         []string{}, // Empty means all allowed
		BlockedPatterns:        []string{},
		SensitiveFields:        []string{"password", "token", "secret", "key"},
		RateLimitEnabled:       true,
		RateLimitWindow:        60,
		RateLimitMaxQueries:    100,
	}
}

// Helper functions
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	
	// Fall back to RemoteAddr
	parts := strings.Split(r.RemoteAddr, ":")
	if len(parts) > 0 {
		return parts[0]
	}
	
	return r.RemoteAddr
}