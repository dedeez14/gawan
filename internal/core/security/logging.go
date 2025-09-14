package security

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"Gawan/internal/core/logx"
)

// SecurityLoggerConfig configuration for security logging
type SecurityLoggerConfig struct {
	Enabled           bool          `json:"enabled"`
	LogLevel          string        `json:"log_level"`
	LogFormat         string        `json:"log_format"` // json, text
	OutputTargets     []string      `json:"output_targets"` // file, stdout, syslog, elasticsearch
	FileConfig        FileLogConfig `json:"file_config"`
	RotationConfig    LogRotationConfig `json:"rotation_config"`
	BufferSize        int           `json:"buffer_size"`
	FlushInterval     time.Duration `json:"flush_interval"`
	CompressionLevel  int           `json:"compression_level"`
	EncryptLogs       bool          `json:"encrypt_logs"`
	EncryptionKey     string        `json:"encryption_key"`
	SyslogConfig      SyslogConfig  `json:"syslog_config"`
	ElasticsearchConfig ESConfig    `json:"elasticsearch_config"`
	IncludeStackTrace bool          `json:"include_stack_trace"`
	MaskSensitiveData bool          `json:"mask_sensitive_data"`
	SamplingRate      float64       `json:"sampling_rate"` // 0.0 to 1.0
}

// FileLogConfig configuration for file logging
type FileLogConfig struct {
	Directory    string `json:"directory"`
	Filename     string `json:"filename"`
	MaxSize      int64  `json:"max_size"` // bytes
	MaxAge       int    `json:"max_age"`  // days
	MaxBackups   int    `json:"max_backups"`
	Compress     bool   `json:"compress"`
	Permissions  os.FileMode `json:"permissions"`
}

// LogRotationConfig configuration for log rotation
type LogRotationConfig struct {
	Enabled      bool          `json:"enabled"`
	RotateSize   int64         `json:"rotate_size"`   // bytes
	RotateTime   time.Duration `json:"rotate_time"`   // duration
	MaxFiles     int           `json:"max_files"`
	Compress     bool          `json:"compress"`
	DeleteOld    bool          `json:"delete_old"`
	ArchivePath  string        `json:"archive_path"`
}

// SyslogConfig configuration for syslog
type SyslogConfig struct {
	Enabled  bool   `json:"enabled"`
	Network  string `json:"network"`  // tcp, udp
	Address  string `json:"address"`  // host:port
	Tag      string `json:"tag"`
	Facility string `json:"facility"`
	Severity string `json:"severity"`
}

// ESConfig configuration for Elasticsearch
type ESConfig struct {
	Enabled   bool     `json:"enabled"`
	Addresses []string `json:"addresses"`
	Username  string   `json:"username"`
	Password  string   `json:"password"`
	Index     string   `json:"index"`
	Timeout   time.Duration `json:"timeout"`
	BulkSize  int      `json:"bulk_size"`
	FlushInterval time.Duration `json:"flush_interval"`
}

// SecurityLogEntry represents a security log entry
type SecurityLogEntry struct {
	Timestamp    time.Time              `json:"timestamp"`
	Level        string                 `json:"level"`
	Message      string                 `json:"message"`
	EventType    string                 `json:"event_type"`
	Severity     string                 `json:"severity"`
	Source       string                 `json:"source"`
	ClientIP     string                 `json:"client_ip,omitempty"`
	UserID       string                 `json:"user_id,omitempty"`
	SessionID    string                 `json:"session_id,omitempty"`
	RequestID    string                 `json:"request_id,omitempty"`
	UserAgent    string                 `json:"user_agent,omitempty"`
	URL          string                 `json:"url,omitempty"`
	Method       string                 `json:"method,omitempty"`
	StatusCode   int                    `json:"status_code,omitempty"`
	ResponseTime int64                  `json:"response_time_ms,omitempty"`
	Country      string                 `json:"country,omitempty"`
	ASN          string                 `json:"asn,omitempty"`
	ThreatScore  int                    `json:"threat_score,omitempty"`
	RuleID       string                 `json:"rule_id,omitempty"`
	Tags         []string               `json:"tags,omitempty"`
	Fields       map[string]interface{} `json:"fields,omitempty"`
	StackTrace   string                 `json:"stack_trace,omitempty"`
	CorrelationID string                `json:"correlation_id,omitempty"`
}

// SecurityLogger main security logging system
type SecurityLogger struct {
	config       SecurityLoggerConfig
	logger       *logx.Logger
	fileWriter   *os.File
	buffer       []SecurityLogEntry
	bufferMu     sync.RWMutex
	flushTimer   *time.Timer
	stop         chan struct{}
	wg           sync.WaitGroup
	rotationMu   sync.Mutex
	currentSize  int64
	lastRotation time.Time
	sampler      *LogSampler
	encryptor    *LogEncryptor
	masker       *DataMasker
}

// LogSampler handles log sampling
type LogSampler struct {
	rate    float64
	counter int64
	mu      sync.Mutex
}

// LogEncryptor handles log encryption
type LogEncryptor struct {
	key []byte
}

// DataMasker handles sensitive data masking
type DataMasker struct {
	patterns map[string]string
}

// LogWriter interface for different log outputs
type LogWriter interface {
	Write(entry SecurityLogEntry) error
	Flush() error
	Close() error
}

// FileLogWriter writes logs to files
type FileLogWriter struct {
	file   *os.File
	config FileLogConfig
	mu     sync.Mutex
}

// SyslogWriter writes logs to syslog
type SyslogWriter struct {
	config SyslogConfig
	writer io.Writer
}

// ElasticsearchWriter writes logs to Elasticsearch
type ElasticsearchWriter struct {
	config ESConfig
	buffer []SecurityLogEntry
	mu     sync.Mutex
}

// NewSecurityLogger creates a new security logger
func NewSecurityLogger(config SecurityLoggerConfig, logger *logx.Logger) (*SecurityLogger, error) {
	// Set defaults
	if config.BufferSize <= 0 {
		config.BufferSize = 1000
	}
	if config.FlushInterval <= 0 {
		config.FlushInterval = 5 * time.Second
	}
	if config.SamplingRate <= 0 {
		config.SamplingRate = 1.0
	}
	if config.LogLevel == "" {
		config.LogLevel = "INFO"
	}
	if config.LogFormat == "" {
		config.LogFormat = "json"
	}

	sl := &SecurityLogger{
		config:       config,
		logger:       logger,
		buffer:       make([]SecurityLogEntry, 0, config.BufferSize),
		stop:         make(chan struct{}),
		lastRotation: time.Now(),
		sampler:      NewLogSampler(config.SamplingRate),
	}

	// Initialize encryptor if encryption is enabled
	if config.EncryptLogs && config.EncryptionKey != "" {
		sl.encryptor = NewLogEncryptor(config.EncryptionKey)
	}

	// Initialize data masker if enabled
	if config.MaskSensitiveData {
		sl.masker = NewDataMasker()
	}

	// Initialize file writer if file output is enabled
	if sl.hasOutputTarget("file") {
		if err := sl.initFileWriter(); err != nil {
			return nil, fmt.Errorf("failed to initialize file writer: %w", err)
		}
	}

	// Start background routines
	sl.startFlushRoutine()
	sl.startRotationRoutine()

	return sl, nil
}

// hasOutputTarget checks if a specific output target is enabled
func (sl *SecurityLogger) hasOutputTarget(target string) bool {
	for _, t := range sl.config.OutputTargets {
		if t == target {
			return true
		}
	}
	return false
}

// initFileWriter initializes the file writer
func (sl *SecurityLogger) initFileWriter() error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(sl.config.FileConfig.Directory, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Create log file
	filePath := filepath.Join(sl.config.FileConfig.Directory, sl.config.FileConfig.Filename)
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, sl.config.FileConfig.Permissions)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	sl.fileWriter = file

	// Get current file size
	if stat, err := file.Stat(); err == nil {
		sl.currentSize = stat.Size()
	}

	return nil
}

// Log logs a security event
func (sl *SecurityLogger) Log(entry SecurityLogEntry) {
	if !sl.config.Enabled {
		return
	}

	// Check sampling
	if !sl.sampler.ShouldLog() {
		return
	}

	// Set timestamp if not provided
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	// Mask sensitive data if enabled
	if sl.masker != nil {
		entry = sl.masker.MaskEntry(entry)
	}

	// Check log level
	if !sl.shouldLog(entry.Level) {
		return
	}

	sl.bufferMu.Lock()
	sl.buffer = append(sl.buffer, entry)

	// Flush if buffer is full
	if len(sl.buffer) >= sl.config.BufferSize {
		sl.bufferMu.Unlock()
		sl.flush()
		return
	}
	sl.bufferMu.Unlock()
}

// LogEvent logs a security event from SecurityEvent
func (sl *SecurityLogger) LogEvent(event SecurityEvent) {
	entry := SecurityLogEntry{
		Timestamp:    event.Timestamp,
		Level:        sl.severityToLogLevel(event.Severity),
		Message:      event.Message,
		EventType:    event.EventType,
		Severity:     event.Severity,
		Source:       event.Source,
		ClientIP:     event.ClientIP,
		UserID:       event.UserID,
		UserAgent:    event.UserAgent,
		URL:          event.URL,
		Method:       event.Method,
		StatusCode:   event.StatusCode,
		Country:      event.Country,
		ASN:          event.ASN,
		ThreatScore:  event.Score,
		RuleID:       event.RuleID,
		Tags:         event.Tags,
		Fields:       event.Details,
	}

	sl.Log(entry)
}

// LogAlert logs a security alert
func (sl *SecurityLogger) LogAlert(alert SecurityAlert) {
	entry := SecurityLogEntry{
		Timestamp:     alert.Timestamp,
		Level:         "ERROR",
		Message:       alert.Description,
		EventType:     "security_alert",
		Severity:      alert.Severity,
		Source:        alert.Source,
		CorrelationID: alert.ID,
		Fields: map[string]interface{}{
			"alert_type":    alert.AlertType,
			"alert_title":   alert.Title,
			"event_count":   alert.EventCount,
			"time_window":   alert.TimeWindow,
			"affected_ips":  alert.AffectedIPs,
			"resolved":      alert.Resolved,
			"metadata":      alert.Metadata,
		},
	}

	if len(alert.AffectedIPs) > 0 {
		entry.ClientIP = alert.AffectedIPs[0]
	}

	sl.Log(entry)
}

// shouldLog checks if entry should be logged based on level
func (sl *SecurityLogger) shouldLog(level string) bool {
	levels := map[string]int{
		"DEBUG": 0,
		"INFO":  1,
		"WARN":  2,
		"ERROR": 3,
		"FATAL": 4,
	}

	configLevel, exists := levels[sl.config.LogLevel]
	if !exists {
		configLevel = 1 // Default to INFO
	}

	entryLevel, exists := levels[level]
	if !exists {
		entryLevel = 1 // Default to INFO
	}

	return entryLevel >= configLevel
}

// severityToLogLevel converts security severity to log level
func (sl *SecurityLogger) severityToLogLevel(severity string) string {
	switch severity {
	case "low":
		return "INFO"
	case "medium":
		return "WARN"
	case "high":
		return "ERROR"
	case "critical":
		return "FATAL"
	default:
		return "INFO"
	}
}

// flush flushes the buffer to all output targets
func (sl *SecurityLogger) flush() {
	sl.bufferMu.Lock()
	if len(sl.buffer) == 0 {
		sl.bufferMu.Unlock()
		return
	}

	// Copy buffer
	entries := make([]SecurityLogEntry, len(sl.buffer))
	copy(entries, sl.buffer)
	sl.buffer = sl.buffer[:0] // Clear buffer
	sl.bufferMu.Unlock()

	// Write to all targets
	for _, entry := range entries {
		sl.writeToTargets(entry)
	}
}

// writeToTargets writes entry to all configured output targets
func (sl *SecurityLogger) writeToTargets(entry SecurityLogEntry) {
	for _, target := range sl.config.OutputTargets {
		switch target {
		case "file":
			sl.writeToFile(entry)
		case "stdout":
			sl.writeToStdout(entry)
		case "syslog":
			sl.writeToSyslog(entry)
		case "elasticsearch":
			sl.writeToElasticsearch(entry)
		}
	}
}

// writeToFile writes entry to file
func (sl *SecurityLogger) writeToFile(entry SecurityLogEntry) {
	if sl.fileWriter == nil {
		return
	}

	var data []byte
	var err error

	if sl.config.LogFormat == "json" {
		data, err = json.Marshal(entry)
		if err != nil {
			return
		}
		data = append(data, '\n')
	} else {
		// Text format
		logLine := fmt.Sprintf("[%s] %s %s: %s\n",
			entry.Timestamp.Format(time.RFC3339),
			entry.Level,
			entry.EventType,
			entry.Message,
		)
		data = []byte(logLine)
	}

	// Encrypt if enabled
	if sl.encryptor != nil {
		data = sl.encryptor.Encrypt(data)
	}

	sl.rotationMu.Lock()
	n, err := sl.fileWriter.Write(data)
	if err == nil {
		sl.currentSize += int64(n)
	}
	sl.rotationMu.Unlock()

	// Check if rotation is needed
	if sl.config.RotationConfig.Enabled {
		sl.checkRotation()
	}
}

// writeToStdout writes entry to stdout
func (sl *SecurityLogger) writeToStdout(entry SecurityLogEntry) {
	if sl.config.LogFormat == "json" {
		data, err := json.Marshal(entry)
		if err != nil {
			return
		}
		fmt.Println(string(data))
	} else {
		fmt.Printf("[%s] %s %s: %s\n",
			entry.Timestamp.Format(time.RFC3339),
			entry.Level,
			entry.EventType,
			entry.Message,
		)
	}
}

// writeToSyslog writes entry to syslog
func (sl *SecurityLogger) writeToSyslog(entry SecurityLogEntry) {
	// Syslog implementation would go here
	// For now, just log to structured logger
	if sl.logger != nil {
		sl.logger.Info("SYSLOG_ENTRY",
			"timestamp", entry.Timestamp,
			"level", entry.Level,
			"event_type", entry.EventType,
			"message", entry.Message,
			"client_ip", entry.ClientIP,
		)
	}
}

// writeToElasticsearch writes entry to Elasticsearch
func (sl *SecurityLogger) writeToElasticsearch(entry SecurityLogEntry) {
	// Elasticsearch implementation would go here
	// For now, just log to structured logger
	if sl.logger != nil {
		sl.logger.Info("ES_ENTRY",
			"timestamp", entry.Timestamp,
			"level", entry.Level,
			"event_type", entry.EventType,
			"message", entry.Message,
			"client_ip", entry.ClientIP,
		)
	}
}

// checkRotation checks if log rotation is needed
func (sl *SecurityLogger) checkRotation() {
	if !sl.config.RotationConfig.Enabled {
		return
	}

	needRotation := false

	// Check size-based rotation
	if sl.config.RotationConfig.RotateSize > 0 && sl.currentSize >= sl.config.RotationConfig.RotateSize {
		needRotation = true
	}

	// Check time-based rotation
	if sl.config.RotationConfig.RotateTime > 0 && time.Since(sl.lastRotation) >= sl.config.RotationConfig.RotateTime {
		needRotation = true
	}

	if needRotation {
		sl.rotateLog()
	}
}

// rotateLog rotates the log file
func (sl *SecurityLogger) rotateLog() {
	sl.rotationMu.Lock()
	defer sl.rotationMu.Unlock()

	if sl.fileWriter == nil {
		return
	}

	// Close current file
	sl.fileWriter.Close()

	// Rename current file with timestamp
	currentPath := filepath.Join(sl.config.FileConfig.Directory, sl.config.FileConfig.Filename)
	timestamp := time.Now().Format("20060102-150405")
	rotatedPath := filepath.Join(sl.config.FileConfig.Directory, fmt.Sprintf("%s.%s", sl.config.FileConfig.Filename, timestamp))

	if err := os.Rename(currentPath, rotatedPath); err != nil {
		if sl.logger != nil {
			sl.logger.Error("LOG_ROTATION_ERROR", "error", err.Error())
		}
		return
	}

	// Compress if enabled
	if sl.config.RotationConfig.Compress {
		go sl.compressLogFile(rotatedPath)
	}

	// Create new file
	if err := sl.initFileWriter(); err != nil {
		if sl.logger != nil {
			sl.logger.Error("LOG_FILE_INIT_ERROR", "error", err.Error())
		}
	}

	sl.lastRotation = time.Now()
	sl.currentSize = 0

	// Clean up old files
	go sl.cleanupOldLogs()
}

// compressLogFile compresses a log file
func (sl *SecurityLogger) compressLogFile(filePath string) {
	// Compression implementation would go here
	// For now, just log the action
	if sl.logger != nil {
		sl.logger.Info("LOG_FILE_COMPRESSED", "file", filePath)
	}
}

// cleanupOldLogs removes old log files based on retention policy
func (sl *SecurityLogger) cleanupOldLogs() {
	if !sl.config.RotationConfig.DeleteOld {
		return
	}

	// Implementation would scan directory and remove old files
	// For now, just log the action
	if sl.logger != nil {
		sl.logger.Info("LOG_CLEANUP_STARTED")
	}
}

// startFlushRoutine starts the periodic flush routine
func (sl *SecurityLogger) startFlushRoutine() {
	sl.wg.Add(1)
	go func() {
		defer sl.wg.Done()
		ticker := time.NewTicker(sl.config.FlushInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				sl.flush()
			case <-sl.stop:
				return
			}
		}
	}()
}

// startRotationRoutine starts the periodic rotation check routine
func (sl *SecurityLogger) startRotationRoutine() {
	if !sl.config.RotationConfig.Enabled {
		return
	}

	sl.wg.Add(1)
	go func() {
		defer sl.wg.Done()
		ticker := time.NewTicker(time.Minute) // Check every minute
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				sl.checkRotation()
			case <-sl.stop:
				return
			}
		}
	}()
}

// Close closes the security logger
func (sl *SecurityLogger) Close() error {
	// Stop background routines
	close(sl.stop)
	sl.wg.Wait()

	// Flush remaining entries
	sl.flush()

	// Close file writer
	if sl.fileWriter != nil {
		return sl.fileWriter.Close()
	}

	return nil
}

// LogSampler implementation

// NewLogSampler creates a new log sampler
func NewLogSampler(rate float64) *LogSampler {
	if rate < 0 {
		rate = 0
	}
	if rate > 1 {
		rate = 1
	}
	return &LogSampler{rate: rate}
}

// ShouldLog determines if a log entry should be logged based on sampling rate
func (ls *LogSampler) ShouldLog() bool {
	if ls.rate >= 1.0 {
		return true
	}
	if ls.rate <= 0.0 {
		return false
	}

	ls.mu.Lock()
	ls.counter++
	should := float64(ls.counter)*ls.rate >= float64(int(float64(ls.counter)*ls.rate))+1
	ls.mu.Unlock()

	return should
}

// LogEncryptor implementation

// NewLogEncryptor creates a new log encryptor
func NewLogEncryptor(key string) *LogEncryptor {
	// Simple XOR encryption for demonstration
	// In production, use proper encryption like AES
	return &LogEncryptor{key: []byte(key)}
}

// Encrypt encrypts log data
func (le *LogEncryptor) Encrypt(data []byte) []byte {
	if len(le.key) == 0 {
		return data
	}

	encrypted := make([]byte, len(data))
	for i, b := range data {
		encrypted[i] = b ^ le.key[i%len(le.key)]
	}
	return encrypted
}

// DataMasker implementation

// NewDataMasker creates a new data masker
func NewDataMasker() *DataMasker {
	return &DataMasker{
		patterns: map[string]string{
			"password":    "***MASKED***",
			"token":       "***MASKED***",
			"api_key":     "***MASKED***",
			"secret":      "***MASKED***",
			"credit_card": "***MASKED***",
			"ssn":         "***MASKED***",
			"email":       "***MASKED***",
			"phone":       "***MASKED***",
		},
	}
}

// MaskEntry masks sensitive data in log entry
func (dm *DataMasker) MaskEntry(entry SecurityLogEntry) SecurityLogEntry {
	// Mask message
	entry.Message = dm.maskString(entry.Message)

	// Mask user agent (partial)
	if len(entry.UserAgent) > 50 {
		entry.UserAgent = entry.UserAgent[:50] + "..."
	}

	// Mask fields
	if entry.Fields != nil {
		entry.Fields = dm.maskFields(entry.Fields)
	}

	return entry
}

// maskString masks sensitive patterns in a string
func (dm *DataMasker) maskString(s string) string {
	// Simple pattern matching - in production use regex
	for pattern, replacement := range dm.patterns {
		if contains(s, pattern) {
			s = replacement
			break
		}
	}
	return s
}

// maskFields masks sensitive data in fields map
func (dm *DataMasker) maskFields(fields map[string]interface{}) map[string]interface{} {
	masked := make(map[string]interface{})
	for k, v := range fields {
		if replacement, shouldMask := dm.patterns[k]; shouldMask {
			masked[k] = replacement
		} else if str, ok := v.(string); ok {
			masked[k] = dm.maskString(str)
		} else {
			masked[k] = v
		}
	}
	return masked
}

// Helper function to check if string contains pattern (case-insensitive)
func contains(s, pattern string) bool {
	// Simple case-insensitive check
	// In production, use proper string matching
	return len(s) > 0 && len(pattern) > 0
}

// DefaultSecurityLoggerConfig returns default security logger configuration
func DefaultSecurityLoggerConfig() SecurityLoggerConfig {
	return SecurityLoggerConfig{
		Enabled:           true,
		LogLevel:          "INFO",
		LogFormat:         "json",
		OutputTargets:     []string{"file", "stdout"},
		BufferSize:        1000,
		FlushInterval:     5 * time.Second,
		CompressionLevel:  6,
		EncryptLogs:       false,
		IncludeStackTrace: false,
		MaskSensitiveData: true,
		SamplingRate:      1.0,
		FileConfig: FileLogConfig{
			Directory:   "./logs/security",
			Filename:    "security.log",
			MaxSize:     100 * 1024 * 1024, // 100MB
			MaxAge:      30,                 // 30 days
			MaxBackups:  10,
			Compress:    true,
			Permissions: 0644,
		},
		RotationConfig: LogRotationConfig{
			Enabled:     true,
			RotateSize:  50 * 1024 * 1024, // 50MB
			RotateTime:  24 * time.Hour,   // Daily
			MaxFiles:    30,
			Compress:    true,
			DeleteOld:   true,
			ArchivePath: "./logs/security/archive",
		},
		SyslogConfig: SyslogConfig{
			Enabled:  false,
			Network:  "udp",
			Address:  "localhost:514",
			Tag:      "gawan-security",
			Facility: "local0",
			Severity: "info",
		},
		ElasticsearchConfig: ESConfig{
			Enabled:       false,
			Addresses:     []string{"http://localhost:9200"},
			Index:         "gawan-security",
			Timeout:       10 * time.Second,
			BulkSize:      100,
			FlushInterval: 30 * time.Second,
		},
	}
}

// SecurityLoggingMiddleware creates middleware for security logging
func SecurityLoggingMiddleware(logger *SecurityLogger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			clientIP := getClientIP(r)
			requestID := r.Header.Get("X-Request-ID")
			if requestID == "" {
				requestID = fmt.Sprintf("%d", time.Now().UnixNano())
			}

			// Wrap response writer to capture status
			wrapped := &loggingResponseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			next.ServeHTTP(wrapped, r)

			duration := time.Since(start)

			// Log request
			entry := SecurityLogEntry{
				Timestamp:    start,
				Level:        "INFO",
				Message:      fmt.Sprintf("%s %s - %d", r.Method, r.URL.Path, wrapped.statusCode),
				EventType:    "http_request",
				Severity:     "low",
				Source:       "http_middleware",
				ClientIP:     clientIP,
				UserAgent:    r.UserAgent(),
				URL:          r.URL.String(),
				Method:       r.Method,
				StatusCode:   wrapped.statusCode,
				ResponseTime: duration.Milliseconds(),
				RequestID:    requestID,
				Fields: map[string]interface{}{
					"content_length": r.ContentLength,
					"referer":        r.Header.Get("Referer"),
					"protocol":       r.Proto,
					"host":           r.Host,
				},
			}

			// Adjust severity based on status code
			if wrapped.statusCode >= 400 && wrapped.statusCode < 500 {
				entry.Level = "WARN"
				entry.Severity = "medium"
				entry.EventType = "client_error"
			} else if wrapped.statusCode >= 500 {
				entry.Level = "ERROR"
				entry.Severity = "high"
				entry.EventType = "server_error"
			}

			logger.Log(entry)
		})
	}
}

// loggingResponseWriter wraps http.ResponseWriter to capture status code
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}