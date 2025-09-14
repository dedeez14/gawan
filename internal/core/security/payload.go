package security

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"Gawan/internal/core/logx"
)

// PayloadLimitConfig holds payload size limit configuration
type PayloadLimitConfig struct {
	// Enabled enables payload size limiting
	Enabled bool `json:"enabled" yaml:"enabled" env:"PAYLOAD_LIMIT_ENABLED" default:"true"`
	// MaxSize is the maximum allowed payload size in bytes
	MaxSize int64 `json:"max_size" yaml:"max_size" env:"PAYLOAD_MAX_SIZE" default:"1048576"` // 1MB default
	// ResponseCode is the HTTP status code to return when limit is exceeded (413 or 400)
	ResponseCode int `json:"response_code" yaml:"response_code" env:"PAYLOAD_RESPONSE_CODE" default:"413"`
	// SkipMethods are HTTP methods to skip payload size checking
	SkipMethods []string `json:"skip_methods" yaml:"skip_methods" env:"PAYLOAD_SKIP_METHODS"`
	// SkipPaths are URL paths to skip payload size checking
	SkipPaths []string `json:"skip_paths" yaml:"skip_paths" env:"PAYLOAD_SKIP_PATHS"`
	// OnLimitExceeded is called when payload limit is exceeded
	OnLimitExceeded PayloadLimitExceededHandler `json:"-" yaml:"-"`
	// Logger for audit events
	Logger *logx.Logger `json:"-" yaml:"-"`
	// AuditLogger for security events
	AuditLogger *AuditLogger `json:"-" yaml:"-"`
}

// PayloadLimitExceededHandler handles payload limit exceeded scenarios
type PayloadLimitExceededHandler func(w http.ResponseWriter, r *http.Request, size int64, maxSize int64, logger *logx.Logger, auditLogger *AuditLogger)

// LimitedReader wraps an io.Reader to enforce size limits
type LimitedReader struct {
	reader   io.Reader
	maxSize  int64
	readSize int64
	exceeded bool
}

// NewLimitedReader creates a new limited reader
func NewLimitedReader(reader io.Reader, maxSize int64) *LimitedReader {
	return &LimitedReader{
		reader:  reader,
		maxSize: maxSize,
	}
}

// Read implements io.Reader interface with size limiting
func (lr *LimitedReader) Read(p []byte) (n int, err error) {
	if lr.exceeded {
		return 0, fmt.Errorf("payload size limit exceeded")
	}
	
	n, err = lr.reader.Read(p)
	lr.readSize += int64(n)
	
	if lr.readSize > lr.maxSize {
		lr.exceeded = true
		return n, fmt.Errorf("payload size limit exceeded: %d bytes > %d bytes", lr.readSize, lr.maxSize)
	}
	
	return n, err
}

// Size returns the current read size
func (lr *LimitedReader) Size() int64 {
	return lr.readSize
}

// Exceeded returns true if the size limit was exceeded
func (lr *LimitedReader) Exceeded() bool {
	return lr.exceeded
}

// DefaultPayloadLimitConfig returns default payload limit configuration
func DefaultPayloadLimitConfig() PayloadLimitConfig {
	return PayloadLimitConfig{
		Enabled:         true,
		MaxSize:         1048576, // 1MB
		ResponseCode:    413,     // Request Entity Too Large
		SkipMethods:     []string{"GET", "HEAD", "OPTIONS"},
		SkipPaths:       []string{},
		OnLimitExceeded: DefaultPayloadLimitExceededHandler,
	}
}

// DefaultPayloadLimitExceededHandler is the default handler for payload limit exceeded
func DefaultPayloadLimitExceededHandler(w http.ResponseWriter, r *http.Request, size int64, maxSize int64, logger *logx.Logger, auditLogger *AuditLogger) {
	// Audit log the payload size violation
	if auditLogger != nil {
		metadata := map[string]interface{}{
			"payload_size": size,
			"max_size":     maxSize,
			"content_type": r.Header.Get("Content-Type"),
		}
		auditLogger.LogSecurityViolation(r, "PAYLOAD_SIZE_EXCEEDED", 
			fmt.Sprintf("Payload size %d bytes exceeds limit of %d bytes", size, maxSize),
			AuditSeverityMedium, metadata)
	}
	
	// Log the violation
	if logger != nil {
		logger.Warn("PAYLOAD_SIZE_EXCEEDED",
			"event", "PAYLOAD_SIZE_EXCEEDED",
			"ip", GetClientIP(r),
			"user_agent", r.UserAgent(),
			"path", r.URL.Path,
			"method", r.Method,
			"payload_size", size,
			"max_size", maxSize,
			"content_type", r.Header.Get("Content-Type"),
		)
	}
	
	// Determine response code (413 or 400)
	responseCode := 413 // Default to Request Entity Too Large
	if size <= 0 {
		responseCode = 400 // Bad Request for invalid size
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(responseCode)
	
	response := map[string]interface{}{
		"error":   "payload_too_large",
		"message": fmt.Sprintf("Ukuran payload %s melebihi batas maksimum %s", formatBytes(size), formatBytes(maxSize)),
		"code":    responseCode,
		"details": map[string]interface{}{
			"payload_size": size,
			"max_size":     maxSize,
			"limit":        "1MB",
		},
	}
	
	jsonResponse, _ := json.Marshal(response)
	w.Write(jsonResponse)
}

// formatBytes formats byte size in human readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// shouldSkipPayloadCheck checks if payload size checking should be skipped
func shouldSkipPayloadCheck(r *http.Request, config PayloadLimitConfig) bool {
	// Skip certain HTTP methods
	for _, method := range config.SkipMethods {
		if strings.EqualFold(r.Method, method) {
			return true
		}
	}
	
	// Skip certain paths
	for _, path := range config.SkipPaths {
		if r.URL.Path == path {
			return true
		}
		// Simple wildcard matching
		if strings.HasSuffix(path, "*") {
			prefix := path[:len(path)-1]
			if strings.HasPrefix(r.URL.Path, prefix) {
				return true
			}
		}
	}
	
	return false
}

// getContentLength gets the content length from request headers
func getContentLength(r *http.Request) int64 {
	if r.ContentLength >= 0 {
		return r.ContentLength
	}
	
	// Try to parse Content-Length header manually
	if cl := r.Header.Get("Content-Length"); cl != "" {
		if length, err := strconv.ParseInt(cl, 10, 64); err == nil {
			return length
		}
	}
	
	return -1
}

// PayloadLimitMiddleware creates a payload size limit middleware
func PayloadLimitMiddleware(config PayloadLimitConfig) func(http.Handler) http.Handler {
	if !config.Enabled {
		return func(next http.Handler) http.Handler {
			return next // Pass through if disabled
		}
	}
	
	// Set defaults
	if config.MaxSize <= 0 {
		config.MaxSize = 1048576 // 1MB default
	}
	if config.ResponseCode != 400 && config.ResponseCode != 413 {
		config.ResponseCode = 413 // Default to Request Entity Too Large
	}
	if config.OnLimitExceeded == nil {
		config.OnLimitExceeded = DefaultPayloadLimitExceededHandler
	}
	if len(config.SkipMethods) == 0 {
		config.SkipMethods = []string{"GET", "HEAD", "OPTIONS"}
	}
	
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip payload check for certain methods/paths
			if shouldSkipPayloadCheck(r, config) {
				next.ServeHTTP(w, r)
				return
			}
			
			// Check Content-Length header first (fast path)
			contentLength := getContentLength(r)
			if contentLength > config.MaxSize {
				config.OnLimitExceeded(w, r, contentLength, config.MaxSize, config.Logger, config.AuditLogger)
				return
			}
			
			// If Content-Length is not available or is 0, we need to wrap the body reader
			if contentLength < 0 || r.Body != nil {
				// Wrap the request body with a limited reader
				limitedReader := NewLimitedReader(r.Body, config.MaxSize)
				r.Body = &limitedReadCloser{
					LimitedReader: limitedReader,
					closer:        r.Body,
				}
				
				// Create a response writer wrapper to check for read errors
				wrapped := &payloadLimitResponseWriter{
					ResponseWriter: w,
					limitedReader:  limitedReader,
					config:         config,
					request:        r,
				}
				
				next.ServeHTTP(wrapped, r)
				return
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// limitedReadCloser combines LimitedReader with io.Closer
type limitedReadCloser struct {
	*LimitedReader
	closer io.Closer
}

// Close implements io.Closer interface
func (lrc *limitedReadCloser) Close() error {
	if lrc.closer != nil {
		return lrc.closer.Close()
	}
	return nil
}

// payloadLimitResponseWriter wraps http.ResponseWriter to handle payload limit violations
type payloadLimitResponseWriter struct {
	http.ResponseWriter
	limitedReader *LimitedReader
	config        PayloadLimitConfig
	request       *http.Request
	headerWritten bool
}

// Write checks for payload limit violations before writing response
func (plrw *payloadLimitResponseWriter) Write(data []byte) (int, error) {
	// Check if the limited reader exceeded the limit
	if plrw.limitedReader.Exceeded() && !plrw.headerWritten {
		// Handle the limit exceeded scenario
		plrw.config.OnLimitExceeded(plrw.ResponseWriter, plrw.request, 
			plrw.limitedReader.Size(), plrw.config.MaxSize, 
			plrw.config.Logger, plrw.config.AuditLogger)
		plrw.headerWritten = true
		return len(data), nil // Pretend we wrote the data to avoid further errors
	}
	
	return plrw.ResponseWriter.Write(data)
}

// WriteHeader captures header writes
func (plrw *payloadLimitResponseWriter) WriteHeader(code int) {
	// Check if the limited reader exceeded the limit
	if plrw.limitedReader.Exceeded() && !plrw.headerWritten {
		// Handle the limit exceeded scenario
		plrw.config.OnLimitExceeded(plrw.ResponseWriter, plrw.request, 
			plrw.limitedReader.Size(), plrw.config.MaxSize, 
			plrw.config.Logger, plrw.config.AuditLogger)
		plrw.headerWritten = true
		return
	}
	
	plrw.ResponseWriter.WriteHeader(code)
	plrw.headerWritten = true
}

// StrictPayloadLimitConfig returns a strict payload limit configuration
func StrictPayloadLimitConfig() PayloadLimitConfig {
	config := DefaultPayloadLimitConfig()
	config.MaxSize = 524288 // 512KB - stricter limit
	config.SkipMethods = []string{"GET", "HEAD"} // Only skip GET and HEAD
	return config
}

// LenientPayloadLimitConfig returns a lenient payload limit configuration
func LenientPayloadLimitConfig() PayloadLimitConfig {
	config := DefaultPayloadLimitConfig()
	config.MaxSize = 10485760 // 10MB - more lenient limit
	config.ResponseCode = 400   // Use 400 instead of 413
	return config
}