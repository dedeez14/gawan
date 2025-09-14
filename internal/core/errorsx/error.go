package errorsx

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"
)

// ErrorType represents different types of errors
type ErrorType string

const (
	ErrorTypeValidation   ErrorType = "validation"
	ErrorTypeNotFound     ErrorType = "not_found"
	ErrorTypeUnauthorized ErrorType = "unauthorized"
	ErrorTypeForbidden    ErrorType = "forbidden"
	ErrorTypeInternal     ErrorType = "internal"
	ErrorTypeDatabase     ErrorType = "database"
	ErrorTypeExternal     ErrorType = "external"
	ErrorTypeTimeout      ErrorType = "timeout"
	ErrorTypeConflict     ErrorType = "conflict"
)

// AppError represents an application error with context
type AppError struct {
	Type       ErrorType              `json:"type"`
	Message    string                 `json:"message"`
	Details    string                 `json:"details,omitempty"`
	Code       string                 `json:"code,omitempty"`
	StatusCode int                    `json:"status_code"`
	Context    map[string]interface{} `json:"context,omitempty"`
	Stack      []StackFrame           `json:"stack,omitempty"`
	Cause      error                  `json:"cause,omitempty"`
	Timestamp  time.Time              `json:"timestamp"`
	RequestID  string                 `json:"request_id,omitempty"`
}

// StackFrame represents a single frame in the stack trace
type StackFrame struct {
	Function string `json:"function"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Package  string `json:"package"`
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("%s: %s - %s", e.Type, e.Message, e.Details)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// Unwrap returns the underlying cause
func (e *AppError) Unwrap() error {
	return e.Cause
}

// New creates a new AppError
func New(errorType ErrorType, message string) *AppError {
	return &AppError{
		Type:       errorType,
		Message:    message,
		StatusCode: getStatusCodeForType(errorType),
		Stack:      captureStack(2),
		Timestamp:  time.Now(),
	}
}

// Newf creates a new AppError with formatted message
func Newf(errorType ErrorType, format string, args ...interface{}) *AppError {
	return New(errorType, fmt.Sprintf(format, args...))
}

// Wrap wraps an existing error with additional context
func Wrap(err error, errorType ErrorType, message string) *AppError {
	if err == nil {
		return nil
	}

	// If it's already an AppError, preserve the original stack
	if appErr, ok := err.(*AppError); ok {
		return &AppError{
			Type:       errorType,
			Message:    message,
			StatusCode: getStatusCodeForType(errorType),
			Stack:      appErr.Stack, // Preserve original stack
			Cause:      appErr,
			Timestamp:  time.Now(),
		}
	}

	return &AppError{
		Type:       errorType,
		Message:    message,
		StatusCode: getStatusCodeForType(errorType),
		Stack:      captureStack(2),
		Cause:      err,
		Timestamp:  time.Now(),
	}
}

// Wrapf wraps an existing error with formatted message
func Wrapf(err error, errorType ErrorType, format string, args ...interface{}) *AppError {
	return Wrap(err, errorType, fmt.Sprintf(format, args...))
}

// WithContext adds context to the error
func (e *AppError) WithContext(key string, value interface{}) *AppError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// WithCode adds an error code
func (e *AppError) WithCode(code string) *AppError {
	e.Code = code
	return e
}

// WithDetails adds additional details
func (e *AppError) WithDetails(details string) *AppError {
	e.Details = details
	return e
}

// WithRequestID adds request ID for tracing
func (e *AppError) WithRequestID(requestID string) *AppError {
	e.RequestID = requestID
	return e
}

// ToJSON converts the error to JSON format
func (e *AppError) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// FormatForDevelopment formats the error for development environment
func (e *AppError) FormatForDevelopment() string {
	var sb strings.Builder

	// Header
	sb.WriteString(fmt.Sprintf("\n🚨 %s ERROR: %s\n", strings.ToUpper(string(e.Type)), e.Message))
	sb.WriteString(strings.Repeat("=", 80) + "\n")

	// Basic info
	if e.Code != "" {
		sb.WriteString(fmt.Sprintf("Code: %s\n", e.Code))
	}
	if e.Details != "" {
		sb.WriteString(fmt.Sprintf("Details: %s\n", e.Details))
	}
	sb.WriteString(fmt.Sprintf("Status: %d\n", e.StatusCode))
	sb.WriteString(fmt.Sprintf("Time: %s\n", e.Timestamp.Format(time.RFC3339)))
	if e.RequestID != "" {
		sb.WriteString(fmt.Sprintf("Request ID: %s\n", e.RequestID))
	}

	// Context
	if len(e.Context) > 0 {
		sb.WriteString("\nContext:\n")
		for k, v := range e.Context {
			sb.WriteString(fmt.Sprintf("  %s: %v\n", k, v))
		}
	}

	// Stack trace
	if len(e.Stack) > 0 {
		sb.WriteString("\nStack Trace:\n")
		for i, frame := range e.Stack {
			sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, frame.Function))
			sb.WriteString(fmt.Sprintf("     %s:%d\n", frame.File, frame.Line))
			if frame.Package != "" {
				sb.WriteString(fmt.Sprintf("     Package: %s\n", frame.Package))
			}
			sb.WriteString("\n")
		}
	}

	// Cause chain
	if e.Cause != nil {
		sb.WriteString("\nCaused by:\n")
		if appErr, ok := e.Cause.(*AppError); ok {
			sb.WriteString(appErr.FormatForDevelopment())
		} else {
			sb.WriteString(fmt.Sprintf("  %s\n", e.Cause.Error()))
		}
	}

	sb.WriteString(strings.Repeat("=", 80) + "\n")
	return sb.String()
}

// FormatForProduction formats the error for production environment (minimal info)
func (e *AppError) FormatForProduction() map[string]interface{} {
	result := map[string]interface{}{
		"error":   true,
		"type":    e.Type,
		"message": e.Message,
		"code":    e.StatusCode,
	}

	if e.Code != "" {
		result["error_code"] = e.Code
	}

	if e.RequestID != "" {
		result["request_id"] = e.RequestID
	}

	// Only include safe context in production
	if len(e.Context) > 0 {
		safeContext := make(map[string]interface{})
		for k, v := range e.Context {
			// Only include non-sensitive context
			if !isSensitiveKey(k) {
				safeContext[k] = v
			}
		}
		if len(safeContext) > 0 {
			result["context"] = safeContext
		}
	}

	return result
}

// captureStack captures the current stack trace
func captureStack(skip int) []StackFrame {
	var frames []StackFrame
	for i := skip; ; i++ {
		pc, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}

		fn := runtime.FuncForPC(pc)
		if fn == nil {
			continue
		}

		funcName := fn.Name()
		packageName := ""
		if lastSlash := strings.LastIndex(funcName, "/"); lastSlash >= 0 {
			packageName = funcName[:lastSlash]
			funcName = funcName[lastSlash+1:]
		}
		if lastDot := strings.LastIndex(funcName, "."); lastDot >= 0 {
			if packageName == "" {
				packageName = funcName[:lastDot]
			}
			funcName = funcName[lastDot+1:]
		}

		frames = append(frames, StackFrame{
			Function: funcName,
			File:     file,
			Line:     line,
			Package:  packageName,
		})

		// Limit stack depth
		if len(frames) >= 20 {
			break
		}
	}

	return frames
}

// getStatusCodeForType returns appropriate HTTP status code for error type
func getStatusCodeForType(errorType ErrorType) int {
	switch errorType {
	case ErrorTypeValidation:
		return http.StatusBadRequest
	case ErrorTypeNotFound:
		return http.StatusNotFound
	case ErrorTypeUnauthorized:
		return http.StatusUnauthorized
	case ErrorTypeForbidden:
		return http.StatusForbidden
	case ErrorTypeConflict:
		return http.StatusConflict
	case ErrorTypeTimeout:
		return http.StatusRequestTimeout
	case ErrorTypeDatabase, ErrorTypeExternal, ErrorTypeInternal:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

// isSensitiveKey checks if a context key contains sensitive information
func isSensitiveKey(key string) bool {
	sensitiveKeys := []string{
		"password", "token", "secret", "key", "auth",
		"credential", "private", "session", "cookie",
	}

	lowerKey := strings.ToLower(key)
	for _, sensitive := range sensitiveKeys {
		if strings.Contains(lowerKey, sensitive) {
			return true
		}
	}
	return false
}

// Common error constructors
func ValidationError(message string) *AppError {
	return New(ErrorTypeValidation, message)
}

func NotFoundError(message string) *AppError {
	return New(ErrorTypeNotFound, message)
}

func UnauthorizedError(message string) *AppError {
	return New(ErrorTypeUnauthorized, message)
}

func ForbiddenError(message string) *AppError {
	return New(ErrorTypeForbidden, message)
}

func InternalError(message string) *AppError {
	return New(ErrorTypeInternal, message)
}

func DatabaseError(message string) *AppError {
	return New(ErrorTypeDatabase, message)
}

func ExternalError(message string) *AppError {
	return New(ErrorTypeExternal, message)
}

func TimeoutError(message string) *AppError {
	return New(ErrorTypeTimeout, message)
}

func ConflictError(message string) *AppError {
	return New(ErrorTypeConflict, message)
}