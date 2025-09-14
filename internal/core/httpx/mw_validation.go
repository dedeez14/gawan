package httpx

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"

	"Gawan/internal/core/validation"
)

// ValidationConfig holds configuration for validation middleware
type ValidationConfig struct {
	// Validator is the validator instance
	Validator *validation.Validator
	// SkipOnError skips validation if request body parsing fails
	SkipOnError bool
	// MaxBodySize limits the request body size for validation
	MaxBodySize int64
}

// DefaultValidationConfig returns default validation middleware configuration
func DefaultValidationConfig(validator *validation.Validator) ValidationConfig {
	return ValidationConfig{
		Validator:   validator,
		SkipOnError: false,
		MaxBodySize: 1024 * 1024, // 1MB
	}
}

// ValidationMiddleware creates request validation middleware
func ValidationMiddleware(config ValidationConfig) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only validate POST, PUT, PATCH requests with JSON content
			if !shouldValidateRequest(r) {
				next.ServeHTTP(w, r)
				return
			}

			// Get validation target from context (set by route handler)
			target := GetValidationTarget(r.Context())
			if target == nil {
				next.ServeHTTP(w, r)
				return
			}

			// Parse request body into target struct
			if err := parseRequestBody(r, target, config.MaxBodySize); err != nil {
				if config.SkipOnError {
					next.ServeHTTP(w, r)
					return
				}
				WriteErrorResponse(w, r, http.StatusBadRequest, "Invalid request body", err)
				return
			}

			// Validate the parsed struct
			if err := config.Validator.Validate(r.Context(), target); err != nil {
				if validationErrors, ok := err.(validation.ValidationErrors); ok {
					WriteValidationErrorResponse(w, r, validationErrors)
					return
				}
				WriteErrorResponse(w, r, http.StatusBadRequest, "Validation failed", err)
				return
			}

			// Store validated data in context for handler use
			ctx := SetValidatedData(r.Context(), target)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// shouldValidateRequest determines if the request should be validated
func shouldValidateRequest(r *http.Request) bool {
	// Only validate requests with JSON content type
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		return false
	}

	// Check for JSON content type
	if !contains(contentType, "application/json") {
		return false
	}

	// Only validate POST, PUT, PATCH requests
	method := r.Method
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch
}

// parseRequestBody parses the request body into the target struct
func parseRequestBody(r *http.Request, target interface{}, maxSize int64) error {
	// Limit request body size
	r.Body = http.MaxBytesReader(nil, r.Body, maxSize)
	defer r.Body.Close()

	// Decode JSON into target
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields() // Strict JSON parsing

	return decoder.Decode(target)
}

// WriteValidationErrorResponse writes a validation error response
func WriteValidationErrorResponse(w http.ResponseWriter, r *http.Request, errors validation.ValidationErrors) {
	response := ValidationErrorResponse{
		Success:   false,
		Message:   "Validation failed",
		RequestID: GetRequestID(r.Context()),
		Errors:    errors.Fields(),
		Details:   make([]ValidationErrorDetail, len(errors)),
	}

	for i, err := range errors {
		response.Details[i] = ValidationErrorDetail{
			Field:   err.Field,
			Tag:     err.Tag,
			Value:   err.Value,
			Message: err.Message,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-ID", response.RequestID)
	w.WriteHeader(http.StatusUnprocessableEntity)

	json.NewEncoder(w).Encode(response)
}

// ValidationErrorResponse represents a validation error response
type ValidationErrorResponse struct {
	Success   bool                      `json:"success"`
	Message   string                    `json:"message"`
	RequestID string                    `json:"request_id"`
	Errors    map[string]string         `json:"errors"`
	Details   []ValidationErrorDetail   `json:"details"`
}

// ValidationErrorDetail provides detailed validation error information
type ValidationErrorDetail struct {
	Field   string      `json:"field"`
	Tag     string      `json:"tag"`
	Value   interface{} `json:"value,omitempty"`
	Message string      `json:"message"`
}

// Context keys for validation
type contextKey string

const (
	validationTargetKey contextKey = "validation_target"
	validatedDataKey    contextKey = "validated_data"
)

// SetValidationTarget sets the validation target in the request context
func SetValidationTarget(ctx context.Context, target interface{}) context.Context {
	return context.WithValue(ctx, validationTargetKey, target)
}

// GetValidationTarget gets the validation target from the request context
func GetValidationTarget(ctx context.Context) interface{} {
	return ctx.Value(validationTargetKey)
}

// SetValidatedData sets the validated data in the request context
func SetValidatedData(ctx context.Context, data interface{}) context.Context {
	return context.WithValue(ctx, validatedDataKey, data)
}

// GetValidatedData gets the validated data from the request context
func GetValidatedData(ctx context.Context) interface{} {
	return ctx.Value(validatedDataKey)
}

// GetValidatedDataAs gets the validated data from context and type asserts it
func GetValidatedDataAs[T any](ctx context.Context) (*T, bool) {
	data := GetValidatedData(ctx)
	if data == nil {
		return nil, false
	}

	if typed, ok := data.(*T); ok {
		return typed, true
	}

	return nil, false
}

// ValidateRequest is a helper function to validate a request with a specific struct
func ValidateRequest[T any](r *http.Request, validator *validation.Validator) (*T, error) {
	var target T
	
	// Parse request body
	if err := parseRequestBody(r, &target, 1024*1024); err != nil {
		return nil, err
	}

	// Validate
	if err := validator.Validate(r.Context(), &target); err != nil {
		return nil, err
	}

	return &target, nil
}

// WithValidation is a helper to create a validation middleware with a specific struct type
func WithValidation[T any](validator *validation.Validator) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if shouldValidateRequest(r) {
				var target T
				ctx := SetValidationTarget(r.Context(), &target)
				r = r.WithContext(ctx)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && 
		   (s == substr || 
			len(s) > len(substr) && 
			(s[:len(substr)] == substr || 
			 s[len(s)-len(substr):] == substr ||
			 indexOfSubstring(s, substr) >= 0))
}

func indexOfSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}