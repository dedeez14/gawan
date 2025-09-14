package httpx

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

// RequestIDKey is the context key for request ID
type RequestIDKey string

const (
	// RequestIDContextKey is the context key for request ID
	RequestIDContextKey RequestIDKey = "request_id"
	// RequestIDHeader is the header name for request ID
	RequestIDHeader = "X-Request-ID"
)

// RequestIDMiddleware adds request ID to context and response header
func RequestIDMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get request ID from header or generate new one
			requestID := r.Header.Get(RequestIDHeader)
			if requestID == "" {
				requestID = uuid.New().String()
			}

			// Add request ID to context
			ctx := context.WithValue(r.Context(), RequestIDContextKey, requestID)
			r = r.WithContext(ctx)

			// Add request ID to response header
			w.Header().Set(RequestIDHeader, requestID)

			next.ServeHTTP(w, r)
		})
	}
}

// GetRequestID extracts request ID from context
func GetRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value(RequestIDContextKey).(string); ok {
		return requestID
	}
	return ""
}

// GetRequestIDFromRequest extracts request ID from request context
func GetRequestIDFromRequest(r *http.Request) string {
	return GetRequestID(r.Context())
}