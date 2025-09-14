package httpx

import (
	"net/http"

	"Gawan/internal/core/errorsx"
	"Gawan/internal/core/logx"
)

// ErrorHandlerMiddleware handles application errors
func ErrorHandlerMiddleware(logger *logx.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					requestID := GetRequestIDFromRequest(r)
					logger.WithRequestID(requestID).Error("Panic recovered",
						"error", err,
						"path", r.URL.Path,
						"method", r.Method,
					)

					// Return internal server error
					appErr := errorsx.InternalServerError("Internal server error", nil)
					WriteErrorResponse(w, r, appErr)
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// WriteErrorResponse writes an error response
func WriteErrorResponse(w http.ResponseWriter, r *http.Request, err *errorsx.AppError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.Code)

	errorResponse := map[string]interface{}{
		"error": map[string]interface{}{
			"code":       err.Code,
			"message":    err.Message,
			"request_id": GetRequestIDFromRequest(r),
		},
	}

	WriteJSON(w, errorResponse)
}

// HandleError is a helper function to handle errors in handlers
func HandleError(w http.ResponseWriter, r *http.Request, err error) {
	if appErr, ok := err.(*errorsx.AppError); ok {
		WriteErrorResponse(w, r, appErr)
		return
	}

	// Convert generic error to internal server error
	appErr := errorsx.InternalServerError("Internal server error", err)
	WriteErrorResponse(w, r, appErr)
}