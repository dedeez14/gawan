package middleware

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"Gawan/internal/core/errorsx"
)

// ErrorMiddleware handles errors and formats them appropriately
func ErrorMiddleware() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		var err error
		var appErr *errorsx.AppError

		// Handle panic recovery
		if recovered != nil {
			if e, ok := recovered.(error); ok {
				err = e
			} else {
				err = fmt.Errorf("%v", recovered)
			}

			// Create AppError from panic
			appErr = errorsx.Wrap(err, errorsx.ErrorTypeInternal, "Internal server error")
			appErr = appErr.WithContext("panic", true)
			appErr = appErr.WithContext("stack_trace", string(debug.Stack()))
		}

		// Get request ID if available
		requestID := c.GetString("request_id")
		if requestID == "" {
			requestID = c.GetHeader("X-Request-ID")
		}
		if requestID != "" {
			appErr = appErr.WithRequestID(requestID)
		}

		// Add request context
		appErr = appErr.WithContext("method", c.Request.Method)
		appErr = appErr.WithContext("path", c.Request.URL.Path)
		appErr = appErr.WithContext("user_agent", c.GetHeader("User-Agent"))
		appErr = appErr.WithContext("remote_addr", c.ClientIP())

		// Handle the error
		handleError(c, appErr)
	})
}

// ErrorHandler middleware for handling errors in the chain
func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Check if there are any errors
		if len(c.Errors) > 0 {
			lastError := c.Errors.Last()
			var appErr *errorsx.AppError

			// Check if it's already an AppError
			if ae, ok := lastError.Err.(*errorsx.AppError); ok {
				appErr = ae
			} else {
				// Wrap the error
				appErr = errorsx.Wrap(lastError.Err, errorsx.ErrorTypeInternal, "Internal server error")
			}

			// Get request ID if available
			requestID := c.GetString("request_id")
			if requestID == "" {
				requestID = c.GetHeader("X-Request-ID")
			}
			if requestID != "" {
				appErr = appErr.WithRequestID(requestID)
			}

			// Add request context
			appErr = appErr.WithContext("method", c.Request.Method)
			appErr = appErr.WithContext("path", c.Request.URL.Path)
			appErr = appErr.WithContext("user_agent", c.GetHeader("User-Agent"))
			appErr = appErr.WithContext("remote_addr", c.ClientIP())

			// Handle the error
			handleError(c, appErr)
			return
		}
	}
}

// handleError processes and responds to errors
func handleError(c *gin.Context, appErr *errorsx.AppError) {
	// Log the error
	logError(appErr)

	// Determine response format based on environment
	isProduction := strings.ToLower(os.Getenv("ENV")) == "production" ||
		strings.ToLower(os.Getenv("GIN_MODE")) == "release"

	if isProduction {
		// Production: minimal error info
		response := appErr.FormatForProduction()
		c.JSON(appErr.StatusCode, response)
	} else {
		// Development: detailed error info
		response := map[string]interface{}{
			"error":       true,
			"type":        appErr.Type,
			"message":     appErr.Message,
			"details":     appErr.Details,
			"code":        appErr.Code,
			"status_code": appErr.StatusCode,
			"context":     appErr.Context,
			"stack":       appErr.Stack,
			"timestamp":   appErr.Timestamp,
			"request_id":  appErr.RequestID,
		}

		// Include cause if present
		if appErr.Cause != nil {
			response["cause"] = appErr.Cause.Error()
		}

		c.JSON(appErr.StatusCode, response)
	}

	// Abort the request
	c.Abort()
}

// logError logs the error with appropriate level
func logError(appErr *errorsx.AppError) {
	// Determine log level based on error type
	logLevel := "ERROR"
	switch appErr.Type {
	case errorsx.ErrorTypeValidation, errorsx.ErrorTypeNotFound:
		logLevel = "WARN"
	case errorsx.ErrorTypeUnauthorized, errorsx.ErrorTypeForbidden:
		logLevel = "WARN"
	case errorsx.ErrorTypeInternal, errorsx.ErrorTypeDatabase:
		logLevel = "ERROR"
	case errorsx.ErrorTypeExternal, errorsx.ErrorTypeTimeout:
		logLevel = "ERROR"
	}

	// Check if we're in development mode
	isProduction := strings.ToLower(os.Getenv("ENV")) == "production" ||
		strings.ToLower(os.Getenv("GIN_MODE")) == "release"

	if !isProduction {
		// Development: pretty formatted error
		fmt.Print(appErr.FormatForDevelopment())
	} else {
		// Production: structured logging
		errorData, _ := json.Marshal(appErr.FormatForProduction())
		log.Printf("[%s] %s %s", logLevel, time.Now().Format(time.RFC3339), string(errorData))
	}
}

// Helper functions for common error responses

// AbortWithError aborts the request with an AppError
func AbortWithError(c *gin.Context, appErr *errorsx.AppError) {
	c.Error(appErr)
	c.Abort()
}

// AbortWithValidationError aborts with a validation error
func AbortWithValidationError(c *gin.Context, message string) {
	AbortWithError(c, errorsx.ValidationError(message))
}

// AbortWithNotFoundError aborts with a not found error
func AbortWithNotFoundError(c *gin.Context, message string) {
	AbortWithError(c, errorsx.NotFoundError(message))
}

// AbortWithUnauthorizedError aborts with an unauthorized error
func AbortWithUnauthorizedError(c *gin.Context, message string) {
	AbortWithError(c, errorsx.UnauthorizedError(message))
}

// AbortWithForbiddenError aborts with a forbidden error
func AbortWithForbiddenError(c *gin.Context, message string) {
	AbortWithError(c, errorsx.ForbiddenError(message))
}

// AbortWithInternalError aborts with an internal error
func AbortWithInternalError(c *gin.Context, message string) {
	AbortWithError(c, errorsx.InternalError(message))
}

// AbortWithDatabaseError aborts with a database error
func AbortWithDatabaseError(c *gin.Context, message string) {
	AbortWithError(c, errorsx.DatabaseError(message))
}

// AbortWithExternalError aborts with an external service error
func AbortWithExternalError(c *gin.Context, message string) {
	AbortWithError(c, errorsx.ExternalError(message))
}

// AbortWithTimeoutError aborts with a timeout error
func AbortWithTimeoutError(c *gin.Context, message string) {
	AbortWithError(c, errorsx.TimeoutError(message))
}

// AbortWithConflictError aborts with a conflict error
func AbortWithConflictError(c *gin.Context, message string) {
	AbortWithError(c, errorsx.ConflictError(message))
}