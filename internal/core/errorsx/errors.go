package errorsx

import (
	"fmt"
	"net/http"
)

// AppError represents an application error
type AppError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Err     error  `json:"-"`
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// NewAppError creates a new application error
func NewAppError(code int, message string, err error) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

// Common error constructors
func BadRequest(message string) *AppError {
	return NewAppError(http.StatusBadRequest, message, nil)
}

func NotFound(message string) *AppError {
	return NewAppError(http.StatusNotFound, message, nil)
}

func InternalServerError(message string, err error) *AppError {
	return NewAppError(http.StatusInternalServerError, message, err)
}

func Unauthorized(message string) *AppError {
	return NewAppError(http.StatusUnauthorized, message, nil)
}

func Forbidden(message string) *AppError {
	return NewAppError(http.StatusForbidden, message, nil)
}