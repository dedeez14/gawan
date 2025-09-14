package validation

import (
	"fmt"
	"strings"
)

// FieldError represents a validation error for a specific field
type FieldError struct {
	Field   string      `json:"field"`
	Tag     string      `json:"tag"`
	Value   interface{} `json:"value,omitempty"`
	Param   string      `json:"param,omitempty"`
	Message string      `json:"message"`
}

// Error returns the error message
func (fe *FieldError) Error() string {
	return fe.Message
}

// ValidationErrors is a slice of FieldError
type ValidationErrors []*FieldError

// Error returns a formatted error message for all validation errors
func (ve ValidationErrors) Error() string {
	if len(ve) == 0 {
		return "validation failed"
	}

	if len(ve) == 1 {
		return ve[0].Error()
	}

	var messages []string
	for _, err := range ve {
		messages = append(messages, err.Error())
	}

	return fmt.Sprintf("validation failed: %s", strings.Join(messages, "; "))
}

// Fields returns a map of field names to their error messages
func (ve ValidationErrors) Fields() map[string]string {
	fields := make(map[string]string)
	for _, err := range ve {
		fields[err.Field] = err.Message
	}
	return fields
}

// HasField checks if a specific field has validation errors
func (ve ValidationErrors) HasField(field string) bool {
	for _, err := range ve {
		if err.Field == field {
			return true
		}
	}
	return false
}

// GetField returns the first validation error for a specific field
func (ve ValidationErrors) GetField(field string) *FieldError {
	for _, err := range ve {
		if err.Field == field {
			return err
		}
	}
	return nil
}

// GetFieldErrors returns all validation errors for a specific field
func (ve ValidationErrors) GetFieldErrors(field string) []*FieldError {
	var errors []*FieldError
	for _, err := range ve {
		if err.Field == field {
			errors = append(errors, err)
		}
	}
	return errors
}