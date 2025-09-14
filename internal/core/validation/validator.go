package validation

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
)

// Validator wraps go-playground/validator with additional functionality
type Validator struct {
	validator *validator.Validate
	config    Config
}

// Config holds validation configuration
type Config struct {
	// TagName is the struct tag name for validation rules
	TagName string `json:"tag_name" yaml:"tag_name" env:"VALIDATION_TAG_NAME" default:"validate"`
	// RequiredTag is the struct tag name to mark fields as required for validation
	RequiredTag string `json:"required_tag" yaml:"required_tag" env:"VALIDATION_REQUIRED_TAG" default:"json"`
	// FailFast stops validation on first error
	FailFast bool `json:"fail_fast" yaml:"fail_fast" env:"VALIDATION_FAIL_FAST" default:"false"`
	// OptIn enables opt-in validation (only validate fields with validation tags)
	OptIn bool `json:"opt_in" yaml:"opt_in" env:"VALIDATION_OPT_IN" default:"false"`
}

// DefaultConfig returns default validation configuration
func DefaultConfig() Config {
	return Config{
		TagName:     "validate",
		RequiredTag: "json",
		FailFast:    false,
		OptIn:       false,
	}
}

// NewValidator creates a new validator instance
func NewValidator(config Config) *Validator {
	v := validator.New()
	
	// Set custom tag name if specified
	if config.TagName != "validate" {
		v.SetTagName(config.TagName)
	}

	// Register custom validations
	registerCustomValidations(v)

	return &Validator{
		validator: v,
		config:    config,
	}
}

// Validate validates a struct with optional context
func (v *Validator) Validate(ctx context.Context, s interface{}) error {
	if s == nil {
		return nil
	}

	// If opt-in is enabled, only validate fields with validation tags
	if v.config.OptIn {
		return v.validateOptIn(ctx, s)
	}

	// Standard validation
	err := v.validator.StructCtx(ctx, s)
	if err != nil {
		return v.formatValidationError(err)
	}

	return nil
}

// ValidateVar validates a single variable
func (v *Validator) ValidateVar(ctx context.Context, field interface{}, tag string) error {
	err := v.validator.VarCtx(ctx, field, tag)
	if err != nil {
		return v.formatValidationError(err)
	}
	return nil
}

// validateOptIn performs opt-in validation
func (v *Validator) validateOptIn(ctx context.Context, s interface{}) error {
	val := reflect.ValueOf(s)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return fmt.Errorf("validation target must be a struct")
	}

	typ := val.Type()
	var errors ValidationErrors

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		// Skip unexported fields
		if !field.CanInterface() {
			continue
		}

		// Check if field has validation tag
		validationTag := fieldType.Tag.Get(v.config.TagName)
		if validationTag == "" || validationTag == "-" {
			continue
		}

		// Validate field
		err := v.validator.VarCtx(ctx, field.Interface(), validationTag)
		if err != nil {
			if validationErrors, ok := err.(validator.ValidationErrors); ok {
				for _, validationError := range validationErrors {
					errors = append(errors, &FieldError{
						Field:   fieldType.Name,
						Tag:     validationError.Tag(),
						Value:   validationError.Value(),
						Param:   validationError.Param(),
						Message: getErrorMessage(validationError),
					})
				}
			}

			if v.config.FailFast {
				break
			}
		}
	}

	if len(errors) > 0 {
		return errors
	}

	return nil
}

// formatValidationError formats validator errors into custom error types
func (v *Validator) formatValidationError(err error) error {
	if validationErrors, ok := err.(validator.ValidationErrors); ok {
		var errors ValidationErrors
		for _, validationError := range validationErrors {
			errors = append(errors, &FieldError{
				Field:   validationError.Field(),
				Tag:     validationError.Tag(),
				Value:   validationError.Value(),
				Param:   validationError.Param(),
				Message: getErrorMessage(validationError),
			})
		}
		return errors
	}
	return err
}

// registerCustomValidations registers custom validation rules
func registerCustomValidations(v *validator.Validate) {
	// Register custom validation for UUID
	v.RegisterValidation("uuid", validateUUID)
	
	// Register custom validation for slug
	v.RegisterValidation("slug", validateSlug)
	
	// Register custom validation for password strength
	v.RegisterValidation("password", validatePassword)
}

// validateUUID validates UUID format
func validateUUID(fl validator.FieldLevel) bool {
	uuidRegex := `^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`
	return regexp.MustCompile(uuidRegex).MatchString(fl.Field().String())
}

// validateSlug validates slug format (lowercase letters, numbers, hyphens)
func validateSlug(fl validator.FieldLevel) bool {
	slugRegex := `^[a-z0-9]+(?:-[a-z0-9]+)*$`
	return regexp.MustCompile(slugRegex).MatchString(fl.Field().String())
}

// validatePassword validates password strength
func validatePassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()
	if len(password) < 8 {
		return false
	}
	
	// Check for at least one uppercase, one lowercase, one digit
	hasUpper := strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	hasLower := strings.ContainsAny(password, "abcdefghijklmnopqrstuvwxyz")
	hasDigit := strings.ContainsAny(password, "0123456789")
	
	return hasUpper && hasLower && hasDigit
}

// getErrorMessage returns a human-readable error message
func getErrorMessage(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return fmt.Sprintf("%s is required", fe.Field())
	case "email":
		return fmt.Sprintf("%s must be a valid email address", fe.Field())
	case "min":
		return fmt.Sprintf("%s must be at least %s characters long", fe.Field(), fe.Param())
	case "max":
		return fmt.Sprintf("%s must be at most %s characters long", fe.Field(), fe.Param())
	case "uuid":
		return fmt.Sprintf("%s must be a valid UUID", fe.Field())
	case "slug":
		return fmt.Sprintf("%s must be a valid slug", fe.Field())
	case "password":
		return fmt.Sprintf("%s must be at least 8 characters with uppercase, lowercase, and digit", fe.Field())
	default:
		return fmt.Sprintf("%s is invalid", fe.Field())
	}
}