package multitenancy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Tenant represents a tenant in the multi-tenant system
type Tenant struct {
	ID          string            `json:"id" db:"id"`
	Name        string            `json:"name" db:"name"`
	Slug        string            `json:"slug" db:"slug"`
	Domain      string            `json:"domain,omitempty" db:"domain"`
	Subdomain   string            `json:"subdomain,omitempty" db:"subdomain"`
	Status      TenantStatus      `json:"status" db:"status"`
	Settings    map[string]string `json:"settings,omitempty" db:"settings"`
	Metadata    map[string]string `json:"metadata,omitempty" db:"metadata"`
	CreatedAt   time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" db:"updated_at"`
	ActivatedAt *time.Time        `json:"activated_at,omitempty" db:"activated_at"`
	SuspendedAt *time.Time        `json:"suspended_at,omitempty" db:"suspended_at"`
}

// TenantStatus represents the status of a tenant
type TenantStatus string

const (
	TenantStatusActive    TenantStatus = "active"
	TenantStatusInactive  TenantStatus = "inactive"
	TenantStatusSuspended TenantStatus = "suspended"
	TenantStatusDeleted   TenantStatus = "deleted"
)

// IsActive checks if the tenant is active
func (t *Tenant) IsActive() bool {
	return t.Status == TenantStatusActive
}

// IsAccessible checks if the tenant can be accessed
func (t *Tenant) IsAccessible() bool {
	return t.Status == TenantStatusActive || t.Status == TenantStatusInactive
}

// GetSetting retrieves a tenant setting
func (t *Tenant) GetSetting(key string) (string, bool) {
	if t.Settings == nil {
		return "", false
	}
	value, exists := t.Settings[key]
	return value, exists
}

// SetSetting sets a tenant setting
func (t *Tenant) SetSetting(key, value string) {
	if t.Settings == nil {
		t.Settings = make(map[string]string)
	}
	t.Settings[key] = value
}

// GetMetadata retrieves tenant metadata
func (t *Tenant) GetMetadata(key string) (string, bool) {
	if t.Metadata == nil {
		return "", false
	}
	value, exists := t.Metadata[key]
	return value, exists
}

// SetMetadata sets tenant metadata
func (t *Tenant) SetMetadata(key, value string) {
	if t.Metadata == nil {
		t.Metadata = make(map[string]string)
	}
	t.Metadata[key] = value
}

// Validate validates the tenant data
func (t *Tenant) Validate() error {
	if t.ID == "" {
		return errors.New("tenant ID is required")
	}
	if t.Name == "" {
		return errors.New("tenant name is required")
	}
	if t.Slug == "" {
		return errors.New("tenant slug is required")
	}
	if !isValidSlug(t.Slug) {
		return errors.New("tenant slug must contain only lowercase letters, numbers, and hyphens")
	}
	if t.Status == "" {
		t.Status = TenantStatusInactive
	}
	return nil
}

// TenantContext represents tenant-specific context information
type TenantContext struct {
	Tenant    *Tenant
	UserID    string
	RequestID string
	Headers   map[string]string
}

// TenantRepository defines the interface for tenant data access
type TenantRepository interface {
	// GetByID retrieves a tenant by ID
	GetByID(ctx context.Context, id string) (*Tenant, error)
	
	// GetBySlug retrieves a tenant by slug
	GetBySlug(ctx context.Context, slug string) (*Tenant, error)
	
	// GetByDomain retrieves a tenant by domain
	GetByDomain(ctx context.Context, domain string) (*Tenant, error)
	
	// GetBySubdomain retrieves a tenant by subdomain
	GetBySubdomain(ctx context.Context, subdomain string) (*Tenant, error)
	
	// Create creates a new tenant
	Create(ctx context.Context, tenant *Tenant) error
	
	// Update updates an existing tenant
	Update(ctx context.Context, tenant *Tenant) error
	
	// Delete deletes a tenant (soft delete)
	Delete(ctx context.Context, id string) error
	
	// List retrieves all tenants with pagination
	List(ctx context.Context, offset, limit int) ([]*Tenant, error)
	
	// Count returns the total number of tenants
	Count(ctx context.Context) (int64, error)
}

// TenantService defines the interface for tenant business logic
type TenantService interface {
	// CreateTenant creates a new tenant
	CreateTenant(ctx context.Context, tenant *Tenant) error
	
	// GetTenant retrieves a tenant by ID
	GetTenant(ctx context.Context, id string) (*Tenant, error)
	
	// UpdateTenant updates an existing tenant
	UpdateTenant(ctx context.Context, tenant *Tenant) error
	
	// DeleteTenant deletes a tenant
	DeleteTenant(ctx context.Context, id string) error
	
	// ActivateTenant activates a tenant
	ActivateTenant(ctx context.Context, id string) error
	
	// SuspendTenant suspends a tenant
	SuspendTenant(ctx context.Context, id string) error
	
	// ListTenants retrieves all tenants with pagination
	ListTenants(ctx context.Context, offset, limit int) ([]*Tenant, error)
}

// TenantResolver defines the interface for resolving tenants from requests
type TenantResolver interface {
	// ResolveTenant resolves a tenant from the given context
	ResolveTenant(ctx context.Context) (*Tenant, error)
}

// ResolutionStrategy defines how tenants are resolved
type ResolutionStrategy string

const (
	ResolutionStrategyHeader    ResolutionStrategy = "header"
	ResolutionStrategySubdomain ResolutionStrategy = "subdomain"
	ResolutionStrategyDomain    ResolutionStrategy = "domain"
	ResolutionStrategyPath      ResolutionStrategy = "path"
	ResolutionStrategyQuery     ResolutionStrategy = "query"
)

// TenantConfig holds configuration for multi-tenancy
type TenantConfig struct {
	// Primary resolution strategy
	Strategy ResolutionStrategy `json:"strategy"`
	
	// Fallback strategies (tried in order if primary fails)
	FallbackStrategies []ResolutionStrategy `json:"fallback_strategies,omitempty"`
	
	// Header name for header-based resolution
	HeaderName string `json:"header_name,omitempty"`
	
	// Query parameter name for query-based resolution
	QueryParam string `json:"query_param,omitempty"`
	
	// Path prefix for path-based resolution
	PathPrefix string `json:"path_prefix,omitempty"`
	
	// Default tenant ID/slug to use when resolution fails
	DefaultTenant string `json:"default_tenant,omitempty"`
	
	// Whether to allow access without a resolved tenant
	AllowNoTenant bool `json:"allow_no_tenant,omitempty"`
	
	// Cache settings
	CacheEnabled bool          `json:"cache_enabled,omitempty"`
	CacheTTL     time.Duration `json:"cache_ttl,omitempty"`
}

// DefaultTenantConfig returns default tenant configuration
func DefaultTenantConfig() *TenantConfig {
	return &TenantConfig{
		Strategy:           ResolutionStrategyHeader,
		FallbackStrategies: []ResolutionStrategy{ResolutionStrategySubdomain},
		HeaderName:         "X-Tenant-ID",
		QueryParam:         "tenant",
		PathPrefix:         "/tenant",
		AllowNoTenant:      false,
		CacheEnabled:       true,
		CacheTTL:           5 * time.Minute,
	}
}

// Context keys for tenant information
type contextKey string

const (
	TenantContextKey        contextKey = "tenant"
	TenantIDContextKey      contextKey = "tenant_id"
	TenantContextInfoKey    contextKey = "tenant_context"
	TenantResolutionInfoKey contextKey = "tenant_resolution_info"
)

// TenantResolutionInfo contains information about how a tenant was resolved
type TenantResolutionInfo struct {
	Strategy   ResolutionStrategy `json:"strategy"`
	Value      string             `json:"value"`
	ResolvedAt time.Time          `json:"resolved_at"`
	CacheHit   bool               `json:"cache_hit"`
}

// Context helper functions

// WithTenant adds a tenant to the context
func WithTenant(ctx context.Context, tenant *Tenant) context.Context {
	ctx = context.WithValue(ctx, TenantContextKey, tenant)
	if tenant != nil {
		ctx = context.WithValue(ctx, TenantIDContextKey, tenant.ID)
	}
	return ctx
}

// TenantFromContext retrieves the tenant from context
func TenantFromContext(ctx context.Context) (*Tenant, bool) {
	tenant, ok := ctx.Value(TenantContextKey).(*Tenant)
	return tenant, ok
}

// TenantIDFromContext retrieves the tenant ID from context
func TenantIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(TenantIDContextKey).(string)
	return id, ok
}

// WithTenantContext adds tenant context information
func WithTenantContext(ctx context.Context, tenantCtx *TenantContext) context.Context {
	return context.WithValue(ctx, TenantContextInfoKey, tenantCtx)
}

// TenantContextFromContext retrieves tenant context information
func TenantContextFromContext(ctx context.Context) (*TenantContext, bool) {
	tenantCtx, ok := ctx.Value(TenantContextInfoKey).(*TenantContext)
	return tenantCtx, ok
}

// WithTenantResolutionInfo adds tenant resolution information to context
func WithTenantResolutionInfo(ctx context.Context, info *TenantResolutionInfo) context.Context {
	return context.WithValue(ctx, TenantResolutionInfoKey, info)
}

// TenantResolutionInfoFromContext retrieves tenant resolution information
func TenantResolutionInfoFromContext(ctx context.Context) (*TenantResolutionInfo, bool) {
	info, ok := ctx.Value(TenantResolutionInfoKey).(*TenantResolutionInfo)
	return info, ok
}

// Utility functions

// isValidSlug checks if a slug is valid
func isValidSlug(slug string) bool {
	if slug == "" {
		return false
	}
	
	// Must start and end with alphanumeric character
	if !isAlphanumeric(rune(slug[0])) || !isAlphanumeric(rune(slug[len(slug)-1])) {
		return false
	}
	
	// Can contain lowercase letters, numbers, and hyphens
	for _, r := range slug {
		if !isAlphanumeric(r) && r != '-' {
			return false
		}
	}
	
	// Cannot contain consecutive hyphens
	if strings.Contains(slug, "--") {
		return false
	}
	
	return true
}

// isAlphanumeric checks if a rune is alphanumeric (lowercase)
func isAlphanumeric(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
}

// GenerateSlug generates a slug from a name
func GenerateSlug(name string) string {
	// Convert to lowercase
	slug := strings.ToLower(name)
	
	// Replace spaces and special characters with hyphens
	slug = strings.ReplaceAll(slug, " ", "-")
	slug = strings.ReplaceAll(slug, "_", "-")
	
	// Remove non-alphanumeric characters except hyphens
	var result strings.Builder
	for _, r := range slug {
		if isAlphanumeric(r) || r == '-' {
			result.WriteRune(r)
		}
	}
	slug = result.String()
	
	// Remove consecutive hyphens
	for strings.Contains(slug, "--") {
		slug = strings.ReplaceAll(slug, "--", "-")
	}
	
	// Trim hyphens from start and end
	slug = strings.Trim(slug, "-")
	
	return slug
}

// ExtractSubdomain extracts subdomain from a host
func ExtractSubdomain(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) < 3 {
		return ""
	}
	return parts[0]
}

// ExtractDomain extracts domain from a host
func ExtractDomain(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// Errors
var (
	ErrTenantNotFound      = errors.New("tenant not found")
	ErrTenantNotResolved   = errors.New("tenant could not be resolved")
	ErrTenantInactive      = errors.New("tenant is inactive")
	ErrTenantSuspended     = errors.New("tenant is suspended")
	ErrTenantDeleted       = errors.New("tenant is deleted")
	ErrInvalidTenantID     = errors.New("invalid tenant ID")
	ErrInvalidTenantSlug   = errors.New("invalid tenant slug")
	ErrTenantAlreadyExists = errors.New("tenant already exists")
	ErrTenantRequired      = errors.New("tenant is required")
)

// TenantError represents a tenant-specific error
type TenantError struct {
	TenantID string
	Message  string
	Cause    error
}

// Error implements the error interface
func (e *TenantError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("tenant %s: %s: %v", e.TenantID, e.Message, e.Cause)
	}
	return fmt.Sprintf("tenant %s: %s", e.TenantID, e.Message)
}

// Unwrap returns the underlying error
func (e *TenantError) Unwrap() error {
	return e.Cause
}

// NewTenantError creates a new tenant error
func NewTenantError(tenantID, message string, cause error) *TenantError {
	return &TenantError{
		TenantID: tenantID,
		Message:  message,
		Cause:    cause,
	}
}