package multitenancy

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// MultiTenancyManager manages all multi-tenancy components
type MultiTenancyManager struct {
	service    TenantService
	resolver   TenantResolver
	middleware *TenantMiddleware
	config     *MultiTenancyConfig
}

// MultiTenancyConfig holds configuration for multi-tenancy
type MultiTenancyConfig struct {
	// Tenant resolution configuration
	Resolution *TenantResolutionConfig `json:"resolution,omitempty"`
	
	// Service configuration
	Service *ServiceConfig `json:"service,omitempty"`
	
	// Cache configuration
	Cache *CacheConfig `json:"cache,omitempty"`
	
	// Middleware configuration
	Middleware *MiddlewareConfig `json:"middleware,omitempty"`
	
	// Enable development mode features
	DevelopmentMode bool `json:"development_mode,omitempty"`
	
	// Default tenant for fallback
	DefaultTenant *Tenant `json:"default_tenant,omitempty"`
}

// CacheConfig holds cache configuration
type CacheConfig struct {
	Enabled bool          `json:"enabled,omitempty"`
	TTL     time.Duration `json:"ttl,omitempty"`
	Size    int           `json:"size,omitempty"`
}

// DefaultMultiTenancyConfig returns default configuration
func DefaultMultiTenancyConfig() *MultiTenancyConfig {
	return &MultiTenancyConfig{
		Resolution: DefaultTenantResolutionConfig(),
		Service:    DefaultServiceConfig(),
		Cache: &CacheConfig{
			Enabled: true,
			TTL:     10 * time.Minute,
			Size:    1000,
		},
		Middleware: &MiddlewareConfig{
			Required:           false,
			SkipPaths:          []string{"/health", "/metrics"},
			ErrorHandler:       nil,
			NotFoundHandler:    nil,
			InactiveHandler:    nil,
			SuspendedHandler:   nil,
			ContextKey:         DefaultTenantContextKey,
			HeaderName:         "X-Tenant-ID",
			QueryParam:         "tenant",
			AllowQueryFallback: true,
		},
		DevelopmentMode: false,
	}
}

// NewMultiTenancyManager creates a new multi-tenancy manager
func NewMultiTenancyManager(service TenantService, resolver TenantResolver, config *MultiTenancyConfig) *MultiTenancyManager {
	if config == nil {
		config = DefaultMultiTenancyConfig()
	}

	middleware := NewTenantMiddleware(resolver, config.Middleware)

	return &MultiTenancyManager{
		service:    service,
		resolver:   resolver,
		middleware: middleware,
		config:     config,
	}
}

// Service returns the tenant service
func (m *MultiTenancyManager) Service() TenantService {
	return m.service
}

// Resolver returns the tenant resolver
func (m *MultiTenancyManager) Resolver() TenantResolver {
	return m.resolver
}

// Middleware returns the tenant middleware
func (m *MultiTenancyManager) Middleware() gin.HandlerFunc {
	return m.middleware.Handler()
}

// RequiredMiddleware returns middleware that requires a tenant
func (m *MultiTenancyManager) RequiredMiddleware() gin.HandlerFunc {
	return m.middleware.RequiredHandler()
}

// OptionalMiddleware returns middleware that optionally resolves a tenant
func (m *MultiTenancyManager) OptionalMiddleware() gin.HandlerFunc {
	return m.middleware.OptionalHandler()
}

// Config returns the configuration
func (m *MultiTenancyManager) Config() *MultiTenancyConfig {
	return m.config
}

// SetupBuilder provides a fluent interface for setting up multi-tenancy
type SetupBuilder struct {
	config     *MultiTenancyConfig
	repository TenantRepository
	cache      TenantCache
	err        error
}

// NewSetupBuilder creates a new setup builder
func NewSetupBuilder() *SetupBuilder {
	return &SetupBuilder{
		config: DefaultMultiTenancyConfig(),
	}
}

// WithConfig sets the configuration
func (b *SetupBuilder) WithConfig(config *MultiTenancyConfig) *SetupBuilder {
	if b.err != nil {
		return b
	}
	b.config = config
	return b
}

// WithGormRepository sets up GORM repository
func (b *SetupBuilder) WithGormRepository(db *gorm.DB) *SetupBuilder {
	if b.err != nil {
		return b
	}
	b.repository = NewGormTenantRepository(db)
	return b
}

// WithSQLRepository sets up SQL repository
func (b *SetupBuilder) WithSQLRepository(db *sql.DB) *SetupBuilder {
	if b.err != nil {
		return b
	}
	b.repository = NewSQLTenantRepository(db)
	return b
}

// WithMemoryRepository sets up memory repository (for testing)
func (b *SetupBuilder) WithMemoryRepository() *SetupBuilder {
	if b.err != nil {
		return b
	}
	b.repository = NewMemoryTenantRepository()
	return b
}

// WithMemoryCache sets up memory cache
func (b *SetupBuilder) WithMemoryCache() *SetupBuilder {
	if b.err != nil {
		return b
	}
	if b.config.Cache != nil && b.config.Cache.Enabled {
		b.cache = NewMemoryTenantCache(b.config.Cache.Size, b.config.Cache.TTL)
	}
	return b
}

// WithCustomCache sets up custom cache
func (b *SetupBuilder) WithCustomCache(cache TenantCache) *SetupBuilder {
	if b.err != nil {
		return b
	}
	b.cache = cache
	return b
}

// EnableDevelopmentMode enables development mode
func (b *SetupBuilder) EnableDevelopmentMode() *SetupBuilder {
	if b.err != nil {
		return b
	}
	b.config.DevelopmentMode = true
	return b
}

// WithDefaultTenant sets a default tenant for fallback
func (b *SetupBuilder) WithDefaultTenant(tenant *Tenant) *SetupBuilder {
	if b.err != nil {
		return b
	}
	b.config.DefaultTenant = tenant
	return b
}

// Build creates the multi-tenancy manager
func (b *SetupBuilder) Build() (*MultiTenancyManager, error) {
	if b.err != nil {
		return nil, b.err
	}

	if b.repository == nil {
		return nil, fmt.Errorf("repository is required")
	}

	// Create service
	service := NewDefaultTenantService(b.repository, b.cache, b.config.Service)

	// Create resolver
	var resolver TenantResolver
	if b.config.Cache != nil && b.config.Cache.Enabled && b.cache != nil {
		baseResolver := NewHTTPTenantResolver(service, b.config.Resolution)
		resolver = NewCachingTenantResolver(baseResolver, b.cache)
	} else {
		resolver = NewHTTPTenantResolver(service, b.config.Resolution)
	}

	// Create manager
	manager := NewMultiTenancyManager(service, resolver, b.config)

	return manager, nil
}

// QuickSetup provides quick setup functions for common scenarios

// SetupWithGorm sets up multi-tenancy with GORM
func SetupWithGorm(db *gorm.DB, config *MultiTenancyConfig) (*MultiTenancyManager, error) {
	return NewSetupBuilder().
		WithConfig(config).
		WithGormRepository(db).
		WithMemoryCache().
		Build()
}

// SetupWithSQL sets up multi-tenancy with SQL
func SetupWithSQL(db *sql.DB, config *MultiTenancyConfig) (*MultiTenancyManager, error) {
	return NewSetupBuilder().
		WithConfig(config).
		WithSQLRepository(db).
		WithMemoryCache().
		Build()
}

// SetupInMemory sets up multi-tenancy with in-memory storage (for testing)
func SetupInMemory(config *MultiTenancyConfig) (*MultiTenancyManager, error) {
	return NewSetupBuilder().
		WithConfig(config).
		WithMemoryRepository().
		WithMemoryCache().
		Build()
}

// SetupForDevelopment sets up multi-tenancy for development
func SetupForDevelopment() (*MultiTenancyManager, error) {
	config := DefaultMultiTenancyConfig()
	config.DevelopmentMode = true
	config.Middleware.Required = false
	config.Resolution.Strategies = []ResolutionStrategy{
		ResolutionStrategyHeader,
		ResolutionStrategyQuery,
		ResolutionStrategySubdomain,
	}

	return NewSetupBuilder().
		WithConfig(config).
		WithMemoryRepository().
		WithMemoryCache().
		EnableDevelopmentMode().
		Build()
}

// SetupForProduction sets up multi-tenancy for production
func SetupForProduction(db *gorm.DB) (*MultiTenancyManager, error) {
	config := DefaultMultiTenancyConfig()
	config.DevelopmentMode = false
	config.Middleware.Required = true
	config.Resolution.Strategies = []ResolutionStrategy{
		ResolutionStrategySubdomain,
		ResolutionStrategyDomain,
		ResolutionStrategyHeader,
	}

	return NewSetupBuilder().
		WithConfig(config).
		WithGormRepository(db).
		WithMemoryCache().
		Build()
}

// Utility functions for common operations

// CreateDefaultTenant creates a default tenant for development
func CreateDefaultTenant(ctx context.Context, service TenantService) (*Tenant, error) {
	tenant := &Tenant{
		ID:        "default",
		Name:      "Default Tenant",
		Slug:      "default",
		Domain:    "localhost",
		Subdomain: "app",
		Status:    TenantStatusActive,
		Settings: map[string]string{
			"theme":    "default",
			"language": "en",
			"timezone": "UTC",
		},
		Metadata: map[string]string{
			"created_by": "system",
			"type":       "default",
		},
	}

	err := service.CreateTenant(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("failed to create default tenant: %w", err)
	}

	return tenant, nil
}

// SeedDevelopmentTenants creates sample tenants for development
func SeedDevelopmentTenants(ctx context.Context, service TenantService) error {
	tenants := []*Tenant{
		{
			ID:        "tenant1",
			Name:      "Acme Corporation",
			Slug:      "acme",
			Domain:    "acme.example.com",
			Subdomain: "acme",
			Status:    TenantStatusActive,
			Settings: map[string]string{
				"theme":    "corporate",
				"language": "en",
				"timezone": "America/New_York",
			},
			Metadata: map[string]string{
				"industry": "technology",
				"size":     "large",
			},
		},
		{
			ID:        "tenant2",
			Name:      "Beta Solutions",
			Slug:      "beta",
			Domain:    "beta.example.com",
			Subdomain: "beta",
			Status:    TenantStatusActive,
			Settings: map[string]string{
				"theme":    "modern",
				"language": "en",
				"timezone": "Europe/London",
			},
			Metadata: map[string]string{
				"industry": "consulting",
				"size":     "medium",
			},
		},
		{
			ID:        "tenant3",
			Name:      "Gamma Startup",
			Slug:      "gamma",
			Domain:    "gamma.example.com",
			Subdomain: "gamma",
			Status:    TenantStatusInactive,
			Settings: map[string]string{
				"theme":    "minimal",
				"language": "en",
				"timezone": "America/Los_Angeles",
			},
			Metadata: map[string]string{
				"industry": "fintech",
				"size":     "small",
			},
		},
	}

	for _, tenant := range tenants {
		if err := service.CreateTenant(ctx, tenant); err != nil {
			return fmt.Errorf("failed to create tenant %s: %w", tenant.Name, err)
		}
	}

	return nil
}

// ValidateMultiTenancySetup validates the multi-tenancy setup
func ValidateMultiTenancySetup(ctx context.Context, manager *MultiTenancyManager) error {
	// Test service
	if _, err := manager.Service().ListTenants(ctx, 0, 1); err != nil {
		return fmt.Errorf("service validation failed: %w", err)
	}

	// Test resolver (if possible)
	if httpResolver, ok := manager.Resolver().(*HTTPTenantResolver); ok {
		// Create a mock request context for testing
		_ = httpResolver // We could test this with a mock HTTP context
	}

	return nil
}

// GetTenantFromGinContext is a helper to get tenant from Gin context
func GetTenantFromGinContext(c *gin.Context) (*Tenant, bool) {
	return GetTenantFromContext(c.Request.Context())
}

// RequireTenantFromGinContext gets tenant from Gin context or aborts with error
func RequireTenantFromGinContext(c *gin.Context) (*Tenant, bool) {
	tenant, exists := GetTenantFromGinContext(c)
	if !exists {
		c.JSON(400, gin.H{"error": "Tenant context required"})
		c.Abort()
		return nil, false
	}
	return tenant, true
}

// GetTenantIDFromGinContext gets tenant ID from Gin context
func GetTenantIDFromGinContext(c *gin.Context) (string, bool) {
	tenant, exists := GetTenantFromGinContext(c)
	if !exists {
		return "", false
	}
	return tenant.ID, true
}