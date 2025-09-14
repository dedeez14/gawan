package multitenancy

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// TenantMiddleware provides tenant resolution middleware for Gin
type TenantMiddleware struct {
	resolver TenantResolver
	config   *MiddlewareConfig
}

// MiddlewareConfig holds configuration for tenant middleware
type MiddlewareConfig struct {
	// Skip tenant resolution for certain paths
	SkipPaths []string `json:"skip_paths,omitempty"`
	
	// Skip tenant resolution for certain methods
	SkipMethods []string `json:"skip_methods,omitempty"`
	
	// Require tenant for all requests (return 400 if not found)
	RequireTenant bool `json:"require_tenant,omitempty"`
	
	// Custom error handler for tenant resolution failures
	ErrorHandler func(*gin.Context, error) `json:"-"`
	
	// Custom success handler called after successful tenant resolution
	SuccessHandler func(*gin.Context, *Tenant) `json:"-"`
	
	// Add tenant information to response headers
	AddResponseHeaders bool `json:"add_response_headers,omitempty"`
	
	// Log tenant resolution information
	LogResolution bool `json:"log_resolution,omitempty"`
	
	// Timeout for tenant resolution
	Timeout time.Duration `json:"timeout,omitempty"`
}

// DefaultMiddlewareConfig returns default middleware configuration
func DefaultMiddlewareConfig() *MiddlewareConfig {
	return &MiddlewareConfig{
		SkipPaths:          []string{"/health", "/metrics", "/favicon.ico"},
		SkipMethods:        []string{"OPTIONS"},
		RequireTenant:      false,
		AddResponseHeaders: true,
		LogResolution:      true,
		Timeout:            5 * time.Second,
	}
}

// NewTenantMiddleware creates a new tenant middleware
func NewTenantMiddleware(resolver TenantResolver, config *MiddlewareConfig) *TenantMiddleware {
	if config == nil {
		config = DefaultMiddlewareConfig()
	}
	return &TenantMiddleware{
		resolver: resolver,
		config:   config,
	}
}

// Handler returns the Gin middleware handler
func (m *TenantMiddleware) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if we should skip tenant resolution
		if m.shouldSkip(c) {
			c.Next()
			return
		}

		// Set timeout if configured
		ctx := c.Request.Context()
		if m.config.Timeout > 0 {
			var cancel func()
			ctx, cancel = context.WithTimeout(ctx, m.config.Timeout)
			defer cancel()
		}

		// Resolve tenant
		tenant, err := m.resolver.ResolveTenant(c)
		if err != nil {
			m.handleError(c, err)
			return
		}

		// Handle case where no tenant was resolved
		if tenant == nil {
			if m.config.RequireTenant {
				m.handleError(c, ErrTenantRequired)
				return
			}
			// Continue without tenant
			c.Next()
			return
		}

		// Add tenant to context
		ctx = WithTenant(ctx, tenant)
		c.Request = c.Request.WithContext(ctx)

		// Add tenant context information
		tenantCtx := &TenantContext{
			Tenant:    tenant,
			RequestID: c.GetString("request_id"),
			Headers:   make(map[string]string),
		}

		// Copy relevant headers
		for name, values := range c.Request.Header {
			if len(values) > 0 {
				tenantCtx.Headers[name] = values[0]
			}
		}

		ctx = WithTenantContext(ctx, tenantCtx)
		c.Request = c.Request.WithContext(ctx)

		// Add response headers if configured
		if m.config.AddResponseHeaders {
			m.addResponseHeaders(c, tenant)
		}

		// Log resolution if configured
		if m.config.LogResolution {
			m.logResolution(c, tenant)
		}

		// Call success handler if configured
		if m.config.SuccessHandler != nil {
			m.config.SuccessHandler(c, tenant)
		}

		// Continue to next handler
		c.Next()
	}
}

// shouldSkip checks if tenant resolution should be skipped
func (m *TenantMiddleware) shouldSkip(c *gin.Context) bool {
	// Check skip paths
	for _, path := range m.config.SkipPaths {
		if c.Request.URL.Path == path {
			return true
		}
	}

	// Check skip methods
	for _, method := range m.config.SkipMethods {
		if c.Request.Method == method {
			return true
		}
	}

	return false
}

// handleError handles tenant resolution errors
func (m *TenantMiddleware) handleError(c *gin.Context, err error) {
	if m.config.ErrorHandler != nil {
		m.config.ErrorHandler(c, err)
		return
	}

	// Default error handling
	switch err {
	case ErrTenantNotFound:
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "tenant_not_found",
			"message": "The requested tenant was not found",
		})
	case ErrTenantNotResolved:
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "tenant_not_resolved",
			"message": "Unable to resolve tenant from request",
		})
	case ErrTenantInactive:
		c.JSON(http.StatusForbidden, gin.H{
			"error":   "tenant_inactive",
			"message": "The tenant is currently inactive",
		})
	case ErrTenantSuspended:
		c.JSON(http.StatusForbidden, gin.H{
			"error":   "tenant_suspended",
			"message": "The tenant has been suspended",
		})
	case ErrTenantDeleted:
		c.JSON(http.StatusGone, gin.H{
			"error":   "tenant_deleted",
			"message": "The tenant has been deleted",
		})
	case ErrTenantRequired:
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "tenant_required",
			"message": "A tenant identifier is required for this request",
		})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "tenant_resolution_error",
			"message": "An error occurred while resolving the tenant",
		})
	}

	c.Abort()
}

// addResponseHeaders adds tenant information to response headers
func (m *TenantMiddleware) addResponseHeaders(c *gin.Context, tenant *Tenant) {
	c.Header("X-Tenant-ID", tenant.ID)
	c.Header("X-Tenant-Name", tenant.Name)
	c.Header("X-Tenant-Slug", tenant.Slug)

	// Add resolution info if available
	if info, ok := TenantResolutionInfoFromContext(c.Request.Context()); ok {
		c.Header("X-Tenant-Resolution-Strategy", string(info.Strategy))
		c.Header("X-Tenant-Resolution-Value", info.Value)
		if info.CacheHit {
			c.Header("X-Tenant-Cache-Hit", "true")
		}
	}
}

// logResolution logs tenant resolution information
func (m *TenantMiddleware) logResolution(c *gin.Context, tenant *Tenant) {
	// This would typically use a proper logger
	// For now, we'll just add it to the Gin context for potential logging middleware
	c.Set("tenant_resolution", map[string]interface{}{
		"tenant_id":   tenant.ID,
		"tenant_name": tenant.Name,
		"tenant_slug": tenant.Slug,
		"resolved_at": time.Now(),
	})

	if info, ok := TenantResolutionInfoFromContext(c.Request.Context()); ok {
		c.Set("tenant_resolution_info", map[string]interface{}{
			"strategy":   string(info.Strategy),
			"value":      info.Value,
			"cache_hit":  info.CacheHit,
			"resolved_at": info.ResolvedAt,
		})
	}
}

// RequireTenantMiddleware creates middleware that requires a tenant
func RequireTenantMiddleware(resolver TenantResolver) gin.HandlerFunc {
	config := DefaultMiddlewareConfig()
	config.RequireTenant = true
	middleware := NewTenantMiddleware(resolver, config)
	return middleware.Handler()
}

// OptionalTenantMiddleware creates middleware that optionally resolves a tenant
func OptionalTenantMiddleware(resolver TenantResolver) gin.HandlerFunc {
	config := DefaultMiddlewareConfig()
	config.RequireTenant = false
	middleware := NewTenantMiddleware(resolver, config)
	return middleware.Handler()
}

// TenantMiddlewareWithConfig creates middleware with custom configuration
func TenantMiddlewareWithConfig(resolver TenantResolver, config *MiddlewareConfig) gin.HandlerFunc {
	middleware := NewTenantMiddleware(resolver, config)
	return middleware.Handler()
}

// Helper middleware functions

// RequireActiveTenant middleware that ensures the tenant is active
func RequireActiveTenant() gin.HandlerFunc {
	return func(c *gin.Context) {
		tenant, exists := TenantFromContext(c.Request.Context())
		if !exists {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "tenant_required",
				"message": "A tenant is required for this request",
			})
			c.Abort()
			return
		}

		if !tenant.IsActive() {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "tenant_not_active",
				"message": "The tenant must be active to access this resource",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// TenantScopedMiddleware ensures requests are scoped to the resolved tenant
func TenantScopedMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tenant, exists := TenantFromContext(c.Request.Context())
		if !exists {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "tenant_required",
				"message": "This endpoint requires tenant context",
			})
			c.Abort()
			return
		}

		// Add tenant ID to all query operations
		c.Set("tenant_id", tenant.ID)
		c.Set("tenant_scoped", true)

		c.Next()
	}
}

// TenantMetricsMiddleware adds tenant information to metrics
func TenantMetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tenant, exists := TenantFromContext(c.Request.Context())
		if exists {
			// Add tenant labels for metrics
			c.Set("metrics_tenant_id", tenant.ID)
			c.Set("metrics_tenant_name", tenant.Name)
			c.Set("metrics_tenant_status", string(tenant.Status))
		}

		c.Next()
	}
}

// TenantValidationMiddleware validates tenant access permissions
func TenantValidationMiddleware(validator func(*Tenant, *gin.Context) error) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenant, exists := TenantFromContext(c.Request.Context())
		if !exists {
			c.Next()
			return
		}

		if err := validator(tenant, c); err != nil {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "tenant_validation_failed",
				"message": err.Error(),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// TenantRateLimitMiddleware applies rate limiting per tenant
func TenantRateLimitMiddleware(limiter func(tenantID string) bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenant, exists := TenantFromContext(c.Request.Context())
		if !exists {
			c.Next()
			return
		}

		if !limiter(tenant.ID) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "rate_limit_exceeded",
				"message": "Rate limit exceeded for tenant",
				"tenant":  tenant.ID,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// Gin context helpers

// GetTenant retrieves the tenant from Gin context
func GetTenant(c *gin.Context) (*Tenant, bool) {
	return TenantFromContext(c.Request.Context())
}

// GetTenantID retrieves the tenant ID from Gin context
func GetTenantID(c *gin.Context) (string, bool) {
	return TenantIDFromContext(c.Request.Context())
}

// MustGetTenant retrieves the tenant from Gin context or panics
func MustGetTenant(c *gin.Context) *Tenant {
	tenant, exists := GetTenant(c)
	if !exists {
		panic("tenant not found in context")
	}
	return tenant
}

// MustGetTenantID retrieves the tenant ID from Gin context or panics
func MustGetTenantID(c *gin.Context) string {
	tenantID, exists := GetTenantID(c)
	if !exists {
		panic("tenant ID not found in context")
	}
	return tenantID
}

// GetTenantContext retrieves the tenant context from Gin context
func GetTenantContext(c *gin.Context) (*TenantContext, bool) {
	return TenantContextFromContext(c.Request.Context())
}

// GetTenantResolutionInfo retrieves tenant resolution info from Gin context
func GetTenantResolutionInfo(c *gin.Context) (*TenantResolutionInfo, bool) {
	return TenantResolutionInfoFromContext(c.Request.Context())
}