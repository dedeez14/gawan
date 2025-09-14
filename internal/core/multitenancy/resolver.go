package multitenancy

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// DefaultTenantResolver implements TenantResolver with multiple resolution strategies
type DefaultTenantResolver struct {
	config     *TenantConfig
	repository TenantRepository
	cache      TenantCache
	mu         sync.RWMutex
}

// NewDefaultTenantResolver creates a new default tenant resolver
func NewDefaultTenantResolver(config *TenantConfig, repository TenantRepository, cache TenantCache) *DefaultTenantResolver {
	if config == nil {
		config = DefaultTenantConfig()
	}
	return &DefaultTenantResolver{
		config:     config,
		repository: repository,
		cache:      cache,
	}
}

// ResolveTenant resolves a tenant from the given context
func (r *DefaultTenantResolver) ResolveTenant(ctx context.Context) (*Tenant, error) {
	// Try primary strategy first
	tenant, info, err := r.resolveTenantWithStrategy(ctx, r.config.Strategy)
	if err == nil && tenant != nil {
		ctx = WithTenantResolutionInfo(ctx, info)
		return tenant, nil
	}

	// Try fallback strategies
	for _, strategy := range r.config.FallbackStrategies {
		tenant, info, err = r.resolveTenantWithStrategy(ctx, strategy)
		if err == nil && tenant != nil {
			ctx = WithTenantResolutionInfo(ctx, info)
			return tenant, nil
		}
	}

	// Try default tenant if configured
	if r.config.DefaultTenant != "" {
		tenant, err := r.getTenantByIdentifier(ctx, r.config.DefaultTenant)
		if err == nil && tenant != nil {
			info := &TenantResolutionInfo{
				Strategy:   "default",
				Value:      r.config.DefaultTenant,
				ResolvedAt: time.Now(),
				CacheHit:   false,
			}
			ctx = WithTenantResolutionInfo(ctx, info)
			return tenant, nil
		}
	}

	// Return error if no tenant found and not allowed
	if !r.config.AllowNoTenant {
		return nil, ErrTenantNotResolved
	}

	return nil, nil
}

// resolveTenantWithStrategy resolves tenant using a specific strategy
func (r *DefaultTenantResolver) resolveTenantWithStrategy(ctx context.Context, strategy ResolutionStrategy) (*Tenant, *TenantResolutionInfo, error) {
	var identifier string
	var err error

	switch strategy {
	case ResolutionStrategyHeader:
		identifier, err = r.resolveFromHeader(ctx)
	case ResolutionStrategySubdomain:
		identifier, err = r.resolveFromSubdomain(ctx)
	case ResolutionStrategyDomain:
		identifier, err = r.resolveFromDomain(ctx)
	case ResolutionStrategyPath:
		identifier, err = r.resolveFromPath(ctx)
	case ResolutionStrategyQuery:
		identifier, err = r.resolveFromQuery(ctx)
	default:
		return nil, nil, fmt.Errorf("unsupported resolution strategy: %s", strategy)
	}

	if err != nil || identifier == "" {
		return nil, nil, err
	}

	// Check cache first
	var cacheHit bool
	var tenant *Tenant

	if r.config.CacheEnabled && r.cache != nil {
		tenant, err = r.cache.Get(ctx, identifier)
		if err == nil && tenant != nil {
			cacheHit = true
		}
	}

	// Fetch from repository if not in cache
	if tenant == nil {
		tenant, err = r.getTenantByIdentifier(ctx, identifier)
		if err != nil {
			return nil, nil, err
		}

		// Cache the result
		if r.config.CacheEnabled && r.cache != nil && tenant != nil {
			_ = r.cache.Set(ctx, identifier, tenant, r.config.CacheTTL)
		}
	}

	if tenant == nil {
		return nil, nil, ErrTenantNotFound
	}

	// Check tenant status
	if !tenant.IsAccessible() {
		switch tenant.Status {
		case TenantStatusSuspended:
			return nil, nil, ErrTenantSuspended
		case TenantStatusDeleted:
			return nil, nil, ErrTenantDeleted
		default:
			return nil, nil, ErrTenantInactive
		}
	}

	info := &TenantResolutionInfo{
		Strategy:   strategy,
		Value:      identifier,
		ResolvedAt: time.Now(),
		CacheHit:   cacheHit,
	}

	return tenant, info, nil
}

// resolveFromHeader resolves tenant from HTTP header
func (r *DefaultTenantResolver) resolveFromHeader(ctx context.Context) (string, error) {
	ginCtx, ok := ctx.(*gin.Context)
	if !ok {
		return "", fmt.Errorf("gin context required for header resolution")
	}

	headerName := r.config.HeaderName
	if headerName == "" {
		headerName = "X-Tenant-ID"
	}

	value := ginCtx.GetHeader(headerName)
	if value == "" {
		return "", fmt.Errorf("header %s not found", headerName)
	}

	return strings.TrimSpace(value), nil
}

// resolveFromSubdomain resolves tenant from subdomain
func (r *DefaultTenantResolver) resolveFromSubdomain(ctx context.Context) (string, error) {
	ginCtx, ok := ctx.(*gin.Context)
	if !ok {
		return "", fmt.Errorf("gin context required for subdomain resolution")
	}

	host := ginCtx.Request.Host
	if host == "" {
		return "", fmt.Errorf("host header not found")
	}

	// Remove port if present
	if colonIndex := strings.LastIndex(host, ":"); colonIndex != -1 {
		host = host[:colonIndex]
	}

	subdomain := ExtractSubdomain(host)
	if subdomain == "" {
		return "", fmt.Errorf("no subdomain found in host: %s", host)
	}

	// Skip common subdomains
	if isCommonSubdomain(subdomain) {
		return "", fmt.Errorf("common subdomain ignored: %s", subdomain)
	}

	return subdomain, nil
}

// resolveFromDomain resolves tenant from domain
func (r *DefaultTenantResolver) resolveFromDomain(ctx context.Context) (string, error) {
	ginCtx, ok := ctx.(*gin.Context)
	if !ok {
		return "", fmt.Errorf("gin context required for domain resolution")
	}

	host := ginCtx.Request.Host
	if host == "" {
		return "", fmt.Errorf("host header not found")
	}

	// Remove port if present
	if colonIndex := strings.LastIndex(host, ":"); colonIndex != -1 {
		host = host[:colonIndex]
	}

	return host, nil
}

// resolveFromPath resolves tenant from URL path
func (r *DefaultTenantResolver) resolveFromPath(ctx context.Context) (string, error) {
	ginCtx, ok := ctx.(*gin.Context)
	if !ok {
		return "", fmt.Errorf("gin context required for path resolution")
	}

	path := ginCtx.Request.URL.Path
	prefix := r.config.PathPrefix
	if prefix == "" {
		prefix = "/tenant"
	}

	if !strings.HasPrefix(path, prefix+"/") {
		return "", fmt.Errorf("path does not start with %s/", prefix)
	}

	// Extract tenant identifier from path
	remainingPath := strings.TrimPrefix(path, prefix+"/")
	parts := strings.Split(remainingPath, "/")
	if len(parts) == 0 || parts[0] == "" {
		return "", fmt.Errorf("no tenant identifier found in path")
	}

	return parts[0], nil
}

// resolveFromQuery resolves tenant from query parameter
func (r *DefaultTenantResolver) resolveFromQuery(ctx context.Context) (string, error) {
	ginCtx, ok := ctx.(*gin.Context)
	if !ok {
		return "", fmt.Errorf("gin context required for query resolution")
	}

	queryParam := r.config.QueryParam
	if queryParam == "" {
		queryParam = "tenant"
	}

	value := ginCtx.Query(queryParam)
	if value == "" {
		return "", fmt.Errorf("query parameter %s not found", queryParam)
	}

	return strings.TrimSpace(value), nil
}

// getTenantByIdentifier retrieves tenant by ID, slug, domain, or subdomain
func (r *DefaultTenantResolver) getTenantByIdentifier(ctx context.Context, identifier string) (*Tenant, error) {
	if identifier == "" {
		return nil, ErrInvalidTenantID
	}

	// Try by ID first
	tenant, err := r.repository.GetByID(ctx, identifier)
	if err == nil && tenant != nil {
		return tenant, nil
	}

	// Try by slug
	tenant, err = r.repository.GetBySlug(ctx, identifier)
	if err == nil && tenant != nil {
		return tenant, nil
	}

	// Try by subdomain
	tenant, err = r.repository.GetBySubdomain(ctx, identifier)
	if err == nil && tenant != nil {
		return tenant, nil
	}

	// Try by domain
	tenant, err = r.repository.GetByDomain(ctx, identifier)
	if err == nil && tenant != nil {
		return tenant, nil
	}

	return nil, ErrTenantNotFound
}

// isCommonSubdomain checks if a subdomain is commonly used and should be ignored
func isCommonSubdomain(subdomain string) bool {
	commonSubdomains := []string{
		"www", "api", "app", "admin", "mail", "ftp", "blog",
		"shop", "store", "cdn", "static", "assets", "media",
		"dev", "test", "staging", "prod", "production",
	}

	for _, common := range commonSubdomains {
		if subdomain == common {
			return true
		}
	}
	return false
}

// HTTPTenantResolver resolves tenants from HTTP requests
type HTTPTenantResolver struct {
	resolver TenantResolver
}

// NewHTTPTenantResolver creates a new HTTP tenant resolver
func NewHTTPTenantResolver(resolver TenantResolver) *HTTPTenantResolver {
	return &HTTPTenantResolver{
		resolver: resolver,
	}
}

// ResolveFromRequest resolves tenant from HTTP request
func (r *HTTPTenantResolver) ResolveFromRequest(req *http.Request) (*Tenant, error) {
	// Create a minimal context with request information
	ctx := &httpRequestContext{
		request: req,
		headers: make(map[string]string),
	}

	// Copy headers
	for name, values := range req.Header {
		if len(values) > 0 {
			ctx.headers[name] = values[0]
		}
	}

	return r.resolver.ResolveTenant(ctx)
}

// httpRequestContext implements a minimal context for HTTP request resolution
type httpRequestContext struct {
	request *http.Request
	headers map[string]string
}

func (c *httpRequestContext) Deadline() (deadline time.Time, ok bool) {
	return time.Time{}, false
}

func (c *httpRequestContext) Done() <-chan struct{} {
	return nil
}

func (c *httpRequestContext) Err() error {
	return nil
}

func (c *httpRequestContext) Value(key interface{}) interface{} {
	return nil
}

// GetHeader returns header value
func (c *httpRequestContext) GetHeader(name string) string {
	return c.headers[name]
}

// Query returns query parameter value
func (c *httpRequestContext) Query(name string) string {
	if c.request.URL == nil {
		return ""
	}
	return c.request.URL.Query().Get(name)
}

// ChainedTenantResolver tries multiple resolvers in sequence
type ChainedTenantResolver struct {
	resolvers []TenantResolver
}

// NewChainedTenantResolver creates a new chained tenant resolver
func NewChainedTenantResolver(resolvers ...TenantResolver) *ChainedTenantResolver {
	return &ChainedTenantResolver{
		resolvers: resolvers,
	}
}

// ResolveTenant tries each resolver until one succeeds
func (r *ChainedTenantResolver) ResolveTenant(ctx context.Context) (*Tenant, error) {
	var lastErr error

	for _, resolver := range r.resolvers {
		tenant, err := resolver.ResolveTenant(ctx)
		if err == nil && tenant != nil {
			return tenant, nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrTenantNotResolved
}

// CachingTenantResolver wraps another resolver with caching
type CachingTenantResolver struct {
	resolver TenantResolver
	cache    TenantCache
	ttl      time.Duration
}

// NewCachingTenantResolver creates a new caching tenant resolver
func NewCachingTenantResolver(resolver TenantResolver, cache TenantCache, ttl time.Duration) *CachingTenantResolver {
	return &CachingTenantResolver{
		resolver: resolver,
		cache:    cache,
		ttl:      ttl,
	}
}

// ResolveTenant resolves tenant with caching
func (r *CachingTenantResolver) ResolveTenant(ctx context.Context) (*Tenant, error) {
	// Generate cache key from context
	cacheKey := r.generateCacheKey(ctx)
	if cacheKey == "" {
		return r.resolver.ResolveTenant(ctx)
	}

	// Check cache first
	if r.cache != nil {
		tenant, err := r.cache.Get(ctx, cacheKey)
		if err == nil && tenant != nil {
			return tenant, nil
		}
	}

	// Resolve from underlying resolver
	tenant, err := r.resolver.ResolveTenant(ctx)
	if err != nil {
		return nil, err
	}

	// Cache the result
	if r.cache != nil && tenant != nil {
		_ = r.cache.Set(ctx, cacheKey, tenant, r.ttl)
	}

	return tenant, nil
}

// generateCacheKey generates a cache key from context
func (r *CachingTenantResolver) generateCacheKey(ctx context.Context) string {
	ginCtx, ok := ctx.(*gin.Context)
	if !ok {
		return ""
	}

	// Use host + path + relevant headers as cache key
	host := ginCtx.Request.Host
	path := ginCtx.Request.URL.Path
	tenantHeader := ginCtx.GetHeader("X-Tenant-ID")

	if tenantHeader != "" {
		return fmt.Sprintf("tenant:header:%s", tenantHeader)
	}

	if host != "" {
		return fmt.Sprintf("tenant:host:%s", host)
	}

	if path != "" {
		return fmt.Sprintf("tenant:path:%s", path)
	}

	return ""
}

// TenantCache defines the interface for tenant caching
type TenantCache interface {
	// Get retrieves a tenant from cache
	Get(ctx context.Context, key string) (*Tenant, error)
	
	// Set stores a tenant in cache
	Set(ctx context.Context, key string, tenant *Tenant, ttl time.Duration) error
	
	// Delete removes a tenant from cache
	Delete(ctx context.Context, key string) error
	
	// Clear clears all cached tenants
	Clear(ctx context.Context) error
}

// MemoryTenantCache implements TenantCache using in-memory storage
type MemoryTenantCache struct {
	cache map[string]*cacheEntry
	mu    sync.RWMutex
}

type cacheEntry struct {
	tenant    *Tenant
	expiresAt time.Time
}

// NewMemoryTenantCache creates a new memory-based tenant cache
func NewMemoryTenantCache() *MemoryTenantCache {
	cache := &MemoryTenantCache{
		cache: make(map[string]*cacheEntry),
	}
	
	// Start cleanup goroutine
	go cache.cleanup()
	
	return cache
}

// Get retrieves a tenant from cache
func (c *MemoryTenantCache) Get(ctx context.Context, key string) (*Tenant, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.cache[key]
	if !exists {
		return nil, fmt.Errorf("tenant not found in cache")
	}

	if time.Now().After(entry.expiresAt) {
		return nil, fmt.Errorf("tenant cache entry expired")
	}

	return entry.tenant, nil
}

// Set stores a tenant in cache
func (c *MemoryTenantCache) Set(ctx context.Context, key string, tenant *Tenant, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache[key] = &cacheEntry{
		tenant:    tenant,
		expiresAt: time.Now().Add(ttl),
	}

	return nil
}

// Delete removes a tenant from cache
func (c *MemoryTenantCache) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.cache, key)
	return nil
}

// Clear clears all cached tenants
func (c *MemoryTenantCache) Clear(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache = make(map[string]*cacheEntry)
	return nil
}

// cleanup removes expired entries
func (c *MemoryTenantCache) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, entry := range c.cache {
			if now.After(entry.expiresAt) {
				delete(c.cache, key)
			}
		}
		c.mu.Unlock()
	}
}