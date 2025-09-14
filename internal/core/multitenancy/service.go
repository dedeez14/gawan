package multitenancy

import (
	"context"
	"fmt"
	"time"
	"strings"
	"sync"
)

// DefaultTenantService implements TenantService
type DefaultTenantService struct {
	repository TenantRepository
	cache      TenantCache
	config     *ServiceConfig
}

// ServiceConfig holds configuration for tenant service
type ServiceConfig struct {
	// Enable caching for tenant operations
	CacheEnabled bool `json:"cache_enabled,omitempty"`
	
	// Cache TTL for tenant data
	CacheTTL time.Duration `json:"cache_ttl,omitempty"`
	
	// Auto-generate slugs from names
	AutoGenerateSlug bool `json:"auto_generate_slug,omitempty"`
	
	// Validate tenant data on operations
	ValidateData bool `json:"validate_data,omitempty"`
	
	// Default tenant status for new tenants
	DefaultStatus TenantStatus `json:"default_status,omitempty"`
	
	// Maximum number of tenants allowed
	MaxTenants int64 `json:"max_tenants,omitempty"`
}

// DefaultServiceConfig returns default service configuration
func DefaultServiceConfig() *ServiceConfig {
	return &ServiceConfig{
		CacheEnabled:     true,
		CacheTTL:         10 * time.Minute,
		AutoGenerateSlug: true,
		ValidateData:     true,
		DefaultStatus:    TenantStatusInactive,
		MaxTenants:       1000,
	}
}

// NewDefaultTenantService creates a new default tenant service
func NewDefaultTenantService(repository TenantRepository, cache TenantCache, config *ServiceConfig) *DefaultTenantService {
	if config == nil {
		config = DefaultServiceConfig()
	}
	return &DefaultTenantService{
		repository: repository,
		cache:      cache,
		config:     config,
	}
}

// CreateTenant creates a new tenant
func (s *DefaultTenantService) CreateTenant(ctx context.Context, tenant *Tenant) error {
	if tenant == nil {
		return fmt.Errorf("tenant cannot be nil")
	}

	// Check tenant limit
	if s.config.MaxTenants > 0 {
		count, err := s.repository.Count(ctx)
		if err != nil {
			return fmt.Errorf("failed to check tenant count: %w", err)
		}
		if count >= s.config.MaxTenants {
			return fmt.Errorf("maximum number of tenants (%d) reached", s.config.MaxTenants)
		}
	}

	// Auto-generate slug if not provided
	if s.config.AutoGenerateSlug && tenant.Slug == "" {
		tenant.Slug = GenerateSlug(tenant.Name)
	}

	// Set default status if not provided
	if tenant.Status == "" {
		tenant.Status = s.config.DefaultStatus
	}

	// Set timestamps
	now := time.Now()
	tenant.CreatedAt = now
	tenant.UpdatedAt = now

	// Validate tenant data
	if s.config.ValidateData {
		if err := tenant.Validate(); err != nil {
			return fmt.Errorf("tenant validation failed: %w", err)
		}
	}

	// Check for existing tenant with same slug
	existing, err := s.repository.GetBySlug(ctx, tenant.Slug)
	if err == nil && existing != nil {
		return ErrTenantAlreadyExists
	}

	// Create tenant
	if err := s.repository.Create(ctx, tenant); err != nil {
		return fmt.Errorf("failed to create tenant: %w", err)
	}

	// Cache the tenant
	if s.config.CacheEnabled && s.cache != nil {
		_ = s.cache.Set(ctx, tenant.ID, tenant, s.config.CacheTTL)
		_ = s.cache.Set(ctx, "slug:"+tenant.Slug, tenant, s.config.CacheTTL)
	}

	return nil
}

// GetTenant retrieves a tenant by ID
func (s *DefaultTenantService) GetTenant(ctx context.Context, id string) (*Tenant, error) {
	if id == "" {
		return nil, ErrInvalidTenantID
	}

	// Check cache first
	if s.config.CacheEnabled && s.cache != nil {
		tenant, err := s.cache.Get(ctx, id)
		if err == nil && tenant != nil {
			return tenant, nil
		}
	}

	// Get from repository
	tenant, err := s.repository.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}

	if tenant == nil {
		return nil, ErrTenantNotFound
	}

	// Cache the result
	if s.config.CacheEnabled && s.cache != nil {
		_ = s.cache.Set(ctx, id, tenant, s.config.CacheTTL)
	}

	return tenant, nil
}

// UpdateTenant updates an existing tenant
func (s *DefaultTenantService) UpdateTenant(ctx context.Context, tenant *Tenant) error {
	if tenant == nil {
		return fmt.Errorf("tenant cannot be nil")
	}

	if tenant.ID == "" {
		return ErrInvalidTenantID
	}

	// Validate tenant data
	if s.config.ValidateData {
		if err := tenant.Validate(); err != nil {
			return fmt.Errorf("tenant validation failed: %w", err)
		}
	}

	// Check if tenant exists
	existing, err := s.repository.GetByID(ctx, tenant.ID)
	if err != nil {
		return fmt.Errorf("failed to check existing tenant: %w", err)
	}
	if existing == nil {
		return ErrTenantNotFound
	}

	// Check for slug conflicts (if slug changed)
	if existing.Slug != tenant.Slug {
		conflict, err := s.repository.GetBySlug(ctx, tenant.Slug)
		if err == nil && conflict != nil && conflict.ID != tenant.ID {
			return fmt.Errorf("tenant with slug '%s' already exists", tenant.Slug)
		}
	}

	// Update timestamp
	tenant.UpdatedAt = time.Now()

	// Update tenant
	if err := s.repository.Update(ctx, tenant); err != nil {
		return fmt.Errorf("failed to update tenant: %w", err)
	}

	// Update cache
	if s.config.CacheEnabled && s.cache != nil {
		_ = s.cache.Set(ctx, tenant.ID, tenant, s.config.CacheTTL)
		_ = s.cache.Set(ctx, "slug:"+tenant.Slug, tenant, s.config.CacheTTL)
		
		// Remove old slug from cache if it changed
		if existing.Slug != tenant.Slug {
			_ = s.cache.Delete(ctx, "slug:"+existing.Slug)
		}
	}

	return nil
}

// DeleteTenant deletes a tenant
func (s *DefaultTenantService) DeleteTenant(ctx context.Context, id string) error {
	if id == "" {
		return ErrInvalidTenantID
	}

	// Get tenant first to check if it exists
	tenant, err := s.repository.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get tenant: %w", err)
	}
	if tenant == nil {
		return ErrTenantNotFound
	}

	// Delete tenant (soft delete)
	if err := s.repository.Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete tenant: %w", err)
	}

	// Remove from cache
	if s.config.CacheEnabled && s.cache != nil {
		_ = s.cache.Delete(ctx, id)
		_ = s.cache.Delete(ctx, "slug:"+tenant.Slug)
		if tenant.Domain != "" {
			_ = s.cache.Delete(ctx, "domain:"+tenant.Domain)
		}
		if tenant.Subdomain != "" {
			_ = s.cache.Delete(ctx, "subdomain:"+tenant.Subdomain)
		}
	}

	return nil
}

// ActivateTenant activates a tenant
func (s *DefaultTenantService) ActivateTenant(ctx context.Context, id string) error {
	tenant, err := s.GetTenant(ctx, id)
	if err != nil {
		return err
	}

	tenant.Status = TenantStatusActive
	now := time.Now()
	tenant.ActivatedAt = &now
	tenant.UpdatedAt = now

	return s.UpdateTenant(ctx, tenant)
}

// SuspendTenant suspends a tenant
func (s *DefaultTenantService) SuspendTenant(ctx context.Context, id string) error {
	tenant, err := s.GetTenant(ctx, id)
	if err != nil {
		return err
	}

	tenant.Status = TenantStatusSuspended
	now := time.Now()
	tenant.SuspendedAt = &now
	tenant.UpdatedAt = now

	return s.UpdateTenant(ctx, tenant)
}

// ListTenants retrieves all tenants with pagination
func (s *DefaultTenantService) ListTenants(ctx context.Context, offset, limit int) ([]*Tenant, error) {
	if limit <= 0 {
		limit = 50 // Default limit
	}
	if limit > 1000 {
		limit = 1000 // Maximum limit
	}

	tenants, err := s.repository.List(ctx, offset, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list tenants: %w", err)
	}

	return tenants, nil
}

// GetTenantBySlug retrieves a tenant by slug
func (s *DefaultTenantService) GetTenantBySlug(ctx context.Context, slug string) (*Tenant, error) {
	if slug == "" {
		return nil, ErrInvalidTenantSlug
	}

	// Check cache first
	cacheKey := "slug:" + slug
	if s.config.CacheEnabled && s.cache != nil {
		tenant, err := s.cache.Get(ctx, cacheKey)
		if err == nil && tenant != nil {
			return tenant, nil
		}
	}

	// Get from repository
	tenant, err := s.repository.GetBySlug(ctx, slug)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant by slug: %w", err)
	}

	if tenant == nil {
		return nil, ErrTenantNotFound
	}

	// Cache the result
	if s.config.CacheEnabled && s.cache != nil {
		_ = s.cache.Set(ctx, cacheKey, tenant, s.config.CacheTTL)
		_ = s.cache.Set(ctx, tenant.ID, tenant, s.config.CacheTTL)
	}

	return tenant, nil
}

// GetTenantByDomain retrieves a tenant by domain
func (s *DefaultTenantService) GetTenantByDomain(ctx context.Context, domain string) (*Tenant, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain cannot be empty")
	}

	// Check cache first
	cacheKey := "domain:" + domain
	if s.config.CacheEnabled && s.cache != nil {
		tenant, err := s.cache.Get(ctx, cacheKey)
		if err == nil && tenant != nil {
			return tenant, nil
		}
	}

	// Get from repository
	tenant, err := s.repository.GetByDomain(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant by domain: %w", err)
	}

	if tenant == nil {
		return nil, ErrTenantNotFound
	}

	// Cache the result
	if s.config.CacheEnabled && s.cache != nil {
		_ = s.cache.Set(ctx, cacheKey, tenant, s.config.CacheTTL)
		_ = s.cache.Set(ctx, tenant.ID, tenant, s.config.CacheTTL)
	}

	return tenant, nil
}

// GetTenantBySubdomain retrieves a tenant by subdomain
func (s *DefaultTenantService) GetTenantBySubdomain(ctx context.Context, subdomain string) (*Tenant, error) {
	if subdomain == "" {
		return nil, fmt.Errorf("subdomain cannot be empty")
	}

	// Check cache first
	cacheKey := "subdomain:" + subdomain
	if s.config.CacheEnabled && s.cache != nil {
		tenant, err := s.cache.Get(ctx, cacheKey)
		if err == nil && tenant != nil {
			return tenant, nil
		}
	}

	// Get from repository
	tenant, err := s.repository.GetBySubdomain(ctx, subdomain)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant by subdomain: %w", err)
	}

	if tenant == nil {
		return nil, ErrTenantNotFound
	}

	// Cache the result
	if s.config.CacheEnabled && s.cache != nil {
		_ = s.cache.Set(ctx, cacheKey, tenant, s.config.CacheTTL)
		_ = s.cache.Set(ctx, tenant.ID, tenant, s.config.CacheTTL)
	}

	return tenant, nil
}

// GetTenantStats returns statistics about tenants
func (s *DefaultTenantService) GetTenantStats(ctx context.Context) (*TenantStats, error) {
	total, err := s.repository.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant count: %w", err)
	}

	// For now, return basic stats
	// In a real implementation, you might want to add more detailed statistics
	stats := &TenantStats{
		Total:     total,
		Active:    0, // Would need additional repository methods
		Inactive:  0,
		Suspended: 0,
		Deleted:   0,
	}

	return stats, nil
}

// ValidateTenantSlug validates if a slug is available
func (s *DefaultTenantService) ValidateTenantSlug(ctx context.Context, slug string, excludeID string) error {
	if !isValidSlug(slug) {
		return ErrInvalidTenantSlug
	}

	existing, err := s.repository.GetBySlug(ctx, slug)
	if err != nil {
		return fmt.Errorf("failed to check slug availability: %w", err)
	}

	if existing != nil && existing.ID != excludeID {
		return fmt.Errorf("slug '%s' is already taken", slug)
	}

	return nil
}

// ClearTenantCache clears all tenant cache entries
func (s *DefaultTenantService) ClearTenantCache(ctx context.Context) error {
	if s.cache != nil {
		return s.cache.Clear(ctx)
	}
	return nil
}

// TenantStats represents tenant statistics
type TenantStats struct {
	Total     int64 `json:"total"`
	Active    int64 `json:"active"`
	Inactive  int64 `json:"inactive"`
	Suspended int64 `json:"suspended"`
	Deleted   int64 `json:"deleted"`
}

// MemoryTenantRepository implements TenantRepository using in-memory storage
// This is mainly for testing and development purposes
type MemoryTenantRepository struct {
	tenants map[string]*Tenant
	mu      sync.RWMutex
}

// NewMemoryTenantRepository creates a new memory-based tenant repository
func NewMemoryTenantRepository() *MemoryTenantRepository {
	return &MemoryTenantRepository{
		tenants: make(map[string]*Tenant),
	}
}

// GetByID retrieves a tenant by ID
func (r *MemoryTenantRepository) GetByID(ctx context.Context, id string) (*Tenant, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tenant, exists := r.tenants[id]
	if !exists {
		return nil, nil
	}

	// Return a copy to prevent external modifications
	return r.copyTenant(tenant), nil
}

// GetBySlug retrieves a tenant by slug
func (r *MemoryTenantRepository) GetBySlug(ctx context.Context, slug string) (*Tenant, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, tenant := range r.tenants {
		if tenant.Slug == slug {
			return r.copyTenant(tenant), nil
		}
	}

	return nil, nil
}

// GetByDomain retrieves a tenant by domain
func (r *MemoryTenantRepository) GetByDomain(ctx context.Context, domain string) (*Tenant, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, tenant := range r.tenants {
		if tenant.Domain == domain {
			return r.copyTenant(tenant), nil
		}
	}

	return nil, nil
}

// GetBySubdomain retrieves a tenant by subdomain
func (r *MemoryTenantRepository) GetBySubdomain(ctx context.Context, subdomain string) (*Tenant, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, tenant := range r.tenants {
		if tenant.Subdomain == subdomain {
			return r.copyTenant(tenant), nil
		}
	}

	return nil, nil
}

// Create creates a new tenant
func (r *MemoryTenantRepository) Create(ctx context.Context, tenant *Tenant) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.tenants[tenant.ID]; exists {
		return ErrTenantAlreadyExists
	}

	r.tenants[tenant.ID] = r.copyTenant(tenant)
	return nil
}

// Update updates an existing tenant
func (r *MemoryTenantRepository) Update(ctx context.Context, tenant *Tenant) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.tenants[tenant.ID]; !exists {
		return ErrTenantNotFound
	}

	r.tenants[tenant.ID] = r.copyTenant(tenant)
	return nil
}

// Delete deletes a tenant (soft delete)
func (r *MemoryTenantRepository) Delete(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	tenant, exists := r.tenants[id]
	if !exists {
		return ErrTenantNotFound
	}

	// Soft delete by setting status
	tenant.Status = TenantStatusDeleted
	tenant.UpdatedAt = time.Now()

	return nil
}

// List retrieves all tenants with pagination
func (r *MemoryTenantRepository) List(ctx context.Context, offset, limit int) ([]*Tenant, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var tenants []*Tenant
	for _, tenant := range r.tenants {
		if tenant.Status != TenantStatusDeleted {
			tenants = append(tenants, r.copyTenant(tenant))
		}
	}

	// Simple pagination
	if offset >= len(tenants) {
		return []*Tenant{}, nil
	}

	end := offset + limit
	if end > len(tenants) {
		end = len(tenants)
	}

	return tenants[offset:end], nil
}

// Count returns the total number of tenants
func (r *MemoryTenantRepository) Count(ctx context.Context) (int64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	count := int64(0)
	for _, tenant := range r.tenants {
		if tenant.Status != TenantStatusDeleted {
			count++
		}
	}

	return count, nil
}

// copyTenant creates a deep copy of a tenant
func (r *MemoryTenantRepository) copyTenant(tenant *Tenant) *Tenant {
	copy := *tenant
	
	// Copy maps
	if tenant.Settings != nil {
		copy.Settings = make(map[string]string)
		for k, v := range tenant.Settings {
			copy.Settings[k] = v
		}
	}
	
	if tenant.Metadata != nil {
		copy.Metadata = make(map[string]string)
		for k, v := range tenant.Metadata {
			copy.Metadata[k] = v
		}
	}
	
	return &copy
}