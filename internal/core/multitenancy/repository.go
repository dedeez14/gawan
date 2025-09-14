package multitenancy

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
	"encoding/json"

	"gorm.io/gorm"
)

// GormTenantRepository implements TenantRepository using GORM
type GormTenantRepository struct {
	db *gorm.DB
}

// NewGormTenantRepository creates a new GORM-based tenant repository
func NewGormTenantRepository(db *gorm.DB) *GormTenantRepository {
	return &GormTenantRepository{db: db}
}

// TenantModel represents the database model for tenants
type TenantModel struct {
	ID          string         `gorm:"primaryKey;type:varchar(36)" json:"id"`
	Name        string         `gorm:"not null;size:255" json:"name"`
	Slug        string         `gorm:"uniqueIndex;not null;size:100" json:"slug"`
	Domain      string         `gorm:"index;size:255" json:"domain,omitempty"`
	Subdomain   string         `gorm:"index;size:100" json:"subdomain,omitempty"`
	Status      TenantStatus   `gorm:"not null;default:'inactive'" json:"status"`
	Settings    string         `gorm:"type:text" json:"settings,omitempty"`
	Metadata    string         `gorm:"type:text" json:"metadata,omitempty"`
	CreatedAt   time.Time      `gorm:"not null" json:"created_at"`
	UpdatedAt   time.Time      `gorm:"not null" json:"updated_at"`
	ActivatedAt *time.Time     `json:"activated_at,omitempty"`
	SuspendedAt *time.Time     `json:"suspended_at,omitempty"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

// TableName returns the table name for the tenant model
func (TenantModel) TableName() string {
	return "tenants"
}

// ToTenant converts TenantModel to Tenant
func (tm *TenantModel) ToTenant() (*Tenant, error) {
	tenant := &Tenant{
		ID:          tm.ID,
		Name:        tm.Name,
		Slug:        tm.Slug,
		Domain:      tm.Domain,
		Subdomain:   tm.Subdomain,
		Status:      tm.Status,
		CreatedAt:   tm.CreatedAt,
		UpdatedAt:   tm.UpdatedAt,
		ActivatedAt: tm.ActivatedAt,
		SuspendedAt: tm.SuspendedAt,
	}

	// Parse settings JSON
	if tm.Settings != "" {
		var settings map[string]string
		if err := json.Unmarshal([]byte(tm.Settings), &settings); err != nil {
			return nil, fmt.Errorf("failed to parse settings: %w", err)
		}
		tenant.Settings = settings
	}

	// Parse metadata JSON
	if tm.Metadata != "" {
		var metadata map[string]string
		if err := json.Unmarshal([]byte(tm.Metadata), &metadata); err != nil {
			return nil, fmt.Errorf("failed to parse metadata: %w", err)
		}
		tenant.Metadata = metadata
	}

	return tenant, nil
}

// FromTenant converts Tenant to TenantModel
func (tm *TenantModel) FromTenant(tenant *Tenant) error {
	tm.ID = tenant.ID
	tm.Name = tenant.Name
	tm.Slug = tenant.Slug
	tm.Domain = tenant.Domain
	tm.Subdomain = tenant.Subdomain
	tm.Status = tenant.Status
	tm.CreatedAt = tenant.CreatedAt
	tm.UpdatedAt = tenant.UpdatedAt
	tm.ActivatedAt = tenant.ActivatedAt
	tm.SuspendedAt = tenant.SuspendedAt

	// Serialize settings to JSON
	if tenant.Settings != nil {
		settingsJSON, err := json.Marshal(tenant.Settings)
		if err != nil {
			return fmt.Errorf("failed to serialize settings: %w", err)
		}
		tm.Settings = string(settingsJSON)
	}

	// Serialize metadata to JSON
	if tenant.Metadata != nil {
		metadataJSON, err := json.Marshal(tenant.Metadata)
		if err != nil {
			return fmt.Errorf("failed to serialize metadata: %w", err)
		}
		tm.Metadata = string(metadataJSON)
	}

	return nil
}

// GetByID retrieves a tenant by ID
func (r *GormTenantRepository) GetByID(ctx context.Context, id string) (*Tenant, error) {
	var model TenantModel
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&model).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get tenant by ID: %w", err)
	}

	return model.ToTenant()
}

// GetBySlug retrieves a tenant by slug
func (r *GormTenantRepository) GetBySlug(ctx context.Context, slug string) (*Tenant, error) {
	var model TenantModel
	err := r.db.WithContext(ctx).Where("slug = ?", slug).First(&model).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get tenant by slug: %w", err)
	}

	return model.ToTenant()
}

// GetByDomain retrieves a tenant by domain
func (r *GormTenantRepository) GetByDomain(ctx context.Context, domain string) (*Tenant, error) {
	var model TenantModel
	err := r.db.WithContext(ctx).Where("domain = ?", domain).First(&model).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get tenant by domain: %w", err)
	}

	return model.ToTenant()
}

// GetBySubdomain retrieves a tenant by subdomain
func (r *GormTenantRepository) GetBySubdomain(ctx context.Context, subdomain string) (*Tenant, error) {
	var model TenantModel
	err := r.db.WithContext(ctx).Where("subdomain = ?", subdomain).First(&model).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get tenant by subdomain: %w", err)
	}

	return model.ToTenant()
}

// Create creates a new tenant
func (r *GormTenantRepository) Create(ctx context.Context, tenant *Tenant) error {
	var model TenantModel
	if err := model.FromTenant(tenant); err != nil {
		return fmt.Errorf("failed to convert tenant to model: %w", err)
	}

	err := r.db.WithContext(ctx).Create(&model).Error
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			return ErrTenantAlreadyExists
		}
		return fmt.Errorf("failed to create tenant: %w", err)
	}

	return nil
}

// Update updates an existing tenant
func (r *GormTenantRepository) Update(ctx context.Context, tenant *Tenant) error {
	var model TenantModel
	if err := model.FromTenant(tenant); err != nil {
		return fmt.Errorf("failed to convert tenant to model: %w", err)
	}

	result := r.db.WithContext(ctx).Where("id = ?", tenant.ID).Updates(&model)
	if result.Error != nil {
		if strings.Contains(result.Error.Error(), "duplicate") || strings.Contains(result.Error.Error(), "unique") {
			return fmt.Errorf("tenant with slug '%s' already exists", tenant.Slug)
		}
		return fmt.Errorf("failed to update tenant: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrTenantNotFound
	}

	return nil
}

// Delete deletes a tenant (soft delete)
func (r *GormTenantRepository) Delete(ctx context.Context, id string) error {
	result := r.db.WithContext(ctx).Delete(&TenantModel{}, "id = ?", id)
	if result.Error != nil {
		return fmt.Errorf("failed to delete tenant: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrTenantNotFound
	}

	return nil
}

// List retrieves all tenants with pagination
func (r *GormTenantRepository) List(ctx context.Context, offset, limit int) ([]*Tenant, error) {
	var models []TenantModel
	err := r.db.WithContext(ctx).Offset(offset).Limit(limit).Order("created_at DESC").Find(&models).Error
	if err != nil {
		return nil, fmt.Errorf("failed to list tenants: %w", err)
	}

	tenants := make([]*Tenant, len(models))
	for i, model := range models {
		tenant, err := model.ToTenant()
		if err != nil {
			return nil, fmt.Errorf("failed to convert model to tenant: %w", err)
		}
		tenants[i] = tenant
	}

	return tenants, nil
}

// Count returns the total number of tenants
func (r *GormTenantRepository) Count(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&TenantModel{}).Count(&count).Error
	if err != nil {
		return 0, fmt.Errorf("failed to count tenants: %w", err)
	}

	return count, nil
}

// SQLTenantRepository implements TenantRepository using raw SQL
type SQLTenantRepository struct {
	db *sql.DB
}

// NewSQLTenantRepository creates a new SQL-based tenant repository
func NewSQLTenantRepository(db *sql.DB) *SQLTenantRepository {
	return &SQLTenantRepository{db: db}
}

// GetByID retrieves a tenant by ID
func (r *SQLTenantRepository) GetByID(ctx context.Context, id string) (*Tenant, error) {
	query := `
		SELECT id, name, slug, domain, subdomain, status, settings, metadata,
		       created_at, updated_at, activated_at, suspended_at
		FROM tenants 
		WHERE id = ? AND deleted_at IS NULL
	`

	row := r.db.QueryRowContext(ctx, query, id)
	return r.scanTenant(row)
}

// GetBySlug retrieves a tenant by slug
func (r *SQLTenantRepository) GetBySlug(ctx context.Context, slug string) (*Tenant, error) {
	query := `
		SELECT id, name, slug, domain, subdomain, status, settings, metadata,
		       created_at, updated_at, activated_at, suspended_at
		FROM tenants 
		WHERE slug = ? AND deleted_at IS NULL
	`

	row := r.db.QueryRowContext(ctx, query, slug)
	return r.scanTenant(row)
}

// GetByDomain retrieves a tenant by domain
func (r *SQLTenantRepository) GetByDomain(ctx context.Context, domain string) (*Tenant, error) {
	query := `
		SELECT id, name, slug, domain, subdomain, status, settings, metadata,
		       created_at, updated_at, activated_at, suspended_at
		FROM tenants 
		WHERE domain = ? AND deleted_at IS NULL
	`

	row := r.db.QueryRowContext(ctx, query, domain)
	return r.scanTenant(row)
}

// GetBySubdomain retrieves a tenant by subdomain
func (r *SQLTenantRepository) GetBySubdomain(ctx context.Context, subdomain string) (*Tenant, error) {
	query := `
		SELECT id, name, slug, domain, subdomain, status, settings, metadata,
		       created_at, updated_at, activated_at, suspended_at
		FROM tenants 
		WHERE subdomain = ? AND deleted_at IS NULL
	`

	row := r.db.QueryRowContext(ctx, query, subdomain)
	return r.scanTenant(row)
}

// Create creates a new tenant
func (r *SQLTenantRepository) Create(ctx context.Context, tenant *Tenant) error {
	query := `
		INSERT INTO tenants (id, name, slug, domain, subdomain, status, settings, metadata, created_at, updated_at, activated_at, suspended_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	settingsJSON, _ := json.Marshal(tenant.Settings)
	metadataJSON, _ := json.Marshal(tenant.Metadata)

	_, err := r.db.ExecContext(ctx, query,
		tenant.ID, tenant.Name, tenant.Slug, tenant.Domain, tenant.Subdomain,
		tenant.Status, string(settingsJSON), string(metadataJSON),
		tenant.CreatedAt, tenant.UpdatedAt, tenant.ActivatedAt, tenant.SuspendedAt)

	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			return ErrTenantAlreadyExists
		}
		return fmt.Errorf("failed to create tenant: %w", err)
	}

	return nil
}

// Update updates an existing tenant
func (r *SQLTenantRepository) Update(ctx context.Context, tenant *Tenant) error {
	query := `
		UPDATE tenants 
		SET name = ?, slug = ?, domain = ?, subdomain = ?, status = ?, 
		    settings = ?, metadata = ?, updated_at = ?, activated_at = ?, suspended_at = ?
		WHERE id = ? AND deleted_at IS NULL
	`

	settingsJSON, _ := json.Marshal(tenant.Settings)
	metadataJSON, _ := json.Marshal(tenant.Metadata)

	result, err := r.db.ExecContext(ctx, query,
		tenant.Name, tenant.Slug, tenant.Domain, tenant.Subdomain, tenant.Status,
		string(settingsJSON), string(metadataJSON), tenant.UpdatedAt,
		tenant.ActivatedAt, tenant.SuspendedAt, tenant.ID)

	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			return fmt.Errorf("tenant with slug '%s' already exists", tenant.Slug)
		}
		return fmt.Errorf("failed to update tenant: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrTenantNotFound
	}

	return nil
}

// Delete deletes a tenant (soft delete)
func (r *SQLTenantRepository) Delete(ctx context.Context, id string) error {
	query := `UPDATE tenants SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL`

	result, err := r.db.ExecContext(ctx, query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to delete tenant: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrTenantNotFound
	}

	return nil
}

// List retrieves all tenants with pagination
func (r *SQLTenantRepository) List(ctx context.Context, offset, limit int) ([]*Tenant, error) {
	query := `
		SELECT id, name, slug, domain, subdomain, status, settings, metadata,
		       created_at, updated_at, activated_at, suspended_at
		FROM tenants 
		WHERE deleted_at IS NULL
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`

	rows, err := r.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list tenants: %w", err)
	}
	defer rows.Close()

	var tenants []*Tenant
	for rows.Next() {
		tenant, err := r.scanTenantFromRows(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan tenant: %w", err)
		}
		tenants = append(tenants, tenant)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return tenants, nil
}

// Count returns the total number of tenants
func (r *SQLTenantRepository) Count(ctx context.Context) (int64, error) {
	query := `SELECT COUNT(*) FROM tenants WHERE deleted_at IS NULL`

	var count int64
	err := r.db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count tenants: %w", err)
	}

	return count, nil
}

// scanTenant scans a single tenant from a row
func (r *SQLTenantRepository) scanTenant(row *sql.Row) (*Tenant, error) {
	var tenant Tenant
	var settingsJSON, metadataJSON sql.NullString
	var activatedAt, suspendedAt sql.NullTime

	err := row.Scan(
		&tenant.ID, &tenant.Name, &tenant.Slug, &tenant.Domain, &tenant.Subdomain,
		&tenant.Status, &settingsJSON, &metadataJSON,
		&tenant.CreatedAt, &tenant.UpdatedAt, &activatedAt, &suspendedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to scan tenant: %w", err)
	}

	// Parse JSON fields
	if settingsJSON.Valid && settingsJSON.String != "" {
		if err := json.Unmarshal([]byte(settingsJSON.String), &tenant.Settings); err != nil {
			return nil, fmt.Errorf("failed to parse settings: %w", err)
		}
	}

	if metadataJSON.Valid && metadataJSON.String != "" {
		if err := json.Unmarshal([]byte(metadataJSON.String), &tenant.Metadata); err != nil {
			return nil, fmt.Errorf("failed to parse metadata: %w", err)
		}
	}

	// Handle nullable timestamps
	if activatedAt.Valid {
		tenant.ActivatedAt = &activatedAt.Time
	}
	if suspendedAt.Valid {
		tenant.SuspendedAt = &suspendedAt.Time
	}

	return &tenant, nil
}

// scanTenantFromRows scans a tenant from rows
func (r *SQLTenantRepository) scanTenantFromRows(rows *sql.Rows) (*Tenant, error) {
	var tenant Tenant
	var settingsJSON, metadataJSON sql.NullString
	var activatedAt, suspendedAt sql.NullTime

	err := rows.Scan(
		&tenant.ID, &tenant.Name, &tenant.Slug, &tenant.Domain, &tenant.Subdomain,
		&tenant.Status, &settingsJSON, &metadataJSON,
		&tenant.CreatedAt, &tenant.UpdatedAt, &activatedAt, &suspendedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan tenant: %w", err)
	}

	// Parse JSON fields
	if settingsJSON.Valid && settingsJSON.String != "" {
		if err := json.Unmarshal([]byte(settingsJSON.String), &tenant.Settings); err != nil {
			return nil, fmt.Errorf("failed to parse settings: %w", err)
		}
	}

	if metadataJSON.Valid && metadataJSON.String != "" {
		if err := json.Unmarshal([]byte(metadataJSON.String), &tenant.Metadata); err != nil {
			return nil, fmt.Errorf("failed to parse metadata: %w", err)
		}
	}

	// Handle nullable timestamps
	if activatedAt.Valid {
		tenant.ActivatedAt = &activatedAt.Time
	}
	if suspendedAt.Valid {
		tenant.SuspendedAt = &suspendedAt.Time
	}

	return &tenant, nil
}

// CreateTenantTable creates the tenants table (for migrations)
func CreateTenantTable(db *sql.DB) error {
	query := `
		CREATE TABLE IF NOT EXISTS tenants (
			id VARCHAR(36) PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			slug VARCHAR(100) NOT NULL UNIQUE,
			domain VARCHAR(255),
			subdomain VARCHAR(100),
			status VARCHAR(20) NOT NULL DEFAULT 'inactive',
			settings TEXT,
			metadata TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			activated_at TIMESTAMP NULL,
			suspended_at TIMESTAMP NULL,
			deleted_at TIMESTAMP NULL,
			INDEX idx_tenants_domain (domain),
			INDEX idx_tenants_subdomain (subdomain),
			INDEX idx_tenants_status (status),
			INDEX idx_tenants_deleted_at (deleted_at)
		)
	`

	_, err := db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create tenants table: %w", err)
	}

	return nil
}