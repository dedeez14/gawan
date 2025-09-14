package ports

import (
	"context"
	"database/sql"
)

// DBPort defines the interface for database operations
type DBPort interface {
	// Query executes a query that returns rows
	Query(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)

	// QueryRow executes a query that returns at most one row
	QueryRow(ctx context.Context, query string, args ...interface{}) *sql.Row

	// Exec executes a query without returning any rows
	Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error)

	// Begin starts a transaction
	Begin(ctx context.Context) (TxPort, error)

	// Ping verifies a connection to the database is still alive
	Ping(ctx context.Context) error

	// Close closes the database connection
	Close() error

	// Stats returns database statistics
	Stats() sql.DBStats
}

// TxPort defines the interface for database transaction operations
type TxPort interface {
	// Query executes a query that returns rows within a transaction
	Query(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)

	// QueryRow executes a query that returns at most one row within a transaction
	QueryRow(ctx context.Context, query string, args ...interface{}) *sql.Row

	// Exec executes a query without returning any rows within a transaction
	Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error)

	// Commit commits the transaction
	Commit() error

	// Rollback aborts the transaction
	Rollback() error
}

// DBConfig holds database configuration
type DBConfig struct {
	Driver          string
	Host            string
	Port            int
	Username        string
	Password        string
	Database        string
	SSLMode         string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime string
}

// Repository defines a generic repository interface
type Repository[T any] interface {
	// Create creates a new entity
	Create(ctx context.Context, entity *T) error

	// GetByID retrieves an entity by ID
	GetByID(ctx context.Context, id interface{}) (*T, error)

	// Update updates an existing entity
	Update(ctx context.Context, entity *T) error

	// Delete deletes an entity by ID
	Delete(ctx context.Context, id interface{}) error

	// List retrieves a list of entities with pagination
	List(ctx context.Context, limit, offset int) ([]*T, error)

	// Count returns the total count of entities
	Count(ctx context.Context) (int64, error)
}