package ports

import (
	"context"
	"time"
)

// CachePort defines the interface for cache operations
type CachePort interface {
	// Get retrieves a value from cache
	Get(ctx context.Context, key string) ([]byte, error)

	// Set stores a value in cache with expiration
	Set(ctx context.Context, key string, value []byte, expiration time.Duration) error

	// Delete removes a value from cache
	Delete(ctx context.Context, key string) error

	// Exists checks if a key exists in cache
	Exists(ctx context.Context, key string) (bool, error)

	// Clear removes all values from cache
	Clear(ctx context.Context) error

	// GetMultiple retrieves multiple values from cache
	GetMultiple(ctx context.Context, keys []string) (map[string][]byte, error)

	// SetMultiple stores multiple values in cache
	SetMultiple(ctx context.Context, items map[string][]byte, expiration time.Duration) error

	// Increment increments a numeric value in cache
	Increment(ctx context.Context, key string, delta int64) (int64, error)

	// Decrement decrements a numeric value in cache
	Decrement(ctx context.Context, key string, delta int64) (int64, error)

	// Close closes the cache connection
	Close() error
}

// CacheConfig holds cache configuration
type CacheConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
	Timeout  time.Duration
}