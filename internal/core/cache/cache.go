package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"Gawan/internal/ports"
)

// Common cache errors
var (
	ErrCacheMiss     = errors.New("cache miss")
	ErrInvalidConfig = errors.New("invalid cache configuration")
)

// CacheType represents the type of cache to use
type CacheType string

const (
	RedisCache  CacheType = "redis"
	MemoryCache CacheType = "memory"
	MultiCache  CacheType = "multi"
)

// Config holds cache configuration
type Config struct {
	Type   CacheType     `json:"type" yaml:"type" env:"CACHE_TYPE" default:"memory"`
	Redis  RedisConfig   `json:"redis" yaml:"redis"`
	Memory MemoryConfig  `json:"memory" yaml:"memory"`
	Multi  MultiConfig   `json:"multi" yaml:"multi"`
}

// MultiConfig holds multi-level cache configuration
type MultiConfig struct {
	L1 CacheType `json:"l1" yaml:"l1" default:"memory"` // Level 1 cache (fastest)
	L2 CacheType `json:"l2" yaml:"l2" default:"redis"`  // Level 2 cache (persistent)
}

// Factory creates cache instances
type Factory struct {
	config Config
}

// NewFactory creates a new cache factory
func NewFactory(config Config) *Factory {
	return &Factory{config: config}
}

// CreateCache creates a cache instance based on configuration
func (f *Factory) CreateCache() (ports.CachePort, error) {
	switch f.config.Type {
	case RedisCache:
		return NewRedisCache(f.config.Redis)
	case MemoryCache:
		return NewMemoryCache(f.config.Memory), nil
	case MultiCache:
		return f.createMultiCache()
	default:
		return nil, fmt.Errorf("%w: unsupported cache type: %s", ErrInvalidConfig, f.config.Type)
	}
}

// createMultiCache creates a multi-level cache
func (f *Factory) createMultiCache() (ports.CachePort, error) {
	var l1, l2 ports.CachePort
	var err error

	// Create L1 cache
	switch f.config.Multi.L1 {
	case MemoryCache:
		l1 = NewMemoryCache(f.config.Memory)
	case RedisCache:
		l1, err = NewRedisCache(f.config.Redis)
		if err != nil {
			return nil, fmt.Errorf("failed to create L1 cache: %w", err)
		}
	default:
		return nil, fmt.Errorf("%w: unsupported L1 cache type: %s", ErrInvalidConfig, f.config.Multi.L1)
	}

	// Create L2 cache
	switch f.config.Multi.L2 {
	case RedisCache:
		l2, err = NewRedisCache(f.config.Redis)
		if err != nil {
			return nil, fmt.Errorf("failed to create L2 cache: %w", err)
		}
	case MemoryCache:
		l2 = NewMemoryCache(f.config.Memory)
	default:
		return nil, fmt.Errorf("%w: unsupported L2 cache type: %s", ErrInvalidConfig, f.config.Multi.L2)
	}

	return NewMultiLevelCache(l1, l2), nil
}

// MultiLevelCache implements a two-level caching system
type MultiLevelCache struct {
	l1 ports.CachePort // Level 1 cache (fast, small)
	l2 ports.CachePort // Level 2 cache (slower, larger)
}

// NewMultiLevelCache creates a new multi-level cache
func NewMultiLevelCache(l1, l2 ports.CachePort) *MultiLevelCache {
	return &MultiLevelCache{
		l1: l1,
		l2: l2,
	}
}

// Get retrieves a value from multi-level cache
func (m *MultiLevelCache) Get(ctx context.Context, key string) ([]byte, error) {
	// Try L1 cache first
	value, err := m.l1.Get(ctx, key)
	if err == nil {
		return value, nil
	}

	// If not found in L1, try L2
	value, err = m.l2.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	// Store in L1 for future access (with shorter expiration)
	_ = m.l1.Set(ctx, key, value, 5*time.Minute)

	return value, nil
}

// Set stores a value in both cache levels
func (m *MultiLevelCache) Set(ctx context.Context, key string, value []byte, expiration time.Duration) error {
	// Store in both levels
	err1 := m.l1.Set(ctx, key, value, expiration)
	err2 := m.l2.Set(ctx, key, value, expiration)

	// Return error if both failed
	if err1 != nil && err2 != nil {
		return fmt.Errorf("failed to set in both cache levels: L1=%v, L2=%v", err1, err2)
	}

	return nil
}

// Delete removes a value from both cache levels
func (m *MultiLevelCache) Delete(ctx context.Context, key string) error {
	err1 := m.l1.Delete(ctx, key)
	err2 := m.l2.Delete(ctx, key)

	// Return error if both failed
	if err1 != nil && err2 != nil {
		return fmt.Errorf("failed to delete from both cache levels: L1=%v, L2=%v", err1, err2)
	}

	return nil
}

// Exists checks if a key exists in either cache level
func (m *MultiLevelCache) Exists(ctx context.Context, key string) (bool, error) {
	// Check L1 first
	exists, err := m.l1.Exists(ctx, key)
	if err == nil && exists {
		return true, nil
	}

	// Check L2
	return m.l2.Exists(ctx, key)
}

// Clear removes all values from both cache levels
func (m *MultiLevelCache) Clear(ctx context.Context) error {
	err1 := m.l1.Clear(ctx)
	err2 := m.l2.Clear(ctx)

	if err1 != nil && err2 != nil {
		return fmt.Errorf("failed to clear both cache levels: L1=%v, L2=%v", err1, err2)
	}

	return nil
}

// GetMultiple retrieves multiple values from cache
func (m *MultiLevelCache) GetMultiple(ctx context.Context, keys []string) (map[string][]byte, error) {
	// Try L1 first
	result, err := m.l1.GetMultiple(ctx, keys)
	if err != nil {
		result = make(map[string][]byte)
	}

	// Find missing keys
	var missingKeys []string
	for _, key := range keys {
		if _, exists := result[key]; !exists {
			missingKeys = append(missingKeys, key)
		}
	}

	// Get missing keys from L2
	if len(missingKeys) > 0 {
		l2Result, err := m.l2.GetMultiple(ctx, missingKeys)
		if err == nil {
			// Merge results
			for key, value := range l2Result {
				result[key] = value
				// Store in L1 for future access
				_ = m.l1.Set(ctx, key, value, 5*time.Minute)
			}
		}
	}

	return result, nil
}

// SetMultiple stores multiple values in both cache levels
func (m *MultiLevelCache) SetMultiple(ctx context.Context, items map[string][]byte, expiration time.Duration) error {
	err1 := m.l1.SetMultiple(ctx, items, expiration)
	err2 := m.l2.SetMultiple(ctx, items, expiration)

	if err1 != nil && err2 != nil {
		return fmt.Errorf("failed to set multiple in both cache levels: L1=%v, L2=%v", err1, err2)
	}

	return nil
}

// Increment increments a numeric value in both cache levels
func (m *MultiLevelCache) Increment(ctx context.Context, key string, delta int64) (int64, error) {
	// Try L1 first
	value, err := m.l1.Increment(ctx, key, delta)
	if err == nil {
		// Sync with L2
		_ = m.l2.Set(ctx, key, []byte(fmt.Sprintf("%d", value)), time.Hour)
		return value, nil
	}

	// Fallback to L2
	return m.l2.Increment(ctx, key, delta)
}

// Decrement decrements a numeric value in both cache levels
func (m *MultiLevelCache) Decrement(ctx context.Context, key string, delta int64) (int64, error) {
	return m.Increment(ctx, key, -delta)
}

// Close closes both cache levels
func (m *MultiLevelCache) Close() error {
	err1 := m.l1.Close()
	err2 := m.l2.Close()

	if err1 != nil && err2 != nil {
		return fmt.Errorf("failed to close both cache levels: L1=%v, L2=%v", err1, err2)
	}

	return nil
}

// DefaultConfig returns default cache configuration
func DefaultConfig() Config {
	return Config{
		Type: MemoryCache,
		Redis: RedisConfig{
			Host:         "localhost",
			Port:         6379,
			DB:           0,
			PoolSize:     10,
			MinIdleConns: 5,
			MaxRetries:   3,
			DialTimeout:  5 * time.Second,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
			IdleTimeout:  5 * time.Minute,
		},
		Memory: MemoryConfig{
			MaxSize:           1000,
			DefaultExpiration: time.Hour,
			CleanupInterval:   10 * time.Minute,
			EvictionPolicy:    "lru",
		},
		Multi: MultiConfig{
			L1: MemoryCache,
			L2: RedisCache,
		},
	}
}