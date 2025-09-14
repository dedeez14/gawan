package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// MemoryCache implements CachePort using in-memory storage
type MemoryCache struct {
	mu      sync.RWMutex
	items   map[string]*cacheItem
	config  MemoryConfig
	stopCh  chan struct{}
	cleaner *time.Ticker
}

// cacheItem represents a cached item with expiration
type cacheItem struct {
	value      []byte
	expiration int64
	createdAt  int64
	accessedAt int64
	accessCount int64
}

// MemoryConfig holds in-memory cache configuration
type MemoryConfig struct {
	MaxSize           int           `json:"max_size" yaml:"max_size" env:"MEMORY_CACHE_MAX_SIZE" default:"1000"`
	DefaultExpiration time.Duration `json:"default_expiration" yaml:"default_expiration" env:"MEMORY_CACHE_DEFAULT_EXPIRATION" default:"1h"`
	CleanupInterval   time.Duration `json:"cleanup_interval" yaml:"cleanup_interval" env:"MEMORY_CACHE_CLEANUP_INTERVAL" default:"10m"`
	EvictionPolicy    string        `json:"eviction_policy" yaml:"eviction_policy" env:"MEMORY_CACHE_EVICTION_POLICY" default:"lru"`
}

// NewMemoryCache creates a new in-memory cache instance
func NewMemoryCache(config MemoryConfig) *MemoryCache {
	c := &MemoryCache{
		items:  make(map[string]*cacheItem),
		config: config,
		stopCh: make(chan struct{}),
	}

	// Start cleanup goroutine
	c.cleaner = time.NewTicker(config.CleanupInterval)
	go c.cleanupExpired()

	return c
}

// Get retrieves a value from memory cache
func (m *MemoryCache) Get(ctx context.Context, key string) ([]byte, error) {
	m.mu.RLock()
	item, exists := m.items[key]
	m.mu.RUnlock()

	if !exists {
		return nil, ErrCacheMiss
	}

	now := time.Now().UnixNano()
	if item.expiration > 0 && now > item.expiration {
		m.mu.Lock()
		delete(m.items, key)
		m.mu.Unlock()
		return nil, ErrCacheMiss
	}

	// Update access statistics
	m.mu.Lock()
	item.accessedAt = now
	item.accessCount++
	m.mu.Unlock()

	return item.value, nil
}

// Set stores a value in memory cache with expiration
func (m *MemoryCache) Set(ctx context.Context, key string, value []byte, expiration time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if we need to evict items
	if len(m.items) >= m.config.MaxSize {
		m.evictItems(1)
	}

	now := time.Now().UnixNano()
	var exp int64
	if expiration > 0 {
		exp = now + int64(expiration)
	}

	m.items[key] = &cacheItem{
		value:       make([]byte, len(value)),
		expiration:  exp,
		createdAt:   now,
		accessedAt:  now,
		accessCount: 0,
	}
	copy(m.items[key].value, value)

	return nil
}

// Delete removes a value from memory cache
func (m *MemoryCache) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	delete(m.items, key)
	m.mu.Unlock()
	return nil
}

// Exists checks if a key exists in memory cache
func (m *MemoryCache) Exists(ctx context.Context, key string) (bool, error) {
	m.mu.RLock()
	item, exists := m.items[key]
	m.mu.RUnlock()

	if !exists {
		return false, nil
	}

	// Check expiration
	if item.expiration > 0 && time.Now().UnixNano() > item.expiration {
		m.mu.Lock()
		delete(m.items, key)
		m.mu.Unlock()
		return false, nil
	}

	return true, nil
}

// Clear removes all values from memory cache
func (m *MemoryCache) Clear(ctx context.Context) error {
	m.mu.Lock()
	m.items = make(map[string]*cacheItem)
	m.mu.Unlock()
	return nil
}

// GetMultiple retrieves multiple values from memory cache
func (m *MemoryCache) GetMultiple(ctx context.Context, keys []string) (map[string][]byte, error) {
	result := make(map[string][]byte)
	now := time.Now().UnixNano()

	m.mu.RLock()
	for _, key := range keys {
		if item, exists := m.items[key]; exists {
			if item.expiration == 0 || now <= item.expiration {
				result[key] = make([]byte, len(item.value))
				copy(result[key], item.value)
				// Update access statistics
				item.accessedAt = now
				item.accessCount++
			}
		}
	}
	m.mu.RUnlock()

	return result, nil
}

// SetMultiple stores multiple values in memory cache
func (m *MemoryCache) SetMultiple(ctx context.Context, items map[string][]byte, expiration time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if we need to evict items
	neededSpace := len(items)
	if len(m.items)+neededSpace > m.config.MaxSize {
		m.evictItems(neededSpace)
	}

	now := time.Now().UnixNano()
	var exp int64
	if expiration > 0 {
		exp = now + int64(expiration)
	}

	for key, value := range items {
		m.items[key] = &cacheItem{
			value:       make([]byte, len(value)),
			expiration:  exp,
			createdAt:   now,
			accessedAt:  now,
			accessCount: 0,
		}
		copy(m.items[key].value, value)
	}

	return nil
}

// Increment increments a numeric value in memory cache
func (m *MemoryCache) Increment(ctx context.Context, key string, delta int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	item, exists := m.items[key]
	if !exists {
		// Create new item with delta value
		value := fmt.Sprintf("%d", delta)
		m.items[key] = &cacheItem{
			value:       []byte(value),
			expiration:  0,
			createdAt:   time.Now().UnixNano(),
			accessedAt:  time.Now().UnixNano(),
			accessCount: 0,
		}
		return delta, nil
	}

	// Parse current value
	var current int64
	if err := json.Unmarshal(item.value, &current); err != nil {
		return 0, fmt.Errorf("value is not a number: %w", err)
	}

	newValue := current + delta
	value := fmt.Sprintf("%d", newValue)
	item.value = []byte(value)
	item.accessedAt = time.Now().UnixNano()
	item.accessCount++

	return newValue, nil
}

// Decrement decrements a numeric value in memory cache
func (m *MemoryCache) Decrement(ctx context.Context, key string, delta int64) (int64, error) {
	return m.Increment(ctx, key, -delta)
}

// Close closes the memory cache and stops cleanup goroutine
func (m *MemoryCache) Close() error {
	close(m.stopCh)
	if m.cleaner != nil {
		m.cleaner.Stop()
	}
	m.mu.Lock()
	m.items = nil
	m.mu.Unlock()
	return nil
}

// cleanupExpired removes expired items from cache
func (m *MemoryCache) cleanupExpired() {
	for {
		select {
		case <-m.cleaner.C:
			m.mu.Lock()
			now := time.Now().UnixNano()
			for key, item := range m.items {
				if item.expiration > 0 && now > item.expiration {
					delete(m.items, key)
				}
			}
			m.mu.Unlock()
		case <-m.stopCh:
			return
		}
	}
}

// evictItems removes items based on eviction policy
func (m *MemoryCache) evictItems(count int) {
	if len(m.items) == 0 {
		return
	}

	switch m.config.EvictionPolicy {
	case "lru": // Least Recently Used
		m.evictLRU(count)
	case "lfu": // Least Frequently Used
		m.evictLFU(count)
	case "fifo": // First In First Out
		m.evictFIFO(count)
	default:
		m.evictLRU(count)
	}
}

// evictLRU removes least recently used items
func (m *MemoryCache) evictLRU(count int) {
	type keyTime struct {
		key  string
		time int64
	}

	var candidates []keyTime
	for key, item := range m.items {
		candidates = append(candidates, keyTime{key: key, time: item.accessedAt})
	}

	// Sort by access time (oldest first)
	for i := 0; i < len(candidates)-1; i++ {
		for j := i + 1; j < len(candidates); j++ {
			if candidates[i].time > candidates[j].time {
				candidates[i], candidates[j] = candidates[j], candidates[i]
			}
		}
	}

	// Remove oldest items
	for i := 0; i < count && i < len(candidates); i++ {
		delete(m.items, candidates[i].key)
	}
}

// evictLFU removes least frequently used items
func (m *MemoryCache) evictLFU(count int) {
	type keyCount struct {
		key   string
		count int64
	}

	var candidates []keyCount
	for key, item := range m.items {
		candidates = append(candidates, keyCount{key: key, count: item.accessCount})
	}

	// Sort by access count (lowest first)
	for i := 0; i < len(candidates)-1; i++ {
		for j := i + 1; j < len(candidates); j++ {
			if candidates[i].count > candidates[j].count {
				candidates[i], candidates[j] = candidates[j], candidates[i]
			}
		}
	}

	// Remove least used items
	for i := 0; i < count && i < len(candidates); i++ {
		delete(m.items, candidates[i].key)
	}
}

// evictFIFO removes first in first out items
func (m *MemoryCache) evictFIFO(count int) {
	type keyTime struct {
		key  string
		time int64
	}

	var candidates []keyTime
	for key, item := range m.items {
		candidates = append(candidates, keyTime{key: key, time: item.createdAt})
	}

	// Sort by creation time (oldest first)
	for i := 0; i < len(candidates)-1; i++ {
		for j := i + 1; j < len(candidates); j++ {
			if candidates[i].time > candidates[j].time {
				candidates[i], candidates[j] = candidates[j], candidates[i]
			}
		}
	}

	// Remove oldest items
	for i := 0; i < count && i < len(candidates); i++ {
		delete(m.items, candidates[i].key)
	}
}

// Stats returns cache statistics
func (m *MemoryCache) Stats() CacheStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return CacheStats{
		Items:    len(m.items),
		MaxSize:  m.config.MaxSize,
		HitRatio: 0, // Would need to track hits/misses
	}
}

// CacheStats represents cache statistics
type CacheStats struct {
	Items    int     `json:"items"`
	MaxSize  int     `json:"max_size"`
	HitRatio float64 `json:"hit_ratio"`
}