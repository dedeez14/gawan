package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

// RedisCache implements CachePort using Redis
type RedisCache struct {
	client *redis.Client
	config RedisConfig
}

// RedisConfig holds Redis configuration
type RedisConfig struct {
	Host         string        `json:"host" yaml:"host" env:"REDIS_HOST" default:"localhost"`
	Port         int           `json:"port" yaml:"port" env:"REDIS_PORT" default:"6379"`
	Password     string        `json:"password" yaml:"password" env:"REDIS_PASSWORD"`
	DB           int           `json:"db" yaml:"db" env:"REDIS_DB" default:"0"`
	PoolSize     int           `json:"pool_size" yaml:"pool_size" env:"REDIS_POOL_SIZE" default:"10"`
	MinIdleConns int           `json:"min_idle_conns" yaml:"min_idle_conns" env:"REDIS_MIN_IDLE_CONNS" default:"5"`
	MaxRetries   int           `json:"max_retries" yaml:"max_retries" env:"REDIS_MAX_RETRIES" default:"3"`
	DialTimeout  time.Duration `json:"dial_timeout" yaml:"dial_timeout" env:"REDIS_DIAL_TIMEOUT" default:"5s"`
	ReadTimeout  time.Duration `json:"read_timeout" yaml:"read_timeout" env:"REDIS_READ_TIMEOUT" default:"3s"`
	WriteTimeout time.Duration `json:"write_timeout" yaml:"write_timeout" env:"REDIS_WRITE_TIMEOUT" default:"3s"`
	IdleTimeout  time.Duration `json:"idle_timeout" yaml:"idle_timeout" env:"REDIS_IDLE_TIMEOUT" default:"5m"`
}

// NewRedisCache creates a new Redis cache instance
func NewRedisCache(config RedisConfig) (*RedisCache, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", config.Host, config.Port),
		Password:     config.Password,
		DB:           config.DB,
		PoolSize:     config.PoolSize,
		MinIdleConns: config.MinIdleConns,
		MaxRetries:   config.MaxRetries,
		DialTimeout:  config.DialTimeout,
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
		IdleTimeout:  config.IdleTimeout,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisCache{
		client: rdb,
		config: config,
	}, nil
}

// Get retrieves a value from Redis cache
func (r *RedisCache) Get(ctx context.Context, key string) ([]byte, error) {
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, ErrCacheMiss
		}
		return nil, fmt.Errorf("failed to get key %s: %w", key, err)
	}
	return []byte(val), nil
}

// Set stores a value in Redis cache with expiration
func (r *RedisCache) Set(ctx context.Context, key string, value []byte, expiration time.Duration) error {
	err := r.client.Set(ctx, key, value, expiration).Err()
	if err != nil {
		return fmt.Errorf("failed to set key %s: %w", key, err)
	}
	return nil
}

// Delete removes a value from Redis cache
func (r *RedisCache) Delete(ctx context.Context, key string) error {
	err := r.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to delete key %s: %w", key, err)
	}
	return nil
}

// Exists checks if a key exists in Redis cache
func (r *RedisCache) Exists(ctx context.Context, key string) (bool, error) {
	count, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check existence of key %s: %w", key, err)
	}
	return count > 0, nil
}

// Clear removes all values from Redis cache
func (r *RedisCache) Clear(ctx context.Context) error {
	err := r.client.FlushDB(ctx).Err()
	if err != nil {
		return fmt.Errorf("failed to clear cache: %w", err)
	}
	return nil
}

// GetMultiple retrieves multiple values from Redis cache
func (r *RedisCache) GetMultiple(ctx context.Context, keys []string) (map[string][]byte, error) {
	if len(keys) == 0 {
		return make(map[string][]byte), nil
	}

	vals, err := r.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get multiple keys: %w", err)
	}

	result := make(map[string][]byte)
	for i, val := range vals {
		if val != nil {
			if str, ok := val.(string); ok {
				result[keys[i]] = []byte(str)
			}
		}
	}

	return result, nil
}

// SetMultiple stores multiple values in Redis cache
func (r *RedisCache) SetMultiple(ctx context.Context, items map[string][]byte, expiration time.Duration) error {
	pipe := r.client.Pipeline()

	for key, value := range items {
		pipe.Set(ctx, key, value, expiration)
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to set multiple keys: %w", err)
	}

	return nil
}

// Increment increments a numeric value in Redis cache
func (r *RedisCache) Increment(ctx context.Context, key string, delta int64) (int64, error) {
	val, err := r.client.IncrBy(ctx, key, delta).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to increment key %s: %w", key, err)
	}
	return val, nil
}

// Decrement decrements a numeric value in Redis cache
func (r *RedisCache) Decrement(ctx context.Context, key string, delta int64) (int64, error) {
	val, err := r.client.DecrBy(ctx, key, delta).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to decrement key %s: %w", key, err)
	}
	return val, nil
}

// Close closes the Redis connection
func (r *RedisCache) Close() error {
	return r.client.Close()
}

// GetJSON retrieves and unmarshals JSON data from cache
func (r *RedisCache) GetJSON(ctx context.Context, key string, dest interface{}) error {
	data, err := r.Get(ctx, key)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dest)
}

// SetJSON marshals and stores JSON data in cache
func (r *RedisCache) SetJSON(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return r.Set(ctx, key, data, expiration)
}

// Stats returns Redis connection statistics
func (r *RedisCache) Stats() *redis.PoolStats {
	return r.client.PoolStats()
}