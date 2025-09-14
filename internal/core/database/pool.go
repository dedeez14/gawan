package database

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"Gawan/internal/ports"
)

// PoolConfig holds database connection pool configuration
type PoolConfig struct {
	// Connection settings
	Driver   string `json:"driver" yaml:"driver" env:"DB_DRIVER" default:"sqlite3"`
	Host     string `json:"host" yaml:"host" env:"DB_HOST" default:"localhost"`
	Port     int    `json:"port" yaml:"port" env:"DB_PORT" default:"5432"`
	Database string `json:"database" yaml:"database" env:"DB_NAME" default:"gawan.db"`
	Username string `json:"username" yaml:"username" env:"DB_USER" default:""`
	Password string `json:"password" yaml:"password" env:"DB_PASSWORD" default:""`
	SSLMode  string `json:"ssl_mode" yaml:"ssl_mode" env:"DB_SSL_MODE" default:"disable"`

	// Pool settings
	MaxOpenConns    int           `json:"max_open_conns" yaml:"max_open_conns" env:"DB_MAX_OPEN_CONNS" default:"25"`
	MaxIdleConns    int           `json:"max_idle_conns" yaml:"max_idle_conns" env:"DB_MAX_IDLE_CONNS" default:"5"`
	ConnMaxLifetime time.Duration `json:"conn_max_lifetime" yaml:"conn_max_lifetime" env:"DB_CONN_MAX_LIFETIME" default:"1h"`
	ConnMaxIdleTime time.Duration `json:"conn_max_idle_time" yaml:"conn_max_idle_time" env:"DB_CONN_MAX_IDLE_TIME" default:"30m"`

	// Timeout settings
	ConnectTimeout time.Duration `json:"connect_timeout" yaml:"connect_timeout" env:"DB_CONNECT_TIMEOUT" default:"10s"`
	QueryTimeout   time.Duration `json:"query_timeout" yaml:"query_timeout" env:"DB_QUERY_TIMEOUT" default:"30s"`

	// Health check settings
	HealthCheckInterval time.Duration `json:"health_check_interval" yaml:"health_check_interval" env:"DB_HEALTH_CHECK_INTERVAL" default:"1m"`
	MaxRetries          int           `json:"max_retries" yaml:"max_retries" env:"DB_MAX_RETRIES" default:"3"`
	RetryDelay          time.Duration `json:"retry_delay" yaml:"retry_delay" env:"DB_RETRY_DELAY" default:"1s"`
}

// Pool represents an optimized database connection pool
type Pool struct {
	db     *sql.DB
	config PoolConfig
	mu     sync.RWMutex
	stats  PoolStats
	stopCh chan struct{}
}

// PoolStats holds connection pool statistics
type PoolStats struct {
	TotalConnections   int64         `json:"total_connections"`
	ActiveConnections  int64         `json:"active_connections"`
	IdleConnections    int64         `json:"idle_connections"`
	FailedConnections  int64         `json:"failed_connections"`
	TotalQueries       int64         `json:"total_queries"`
	FailedQueries      int64         `json:"failed_queries"`
	AverageQueryTime   time.Duration `json:"average_query_time"`
	LastHealthCheck    time.Time     `json:"last_health_check"`
	HealthCheckStatus  string        `json:"health_check_status"`
}

// NewPool creates a new optimized database connection pool
func NewPool(config PoolConfig) (*Pool, error) {
	dsn, err := buildDSN(config)
	if err != nil {
		return nil, fmt.Errorf("failed to build DSN: %w", err)
	}

	db, err := sql.Open(config.Driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(config.MaxOpenConns)
	db.SetMaxIdleConns(config.MaxIdleConns)
	db.SetConnMaxLifetime(config.ConnMaxLifetime)
	db.SetConnMaxIdleTime(config.ConnMaxIdleTime)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), config.ConnectTimeout)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	pool := &Pool{
		db:     db,
		config: config,
		stopCh: make(chan struct{}),
	}

	// Start health check goroutine
	go pool.healthCheckLoop()

	return pool, nil
}

// buildDSN builds database connection string based on driver
func buildDSN(config PoolConfig) (string, error) {
	switch config.Driver {
	case "postgres":
		return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			config.Host, config.Port, config.Username, config.Password, config.Database, config.SSLMode), nil
	case "mysql":
		return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true",
			config.Username, config.Password, config.Host, config.Port, config.Database), nil
	case "sqlite3":
		return config.Database, nil
	default:
		return "", fmt.Errorf("unsupported database driver: %s", config.Driver)
	}
}

// Query executes a query with retry logic and timeout
func (p *Pool) Query(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	start := time.Now()
	defer func() {
		p.updateQueryStats(time.Since(start), nil)
	}()

	ctx, cancel := context.WithTimeout(ctx, p.config.QueryTimeout)
	defer cancel()

	var rows *sql.Rows
	var err error

	for attempt := 0; attempt <= p.config.MaxRetries; attempt++ {
		rows, err = p.db.QueryContext(ctx, query, args...)
		if err == nil {
			return rows, nil
		}

		// Check if error is retryable
		if !isRetryableError(err) {
			break
		}

		if attempt < p.config.MaxRetries {
			select {
			case <-time.After(p.config.RetryDelay * time.Duration(attempt+1)):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}

	p.updateQueryStats(time.Since(start), err)
	return nil, fmt.Errorf("query failed after %d attempts: %w", p.config.MaxRetries+1, err)
}

// QueryRow executes a query that returns at most one row
func (p *Pool) QueryRow(ctx context.Context, query string, args ...interface{}) *sql.Row {
	start := time.Now()
	defer func() {
		p.updateQueryStats(time.Since(start), nil)
	}()

	ctx, cancel := context.WithTimeout(ctx, p.config.QueryTimeout)
	defer cancel()

	return p.db.QueryRowContext(ctx, query, args...)
}

// Exec executes a query without returning rows
func (p *Pool) Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	start := time.Now()
	defer func() {
		p.updateQueryStats(time.Since(start), nil)
	}()

	ctx, cancel := context.WithTimeout(ctx, p.config.QueryTimeout)
	defer cancel()

	var result sql.Result
	var err error

	for attempt := 0; attempt <= p.config.MaxRetries; attempt++ {
		result, err = p.db.ExecContext(ctx, query, args...)
		if err == nil {
			return result, nil
		}

		// Check if error is retryable
		if !isRetryableError(err) {
			break
		}

		if attempt < p.config.MaxRetries {
			select {
			case <-time.After(p.config.RetryDelay * time.Duration(attempt+1)):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}

	p.updateQueryStats(time.Since(start), err)
	return nil, fmt.Errorf("exec failed after %d attempts: %w", p.config.MaxRetries+1, err)
}

// Begin starts a transaction
func (p *Pool) Begin(ctx context.Context) (ports.TxPort, error) {
	ctx, cancel := context.WithTimeout(ctx, p.config.QueryTimeout)
	defer cancel()

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}

	return &Transaction{tx: tx, pool: p}, nil
}

// Ping verifies connection to database
func (p *Pool) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, p.config.ConnectTimeout)
	defer cancel()

	return p.db.PingContext(ctx)
}

// Close closes the database connection pool
func (p *Pool) Close() error {
	close(p.stopCh)
	return p.db.Close()
}

// Stats returns database connection pool statistics
func (p *Pool) Stats() sql.DBStats {
	return p.db.Stats()
}

// GetPoolStats returns custom pool statistics
func (p *Pool) GetPoolStats() PoolStats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.stats
}

// updateQueryStats updates query statistics
func (p *Pool) updateQueryStats(duration time.Duration, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.stats.TotalQueries++
	if err != nil {
		p.stats.FailedQueries++
	}

	// Update average query time (simple moving average)
	if p.stats.TotalQueries == 1 {
		p.stats.AverageQueryTime = duration
	} else {
		p.stats.AverageQueryTime = (p.stats.AverageQueryTime + duration) / 2
	}
}

// healthCheckLoop performs periodic health checks
func (p *Pool) healthCheckLoop() {
	ticker := time.NewTicker(p.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.performHealthCheck()
		case <-p.stopCh:
			return
		}
	}
}

// performHealthCheck performs a health check on the database
func (p *Pool) performHealthCheck() {
	ctx, cancel := context.WithTimeout(context.Background(), p.config.ConnectTimeout)
	defer cancel()

	p.mu.Lock()
	defer p.mu.Unlock()

	p.stats.LastHealthCheck = time.Now()

	if err := p.db.PingContext(ctx); err != nil {
		p.stats.HealthCheckStatus = fmt.Sprintf("unhealthy: %v", err)
		p.stats.FailedConnections++
	} else {
		p.stats.HealthCheckStatus = "healthy"
	}

	// Update connection stats
	dbStats := p.db.Stats()
	p.stats.ActiveConnections = int64(dbStats.InUse)
	p.stats.IdleConnections = int64(dbStats.Idle)
	p.stats.TotalConnections = int64(dbStats.OpenConnections)
}

// isRetryableError checks if an error is retryable
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Add specific error checks based on database driver
	errorStr := err.Error()
	retryableErrors := []string{
		"connection refused",
		"connection reset",
		"timeout",
		"temporary failure",
		"server closed",
	}

	for _, retryable := range retryableErrors {
		if contains(errorStr, retryable) {
			return true
		}
	}

	return false
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || 
		(len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || 
			containsHelper(s, substr))))
}

// containsHelper is a helper function for substring search
func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Transaction represents a database transaction
type Transaction struct {
	tx   *sql.Tx
	pool *Pool
}

// Query executes a query within transaction
func (t *Transaction) Query(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	start := time.Now()
	defer func() {
		t.pool.updateQueryStats(time.Since(start), nil)
	}()

	ctx, cancel := context.WithTimeout(ctx, t.pool.config.QueryTimeout)
	defer cancel()

	return t.tx.QueryContext(ctx, query, args...)
}

// QueryRow executes a query that returns at most one row within transaction
func (t *Transaction) QueryRow(ctx context.Context, query string, args ...interface{}) *sql.Row {
	start := time.Now()
	defer func() {
		t.pool.updateQueryStats(time.Since(start), nil)
	}()

	ctx, cancel := context.WithTimeout(ctx, t.pool.config.QueryTimeout)
	defer cancel()

	return t.tx.QueryRowContext(ctx, query, args...)
}

// Exec executes a query without returning rows within transaction
func (t *Transaction) Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	start := time.Now()
	defer func() {
		t.pool.updateQueryStats(time.Since(start), nil)
	}()

	ctx, cancel := context.WithTimeout(ctx, t.pool.config.QueryTimeout)
	defer cancel()

	return t.tx.ExecContext(ctx, query, args...)
}

// Commit commits the transaction
func (t *Transaction) Commit() error {
	return t.tx.Commit()
}

// Rollback aborts the transaction
func (t *Transaction) Rollback() error {
	return t.tx.Rollback()
}