package config

import (
	"os"
	"strconv"
	"time"
)

// Config represents the application configuration
type Config struct {
	// Server configuration
	Server ServerConfig `yaml:"server" json:"server"`

	// Database configuration
	Database DatabaseConfig `yaml:"database" json:"database"`

	// Redis configuration
	Redis RedisConfig `yaml:"redis" json:"redis"`

	// JWT configuration
	JWT JWTConfig `yaml:"jwt" json:"jwt"`

	// Logging configuration
	Logging LoggingConfig `yaml:"logging" json:"logging"`

	// Application configuration
	App AppConfig `yaml:"app" json:"app"`
}

// ServerConfig holds server-related configuration
type ServerConfig struct {
	Host         string        `yaml:"host" json:"host" env:"HOST" flag:"host"`
	Port         int           `yaml:"port" json:"port" env:"PORT" flag:"port"`
	ReadTimeout  time.Duration `yaml:"read_timeout" json:"read_timeout" env:"READ_TIMEOUT" flag:"read-timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout" json:"write_timeout" env:"WRITE_TIMEOUT" flag:"write-timeout"`
	IdleTimeout  time.Duration `yaml:"idle_timeout" json:"idle_timeout" env:"IDLE_TIMEOUT" flag:"idle-timeout"`
	TLS          TLSConfig     `yaml:"tls" json:"tls"`
}

// TLSConfig holds TLS-related configuration
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled" json:"enabled" env:"TLS_ENABLED" flag:"tls-enabled"`
	CertFile string `yaml:"cert_file" json:"cert_file" env:"TLS_CERT_FILE" flag:"tls-cert-file"`
	KeyFile  string `yaml:"key_file" json:"key_file" env:"TLS_KEY_FILE" flag:"tls-key-file"`
}

// DatabaseConfig holds database-related configuration
type DatabaseConfig struct {
	Driver          string        `yaml:"driver" json:"driver" env:"DB_DRIVER" flag:"db-driver"`
	Host            string        `yaml:"host" json:"host" env:"DB_HOST" flag:"db-host"`
	Port            int           `yaml:"port" json:"port" env:"DB_PORT" flag:"db-port"`
	Username        string        `yaml:"username" json:"username" env:"DB_USERNAME" flag:"db-username"`
	Password        string        `yaml:"password" json:"password" env:"DB_PASSWORD" flag:"db-password" vault:"database/creds" vault_key:"password"`
	Database        string        `yaml:"database" json:"database" env:"DB_DATABASE" flag:"db-database"`
	SSLMode         string        `yaml:"ssl_mode" json:"ssl_mode" env:"DB_SSL_MODE" flag:"db-ssl-mode"`
	MaxOpenConns    int           `yaml:"max_open_conns" json:"max_open_conns" env:"DB_MAX_OPEN_CONNS" flag:"db-max-open-conns"`
	MaxIdleConns    int           `yaml:"max_idle_conns" json:"max_idle_conns" env:"DB_MAX_IDLE_CONNS" flag:"db-max-idle-conns"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime" json:"conn_max_lifetime" env:"DB_CONN_MAX_LIFETIME" flag:"db-conn-max-lifetime"`
}

// RedisConfig holds Redis-related configuration
type RedisConfig struct {
	Host         string        `yaml:"host" json:"host" env:"REDIS_HOST" flag:"redis-host"`
	Port         int           `yaml:"port" json:"port" env:"REDIS_PORT" flag:"redis-port"`
	Password     string        `yaml:"password" json:"password" env:"REDIS_PASSWORD" flag:"redis-password" vault:"redis/creds" vault_key:"password"`
	DB           int           `yaml:"db" json:"db" env:"REDIS_DB" flag:"redis-db"`
	PoolSize     int           `yaml:"pool_size" json:"pool_size" env:"REDIS_POOL_SIZE" flag:"redis-pool-size"`
	DialTimeout  time.Duration `yaml:"dial_timeout" json:"dial_timeout" env:"REDIS_DIAL_TIMEOUT" flag:"redis-dial-timeout"`
	ReadTimeout  time.Duration `yaml:"read_timeout" json:"read_timeout" env:"REDIS_READ_TIMEOUT" flag:"redis-read-timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout" json:"write_timeout" env:"REDIS_WRITE_TIMEOUT" flag:"redis-write-timeout"`
}

// JWTConfig holds JWT-related configuration
type JWTConfig struct {
	Secret           string        `yaml:"secret" json:"secret" env:"JWT_SECRET" flag:"jwt-secret" vault:"jwt/secret" vault_key:"secret"`
	Expiration       time.Duration `yaml:"expiration" json:"expiration" env:"JWT_EXPIRATION" flag:"jwt-expiration"`
	RefreshExpiration time.Duration `yaml:"refresh_expiration" json:"refresh_expiration" env:"JWT_REFRESH_EXPIRATION" flag:"jwt-refresh-expiration"`
	Issuer           string        `yaml:"issuer" json:"issuer" env:"JWT_ISSUER" flag:"jwt-issuer"`
	Audience         []string      `yaml:"audience" json:"audience" env:"JWT_AUDIENCE" flag:"jwt-audience"`
}

// LoggingConfig holds logging-related configuration
type LoggingConfig struct {
	Level      string `yaml:"level" json:"level" env:"LOG_LEVEL" flag:"log-level"`
	Format     string `yaml:"format" json:"format" env:"LOG_FORMAT" flag:"log-format"`
	Output     string `yaml:"output" json:"output" env:"LOG_OUTPUT" flag:"log-output"`
	File       string `yaml:"file" json:"file" env:"LOG_FILE" flag:"log-file"`
	MaxSize    int    `yaml:"max_size" json:"max_size" env:"LOG_MAX_SIZE" flag:"log-max-size"`
	MaxBackups int    `yaml:"max_backups" json:"max_backups" env:"LOG_MAX_BACKUPS" flag:"log-max-backups"`
	MaxAge     int    `yaml:"max_age" json:"max_age" env:"LOG_MAX_AGE" flag:"log-max-age"`
	Compress   bool   `yaml:"compress" json:"compress" env:"LOG_COMPRESS" flag:"log-compress"`
}

// AppConfig holds application-specific configuration
type AppConfig struct {
	Name        string `yaml:"name" json:"name" env:"APP_NAME" flag:"app-name"`
	Version     string `yaml:"version" json:"version" env:"APP_VERSION" flag:"app-version"`
	Environment string `yaml:"environment" json:"environment" env:"APP_ENV" flag:"app-env"`
	Debug       bool   `yaml:"debug" json:"debug" env:"APP_DEBUG" flag:"app-debug"`
	URL         string `yaml:"url" json:"url" env:"APP_URL" flag:"app-url"`
	Timezone    string `yaml:"timezone" json:"timezone" env:"APP_TIMEZONE" flag:"app-timezone"`
}

// DefaultConfig returns a configuration with default values
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:         "localhost",
			Port:         8080,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
			TLS: TLSConfig{
				Enabled: false,
			},
		},
		Database: DatabaseConfig{
			Driver:          "postgres",
			Host:            "localhost",
			Port:            5432,
			Username:        "postgres",
			Password:        "",
			Database:        "gawan",
			SSLMode:         "disable",
			MaxOpenConns:    25,
			MaxIdleConns:    25,
			ConnMaxLifetime: 5 * time.Minute,
		},
		Redis: RedisConfig{
			Host:         "localhost",
			Port:         6379,
			Password:     "",
			DB:           0,
			PoolSize:     10,
			DialTimeout:  5 * time.Second,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
		},
		JWT: JWTConfig{
			Secret:            "your-secret-key",
			Expiration:        24 * time.Hour,
			RefreshExpiration: 7 * 24 * time.Hour,
			Issuer:            "gawan",
			Audience:          []string{"gawan-users"},
		},
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "json",
			Output:     "stdout",
			File:       "",
			MaxSize:    100,
			MaxBackups: 3,
			MaxAge:     28,
			Compress:   true,
		},
		App: AppConfig{
			Name:        "Gawan App",
			Version:     "1.0.0",
			Environment: "development",
			Debug:       true,
			URL:         "http://localhost:8080",
			Timezone:    "UTC",
		},
	}
}

// Load loads configuration using the ConfigLoader (backward compatibility)
func Load() *Config {
	config, err := LoadConfig("config.yaml", "config.yml", "config.json")
	if err != nil {
		// Fallback to simple config for backward compatibility
		return &Config{
			Server: ServerConfig{
				Host: getEnv("HOST", "localhost"),
				Port: getEnvInt("PORT", 8080),
			},
			Logging: LoggingConfig{
				Level: getEnv("LOG_LEVEL", "info"),
			},
			App: AppConfig{
				Environment: getEnv("ENV", "development"),
			},
		}
	}
	return config
}

// LoadConfig loads configuration using the ConfigLoader
func LoadConfig(configPaths ...string) (*Config, error) {
	config := DefaultConfig()

	loader := NewConfigLoader("GAWAN", configPaths...)

	if err := loader.Load(config, nil); err != nil {
		return nil, err
	}

	return config, nil
}

// LoadConfigWithFlags loads configuration with CLI flags
func LoadConfigWithFlags(flags map[string]interface{}, configPaths ...string) (*Config, error) {
	config := DefaultConfig()

	loader := NewConfigLoader("GAWAN", configPaths...)

	if err := loader.Load(config, flags); err != nil {
		return nil, err
	}

	return config, nil
}

// getEnv gets environment variable with fallback (backward compatibility)
func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// getEnvInt gets environment variable as int with fallback
func getEnvInt(key string, fallback int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return fallback
}