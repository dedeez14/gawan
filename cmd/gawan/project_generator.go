package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
)

// ProjectGenerator generates new Gawan projects
type ProjectGenerator struct {
	Name       string
	ModulePath string
	Directory  string
	Template   string
	NoGit      bool
	NoMod      bool
}

// NewProjectGenerator creates a new project generator
func NewProjectGenerator() *ProjectGenerator {
	return &ProjectGenerator{}
}

// GenerateProject generates a new project with the given parameters
func (pg *ProjectGenerator) GenerateProject(name, projectType, outputDir string, force bool) error {
	pg.Name = name
	pg.ModulePath = name
	pg.Directory = filepath.Join(outputDir, name)
	pg.Template = projectType

	// Check if directory exists
	if _, err := os.Stat(pg.Directory); err == nil && !force {
		return fmt.Errorf("directory %s already exists, use --force to overwrite", pg.Directory)
	}

	return pg.Generate()
}

// Generate creates the project structure
func (pg *ProjectGenerator) Generate() error {
	// Create directory structure
	if err := pg.createDirectoryStructure(); err != nil {
		return fmt.Errorf("failed to create directory structure: %w", err)
	}

	// Generate files based on template
	if err := pg.generateFiles(); err != nil {
		return fmt.Errorf("failed to generate files: %w", err)
	}

	// Initialize go module
	if !pg.NoMod {
		if err := pg.initGoModule(); err != nil {
			return fmt.Errorf("failed to initialize go module: %w", err)
		}
	}

	// Initialize git repository
	if !pg.NoGit {
		if err := pg.initGitRepository(); err != nil {
			// Don't fail if git init fails, just warn
			fmt.Printf("Warning: failed to initialize git repository: %v\n", err)
		}
	}

	return nil
}

func (pg *ProjectGenerator) createDirectoryStructure() error {
	dirs := pg.getDirectoryStructure()

	for _, dir := range dirs {
		fullPath := filepath.Join(pg.Directory, dir)
		if err := os.MkdirAll(fullPath, 0755); err != nil {
			return err
		}
	}

	return nil
}

func (pg *ProjectGenerator) getDirectoryStructure() []string {
	baseDirs := []string{
		"cmd/server",
		"internal/app/controllers",
		"internal/app/services",
		"internal/app/models",
		"internal/app/middleware",
		"internal/app/repositories",
		"internal/core/config",
		"internal/core/database",
		"internal/ports",
		"pkg/utils",
		"web/static/css",
		"web/static/js",
		"web/templates",
		"configs",
		"scripts",
		"docs",
		"test/integration",
		"test/unit",
	}

	switch pg.Template {
	case "api":
		return append(baseDirs, "api/v1", "internal/app/dto")
	case "web":
		return append(baseDirs, "web/assets", "web/views")
	case "microservice":
		return append(baseDirs, "internal/app/grpc", "internal/app/events", "proto")
	default:
		return baseDirs
	}
}

func (pg *ProjectGenerator) generateFiles() error {
	files := pg.getTemplateFiles()

	for _, file := range files {
		if err := pg.generateFile(file); err != nil {
			return fmt.Errorf("failed to generate %s: %w", file.Path, err)
		}
	}

	return nil
}

type templateFile struct {
	Path     string
	Template string
}

func (pg *ProjectGenerator) getTemplateFiles() []templateFile {
	commonFiles := []templateFile{
		{"go.mod", goModTemplate},
		{"README.md", readmeTemplate},
		{"Makefile", makefileTemplate},
		{".gitignore", gitignoreTemplate},
		{".air.toml", airConfigTemplate},
		{"cmd/server/main.go", mainTemplate},
		{"internal/app/app.go", appTemplate},
		{"internal/app/routes.go", routesTemplate},
		{"internal/core/config/config.go", configTemplate},
		{"configs/config.yaml", configYamlTemplate},
		{"pkg/utils/response.go", responseUtilTemplate},
	}

	switch pg.Template {
	case "api":
		return append(commonFiles, []templateFile{
			{"internal/app/controllers/health_controller.go", healthControllerTemplate},
			{"internal/app/dto/response.go", dtoResponseTemplate},
			{"api/v1/openapi.yaml", openapiTemplate},
		}...)
	case "web":
		return append(commonFiles, []templateFile{
			{"internal/app/controllers/home_controller.go", homeControllerTemplate},
			{"web/templates/layout.html", layoutTemplate},
			{"web/templates/home.html", homeTemplate},
			{"web/static/css/style.css", cssTemplate},
		}...)
	case "microservice":
		return append(commonFiles, []templateFile{
			{"internal/app/grpc/server.go", grpcServerTemplate},
			{"proto/service.proto", protoTemplate},
		}...)
	default:
		return append(commonFiles, []templateFile{
			{"internal/app/controllers/example_controller.go", exampleControllerTemplate},
		}...)
	}
}

func (pg *ProjectGenerator) generateFile(file templateFile) error {
	filePath := filepath.Join(pg.Directory, file.Path)

	// Create directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Parse and execute template
	tmpl, err := template.New(file.Path).Parse(file.Template)
	if err != nil {
		return err
	}

	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	data := map[string]interface{}{
		"ProjectName": pg.Name,
		"ModulePath":  pg.ModulePath,
		"Template":    pg.Template,
	}

	return tmpl.Execute(f, data)
}

func (pg *ProjectGenerator) initGoModule() error {
	cmd := exec.Command("go", "mod", "init", pg.ModulePath)
	cmd.Dir = pg.Directory
	return cmd.Run()
}

func (pg *ProjectGenerator) initGitRepository() error {
	// Initialize git repository
	cmd := exec.Command("git", "init")
	cmd.Dir = pg.Directory
	if err := cmd.Run(); err != nil {
		return err
	}

	// Add initial commit
	cmd = exec.Command("git", "add", ".")
	cmd.Dir = pg.Directory
	if err := cmd.Run(); err != nil {
		return err
	}

	cmd = exec.Command("git", "commit", "-m", "Initial commit")
	cmd.Dir = pg.Directory
	return cmd.Run()
}

// Template constants
const goModTemplate = `module {{.ModulePath}}

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/spf13/viper v1.17.0
	github.com/go-playground/validator/v10 v10.16.0
	github.com/golang-jwt/jwt/v5 v5.2.0
)
`

const readmeTemplate = `# {{.ProjectName}}

A Gawan-based Go web application.

## Getting Started

### Prerequisites

- Go 1.21 or higher
- Make (optional)

### Installation

1. Clone the repository:
   ` + "`" + `bash
   git clone <repository-url>
   cd {{.ProjectName}}
   ` + "`" + `

2. Install dependencies:
   ` + "`" + `bash
   go mod tidy
   ` + "`" + `

3. Run the application:
   ` + "`" + `bash
   go run cmd/server/main.go
   ` + "`" + `

   Or using Make:
   ` + "`" + `bash
   make run
   ` + "`" + `

## Project Structure

` + "`" + `
{{.ProjectName}}/
├── cmd/server/          # Application entrypoint
├── internal/app/        # Application logic
│   ├── controllers/     # HTTP handlers
│   ├── services/        # Business logic
│   ├── models/          # Data models
│   └── middleware/      # Custom middleware
├── internal/core/       # Core functionality
├── pkg/                 # Public packages
├── web/                 # Web assets
├── configs/             # Configuration files
└── test/                # Tests
` + "`" + `

## Development

### Available Commands

- ` + "`" + `make run` + "`" + ` - Run the application
- ` + "`" + `make dev` + "`" + ` - Run with hot reload (development mode)
- ` + "`" + `make test` + "`" + ` - Run tests
- ` + "`" + `make build` + "`" + ` - Build the application
- ` + "`" + `make clean` + "`" + ` - Clean build artifacts
- ` + "`" + `make install-air` + "`" + ` - Install air for hot reload

### Development Features

- **Hot Reload**: Automatic recompilation when files change using ` + "`" + `make dev` + "`" + ` or ` + "`" + `gawan dev` + "`" + `
- **Better Error Handling**: Enhanced stacktraces and error formatting for development
- **Layered Configuration**: Environment variables override YAML/JSON config files
- **Structured Logging**: JSON-formatted logs with configurable levels

## License

This project is licensed under the MIT License.
`

const makefileTemplate = `.PHONY: run build test clean dev install-air

# Application name
APP_NAME={{.ProjectName}}

# Build directory
BUILD_DIR=build

# Run the application
run:
	go run cmd/server/main.go

# Run with hot reload (development mode)
dev:
	gawan dev

# Install air for hot reload
install-air:
	go install github.com/cosmtrek/air@latest

# Build the application
build:
	mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(APP_NAME) cmd/server/main.go

# Run tests
test:
	go test -v ./...

# Run tests with coverage
test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# Install dependencies
deps:
	go mod tidy
	go mod download

# Format code
fmt:
	go fmt ./...

# Lint code
lint:
	golangci-lint run

# Generate code
generate:
	go generate ./...
`

const gitignoreTemplate = `# Binaries for programs and plugins
*.exe
*.exe~
*.dll
*.so
*.dylib

# Test binary, built with ` + "`go test -c`" + `
*.test

# Output of the go coverage tool
*.out
coverage.html

# Dependency directories
vendor/

# Go workspace file
go.work

# IDE files
.vscode/
.idea/
*.swp
*.swo
*~

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Application specific
build/
logs/
*.log
.env
.env.local
.env.*.local

# Temporary files
tmp/
temp/
`

const mainTemplate = `package main

import (
	"log"

	"{{.ModulePath}}/internal/app"
	"{{.ModulePath}}/internal/core/config"
)

func main() {
	// Load layered configuration
	cfg, err := config.LoadLayered()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create and start application
	app := app.New(cfg)
	if err := app.Start(); err != nil {
		log.Fatalf("Failed to start application: %v", err)
	}
}
`

const appTemplate = `package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"{{.ModulePath}}/internal/core/config"
	"{{.ModulePath}}/internal/core/middleware"
)

// App represents the application
type App struct {
	config *config.Config
	router *gin.Engine
	server *http.Server
}

// New creates a new application instance
func New(cfg *config.Config) *App {
	// Set Gin mode
	if cfg.App.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	// Use custom error middleware with better stacktraces
	router.Use(gin.Logger(), middleware.ErrorHandler())

	app := &App{
		config: cfg,
		router: router,
	}

	// Setup routes
	app.setupRoutes()

	return app
}

// Start starts the application
func (a *App) Start() error {
	a.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", a.config.Server.Port),
		Handler: a.router,
	}

	// Start server in a goroutine
	go func() {
		if err := a.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Failed to start server: %v\n", err)
			os.Exit(1)
		}
	}()

	fmt.Printf("Server starting on port %d\n", a.config.Server.Port)

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	fmt.Println("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := a.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server forced to shutdown: %w", err)
	}

	fmt.Println("Server exited")
	return nil
}
`

const routesTemplate = `package app

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// setupRoutes configures the application routes
func (a *App) setupRoutes() {
	// Health check endpoint
	a.router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"service": "{{.ProjectName}}",
		})
	})

	// API v1 routes
	v1 := a.router.Group("/api/v1")
	{
		v1.GET("/ping", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"message": "pong",
			})
		})
	}
}
`

const configTemplate = `package config

import (
	"os"
	"strconv"
	"time"
)

// Config represents the layered application configuration
type Config struct {
	Server   ServerConfig   ` + "`" + `json:"server"` + "`" + `
	Database DatabaseConfig ` + "`" + `json:"database"` + "`" + `
	Redis    RedisConfig    ` + "`" + `json:"redis"` + "`" + `
	JWT      JWTConfig      ` + "`" + `json:"jwt"` + "`" + `
	Logging  LoggingConfig  ` + "`" + `json:"logging"` + "`" + `
	App      AppConfig      ` + "`" + `json:"app"` + "`" + `
}

// ServerConfig represents server configuration
type ServerConfig struct {
	Port         int           ` + "`" + `json:"port"` + "`" + `
	Host         string        ` + "`" + `json:"host"` + "`" + `
	ReadTimeout  time.Duration ` + "`" + `json:"read_timeout"` + "`" + `
	WriteTimeout time.Duration ` + "`" + `json:"write_timeout"` + "`" + `
}

// DatabaseConfig represents database configuration
type DatabaseConfig struct {
	Driver          string        ` + "`" + `json:"driver"` + "`" + `
	Host            string        ` + "`" + `json:"host"` + "`" + `
	Port            int           ` + "`" + `json:"port"` + "`" + `
	Username        string        ` + "`" + `json:"username"` + "`" + `
	Password        string        ` + "`" + `json:"password"` + "`" + `
	Database        string        ` + "`" + `json:"database"` + "`" + `
	SSLMode         string        ` + "`" + `json:"ssl_mode"` + "`" + `
	MaxOpenConns    int           ` + "`" + `json:"max_open_conns"` + "`" + `
	MaxIdleConns    int           ` + "`" + `json:"max_idle_conns"` + "`" + `
	ConnMaxLifetime time.Duration ` + "`" + `json:"conn_max_lifetime"` + "`" + `
}

// RedisConfig represents Redis configuration
type RedisConfig struct {
	Host         string        ` + "`" + `json:"host"` + "`" + `
	Port         int           ` + "`" + `json:"port"` + "`" + `
	Password     string        ` + "`" + `json:"password"` + "`" + `
	DB           int           ` + "`" + `json:"db"` + "`" + `
	PoolSize     int           ` + "`" + `json:"pool_size"` + "`" + `
	DialTimeout  time.Duration ` + "`" + `json:"dial_timeout"` + "`" + `
	ReadTimeout  time.Duration ` + "`" + `json:"read_timeout"` + "`" + `
	WriteTimeout time.Duration ` + "`" + `json:"write_timeout"` + "`" + `
}

// JWTConfig represents JWT configuration
type JWTConfig struct {
	Secret           string        ` + "`" + `json:"secret"` + "`" + `
	Expiration       time.Duration ` + "`" + `json:"expiration"` + "`" + `
	RefreshTokenTTL  time.Duration ` + "`" + `json:"refresh_token_ttl"` + "`" + `
	Issuer           string        ` + "`" + `json:"issuer"` + "`" + `
}

// LoggingConfig represents logging configuration
type LoggingConfig struct {
	Level      string ` + "`" + `json:"level"` + "`" + `
	Format     string ` + "`" + `json:"format"` + "`" + `
	Output     string ` + "`" + `json:"output"` + "`" + `
	MaxSize    int    ` + "`" + `json:"max_size"` + "`" + `
	MaxBackups int    ` + "`" + `json:"max_backups"` + "`" + `
	MaxAge     int    ` + "`" + `json:"max_age"` + "`" + `
	Compress   bool   ` + "`" + `json:"compress"` + "`" + `
}

// AppConfig represents application-specific configuration
type AppConfig struct {
	Name        string ` + "`" + `json:"name"` + "`" + `
	Version     string ` + "`" + `json:"version"` + "`" + `
	Environment string ` + "`" + `json:"environment"` + "`" + `
	Debug       bool   ` + "`" + `json:"debug"` + "`" + `
}

// LoadLayered loads configuration using layered approach
// Priority: ENV > YAML/JSON > CLI flags > Vault > Defaults
func LoadLayered() (*Config, error) {
	// Start with defaults
	cfg := getDefaultConfig()

	// Load from config files (YAML/JSON)
	if err := loadFromFile(cfg); err != nil {
		return nil, err
	}

	// Override with environment variables (highest priority)
	loadFromEnv(cfg)

	return cfg, nil
}

// getDefaultConfig returns configuration with default values
func getDefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Port:         8080,
			Host:         "localhost",
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		},
		Database: DatabaseConfig{
			Driver:          "postgres",
			Host:            "localhost",
			Port:            5432,
			SSLMode:         "disable",
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 5 * time.Minute,
		},
		Redis: RedisConfig{
			Host:         "localhost",
			Port:         6379,
			DB:           0,
			PoolSize:     10,
			DialTimeout:  5 * time.Second,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
		},
		JWT: JWTConfig{
			Expiration:      24 * time.Hour,
			RefreshTokenTTL: 7 * 24 * time.Hour,
			Issuer:          "{{.ProjectName}}",
		},
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "json",
			Output:     "stdout",
			MaxSize:    100,
			MaxBackups: 3,
			MaxAge:     28,
			Compress:   true,
		},
		App: AppConfig{
			Name:        "{{.ProjectName}}",
			Version:     "1.0.0",
			Environment: "development",
			Debug:       true,
		},
	}
}

// loadFromFile loads configuration from YAML/JSON files
func loadFromFile(cfg *Config) error {
	// Implementation would load from config.yaml, config.json, etc.
	// For now, return nil (using defaults)
	return nil
}

// loadFromEnv loads configuration from environment variables
func loadFromEnv(cfg *Config) {
	// Server config
	if port := getEnvInt("SERVER_PORT", 0); port > 0 {
		cfg.Server.Port = port
	}
	if host := getEnv("SERVER_HOST", ""); host != "" {
		cfg.Server.Host = host
	}

	// Database config
	if driver := getEnv("DB_DRIVER", ""); driver != "" {
		cfg.Database.Driver = driver
	}
	if host := getEnv("DB_HOST", ""); host != "" {
		cfg.Database.Host = host
	}
	if port := getEnvInt("DB_PORT", 0); port > 0 {
		cfg.Database.Port = port
	}
	if username := getEnv("DB_USERNAME", ""); username != "" {
		cfg.Database.Username = username
	}
	if password := getEnv("DB_PASSWORD", ""); password != "" {
		cfg.Database.Password = password
	}
	if database := getEnv("DB_DATABASE", ""); database != "" {
		cfg.Database.Database = database
	}

	// Redis config
	if host := getEnv("REDIS_HOST", ""); host != "" {
		cfg.Redis.Host = host
	}
	if port := getEnvInt("REDIS_PORT", 0); port > 0 {
		cfg.Redis.Port = port
	}
	if password := getEnv("REDIS_PASSWORD", ""); password != "" {
		cfg.Redis.Password = password
	}

	// JWT config
	if secret := getEnv("JWT_SECRET", ""); secret != "" {
		cfg.JWT.Secret = secret
	}

	// App config
	if env := getEnv("APP_ENV", ""); env != "" {
		cfg.App.Environment = env
	}
	if debug := getEnv("APP_DEBUG", ""); debug != "" {
		cfg.App.Debug = debug == "true"
	}
}

// getEnv gets environment variable with fallback
func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// getEnvInt gets environment variable as integer with fallback
func getEnvInt(key string, fallback int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return fallback
}

// Legacy Load function for backward compatibility
func Load() (*Config, error) {
	return LoadLayered()
}
`

const configYamlTemplate = `environment: development

server:
  port: 8080
  host: localhost

database:
  driver: postgres
  host: localhost
  port: 5432
  username: postgres
  password: password
  database: {{.ProjectName}}
  ssl_mode: disable

redis:
  host: localhost
  port: 6379
  password: ""
  db: 0

jwt:
  secret: your-secret-key-here
  expiration: 3600
`

const responseUtilTemplate = `package utils

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Response represents a standard API response
type Response struct {
	Success bool        ` + "`" + `json:"success"` + "`" + `
	Message string      ` + "`" + `json:"message,omitempty"` + "`" + `
	Data    interface{} ` + "`" + `json:"data,omitempty"` + "`" + `
	Error   string      ` + "`" + `json:"error,omitempty"` + "`" + `
}

// SuccessResponse sends a success response
func SuccessResponse(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, Response{
		Success: true,
		Data:    data,
	})
}

// SuccessResponseWithMessage sends a success response with message
func SuccessResponseWithMessage(c *gin.Context, message string, data interface{}) {
	c.JSON(http.StatusOK, Response{
		Success: true,
		Message: message,
		Data:    data,
	})
}

// ErrorResponse sends an error response
func ErrorResponse(c *gin.Context, statusCode int, message string) {
	c.JSON(statusCode, Response{
		Success: false,
		Error:   message,
	})
}

// BadRequestResponse sends a bad request response
func BadRequestResponse(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusBadRequest, message)
}

// UnauthorizedResponse sends an unauthorized response
func UnauthorizedResponse(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusUnauthorized, message)
}

// ForbiddenResponse sends a forbidden response
func ForbiddenResponse(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusForbidden, message)
}

// NotFoundResponse sends a not found response
func NotFoundResponse(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusNotFound, message)
}

// InternalServerErrorResponse sends an internal server error response
func InternalServerErrorResponse(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusInternalServerError, message)
}
`

const exampleControllerTemplate = `package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"{{.ModulePath}}/pkg/utils"
)

// ExampleController handles example requests
type ExampleController struct{}

// NewExampleController creates a new example controller
func NewExampleController() *ExampleController {
	return &ExampleController{}
}

// GetExample handles GET /examples
func (ec *ExampleController) GetExample(c *gin.Context) {
	utils.SuccessResponse(c, gin.H{
		"message": "Hello from Gawan!",
		"version": "1.0.0",
	})
}

// CreateExample handles POST /examples
func (ec *ExampleController) CreateExample(c *gin.Context) {
	var request struct {
		Name string ` + "`" + `json:"name" binding:"required"` + "`" + `
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		utils.BadRequestResponse(c, err.Error())
		return
	}

	utils.SuccessResponseWithMessage(c, "Example created successfully", gin.H{
		"id":   1,
		"name": request.Name,
	})
}
`

const healthControllerTemplate = `package controllers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// HealthController handles health check requests
type HealthController struct{}

// NewHealthController creates a new health controller
func NewHealthController() *HealthController {
	return &HealthController{}
}

// Health handles GET /health
func (hc *HealthController) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"service":   "{{.ProjectName}}",
		"timestamp": time.Now().UTC(),
		"version":   "1.0.0",
	})
}

// Ready handles GET /ready
func (hc *HealthController) Ready(c *gin.Context) {
	// Add readiness checks here (database, external services, etc.)
	c.JSON(http.StatusOK, gin.H{
		"status": "ready",
	})
}
`

const dtoResponseTemplate = `package dto

import "time"

// APIResponse represents a standard API response
type APIResponse struct {
	Success   bool        ` + "`" + `json:"success"` + "`" + `
	Message   string      ` + "`" + `json:"message,omitempty"` + "`" + `
	Data      interface{} ` + "`" + `json:"data,omitempty"` + "`" + `
	Error     string      ` + "`" + `json:"error,omitempty"` + "`" + `
	Timestamp time.Time   ` + "`" + `json:"timestamp"` + "`" + `
}

// PaginatedResponse represents a paginated API response
type PaginatedResponse struct {
	APIResponse
	Pagination PaginationMeta ` + "`" + `json:"pagination,omitempty"` + "`" + `
}

// PaginationMeta contains pagination metadata
type PaginationMeta struct {
	Page       int ` + "`" + `json:"page"` + "`" + `
	Limit      int ` + "`" + `json:"limit"` + "`" + `
	Total      int ` + "`" + `json:"total"` + "`" + `
	TotalPages int ` + "`" + `json:"total_pages"` + "`" + `
}
`

const openapiTemplate = `openapi: 3.0.3
info:
  title: {{.ProjectName}} API
  description: API documentation for {{.ProjectName}}
  version: 1.0.0
  contact:
    name: API Support
    email: support@example.com

servers:
  - url: http://localhost:8080/api/v1
    description: Development server

paths:
  /health:
    get:
      summary: Health check
      description: Returns the health status of the service
      responses:
        '200':
          description: Service is healthy
          content:
            application/json:
              schema:
                type: object
                properties:
                  status:
                    type: string
                    example: ok
                  service:
                    type: string
                    example: {{.ProjectName}}
                  timestamp:
                    type: string
                    format: date-time
                  version:
                    type: string
                    example: 1.0.0

components:
  schemas:
    APIResponse:
      type: object
      properties:
        success:
          type: boolean
        message:
          type: string
        data:
          type: object
        error:
          type: string
        timestamp:
          type: string
          format: date-time
`

const homeControllerTemplate = `package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// HomeController handles home page requests
type HomeController struct{}

// NewHomeController creates a new home controller
func NewHomeController() *HomeController {
	return &HomeController{}
}

// Index handles GET /
func (hc *HomeController) Index(c *gin.Context) {
	c.HTML(http.StatusOK, "home.html", gin.H{
		"title":   "Welcome to {{.ProjectName}}",
		"message": "Hello from Gawan!",
	})
}
`

const layoutTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.title}} - {{.ProjectName}}</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <header>
        <nav>
            <h1>{{.ProjectName}}</h1>
        </nav>
    </header>
    
    <main>
        <div class="container">
            <h1>{{.title}}</h1>
            <p>{{.message}}</p>
            
            <div class="features">
                <div class="feature">
                    <h3>Fast Development</h3>
                    <p>Get started quickly with Gawan's scaffolding tools.</p>
                </div>
                
                <div class="feature">
                    <h3>Scalable Architecture</h3>
                    <p>Built with clean architecture principles in mind.</p>
                </div>
                
                <div class="feature">
                    <h3>Modern Stack</h3>
                    <p>Uses the latest Go technologies and best practices.</p>
                </div>
            </div>
        </div>
    </main>
    
    <footer>
        <p>&copy; 2024 {{.ProjectName}}. Built with Gawan.</p>
    </footer>
    
    <script src="/static/js/app.js"></script>
</body>
</html>
`

const homeTemplate = `{{define "content"}}
<div class="container">
    <h1>{{.title}}</h1>
    <p>{{.message}}</p>
    
    <div class="features">
        <div class="feature">
            <h3>Fast Development</h3>
            <p>Get started quickly with Gawan's scaffolding tools.</p>
        </div>
        
        <div class="feature">
            <h3>Scalable Architecture</h3>
            <p>Built with clean architecture principles in mind.</p>
        </div>
        
        <div class="feature">
            <h3>Modern Stack</h3>
            <p>Uses the latest Go technologies and best practices.</p>
        </div>
    </div>
</div>
{{end}}
`

const cssTemplate = `/* Reset and base styles */
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    line-height: 1.6;
    color: #333;
    background-color: #f8f9fa;
}

/* Header */
header {
    background-color: #2c3e50;
    color: white;
    padding: 1rem 0;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

nav {
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 2rem;
}

nav h1 {
    font-size: 1.5rem;
    font-weight: 600;
}

/* Main content */
main {
    max-width: 1200px;
    margin: 2rem auto;
    padding: 0 2rem;
    min-height: calc(100vh - 200px);
}

.container {
    background: white;
    padding: 2rem;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.container h1 {
    color: #2c3e50;
    margin-bottom: 1rem;
    font-size: 2.5rem;
}

.container p {
    font-size: 1.1rem;
    margin-bottom: 2rem;
    color: #666;
}

/* Features grid */
.features {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 2rem;
    margin-top: 2rem;
}

.feature {
    padding: 1.5rem;
    background: #f8f9fa;
    border-radius: 6px;
    border-left: 4px solid #3498db;
}

.feature h3 {
    color: #2c3e50;
    margin-bottom: 0.5rem;
}

.feature p {
    color: #666;
    margin: 0;
}

/* Footer */
footer {
    background-color: #34495e;
    color: white;
    text-align: center;
    padding: 1rem 0;
    margin-top: 2rem;
}

/* Responsive design */
@media (max-width: 768px) {
    .container {
        padding: 1rem;
    }
    
    .container h1 {
        font-size: 2rem;
    }
    
    .features {
        grid-template-columns: 1fr;
    }
}
`

const grpcServerTemplate = `package grpc

import (
	"context"
	"net"

	"google.golang.org/grpc"
	"{{.ModulePath}}/internal/core/config"
)

// Server represents the gRPC server
type Server struct {
	config *config.Config
	server *grpc.Server
}

// NewServer creates a new gRPC server
func NewServer(cfg *config.Config) *Server {
	server := grpc.NewServer()
	
	// Register services here
	
	return &Server{
		config: cfg,
		server: server,
	}
}

// Start starts the gRPC server
func (s *Server) Start() error {
	lis, err := net.Listen("tcp", ":9090")
	if err != nil {
		return err
	}
	
	return s.server.Serve(lis)
}

// Stop stops the gRPC server
func (s *Server) Stop() {
	s.server.GracefulStop()
}
`

const protoTemplate = `syntax = "proto3";

package {{.ProjectName}};

option go_package = "{{.ModulePath}}/proto";

// {{.ProjectName}} service definition
service {{.ProjectName}}Service {
  // Health check
  rpc Health(HealthRequest) returns (HealthResponse);
}

// Health check request
message HealthRequest {}

// Health check response
message HealthResponse {
  string status = 1;
  string service = 2;
}
`

const airConfigTemplate = `root = "."
testdata_dir = "testdata"
tmp_dir = "tmp"

[build]
  args_bin = []
  bin = "./tmp/main"
  cmd = "go build -o ./tmp/main ./cmd/server/main.go"
  delay = 1000
  exclude_dir = ["assets", "tmp", "vendor", "testdata", "build", "node_modules"]
  exclude_file = []
  exclude_regex = ["_test.go"]
  exclude_unchanged = false
  follow_symlink = false
  full_bin = ""
  include_dir = []
  include_ext = ["go", "tpl", "tmpl", "html", "yaml", "yml", "json"]
  include_file = []
  kill_delay = "0s"
  log = "build-errors.log"
  poll = false
  poll_interval = 0
  rerun = false
  rerun_delay = 500
  send_interrupt = false
  stop_on_root = false

[color]
  app = ""
  build = "yellow"
  main = "magenta"
  runner = "green"
  watcher = "cyan"

[log]
  main_only = false
  time = false

[misc]
  clean_on_exit = false

[screen]
  clear_on_rebuild = false
  keep_scroll = true
`