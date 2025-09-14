---
layout: page
title: "Getting Started"
description: "Panduan lengkap untuk memulai dengan Gowan Framework"
---

# Getting Started dengan Gowan Framework

Panduan ini akan membantu Anda memulai dengan Gowan Framework dari instalasi hingga deployment aplikasi pertama Anda.

## 📋 Prerequisites

- **Go 1.21+** - [Download Go](https://golang.org/dl/)
- **Git** - [Download Git](https://git-scm.com/downloads)
- **Code Editor** - VS Code, GoLand, atau editor favorit Anda

## 🚀 Installation

### 1. Clone Repository

```bash
# Clone dari GitHub
git clone https://github.com/dedeez14/gawan.git
cd gawan

# Atau fork repository terlebih dahulu
git clone https://github.com/YOUR_USERNAME/gawan.git
cd gawan
```

### 2. Setup Dependencies

```bash
# Download dependencies
go mod download

# Verify installation
go mod verify

# Install development tools (optional)
go install github.com/air-verse/air@latest  # Hot reload
go install github.com/swaggo/swag/cmd/swag@latest  # API docs
```

### 3. Verify Installation

```bash
# Run test server
go run cmd/testserver/main.go

# Test dengan curl
curl http://localhost:8080
# Expected: {"message":"Hello from Gowan Framework!","timestamp":"..."}
```

## 🏗️ Project Structure

```
gowan/
├── cmd/                    # Command-line applications
│   ├── testserver/        # Development server
│   ├── loadtest/          # Load testing tools
│   ├── monitor/           # Performance monitoring
│   └── pentest/           # Security testing
├── internal/              # Internal packages
│   ├── core/              # Core framework
│   │   ├── router/        # HTTP router
│   │   ├── middleware/    # Middleware components
│   │   ├── database/      # Database abstraction
│   │   ├── cache/         # Caching system
│   │   └── security/      # Security features
│   └── ports/             # Interface definitions
├── examples/              # Example applications
├── docs/                  # Documentation
└── test/                  # Test suites
```

## 🎯 Your First Application

### 1. Basic Server

Buat file `main.go`:

```go
package main

import (
    "log"
    "github.com/dedeez14/gawan/internal/core/router"
    "github.com/dedeez14/gawan/internal/core/middleware"
)

func main() {
    // Initialize router
    r := router.New()
    
    // Add middleware
    r.Use(middleware.Logger())
    r.Use(middleware.CORS())
    
    // Basic route
    r.GET("/", func(c *router.Context) {
        c.JSON(200, map[string]interface{}{
            "message": "Welcome to my Gowan app!",
            "version": "1.0.0",
        })
    })
    
    // Start server
    log.Println("🚀 Server starting on :8080")
    r.Run(":8080")
}
```

### 2. Add Routes

```go
// User routes
r.GET("/users", getUsersHandler)
r.GET("/users/:id", getUserHandler)
r.POST("/users", createUserHandler)
r.PUT("/users/:id", updateUserHandler)
r.DELETE("/users/:id", deleteUserHandler)

// Route groups
api := r.Group("/api/v1")
api.GET("/health", healthCheckHandler)
api.GET("/metrics", metricsHandler)
```

### 3. Add Middleware

```go
// Global middleware
r.Use(middleware.Logger())
r.Use(middleware.CORS())
r.Use(middleware.RateLimit(100)) // 100 req/min
r.Use(middleware.Recovery())

// Group-specific middleware
auth := r.Group("/auth")
auth.Use(middleware.JWT("your-secret-key"))
auth.GET("/profile", getProfileHandler)
```

## 🔧 Configuration

### Environment Variables

Buat file `.env`:

```env
# Server Configuration
PORT=8080
HOST=localhost
ENV=development

# Database Configuration
DB_DRIVER=postgres
DB_HOST=localhost
DB_PORT=5432
DB_NAME=gowan_app
DB_USER=postgres
DB_PASSWORD=password

# Cache Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# Security
JWT_SECRET=your-super-secret-key
RATE_LIMIT=100
```

### Configuration Struct

```go
type Config struct {
    Server struct {
        Port string `env:"PORT" envDefault:"8080"`
        Host string `env:"HOST" envDefault:"localhost"`
        Env  string `env:"ENV" envDefault:"development"`
    }
    Database struct {
        Driver   string `env:"DB_DRIVER" envDefault:"postgres"`
        Host     string `env:"DB_HOST" envDefault:"localhost"`
        Port     int    `env:"DB_PORT" envDefault:"5432"`
        Name     string `env:"DB_NAME" envDefault:"gowan_app"`
        User     string `env:"DB_USER" envDefault:"postgres"`
        Password string `env:"DB_PASSWORD"`
    }
    Cache struct {
        Host     string `env:"REDIS_HOST" envDefault:"localhost"`
        Port     int    `env:"REDIS_PORT" envDefault:"6379"`
        Password string `env:"REDIS_PASSWORD"`
    }
}
```

## 🧪 Testing

### Unit Tests

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific package
go test ./internal/core/router -v
```

### Load Testing

```bash
# Basic load test
go run cmd/loadtest/main.go http://localhost:8080 1000 30s

# Progressive load test
go run cmd/loadtest/progressive_test.go http://localhost:8080 5000 500
```

### Performance Monitoring

```bash
# Real-time monitoring
go run cmd/monitor/performance_monitor.go http://localhost:8080 1
```

## 🚀 Development Workflow

### 1. Hot Reload Development

```bash
# Install air (if not already installed)
go install github.com/air-verse/air@latest

# Create .air.toml configuration
air init

# Start development server with hot reload
air
```

### 2. Code Generation

```bash
# Generate API documentation
swag init -g cmd/testserver/main.go

# Generate database models (future feature)
go run cmd/gawan/main.go generate model User

# Generate CRUD handlers (future feature)
go run cmd/gawan/main.go generate handler User
```

### 3. Database Migration

```bash
# Create migration (future feature)
go run cmd/gawan/main.go migrate create create_users_table

# Run migrations (future feature)
go run cmd/gawan/main.go migrate up

# Rollback migrations (future feature)
go run cmd/gawan/main.go migrate down
```

## 📚 Next Steps

1. **[API Reference](api-reference)** - Pelajari semua fitur framework
2. **[Examples](examples)** - Lihat contoh aplikasi lengkap
3. **[Performance Guide](performance)** - Optimasi aplikasi Anda
4. **[Security Guide](security)** - Implementasi keamanan
5. **[Deployment Guide](deployment)** - Deploy ke production

## 🤝 Need Help?

- 📖 [Documentation](https://docs.gowan.dev)
- 💬 [Discord Community](https://discord.gg/gowan)
- 🐛 [GitHub Issues](https://github.com/dedeez14/gawan/issues)
- 📧 [Email Support](mailto:support@gowan.dev)

---

**Selamat coding dengan Gowan Framework! 🚀**