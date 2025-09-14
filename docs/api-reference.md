---
layout: page
title: "API Reference"
description: "Dokumentasi lengkap API Gowan Framework"
---

# API Reference

Dokumentasi lengkap untuk semua komponen dan API yang tersedia di Gowan Framework.

## 🏗️ Core Components

### Router

#### `router.New()`

Membuat instance router baru.

```go
func New() *Router
```

**Example:**
```go
r := router.New()
```

#### `router.Use(middleware ...MiddlewareFunc)`

Menambahkan middleware global.

```go
func (r *Router) Use(middleware ...MiddlewareFunc)
```

**Example:**
```go
r.Use(middleware.Logger())
r.Use(middleware.CORS())
```

#### HTTP Methods

```go
func (r *Router) GET(path string, handler HandlerFunc)
func (r *Router) POST(path string, handler HandlerFunc)
func (r *Router) PUT(path string, handler HandlerFunc)
func (r *Router) DELETE(path string, handler HandlerFunc)
func (r *Router) PATCH(path string, handler HandlerFunc)
func (r *Router) HEAD(path string, handler HandlerFunc)
func (r *Router) OPTIONS(path string, handler HandlerFunc)
```

**Example:**
```go
r.GET("/users/:id", getUserHandler)
r.POST("/users", createUserHandler)
r.PUT("/users/:id", updateUserHandler)
r.DELETE("/users/:id", deleteUserHandler)
```

#### Route Groups

```go
func (r *Router) Group(prefix string) *RouterGroup
```

**Example:**
```go
api := r.Group("/api/v1")
api.GET("/users", getUsersHandler)
api.POST("/users", createUserHandler)

// Nested groups
admin := api.Group("/admin")
admin.Use(middleware.RequireAdmin())
admin.GET("/stats", getStatsHandler)
```

### Context

#### Request Data

```go
// Get path parameters
func (c *Context) Param(key string) string

// Get query parameters
func (c *Context) Query(key string) string
func (c *Context) QueryDefault(key, defaultValue string) string

// Get form data
func (c *Context) FormValue(key string) string

// Get headers
func (c *Context) GetHeader(key string) string
```

**Example:**
```go
func getUserHandler(c *router.Context) {
    userID := c.Param("id")
    page := c.QueryDefault("page", "1")
    authToken := c.GetHeader("Authorization")
    
    // Process request...
}
```

#### Response Methods

```go
// JSON response
func (c *Context) JSON(code int, obj interface{})

// String response
func (c *Context) String(code int, format string, values ...interface{})

// HTML response
func (c *Context) HTML(code int, name string, obj interface{})

// File response
func (c *Context) File(filepath string)

// Redirect
func (c *Context) Redirect(code int, location string)
```

**Example:**
```go
func createUserHandler(c *router.Context) {
    var user User
    if err := c.ShouldBindJSON(&user); err != nil {
        c.JSON(400, map[string]string{"error": err.Error()})
        return
    }
    
    // Create user...
    c.JSON(201, user)
}
```

## 🔧 Middleware

### Built-in Middleware

#### Logger

```go
func Logger() MiddlewareFunc
func LoggerWithConfig(config LoggerConfig) MiddlewareFunc
```

**Example:**
```go
// Default logger
r.Use(middleware.Logger())

// Custom logger
r.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
    Format: "${time_rfc3339} ${method} ${uri} ${status} ${latency_human}\n",
    Output: os.Stdout,
}))
```

#### CORS

```go
func CORS() MiddlewareFunc
func CORSWithConfig(config CORSConfig) MiddlewareFunc
```

**Example:**
```go
// Default CORS
r.Use(middleware.CORS())

// Custom CORS
r.Use(middleware.CORSWithConfig(middleware.CORSConfig{
    AllowOrigins: []string{"https://example.com"},
    AllowMethods: []string{"GET", "POST", "PUT", "DELETE"},
    AllowHeaders: []string{"Origin", "Content-Type", "Authorization"},
}))
```

#### Rate Limiting

```go
func RateLimit(rate int) MiddlewareFunc
func RateLimitWithConfig(config RateLimitConfig) MiddlewareFunc
```

**Example:**
```go
// 100 requests per minute
r.Use(middleware.RateLimit(100))

// Custom rate limiting
r.Use(middleware.RateLimitWithConfig(middleware.RateLimitConfig{
    Rate:     100,
    Duration: time.Minute,
    KeyFunc: func(c *router.Context) string {
        return c.ClientIP()
    },
}))
```

#### JWT Authentication

```go
func JWT(secret string) MiddlewareFunc
func JWTWithConfig(config JWTConfig) MiddlewareFunc
```

**Example:**
```go
// Basic JWT
auth := r.Group("/auth")
auth.Use(middleware.JWT("your-secret-key"))

// Custom JWT
auth.Use(middleware.JWTWithConfig(middleware.JWTConfig{
    Secret:     "your-secret-key",
    Expiration: time.Hour * 24,
    TokenLookup: "header:Authorization,query:token",
}))
```

### Custom Middleware

```go
func CustomMiddleware() MiddlewareFunc {
    return func(next HandlerFunc) HandlerFunc {
        return func(c *Context) {
            // Before request
            start := time.Now()
            
            // Process request
            next(c)
            
            // After request
            duration := time.Since(start)
            log.Printf("Request took %v", duration)
        }
    }
}
```

## 🗄️ Database

### Connection

```go
func Connect(config Config) (*DB, error)
```

**Example:**
```go
db, err := database.Connect(database.Config{
    Driver:   "postgres",
    Host:     "localhost",
    Port:     5432,
    Database: "gowan_app",
    Username: "user",
    Password: "password",
})
if err != nil {
    log.Fatal(err)
}
defer db.Close()
```

### Query Methods

```go
// Execute query
func (db *DB) Query(query string, args ...interface{}) (*sql.Rows, error)

// Execute single row query
func (db *DB) QueryRow(query string, args ...interface{}) *sql.Row

// Execute statement
func (db *DB) Exec(query string, args ...interface{}) (sql.Result, error)
```

**Example:**
```go
// Select multiple rows
rows, err := db.Query("SELECT id, name, email FROM users WHERE active = $1", true)
if err != nil {
    return err
}
defer rows.Close()

// Select single row
var user User
err := db.QueryRow("SELECT id, name, email FROM users WHERE id = $1", userID).Scan(
    &user.ID, &user.Name, &user.Email,
)

// Insert/Update/Delete
result, err := db.Exec("INSERT INTO users (name, email) VALUES ($1, $2)", name, email)
```

## 🚀 Cache

### Redis Cache

```go
func NewRedis(config RedisConfig) Cache
```

**Example:**
```go
cache := cache.NewRedis(cache.RedisConfig{
    Addr:     "localhost:6379",
    Password: "",
    DB:       0,
})

// Set value
cache.Set("key", "value", time.Hour)

// Get value
value, found := cache.Get("key")
if found {
    fmt.Println(value)
}

// Delete value
cache.Delete("key")
```

### Memory Cache

```go
func NewMemory(config MemoryConfig) Cache
```

**Example:**
```go
cache := cache.NewMemory(cache.MemoryConfig{
    MaxSize: 1000,
    TTL:     time.Hour,
})

// Same interface as Redis cache
cache.Set("key", "value", time.Minute)
value, found := cache.Get("key")
```

## 🔒 Security

### Input Validation

```go
func Validate(obj interface{}) error
```

**Example:**
```go
type CreateUserRequest struct {
    Name  string `json:"name" validate:"required,min=2,max=50"`
    Email string `json:"email" validate:"required,email"`
    Age   int    `json:"age" validate:"min=18,max=120"`
}

func createUserHandler(c *router.Context) {
    var req CreateUserRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, map[string]string{"error": err.Error()})
        return
    }
    
    if err := validation.Validate(req); err != nil {
        c.JSON(400, map[string]string{"error": err.Error()})
        return
    }
    
    // Process valid request...
}
```

### RBAC (Role-Based Access Control)

```go
func RBAC(config RBACConfig) MiddlewareFunc
func RequireRole(role string) MiddlewareFunc
func RequirePermission(permission string) MiddlewareFunc
```

**Example:**
```go
// Setup RBAC
rbac := security.RBAC(security.RBACConfig{
    Roles: map[string][]string{
        "admin": {"read", "write", "delete"},
        "user":  {"read"},
    },
})

// Apply to routes
admin := r.Group("/admin")
admin.Use(rbac.RequireRole("admin"))

api := r.Group("/api")
api.Use(rbac.RequirePermission("read"))
```

## 📊 Monitoring

### Metrics Collection

```go
func New(config Config) *Collector
func (c *Collector) Counter(name string) Counter
func (c *Collector) Timer(name string) Timer
func (c *Collector) Gauge(name string) Gauge
```

**Example:**
```go
metrics := metrics.New(metrics.Config{
    Namespace: "gowan_app",
    Subsystem: "api",
})

// Counter
requestCounter := metrics.Counter("requests_total")
requestCounter.Inc()

// Timer
timer := metrics.Timer("request_duration")
defer timer.ObserveDuration()

// Gauge
activeConnections := metrics.Gauge("active_connections")
activeConnections.Set(42)
```

### Health Checks

```go
func NewHealthChecker() *HealthChecker
func (h *HealthChecker) AddCheck(name string, check HealthCheckFunc)
func (h *HealthChecker) Handler() HandlerFunc
```

**Example:**
```go
health := monitoring.NewHealthChecker()

// Add database check
health.AddCheck("database", func() error {
    return db.Ping()
})

// Add Redis check
health.AddCheck("redis", func() error {
    return cache.Ping()
})

// Add health endpoint
r.GET("/health", health.Handler())
```

## 🧪 Testing

### Test Helpers

```go
func NewTestRouter() *Router
func NewTestContext() *Context
func PerformRequest(r *Router, method, path string, body io.Reader) *httptest.ResponseRecorder
```

**Example:**
```go
func TestGetUser(t *testing.T) {
    r := router.NewTestRouter()
    r.GET("/users/:id", getUserHandler)
    
    req := httptest.NewRequest("GET", "/users/123", nil)
    w := httptest.NewRecorder()
    
    r.ServeHTTP(w, req)
    
    assert.Equal(t, 200, w.Code)
    assert.Contains(t, w.Body.String(), "user")
}
```

## 🔧 Configuration

### Environment Configuration

```go
func LoadConfig() (*Config, error)
func LoadConfigFromFile(filename string) (*Config, error)
```

**Example:**
```go
type Config struct {
    Server struct {
        Port string `env:"PORT" envDefault:"8080"`
        Host string `env:"HOST" envDefault:"localhost"`
    }
    Database struct {
        URL string `env:"DATABASE_URL" envDefault:"postgres://localhost/gowan"`
    }
}

config, err := config.LoadConfig()
if err != nil {
    log.Fatal(err)
}
```

---

## 📚 More Resources

- [Getting Started](getting-started) - Panduan instalasi dan setup
- [Examples](examples) - Contoh aplikasi lengkap
- [Performance Guide](performance) - Optimasi performa
- [Security Guide](security) - Best practices keamanan

---

**Need help?** Join our [Discord community](https://discord.gg/gowan) or check [GitHub Issues](https://github.com/dedeez14/gawan/issues).