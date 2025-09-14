---
layout: page
title: "Examples"
description: "Contoh aplikasi dan use cases menggunakan Gowan Framework"
---

# Examples

Kumpulan contoh aplikasi dan use cases menggunakan Gowan Framework untuk berbagai skenario pengembangan.

## 🚀 Basic Examples

### 1. Hello World Server

```go
package main

import (
    "github.com/dedeez14/gawan/internal/core/router"
    "log"
)

func main() {
    r := router.New()
    
    r.GET("/", func(c *router.Context) {
        c.JSON(200, map[string]string{
            "message": "Hello, Gowan!",
        })
    })
    
    log.Println("🚀 Server starting on :8080")
    r.Run(":8080")
}
```

### 2. RESTful API Server

```go
package main

import (
    "github.com/dedeez14/gawan/internal/core/router"
    "github.com/dedeez14/gawan/internal/core/middleware"
    "strconv"
)

type User struct {
    ID    int    `json:"id"`
    Name  string `json:"name"`
    Email string `json:"email"`
}

var users = []User{
    {ID: 1, Name: "John Doe", Email: "john@example.com"},
    {ID: 2, Name: "Jane Smith", Email: "jane@example.com"},
}

func main() {
    r := router.New()
    
    // Middleware
    r.Use(middleware.Logger())
    r.Use(middleware.CORS())
    r.Use(middleware.RateLimit(100))
    
    // API routes
    api := r.Group("/api/v1")
    {
        api.GET("/users", getUsers)
        api.GET("/users/:id", getUser)
        api.POST("/users", createUser)
        api.PUT("/users/:id", updateUser)
        api.DELETE("/users/:id", deleteUser)
    }
    
    r.Run(":8080")
}

func getUsers(c *router.Context) {
    c.JSON(200, users)
}

func getUser(c *router.Context) {
    id, _ := strconv.Atoi(c.Param("id"))
    
    for _, user := range users {
        if user.ID == id {
            c.JSON(200, user)
            return
        }
    }
    
    c.JSON(404, map[string]string{"error": "User not found"})
}

func createUser(c *router.Context) {
    var newUser User
    if err := c.ShouldBindJSON(&newUser); err != nil {
        c.JSON(400, map[string]string{"error": err.Error()})
        return
    }
    
    newUser.ID = len(users) + 1
    users = append(users, newUser)
    
    c.JSON(201, newUser)
}

func updateUser(c *router.Context) {
    id, _ := strconv.Atoi(c.Param("id"))
    
    for i, user := range users {
        if user.ID == id {
            if err := c.ShouldBindJSON(&users[i]); err != nil {
                c.JSON(400, map[string]string{"error": err.Error()})
                return
            }
            users[i].ID = id // Keep original ID
            c.JSON(200, users[i])
            return
        }
    }
    
    c.JSON(404, map[string]string{"error": "User not found"})
}

func deleteUser(c *router.Context) {
    id, _ := strconv.Atoi(c.Param("id"))
    
    for i, user := range users {
        if user.ID == id {
            users = append(users[:i], users[i+1:]...)
            c.JSON(200, map[string]string{"message": "User deleted"})
            return
        }
    }
    
    c.JSON(404, map[string]string{"error": "User not found"})
}
```

## 🔒 Authentication Examples

### 3. JWT Authentication Server

```go
package main

import (
    "github.com/dedeez14/gawan/internal/core/router"
    "github.com/dedeez14/gawan/internal/core/middleware"
    "github.com/dedeez14/gawan/internal/core/security"
    "time"
)

type LoginRequest struct {
    Username string `json:"username" validate:"required"`
    Password string `json:"password" validate:"required"`
}

type User struct {
    ID       int    `json:"id"`
    Username string `json:"username"`
    Role     string `json:"role"`
}

func main() {
    r := router.New()
    
    // Public routes
    r.POST("/login", login)
    r.POST("/register", register)
    
    // Protected routes
    auth := r.Group("/api")
    auth.Use(middleware.JWT("your-secret-key"))
    {
        auth.GET("/profile", getProfile)
        auth.PUT("/profile", updateProfile)
    }
    
    // Admin routes
    admin := auth.Group("/admin")
    admin.Use(middleware.RequireRole("admin"))
    {
        admin.GET("/users", getAllUsers)
        admin.DELETE("/users/:id", deleteUser)
    }
    
    r.Run(":8080")
}

func login(c *router.Context) {
    var req LoginRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, map[string]string{"error": err.Error()})
        return
    }
    
    // Validate credentials (in real app, check against database)
    if req.Username == "admin" && req.Password == "password" {
        token, err := security.GenerateJWT(security.JWTClaims{
            UserID:   1,
            Username: req.Username,
            Role:     "admin",
        }, "your-secret-key", time.Hour*24)
        
        if err != nil {
            c.JSON(500, map[string]string{"error": "Failed to generate token"})
            return
        }
        
        c.JSON(200, map[string]string{
            "token": token,
            "type":  "Bearer",
        })
        return
    }
    
    c.JSON(401, map[string]string{"error": "Invalid credentials"})
}

func register(c *router.Context) {
    // Implementation for user registration
    c.JSON(201, map[string]string{"message": "User registered successfully"})
}

func getProfile(c *router.Context) {
    // Get user from JWT token
    user := c.MustGet("user").(User)
    c.JSON(200, user)
}

func updateProfile(c *router.Context) {
    // Update user profile
    c.JSON(200, map[string]string{"message": "Profile updated"})
}

func getAllUsers(c *router.Context) {
    // Admin only - get all users
    c.JSON(200, []User{
        {ID: 1, Username: "admin", Role: "admin"},
        {ID: 2, Username: "user", Role: "user"},
    })
}

func deleteUser(c *router.Context) {
    // Admin only - delete user
    userID := c.Param("id")
    c.JSON(200, map[string]string{
        "message": "User " + userID + " deleted",
    })
}
```

## 🗄️ Database Integration Examples

### 4. PostgreSQL CRUD Application

```go
package main

import (
    "database/sql"
    "github.com/dedeez14/gawan/internal/core/router"
    "github.com/dedeez14/gawan/internal/core/middleware"
    "github.com/dedeez14/gawan/internal/core/database"
    _ "github.com/lib/pq"
    "log"
)

type Product struct {
    ID          int     `json:"id" db:"id"`
    Name        string  `json:"name" db:"name" validate:"required"`
    Description string  `json:"description" db:"description"`
    Price       float64 `json:"price" db:"price" validate:"required,min=0"`
    Stock       int     `json:"stock" db:"stock" validate:"min=0"`
}

type ProductService struct {
    db *sql.DB
}

func main() {
    // Database connection
    db, err := database.Connect(database.Config{
        Driver:   "postgres",
        Host:     "localhost",
        Port:     5432,
        Database: "gowan_shop",
        Username: "postgres",
        Password: "password",
    })
    if err != nil {
        log.Fatal("Failed to connect to database:", err)
    }
    defer db.Close()
    
    // Initialize service
    productService := &ProductService{db: db}
    
    // Router setup
    r := router.New()
    r.Use(middleware.Logger())
    r.Use(middleware.CORS())
    
    // Product routes
    api := r.Group("/api/v1")
    {
        api.GET("/products", productService.getProducts)
        api.GET("/products/:id", productService.getProduct)
        api.POST("/products", productService.createProduct)
        api.PUT("/products/:id", productService.updateProduct)
        api.DELETE("/products/:id", productService.deleteProduct)
    }
    
    r.Run(":8080")
}

func (ps *ProductService) getProducts(c *router.Context) {
    rows, err := ps.db.Query(`
        SELECT id, name, description, price, stock 
        FROM products 
        ORDER BY id
    `)
    if err != nil {
        c.JSON(500, map[string]string{"error": err.Error()})
        return
    }
    defer rows.Close()
    
    var products []Product
    for rows.Next() {
        var p Product
        err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Price, &p.Stock)
        if err != nil {
            c.JSON(500, map[string]string{"error": err.Error()})
            return
        }
        products = append(products, p)
    }
    
    c.JSON(200, products)
}

func (ps *ProductService) getProduct(c *router.Context) {
    id := c.Param("id")
    
    var p Product
    err := ps.db.QueryRow(`
        SELECT id, name, description, price, stock 
        FROM products 
        WHERE id = $1
    `, id).Scan(&p.ID, &p.Name, &p.Description, &p.Price, &p.Stock)
    
    if err == sql.ErrNoRows {
        c.JSON(404, map[string]string{"error": "Product not found"})
        return
    }
    if err != nil {
        c.JSON(500, map[string]string{"error": err.Error()})
        return
    }
    
    c.JSON(200, p)
}

func (ps *ProductService) createProduct(c *router.Context) {
    var p Product
    if err := c.ShouldBindJSON(&p); err != nil {
        c.JSON(400, map[string]string{"error": err.Error()})
        return
    }
    
    err := ps.db.QueryRow(`
        INSERT INTO products (name, description, price, stock) 
        VALUES ($1, $2, $3, $4) 
        RETURNING id
    `, p.Name, p.Description, p.Price, p.Stock).Scan(&p.ID)
    
    if err != nil {
        c.JSON(500, map[string]string{"error": err.Error()})
        return
    }
    
    c.JSON(201, p)
}

func (ps *ProductService) updateProduct(c *router.Context) {
    id := c.Param("id")
    
    var p Product
    if err := c.ShouldBindJSON(&p); err != nil {
        c.JSON(400, map[string]string{"error": err.Error()})
        return
    }
    
    _, err := ps.db.Exec(`
        UPDATE products 
        SET name = $1, description = $2, price = $3, stock = $4 
        WHERE id = $5
    `, p.Name, p.Description, p.Price, p.Stock, id)
    
    if err != nil {
        c.JSON(500, map[string]string{"error": err.Error()})
        return
    }
    
    c.JSON(200, map[string]string{"message": "Product updated successfully"})
}

func (ps *ProductService) deleteProduct(c *router.Context) {
    id := c.Param("id")
    
    _, err := ps.db.Exec("DELETE FROM products WHERE id = $1", id)
    if err != nil {
        c.JSON(500, map[string]string{"error": err.Error()})
        return
    }
    
    c.JSON(200, map[string]string{"message": "Product deleted successfully"})
}
```

## 🚀 Caching Examples

### 5. Redis Caching Implementation

```go
package main

import (
    "encoding/json"
    "github.com/dedeez14/gawan/internal/core/router"
    "github.com/dedeez14/gawan/internal/core/cache"
    "time"
    "fmt"
)

type CacheService struct {
    cache cache.Cache
}

type Article struct {
    ID      int    `json:"id"`
    Title   string `json:"title"`
    Content string `json:"content"`
    Author  string `json:"author"`
}

func main() {
    // Initialize Redis cache
    redisCache := cache.NewRedis(cache.RedisConfig{
        Addr:     "localhost:6379",
        Password: "",
        DB:       0,
    })
    
    cacheService := &CacheService{cache: redisCache}
    
    r := router.New()
    
    r.GET("/articles/:id", cacheService.getArticle)
    r.POST("/articles", cacheService.createArticle)
    r.PUT("/articles/:id", cacheService.updateArticle)
    r.DELETE("/articles/:id", cacheService.deleteArticle)
    
    r.Run(":8080")
}

func (cs *CacheService) getArticle(c *router.Context) {
    id := c.Param("id")
    cacheKey := fmt.Sprintf("article:%s", id)
    
    // Try to get from cache first
    if cached, found := cs.cache.Get(cacheKey); found {
        var article Article
        if err := json.Unmarshal([]byte(cached.(string)), &article); err == nil {
            c.Header("X-Cache", "HIT")
            c.JSON(200, article)
            return
        }
    }
    
    // Simulate database fetch
    article := Article{
        ID:      1,
        Title:   "Sample Article",
        Content: "This is a sample article content.",
        Author:  "John Doe",
    }
    
    // Cache the result
    if data, err := json.Marshal(article); err == nil {
        cs.cache.Set(cacheKey, string(data), time.Hour)
    }
    
    c.Header("X-Cache", "MISS")
    c.JSON(200, article)
}

func (cs *CacheService) createArticle(c *router.Context) {
    var article Article
    if err := c.ShouldBindJSON(&article); err != nil {
        c.JSON(400, map[string]string{"error": err.Error()})
        return
    }
    
    // Simulate saving to database
    article.ID = 1
    
    // Cache the new article
    cacheKey := fmt.Sprintf("article:%d", article.ID)
    if data, err := json.Marshal(article); err == nil {
        cs.cache.Set(cacheKey, string(data), time.Hour)
    }
    
    c.JSON(201, article)
}

func (cs *CacheService) updateArticle(c *router.Context) {
    id := c.Param("id")
    cacheKey := fmt.Sprintf("article:%s", id)
    
    var article Article
    if err := c.ShouldBindJSON(&article); err != nil {
        c.JSON(400, map[string]string{"error": err.Error()})
        return
    }
    
    // Simulate updating in database
    
    // Update cache
    if data, err := json.Marshal(article); err == nil {
        cs.cache.Set(cacheKey, string(data), time.Hour)
    }
    
    c.JSON(200, article)
}

func (cs *CacheService) deleteArticle(c *router.Context) {
    id := c.Param("id")
    cacheKey := fmt.Sprintf("article:%s", id)
    
    // Simulate deleting from database
    
    // Remove from cache
    cs.cache.Delete(cacheKey)
    
    c.JSON(200, map[string]string{"message": "Article deleted"})
}
```

## 📊 Monitoring Examples

### 6. Performance Monitoring

```go
package main

import (
    "github.com/dedeez14/gawan/internal/core/router"
    "github.com/dedeez14/gawan/internal/core/middleware"
    "github.com/dedeez14/gawan/internal/core/monitoring"
    "time"
)

func main() {
    r := router.New()
    
    // Initialize metrics
    metrics := monitoring.New(monitoring.Config{
        Namespace: "gowan_app",
        Subsystem: "api",
    })
    
    // Add monitoring middleware
    r.Use(middleware.Metrics(metrics))
    r.Use(middleware.Logger())
    
    // Health check
    health := monitoring.NewHealthChecker()
    health.AddCheck("database", func() error {
        // Check database connection
        return nil
    })
    health.AddCheck("redis", func() error {
        // Check Redis connection
        return nil
    })
    
    // Routes
    r.GET("/health", health.Handler())
    r.GET("/metrics", metrics.Handler())
    
    r.GET("/api/slow", slowEndpoint)
    r.GET("/api/fast", fastEndpoint)
    
    r.Run(":8080")
}

func slowEndpoint(c *router.Context) {
    // Simulate slow operation
    time.Sleep(2 * time.Second)
    c.JSON(200, map[string]string{"message": "Slow response"})
}

func fastEndpoint(c *router.Context) {
    c.JSON(200, map[string]string{"message": "Fast response"})
}
```

## 🔧 Custom Middleware Examples

### 7. Custom Logging Middleware

```go
package main

import (
    "github.com/dedeez14/gawan/internal/core/router"
    "log"
    "time"
)

// Custom request ID middleware
func RequestID() router.MiddlewareFunc {
    return func(next router.HandlerFunc) router.HandlerFunc {
        return func(c *router.Context) {
            requestID := generateRequestID()
            c.Set("request_id", requestID)
            c.Header("X-Request-ID", requestID)
            next(c)
        }
    }
}

// Custom audit logging middleware
func AuditLog() router.MiddlewareFunc {
    return func(next router.HandlerFunc) router.HandlerFunc {
        return func(c *router.Context) {
            start := time.Now()
            
            // Process request
            next(c)
            
            // Log after request
            duration := time.Since(start)
            requestID := c.GetString("request_id")
            
            log.Printf("[AUDIT] ID=%s Method=%s Path=%s Status=%d Duration=%v IP=%s",
                requestID,
                c.Request.Method,
                c.Request.URL.Path,
                c.Writer.Status(),
                duration,
                c.ClientIP(),
            )
        }
    }
}

func main() {
    r := router.New()
    
    // Apply custom middleware
    r.Use(RequestID())
    r.Use(AuditLog())
    
    r.GET("/", func(c *router.Context) {
        requestID := c.GetString("request_id")
        c.JSON(200, map[string]string{
            "message":    "Hello World",
            "request_id": requestID,
        })
    })
    
    r.Run(":8080")
}

func generateRequestID() string {
    // Simple request ID generation
    return fmt.Sprintf("%d", time.Now().UnixNano())
}
```

## 📚 More Examples

- **File Upload**: [file-upload-example.go](https://github.com/dedeez14/gawan/tree/main/examples/file-upload)
- **WebSocket**: [websocket-example.go](https://github.com/dedeez14/gawan/tree/main/examples/websocket)
- **Microservices**: [microservices-example/](https://github.com/dedeez14/gawan/tree/main/examples/microservices)
- **GraphQL**: [graphql-example.go](https://github.com/dedeez14/gawan/tree/main/examples/graphql)
- **gRPC**: [grpc-example/](https://github.com/dedeez14/gawan/tree/main/examples/grpc)

---

## 🤝 Contributing Examples

Punya contoh menarik? Kontribusi ke repository kami:

1. Fork repository
2. Buat branch baru: `git checkout -b feature/new-example`
3. Tambahkan contoh di folder `examples/`
4. Commit changes: `git commit -m "feat: add new example"`
5. Push dan buat PR

---

**Need help?** Join our [Discord community](https://discord.gg/gowan) or check [GitHub Issues](https://github.com/dedeez14/gawan/issues).