package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"Gawan/internal/core/di"
	"Gawan/internal/core/multitenancy"
	"Gawan/internal/core/router"
	"Gawan/internal/core/security"
	"Gawan/internal/core/validation"
)

// User represents a user in our application
type User struct {
	ID       uint   `json:"id" gorm:"primaryKey"`
	Name     string `json:"name" validate:"required,min=2,max=100"`
	Email    string `json:"email" validate:"required,email"`
	TenantID string `json:"tenant_id" gorm:"index"`
}

// UserService provides user-related operations
type UserService struct {
	db *gorm.DB
}

// NewUserService creates a new user service
func NewUserService(db *gorm.DB) *UserService {
	return &UserService{db: db}
}

// CreateUser creates a new user
func (s *UserService) CreateUser(ctx context.Context, user *User) error {
	// Get tenant from context
	tenant, exists := multitenancy.GetTenantFromContext(ctx)
	if exists {
		user.TenantID = tenant.ID
	}

	return s.db.WithContext(ctx).Create(user).Error
}

// GetUsers retrieves users for the current tenant
func (s *UserService) GetUsers(ctx context.Context) ([]User, error) {
	var users []User
	query := s.db.WithContext(ctx)

	// Filter by tenant if available
	tenant, exists := multitenancy.GetTenantFromContext(ctx)
	if exists {
		query = query.Where("tenant_id = ?", tenant.ID)
	}

	err := query.Find(&users).Error
	return users, err
}

// UserController handles user-related HTTP requests
type UserController struct {
	userService *UserService
	validator   *validation.Validator
}

// NewUserController creates a new user controller
func NewUserController(userService *UserService, validator *validation.Validator) *UserController {
	return &UserController{
		userService: userService,
		validator:   validator,
	}
}

// CreateUser handles POST /users
func (c *UserController) CreateUser(ctx *gin.Context) {
	var user User
	if err := ctx.ShouldBindJSON(&user); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate user data
	if err := c.validator.Validate(&user); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Create user
	if err := c.userService.CreateUser(ctx.Request.Context(), &user); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	ctx.JSON(http.StatusCreated, user)
}

// GetUsers handles GET /users
func (c *UserController) GetUsers(ctx *gin.Context) {
	users, err := c.userService.GetUsers(ctx.Request.Context())
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get users"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"users": users})
}

// GetTenantInfo handles GET /tenant
func GetTenantInfo(ctx *gin.Context) {
	tenant, exists := multitenancy.GetTenantFromGinContext(ctx)
	if !exists {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "No tenant context"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"tenant": tenant})
}

// HealthCheck handles GET /health
func HealthCheck(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"version":   "1.0.0",
	})
}

func main() {
	// Initialize database
	db, err := gorm.Open(sqlite.Open("example.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Auto-migrate schemas
	if err := db.AutoMigrate(&User{}, &multitenancy.TenantModel{}); err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	// Create dependency injection container
	c := di.New()

	// Register database
	c.RegisterSingleton("db", func() interface{} {
		return db
	})

	// Register validator
	c.RegisterSingleton("validator", func() interface{} {
		return validation.New()
	})

	// Register user service
	c.RegisterSingleton("userService", func() interface{} {
		db := c.MustResolve("db").(*gorm.DB)
		return NewUserService(db)
	})

	// Register user controller
	c.RegisterSingleton("userController", func() interface{} {
		userService := c.MustResolve("userService").(*UserService)
		validator := c.MustResolve("validator").(*validation.Validator)
		return NewUserController(userService, validator)
	})

	// Setup multi-tenancy
	mtManager, err := multitenancy.SetupWithGorm(db, nil)
	if err != nil {
		log.Fatal("Failed to setup multi-tenancy:", err)
	}

	// Seed development tenants
	ctx := context.Background()
	if err := multitenancy.SeedDevelopmentTenants(ctx, mtManager.Service()); err != nil {
		log.Printf("Warning: Failed to seed development tenants: %v", err)
	}

	// Setup security
	securityConfig := security.DevelopmentConfig()
	securityConfig.CORS.AllowOrigins = []string{"http://localhost:3000", "http://localhost:8080"}
	securityConfig.RateLimit.Enabled = true
	securityConfig.RateLimit.RequestsPerMinute = 100

	securityMiddleware := security.NewSecurityMiddleware(securityConfig)

	// Setup router
	routerConfig := &router.Config{
		Mode:           gin.DebugMode,
		TrustedProxies: []string{"127.0.0.1"},
		EnableMetrics:  true,
		EnableLogging:  true,
	}

	r := router.New(routerConfig)

	// Apply global middleware
	r.Use(securityMiddleware.Handler())
	r.Use(mtManager.OptionalMiddleware()) // Optional tenant resolution

	// Public routes (no tenant required)
	public := r.Group("/api/v1")
	{
		public.GET("/health", HealthCheck)
		public.GET("/tenant", GetTenantInfo)
	}

	// Tenant-specific routes (tenant required)
	tenantRoutes := r.Group("/api/v1")
	tenantRoutes.Use(mtManager.RequiredMiddleware()) // Require tenant
	{
		userController := c.MustResolve("userController").(*UserController)
		
		users := tenantRoutes.Group("/users")
		{
			users.POST("", userController.CreateUser)
			users.GET("", userController.GetUsers)
		}
	}

	// Admin routes (with RBAC)
	admin := r.Group("/api/v1/admin")
	admin.Use(mtManager.RequiredMiddleware())
	// admin.Use(security.RequireRole("admin")) // Uncomment when implementing authentication
	{
		admin.GET("/tenants", func(ctx *gin.Context) {
			tenants, err := mtManager.Service().ListTenants(ctx.Request.Context(), 0, 50)
			if err != nil {
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list tenants"})
				return
			}
			ctx.JSON(http.StatusOK, gin.H{"tenants": tenants})
		})
	}

	// Start server
	port := ":8080"
	fmt.Printf("🚀 Server starting on port %s\n", port)
	fmt.Println("📚 API Documentation:")
	fmt.Println("  GET  /api/v1/health          - Health check")
	fmt.Println("  GET  /api/v1/tenant          - Get current tenant info")
	fmt.Println("  POST /api/v1/users           - Create user (requires tenant)")
	fmt.Println("  GET  /api/v1/users           - List users (requires tenant)")
	fmt.Println("  GET  /api/v1/admin/tenants   - List all tenants (admin)")
	fmt.Println("")
	fmt.Println("🏢 Multi-tenancy examples:")
	fmt.Println("  Header: X-Tenant-ID: acme")
	fmt.Println("  Query:  ?tenant=beta")
	fmt.Println("  Subdomain: http://gamma.localhost:8080")
	fmt.Println("")
	fmt.Println("📝 Example requests:")
	fmt.Println(`  curl -H "X-Tenant-ID: acme" http://localhost:8080/api/v1/tenant`)
	fmt.Println(`  curl -H "X-Tenant-ID: acme" -H "Content-Type: application/json" -d '{"name":"John Doe","email":"john@example.com"}' http://localhost:8080/api/v1/users`)

	if err := r.Run(port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}