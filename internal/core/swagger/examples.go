package swagger

import (
	"time"
)

// Example models for API documentation

// User represents a user in the system
type User struct {
	ID        int       `json:"id" description:"Unique identifier for the user" validate:"required"`
	Username  string    `json:"username" description:"Username for login" validate:"required,min=3,max=50"`
	Email     string    `json:"email" description:"User email address" validate:"required,email"`
	FullName  string    `json:"full_name" description:"Full name of the user" validate:"required"`
	Role      string    `json:"role" description:"User role in the system" validate:"required,oneof=admin user guest"`
	Active    bool      `json:"active" description:"Whether the user account is active"`
	CreatedAt time.Time `json:"created_at" description:"Account creation timestamp"`
	UpdatedAt time.Time `json:"updated_at" description:"Last update timestamp"`
}

// CreateUserRequest represents the request body for creating a user
type CreateUserRequest struct {
	Username string `json:"username" description:"Username for the new user" validate:"required,min=3,max=50"`
	Email    string `json:"email" description:"Email address for the new user" validate:"required,email"`
	FullName string `json:"full_name" description:"Full name of the new user" validate:"required"`
	Password string `json:"password" description:"Password for the new user" validate:"required,min=8"`
	Role     string `json:"role" description:"Role to assign to the user" validate:"required,oneof=admin user guest"`
}

// UpdateUserRequest represents the request body for updating a user
type UpdateUserRequest struct {
	Username *string `json:"username,omitempty" description:"New username (optional)"`
	Email    *string `json:"email,omitempty" description:"New email address (optional)"`
	FullName *string `json:"full_name,omitempty" description:"New full name (optional)"`
	Role     *string `json:"role,omitempty" description:"New role (optional)"`
	Active   *bool   `json:"active,omitempty" description:"New active status (optional)"`
}

// LoginRequest represents the login request
type LoginRequest struct {
	Username string `json:"username" description:"Username or email" validate:"required"`
	Password string `json:"password" description:"User password" validate:"required"`
}

// LoginResponse represents the login response
type LoginResponse struct {
	Token     string    `json:"token" description:"JWT access token"`
	ExpiresAt time.Time `json:"expires_at" description:"Token expiration time"`
	User      User      `json:"user" description:"User information"`
}

// Product represents a product in the system
type Product struct {
	ID          int     `json:"id" description:"Unique identifier for the product" validate:"required"`
	Name        string  `json:"name" description:"Product name" validate:"required"`
	Description string  `json:"description" description:"Product description"`
	Price       float64 `json:"price" description:"Product price" validate:"required,min=0"`
	Stock       int     `json:"stock" description:"Available stock quantity" validate:"min=0"`
	Category    string  `json:"category" description:"Product category" validate:"required"`
	Active      bool    `json:"active" description:"Whether the product is active"`
	CreatedAt   time.Time `json:"created_at" description:"Product creation timestamp"`
	UpdatedAt   time.Time `json:"updated_at" description:"Last update timestamp"`
}

// CreateProductRequest represents the request body for creating a product
type CreateProductRequest struct {
	Name        string  `json:"name" description:"Product name" validate:"required"`
	Description string  `json:"description" description:"Product description"`
	Price       float64 `json:"price" description:"Product price" validate:"required,min=0"`
	Stock       int     `json:"stock" description:"Initial stock quantity" validate:"min=0"`
	Category    string  `json:"category" description:"Product category" validate:"required"`
}

// UpdateProductRequest represents the request body for updating a product
type UpdateProductRequest struct {
	Name        *string  `json:"name,omitempty" description:"New product name (optional)"`
	Description *string  `json:"description,omitempty" description:"New product description (optional)"`
	Price       *float64 `json:"price,omitempty" description:"New product price (optional)"`
	Stock       *int     `json:"stock,omitempty" description:"New stock quantity (optional)"`
	Category    *string  `json:"category,omitempty" description:"New product category (optional)"`
	Active      *bool    `json:"active,omitempty" description:"New active status (optional)"`
}

// Order represents an order in the system
type Order struct {
	ID         int         `json:"id" description:"Unique identifier for the order" validate:"required"`
	UserID     int         `json:"user_id" description:"ID of the user who placed the order" validate:"required"`
	Items      []OrderItem `json:"items" description:"List of items in the order" validate:"required,min=1"`
	Total      float64     `json:"total" description:"Total order amount" validate:"required,min=0"`
	Status     string      `json:"status" description:"Order status" validate:"required,oneof=pending processing shipped delivered cancelled"`
	CreatedAt  time.Time   `json:"created_at" description:"Order creation timestamp"`
	UpdatedAt  time.Time   `json:"updated_at" description:"Last update timestamp"`
}

// OrderItem represents an item in an order
type OrderItem struct {
	ProductID int     `json:"product_id" description:"ID of the product" validate:"required"`
	Quantity  int     `json:"quantity" description:"Quantity ordered" validate:"required,min=1"`
	Price     float64 `json:"price" description:"Price per unit at time of order" validate:"required,min=0"`
	Subtotal  float64 `json:"subtotal" description:"Subtotal for this item (quantity * price)"`
}

// CreateOrderRequest represents the request body for creating an order
type CreateOrderRequest struct {
	Items []CreateOrderItem `json:"items" description:"List of items to order" validate:"required,min=1"`
}

// CreateOrderItem represents an item in a create order request
type CreateOrderItem struct {
	ProductID int `json:"product_id" description:"ID of the product to order" validate:"required"`
	Quantity  int `json:"quantity" description:"Quantity to order" validate:"required,min=1"`
}

// UpdateOrderStatusRequest represents the request body for updating order status
type UpdateOrderStatusRequest struct {
	Status string `json:"status" description:"New order status" validate:"required,oneof=pending processing shipped delivered cancelled"`
}

// APIResponse represents a standard API response
type APIResponse struct {
	Success bool        `json:"success" description:"Whether the request was successful"`
	Message string      `json:"message" description:"Response message"`
	Data    interface{} `json:"data,omitempty" description:"Response data (optional)"`
	Error   *APIError   `json:"error,omitempty" description:"Error details (optional)"`
}

// APIError represents an API error
type APIError struct {
	Code    int    `json:"code" description:"Error code"`
	Message string `json:"message" description:"Error message"`
	Details string `json:"details,omitempty" description:"Additional error details (optional)"`
}

// PaginationRequest represents pagination parameters
type PaginationRequest struct {
	Page     int `json:"page" description:"Page number (1-based)" validate:"min=1"`
	PageSize int `json:"page_size" description:"Number of items per page" validate:"min=1,max=100"`
}

// PaginationResponse represents pagination metadata
type PaginationResponse struct {
	Page       int `json:"page" description:"Current page number"`
	PageSize   int `json:"page_size" description:"Number of items per page"`
	TotalItems int `json:"total_items" description:"Total number of items"`
	TotalPages int `json:"total_pages" description:"Total number of pages"`
}

// PaginatedResponse represents a paginated API response
type PaginatedResponse struct {
	Success    bool                `json:"success" description:"Whether the request was successful"`
	Message    string              `json:"message" description:"Response message"`
	Data       interface{}         `json:"data" description:"Response data"`
	Pagination PaginationResponse  `json:"pagination" description:"Pagination metadata"`
	Error      *APIError           `json:"error,omitempty" description:"Error details (optional)"`
}

// SearchRequest represents a search request
type SearchRequest struct {
	Query    string `json:"query" description:"Search query" validate:"required"`
	Category string `json:"category,omitempty" description:"Category filter (optional)"`
	MinPrice *float64 `json:"min_price,omitempty" description:"Minimum price filter (optional)"`
	MaxPrice *float64 `json:"max_price,omitempty" description:"Maximum price filter (optional)"`
	SortBy   string `json:"sort_by,omitempty" description:"Sort field (name, price, created_at)"`
	SortOrder string `json:"sort_order,omitempty" description:"Sort order (asc, desc)"`
	PaginationRequest
}

// HealthStatus represents the health status of the application
type HealthStatus struct {
	Status    string            `json:"status" description:"Overall health status" validate:"required,oneof=healthy unhealthy degraded"`
	Timestamp time.Time         `json:"timestamp" description:"Health check timestamp"`
	Version   string            `json:"version" description:"Application version"`
	Uptime    string            `json:"uptime" description:"Application uptime"`
	Services  map[string]string `json:"services" description:"Status of individual services"`
}

// Metrics represents application metrics
type Metrics struct {
	RequestsTotal      int64   `json:"requests_total" description:"Total number of requests processed"`
	RequestsPerSecond  float64 `json:"requests_per_second" description:"Current requests per second"`
	ResponseTimeAvg    float64 `json:"response_time_avg" description:"Average response time in milliseconds"`
	ResponseTimeP95    float64 `json:"response_time_p95" description:"95th percentile response time in milliseconds"`
	MemoryUsage        int64   `json:"memory_usage" description:"Current memory usage in bytes"`
	CPUUsage           float64 `json:"cpu_usage" description:"Current CPU usage percentage"`
	ActiveConnections  int     `json:"active_connections" description:"Number of active connections"`
	ErrorRate          float64 `json:"error_rate" description:"Current error rate percentage"`
}

// VersionInfo represents application version information
type VersionInfo struct {
	Version    string    `json:"version" description:"Application version"`
	BuildDate  time.Time `json:"build_date" description:"Build date"`
	CommitHash string    `json:"commit_hash" description:"Git commit hash"`
	GoVersion  string    `json:"go_version" description:"Go version used to build"`
	BuildEnv   string    `json:"build_env" description:"Build environment"`
}

// FileUploadRequest represents a file upload request
type FileUploadRequest struct {
	File        []byte `json:"file" description:"File content (base64 encoded)" validate:"required"`
	Filename    string `json:"filename" description:"Original filename" validate:"required"`
	ContentType string `json:"content_type" description:"File content type" validate:"required"`
	Description string `json:"description,omitempty" description:"File description (optional)"`
}

// FileUploadResponse represents a file upload response
type FileUploadResponse struct {
	FileID      string    `json:"file_id" description:"Unique file identifier"`
	Filename    string    `json:"filename" description:"Original filename"`
	Size        int64     `json:"size" description:"File size in bytes"`
	ContentType string    `json:"content_type" description:"File content type"`
	URL         string    `json:"url" description:"File access URL"`
	UploadedAt  time.Time `json:"uploaded_at" description:"Upload timestamp"`
}

// BulkOperationRequest represents a bulk operation request
type BulkOperationRequest struct {
	Operation string        `json:"operation" description:"Operation to perform" validate:"required,oneof=create update delete"`
	Items     []interface{} `json:"items" description:"Items to process" validate:"required,min=1"`
}

// BulkOperationResponse represents a bulk operation response
type BulkOperationResponse struct {
	TotalItems     int                      `json:"total_items" description:"Total number of items processed"`
	SuccessCount   int                      `json:"success_count" description:"Number of successful operations"`
	FailureCount   int                      `json:"failure_count" description:"Number of failed operations"`
	Results        []BulkOperationResult    `json:"results" description:"Detailed results for each item"`
	Errors         []BulkOperationError     `json:"errors,omitempty" description:"Errors that occurred during processing"`
}

// BulkOperationResult represents the result of a single bulk operation
type BulkOperationResult struct {
	Index   int         `json:"index" description:"Index of the item in the original request"`
	Success bool        `json:"success" description:"Whether the operation was successful"`
	Data    interface{} `json:"data,omitempty" description:"Result data (for successful operations)"`
	Error   string      `json:"error,omitempty" description:"Error message (for failed operations)"`
}

// BulkOperationError represents an error in bulk operation
type BulkOperationError struct {
	Index   int    `json:"index" description:"Index of the item that caused the error"`
	Code    string `json:"code" description:"Error code"`
	Message string `json:"message" description:"Error message"`
}

// WebSocketMessage represents a WebSocket message
type WebSocketMessage struct {
	Type      string      `json:"type" description:"Message type" validate:"required"`
	Payload   interface{} `json:"payload" description:"Message payload"`
	Timestamp time.Time   `json:"timestamp" description:"Message timestamp"`
	Sender    string      `json:"sender,omitempty" description:"Message sender (optional)"`
}

// NotificationRequest represents a notification request
type NotificationRequest struct {
	Recipients []string               `json:"recipients" description:"List of recipient IDs" validate:"required,min=1"`
	Title      string                 `json:"title" description:"Notification title" validate:"required"`
	Message    string                 `json:"message" description:"Notification message" validate:"required"`
	Type       string                 `json:"type" description:"Notification type" validate:"required,oneof=info warning error success"`
	Data       map[string]interface{} `json:"data,omitempty" description:"Additional notification data (optional)"`
	ScheduleAt *time.Time             `json:"schedule_at,omitempty" description:"Schedule notification for later (optional)"`
}

// NotificationResponse represents a notification response
type NotificationResponse struct {
	NotificationID string    `json:"notification_id" description:"Unique notification identifier"`
	Status         string    `json:"status" description:"Notification status"`
	SentAt         time.Time `json:"sent_at" description:"Notification sent timestamp"`
	RecipientCount int       `json:"recipient_count" description:"Number of recipients"`
}

// ExampleDocumentationSetup demonstrates how to set up comprehensive API documentation
func ExampleDocumentationSetup() *SwaggerMiddleware {
	// Create Swagger configuration
	config := Config{
		Title:       "Gawan Framework API",
		Description: "Comprehensive API documentation for the Gawan framework with examples for all endpoints",
		Version:     "1.0.0",
		Host:        "localhost:8080",
		BasePath:    "/api/v1",
		Schemes:     []string{"http", "https"},
		Path:        "/docs",
	}
	
	// Create Swagger middleware
	swaggerMW := NewSwaggerMiddleware(config)
	
	// Add security schemes
	swaggerMW.GetGenerator().AddSecurityScheme("bearerAuth", SecurityScheme{
		Type:         "http",
		Scheme:       "bearer",
		BearerFormat: "JWT",
		Description:  "JWT Authorization header using the Bearer scheme. Example: 'Authorization: Bearer {token}'",
	})
	
	swaggerMW.GetGenerator().AddSecurityScheme("apiKey", SecurityScheme{
		Type:        "apiKey",
		In:          "header",
		Name:        "X-API-Key",
		Description: "API key for authentication. Example: 'X-API-Key: your-api-key'",
	})
	
	// Add tags
	swaggerMW.AddTag("Authentication", "User authentication and authorization endpoints")
	swaggerMW.AddTag("Users", "User management endpoints")
	swaggerMW.AddTag("Products", "Product management endpoints")
	swaggerMW.AddTag("Orders", "Order management endpoints")
	swaggerMW.AddTag("Files", "File upload and management endpoints")
	swaggerMW.AddTag("Health", "Health check and monitoring endpoints")
	swaggerMW.AddTag("System", "System information and utilities")
	swaggerMW.AddTag("Notifications", "Notification and messaging endpoints")
	
	// Add servers
	swaggerMW.AddServer("http://localhost:8080", "Development server")
	swaggerMW.AddServer("https://api.example.com", "Production server")
	swaggerMW.AddServer("https://staging-api.example.com", "Staging server")
	
	// Register custom schemas
	swaggerMW.RegisterCustomSchema("User", User{})
	swaggerMW.RegisterCustomSchema("Product", Product{})
	swaggerMW.RegisterCustomSchema("Order", Order{})
	swaggerMW.RegisterCustomSchema("APIResponse", APIResponse{})
	swaggerMW.RegisterCustomSchema("PaginatedResponse", PaginatedResponse{})
	swaggerMW.RegisterCustomSchema("HealthStatus", HealthStatus{})
	swaggerMW.RegisterCustomSchema("Metrics", Metrics{})
	swaggerMW.RegisterCustomSchema("VersionInfo", VersionInfo{})
	
	// Add common endpoints
	swaggerMW.AddCommonEndpoints()
	
	return swaggerMW
}

// GetExampleUsers returns example users for documentation
func GetExampleUsers() []User {
	return []User{
		{
			ID:        1,
			Username:  "admin",
			Email:     "admin@example.com",
			FullName:  "System Administrator",
			Role:      "admin",
			Active:    true,
			CreatedAt: time.Now().AddDate(0, -6, 0),
			UpdatedAt: time.Now(),
		},
		{
			ID:        2,
			Username:  "john_doe",
			Email:     "john.doe@example.com",
			FullName:  "John Doe",
			Role:      "user",
			Active:    true,
			CreatedAt: time.Now().AddDate(0, -3, 0),
			UpdatedAt: time.Now().AddDate(0, 0, -7),
		},
		{
			ID:        3,
			Username:  "jane_smith",
			Email:     "jane.smith@example.com",
			FullName:  "Jane Smith",
			Role:      "user",
			Active:    false,
			CreatedAt: time.Now().AddDate(0, -1, 0),
			UpdatedAt: time.Now().AddDate(0, 0, -3),
		},
	}
}

// GetExampleProducts returns example products for documentation
func GetExampleProducts() []Product {
	return []Product{
		{
			ID:          1,
			Name:        "Laptop Computer",
			Description: "High-performance laptop for professional use",
			Price:       1299.99,
			Stock:       25,
			Category:    "Electronics",
			Active:      true,
			CreatedAt:   time.Now().AddDate(0, -2, 0),
			UpdatedAt:   time.Now().AddDate(0, 0, -5),
		},
		{
			ID:          2,
			Name:        "Wireless Mouse",
			Description: "Ergonomic wireless mouse with long battery life",
			Price:       29.99,
			Stock:       100,
			Category:    "Accessories",
			Active:      true,
			CreatedAt:   time.Now().AddDate(0, -1, -15),
			UpdatedAt:   time.Now().AddDate(0, 0, -2),
		},
		{
			ID:          3,
			Name:        "Office Chair",
			Description: "Comfortable ergonomic office chair",
			Price:       199.99,
			Stock:       0,
			Category:    "Furniture",
			Active:      false,
			CreatedAt:   time.Now().AddDate(0, -3, 0),
			UpdatedAt:   time.Now().AddDate(0, 0, -10),
		},
	}
}

// GetExampleOrders returns example orders for documentation
func GetExampleOrders() []Order {
	return []Order{
		{
			ID:     1,
			UserID: 2,
			Items: []OrderItem{
				{ProductID: 1, Quantity: 1, Price: 1299.99, Subtotal: 1299.99},
				{ProductID: 2, Quantity: 2, Price: 29.99, Subtotal: 59.98},
			},
			Total:     1359.97,
			Status:    "delivered",
			CreatedAt: time.Now().AddDate(0, 0, -14),
			UpdatedAt: time.Now().AddDate(0, 0, -7),
		},
		{
			ID:     2,
			UserID: 3,
			Items: []OrderItem{
				{ProductID: 2, Quantity: 1, Price: 29.99, Subtotal: 29.99},
			},
			Total:     29.99,
			Status:    "processing",
			CreatedAt: time.Now().AddDate(0, 0, -3),
			UpdatedAt: time.Now().AddDate(0, 0, -1),
		},
	}
}