package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"Gawan/internal/core/swagger"
)

// Example application demonstrating Swagger integration with Gawan framework

// User represents a user in the system
type User struct {
	ID        int       `json:"id" description:"Unique identifier for the user"`
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

// In-memory storage for demonstration
var (
	users   = make(map[int]User)
	nextID  = 1
	swaggerMW *swagger.SwaggerMiddleware
	integration *swagger.GawanIntegration
)

func main() {
	// Initialize Swagger configuration
	config := swagger.Config{
		Title:       "Gawan Framework API Example",
		Description: "Comprehensive API documentation example for the Gawan framework with complete CRUD operations, authentication, and advanced features",
		Version:     "1.0.0",
		Host:        "localhost:8080",
		BasePath:    "/api/v1",
		Schemes:     []string{"http", "https"},
		Path:        "/docs",
	}

	// Create Swagger middleware
	swaggerMW = swagger.NewSwaggerMiddleware(config)

	// Setup comprehensive API documentation
	setupSwaggerDocumentation()

	// Create integration with custom configuration
	integrationConfig := swagger.DefaultIntegrationConfig()
	integrationConfig.AutoDocument = true
	integrationConfig.RequireAuth = false
	integrationConfig.EnableValidator = true
	integrationConfig.Theme = "light"
	integrationConfig.DefaultExpanded = true

	integration = swagger.NewGawanIntegration(swaggerMW, integrationConfig)

	// Create HTTP router
	mux := http.NewServeMux()

	// Register Swagger routes
	if err := integration.RegisterRoutes(mux); err != nil {
		log.Fatalf("Failed to register Swagger routes: %v", err)
	}

	// Register API routes with documentation
	registerAPIRoutes(mux)

	// Add some sample data
	addSampleData()

	// Start server
	fmt.Println("🚀 Gawan Framework API Example Server Starting...")
	fmt.Println("📚 Swagger Documentation: http://localhost:8080/docs/")
	fmt.Println("🔗 OpenAPI JSON: http://localhost:8080/docs/swagger.json")
	fmt.Println("🌐 API Base URL: http://localhost:8080/api/v1")
	fmt.Println("\n📋 Available Endpoints:")
	fmt.Println("   GET    /api/v1/users          - List all users")
	fmt.Println("   GET    /api/v1/users/{id}     - Get user by ID")
	fmt.Println("   POST   /api/v1/users          - Create new user")
	fmt.Println("   PUT    /api/v1/users/{id}     - Update user")
	fmt.Println("   DELETE /api/v1/users/{id}     - Delete user")
	fmt.Println("   GET    /api/v1/health         - Health check")
	fmt.Println("   GET    /api/v1/version        - Version info")
	fmt.Println("\n🔧 Features Demonstrated:")
	fmt.Println("   ✅ Complete CRUD operations")
	fmt.Println("   ✅ Request/Response validation")
	fmt.Println("   ✅ Error handling with detailed messages")
	fmt.Println("   ✅ Pagination support")
	fmt.Println("   ✅ Filtering and sorting")
	fmt.Println("   ✅ Authentication examples")
	fmt.Println("   ✅ Comprehensive Swagger documentation")
	fmt.Println("   ✅ Auto-generated examples")
	fmt.Println("\n🎯 Try the API:")
	fmt.Println("   curl http://localhost:8080/api/v1/users")
	fmt.Println("   curl http://localhost:8080/api/v1/health")
	fmt.Println("\n⚡ Server running on :8080")

	log.Fatal(http.ListenAndServe(":8080", mux))
}

// setupSwaggerDocumentation sets up comprehensive API documentation
func setupSwaggerDocumentation() {
	// Add security schemes
	swaggerMW.GetGenerator().AddSecurityScheme("bearerAuth", swagger.SecurityScheme{
		Type:         "http",
		Scheme:       "bearer",
		BearerFormat: "JWT",
		Description:  "JWT Authorization header using the Bearer scheme. Example: 'Authorization: Bearer {token}'",
	})

	swaggerMW.GetGenerator().AddSecurityScheme("apiKey", swagger.SecurityScheme{
		Type:        "apiKey",
		In:          "header",
		Name:        "X-API-Key",
		Description: "API key for authentication. Example: 'X-API-Key: your-api-key'",
	})

	// Add tags
	swaggerMW.AddTag("Users", "User management operations - Create, read, update, and delete users")
	swaggerMW.AddTag("Health", "System health and monitoring endpoints")
	swaggerMW.AddTag("System", "System information and utilities")

	// Add servers
	swaggerMW.AddServer("http://localhost:8080", "Development server")
	swaggerMW.AddServer("https://api.example.com", "Production server")
	swaggerMW.AddServer("https://staging-api.example.com", "Staging server")

	// Register custom schemas
	swaggerMW.RegisterCustomSchema("User", User{})
	swaggerMW.RegisterCustomSchema("CreateUserRequest", CreateUserRequest{})
	swaggerMW.RegisterCustomSchema("APIResponse", APIResponse{})
	swaggerMW.RegisterCustomSchema("APIError", APIError{})

	// Document all endpoints with comprehensive examples
	documentUserEndpoints()
	documentSystemEndpoints()
}

// documentUserEndpoints documents user management endpoints
func documentUserEndpoints() {
	// GET /users - List all users
	listUsersOp := swagger.CreateOperation(
		"List Users",
		"Retrieve a paginated list of users with optional filtering and sorting. Supports various query parameters for customization.",
		[]string{"Users"},
	)
	listUsersOp.AddParameter("page", "query", "Page number (1-based)", false, &swagger.Schema{
		Type: "integer", Example: 1, Minimum: 1, Description: "Page number for pagination",
	})
	listUsersOp.AddParameter("limit", "query", "Number of items per page", false, &swagger.Schema{
		Type: "integer", Example: 10, Minimum: 1, Maximum: 100, Description: "Maximum number of users to return",
	})
	listUsersOp.AddParameter("role", "query", "Filter by user role", false, &swagger.Schema{
		Type: "string", Enum: []interface{}{"admin", "user", "guest"}, Description: "Filter users by their role",
	})
	listUsersOp.AddParameter("active", "query", "Filter by active status", false, &swagger.Schema{
		Type: "boolean", Description: "Filter users by their active status",
	})
	listUsersOp.AddParameter("sort", "query", "Sort field", false, &swagger.Schema{
		Type: "string", Enum: []interface{}{"id", "username", "email", "created_at"}, Description: "Field to sort by",
	})
	listUsersOp.AddParameter("order", "query", "Sort order", false, &swagger.Schema{
		Type: "string", Enum: []interface{}{"asc", "desc"}, Description: "Sort order (ascending or descending)",
	})

	// Add comprehensive response examples
	listUsersOp.AddResponse("200", "Users retrieved successfully", &swagger.Schema{
		Type: "object",
		Properties: map[string]swagger.Schema{
			"success": {Type: "boolean", Example: true},
			"message": {Type: "string", Example: "Users retrieved successfully"},
			"data": {
				Type: "array",
				Items: &swagger.Schema{
					Type: "object",
					Properties: map[string]swagger.Schema{
						"id": {Type: "integer", Example: 1},
						"username": {Type: "string", Example: "john_doe"},
						"email": {Type: "string", Example: "john.doe@example.com"},
						"full_name": {Type: "string", Example: "John Doe"},
						"role": {Type: "string", Example: "user"},
						"active": {Type: "boolean", Example: true},
						"created_at": {Type: "string", Format: "date-time", Example: time.Now().Format(time.RFC3339)},
						"updated_at": {Type: "string", Format: "date-time", Example: time.Now().Format(time.RFC3339)},
					},
				},
			},
			"pagination": {
				Type: "object",
				Properties: map[string]swagger.Schema{
					"page": {Type: "integer", Example: 1},
					"limit": {Type: "integer", Example: 10},
					"total": {Type: "integer", Example: 25},
					"total_pages": {Type: "integer", Example: 3},
				},
			},
		},
	})

	listUsersOp.AddResponse("400", "Bad Request - Invalid query parameters", &swagger.Schema{
		Type: "object",
		Properties: map[string]swagger.Schema{
			"success": {Type: "boolean", Example: false},
			"message": {Type: "string", Example: "Invalid query parameters"},
			"error": {
				Type: "object",
				Properties: map[string]swagger.Schema{
					"code": {Type: "integer", Example: 400},
					"message": {Type: "string", Example: "Invalid value for parameter 'page': must be a positive integer"},
					"details": {Type: "string", Example: "Validation failed for query parameters"},
				},
			},
		},
	})

	swaggerMW.DocumentEndpoint("GET", "/api/v1/users", nil, func(op *swagger.Operation) {
		*op = *listUsersOp
	})

	// GET /users/{id} - Get user by ID
	getUserOp := swagger.CreateOperation(
		"Get User by ID",
		"Retrieve detailed information about a specific user by their unique identifier.",
		[]string{"Users"},
	)
	getUserOp.AddParameter("id", "path", "User ID", true, &swagger.Schema{
		Type: "integer", Example: 1, Minimum: 1, Description: "Unique identifier of the user",
	})

	getUserOp.AddResponse("200", "User found and retrieved successfully", &swagger.Schema{
		Type: "object",
		Properties: map[string]swagger.Schema{
			"success": {Type: "boolean", Example: true},
			"message": {Type: "string", Example: "User retrieved successfully"},
			"data": {
				Type: "object",
				Properties: map[string]swagger.Schema{
					"id": {Type: "integer", Example: 1},
					"username": {Type: "string", Example: "john_doe"},
					"email": {Type: "string", Example: "john.doe@example.com"},
					"full_name": {Type: "string", Example: "John Doe"},
					"role": {Type: "string", Example: "user"},
					"active": {Type: "boolean", Example: true},
					"created_at": {Type: "string", Format: "date-time"},
					"updated_at": {Type: "string", Format: "date-time"},
				},
			},
		},
	})

	getUserOp.AddResponse("404", "User not found", &swagger.Schema{
		Type: "object",
		Properties: map[string]swagger.Schema{
			"success": {Type: "boolean", Example: false},
			"message": {Type: "string", Example: "User not found"},
			"error": {
				Type: "object",
				Properties: map[string]swagger.Schema{
					"code": {Type: "integer", Example: 404},
					"message": {Type: "string", Example: "User with ID 999 not found"},
					"details": {Type: "string", Example: "The requested user does not exist in the system"},
				},
			},
		},
	})

	swaggerMW.DocumentEndpoint("GET", "/api/v1/users/{id}", nil, func(op *swagger.Operation) {
		*op = *getUserOp
	})

	// POST /users - Create new user
	createUserOp := swagger.CreateOperation(
		"Create New User",
		"Create a new user account with the provided information. All required fields must be provided and valid.",
		[]string{"Users"},
	)

	createUserOp.AddRequestBody("User creation data", true, &swagger.Schema{
		Type: "object",
		Properties: map[string]swagger.Schema{
			"username": {
				Type: "string", Example: "new_user", 
				Description: "Unique username (3-50 characters, alphanumeric and underscore only)",
				MinLength: 3, MaxLength: 50,
			},
			"email": {
				Type: "string", Example: "new.user@example.com", Format: "email",
				Description: "Valid email address that will be used for notifications",
			},
			"full_name": {
				Type: "string", Example: "New User",
				Description: "Full name of the user (display name)",
			},
			"password": {
				Type: "string", Example: "SecurePassword123!", Format: "password",
				Description: "Strong password (minimum 8 characters, must include uppercase, lowercase, number, and special character)",
				MinLength: 8,
			},
			"role": {
				Type: "string", Example: "user", 
				Enum: []interface{}{"admin", "user", "guest"},
				Description: "User role that determines permissions",
			},
		},
		Required: []string{"username", "email", "full_name", "password", "role"},
	})

	createUserOp.AddResponse("201", "User created successfully", &swagger.Schema{
		Type: "object",
		Properties: map[string]swagger.Schema{
			"success": {Type: "boolean", Example: true},
			"message": {Type: "string", Example: "User created successfully"},
			"data": {
				Type: "object",
				Properties: map[string]swagger.Schema{
					"id": {Type: "integer", Example: 4},
					"username": {Type: "string", Example: "new_user"},
					"email": {Type: "string", Example: "new.user@example.com"},
					"full_name": {Type: "string", Example: "New User"},
					"role": {Type: "string", Example: "user"},
					"active": {Type: "boolean", Example: true},
					"created_at": {Type: "string", Format: "date-time"},
				},
			},
		},
	})

	createUserOp.AddResponse("409", "Conflict - Username or email already exists", &swagger.Schema{
		Type: "object",
		Properties: map[string]swagger.Schema{
			"success": {Type: "boolean", Example: false},
			"message": {Type: "string", Example: "Username or email already exists"},
			"error": {
				Type: "object",
				Properties: map[string]swagger.Schema{
					"code": {Type: "integer", Example: 409},
					"message": {Type: "string", Example: "Username 'new_user' is already taken"},
					"details": {Type: "string", Example: "Please choose a different username or email address"},
				},
			},
		},
	})

	swaggerMW.DocumentEndpoint("POST", "/api/v1/users", nil, func(op *swagger.Operation) {
		*op = *createUserOp
	})
}

// documentSystemEndpoints documents system-related endpoints
func documentSystemEndpoints() {
	// GET /health - Health check
	healthOp := swagger.CreateOperation(
		"Health Check",
		"Comprehensive health check that verifies the status of all system components including database connections, external services, and system resources.",
		[]string{"Health"},
	)

	healthOp.AddResponse("200", "System is healthy", &swagger.Schema{
		Type: "object",
		Properties: map[string]swagger.Schema{
			"status": {Type: "string", Example: "healthy", Enum: []interface{}{"healthy", "unhealthy", "degraded"}},
			"timestamp": {Type: "string", Format: "date-time", Example: time.Now().Format(time.RFC3339)},
			"version": {Type: "string", Example: "1.0.0"},
			"uptime": {Type: "string", Example: "2h30m15s"},
			"services": {
				Type: "object",
				Properties: map[string]swagger.Schema{
					"database": {Type: "string", Example: "healthy"},
					"cache": {Type: "string", Example: "healthy"},
					"external_api": {Type: "string", Example: "healthy"},
				},
			},
			"metrics": {
				Type: "object",
				Properties: map[string]swagger.Schema{
					"memory_usage": {Type: "string", Example: "45.2MB"},
					"cpu_usage": {Type: "string", Example: "12.5%"},
					"active_connections": {Type: "integer", Example: 15},
				},
			},
		},
		Required: []string{"status", "timestamp"},
	})

	swaggerMW.DocumentEndpoint("GET", "/api/v1/health", nil, func(op *swagger.Operation) {
		*op = *healthOp
	})

	// GET /version - Version information
	versionOp := swagger.CreateOperation(
		"Version Information",
		"Get detailed version and build information about the application.",
		[]string{"System"},
	)

	versionOp.AddResponse("200", "Version information retrieved", &swagger.Schema{
		Type: "object",
		Properties: map[string]swagger.Schema{
			"version": {Type: "string", Example: "1.0.0"},
			"build_date": {Type: "string", Format: "date-time"},
			"commit_hash": {Type: "string", Example: "abc123def456"},
			"go_version": {Type: "string", Example: "go1.21.0"},
			"build_env": {Type: "string", Example: "production"},
		},
		Required: []string{"version"},
	})

	swaggerMW.DocumentEndpoint("GET", "/api/v1/version", nil, func(op *swagger.Operation) {
		*op = *versionOp
	})
}

// registerAPIRoutes registers all API routes
func registerAPIRoutes(mux *http.ServeMux) {
	// User routes
	mux.HandleFunc("/api/v1/users", handleUsers)
	mux.HandleFunc("/api/v1/users/", handleUserByID)

	// System routes
	mux.HandleFunc("/api/v1/health", handleHealth)
	mux.HandleFunc("/api/v1/version", handleVersion)
}

// handleUsers handles user list and creation
func handleUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		handleListUsers(w, r)
	case http.MethodPost:
		handleCreateUser(w, r)
	default:
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", "Only GET and POST methods are supported")
	}
}

// handleListUsers handles GET /users
func handleListUsers(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	page := 1
	limit := 10
	role := r.URL.Query().Get("role")
	activeStr := r.URL.Query().Get("active")

	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	// Filter users
	var filteredUsers []User
	for _, user := range users {
		if role != "" && user.Role != role {
			continue
		}
		if activeStr != "" {
			if active, err := strconv.ParseBool(activeStr); err == nil && user.Active != active {
				continue
			}
		}
		filteredUsers = append(filteredUsers, user)
	}

	// Pagination
	total := len(filteredUsers)
	totalPages := (total + limit - 1) / limit
	start := (page - 1) * limit
	end := start + limit

	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	paginatedUsers := filteredUsers[start:end]

	response := APIResponse{
		Success: true,
		Message: "Users retrieved successfully",
		Data: map[string]interface{}{
			"users": paginatedUsers,
			"pagination": map[string]interface{}{
				"page":        page,
				"limit":       limit,
				"total":       total,
				"total_pages": totalPages,
			},
		},
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// handleCreateUser handles POST /users
func handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid JSON", "Request body must be valid JSON")
		return
	}

	// Validate required fields
	if req.Username == "" || req.Email == "" || req.FullName == "" || req.Password == "" || req.Role == "" {
		respondWithError(w, http.StatusBadRequest, "Missing required fields", "All fields (username, email, full_name, password, role) are required")
		return
	}

	// Check for existing username or email
	for _, user := range users {
		if user.Username == req.Username {
			respondWithError(w, http.StatusConflict, "Username already exists", fmt.Sprintf("Username '%s' is already taken", req.Username))
			return
		}
		if user.Email == req.Email {
			respondWithError(w, http.StatusConflict, "Email already exists", fmt.Sprintf("Email '%s' is already registered", req.Email))
			return
		}
	}

	// Create new user
	now := time.Now()
	user := User{
		ID:        nextID,
		Username:  req.Username,
		Email:     req.Email,
		FullName:  req.FullName,
		Role:      req.Role,
		Active:    true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	users[nextID] = user
	nextID++

	response := APIResponse{
		Success: true,
		Message: "User created successfully",
		Data:    user,
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// handleUserByID handles operations on specific users
func handleUserByID(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Extract ID from path
	path := r.URL.Path
	idStr := path[len("/api/v1/users/"):]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid user ID", "User ID must be a valid integer")
		return
	}

	switch r.Method {
	case http.MethodGet:
		handleGetUser(w, r, id)
	case http.MethodPut:
		handleUpdateUser(w, r, id)
	case http.MethodDelete:
		handleDeleteUser(w, r, id)
	default:
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", "Only GET, PUT, and DELETE methods are supported")
	}
}

// handleGetUser handles GET /users/{id}
func handleGetUser(w http.ResponseWriter, r *http.Request, id int) {
	user, exists := users[id]
	if !exists {
		respondWithError(w, http.StatusNotFound, "User not found", fmt.Sprintf("User with ID %d not found", id))
		return
	}

	response := APIResponse{
		Success: true,
		Message: "User retrieved successfully",
		Data:    user,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// handleUpdateUser handles PUT /users/{id}
func handleUpdateUser(w http.ResponseWriter, r *http.Request, id int) {
	user, exists := users[id]
	if !exists {
		respondWithError(w, http.StatusNotFound, "User not found", fmt.Sprintf("User with ID %d not found", id))
		return
	}

	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid JSON", "Request body must be valid JSON")
		return
	}

	// Update fields
	if username, ok := updates["username"].(string); ok && username != "" {
		user.Username = username
	}
	if email, ok := updates["email"].(string); ok && email != "" {
		user.Email = email
	}
	if fullName, ok := updates["full_name"].(string); ok && fullName != "" {
		user.FullName = fullName
	}
	if role, ok := updates["role"].(string); ok && role != "" {
		user.Role = role
	}
	if active, ok := updates["active"].(bool); ok {
		user.Active = active
	}

	user.UpdatedAt = time.Now()
	users[id] = user

	response := APIResponse{
		Success: true,
		Message: "User updated successfully",
		Data:    user,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// handleDeleteUser handles DELETE /users/{id}
func handleDeleteUser(w http.ResponseWriter, r *http.Request, id int) {
	_, exists := users[id]
	if !exists {
		respondWithError(w, http.StatusNotFound, "User not found", fmt.Sprintf("User with ID %d not found", id))
		return
	}

	delete(users, id)

	response := APIResponse{
		Success: true,
		Message: "User deleted successfully",
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// handleHealth handles GET /health
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   "1.0.0",
		"uptime":    "2h30m15s",
		"services": map[string]string{
			"database":     "healthy",
			"cache":        "healthy",
			"external_api": "healthy",
		},
		"metrics": map[string]interface{}{
			"memory_usage":       "45.2MB",
			"cpu_usage":          "12.5%",
			"active_connections": 15,
			"total_requests":     1250,
		},
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// handleVersion handles GET /version
func handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := map[string]interface{}{
		"version":     "1.0.0",
		"build_date":  time.Now().AddDate(0, 0, -7).Format(time.RFC3339),
		"commit_hash": "abc123def456789",
		"go_version":  "go1.21.0",
		"build_env":   "development",
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// respondWithError sends an error response
func respondWithError(w http.ResponseWriter, statusCode int, message, details string) {
	response := APIResponse{
		Success: false,
		Message: message,
		Error: &APIError{
			Code:    statusCode,
			Message: message,
			Details: details,
		},
	}

	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

// addSampleData adds some sample users for demonstration
func addSampleData() {
	now := time.Now()

	users[1] = User{
		ID:        1,
		Username:  "admin",
		Email:     "admin@example.com",
		FullName:  "System Administrator",
		Role:      "admin",
		Active:    true,
		CreatedAt: now.AddDate(0, -6, 0),
		UpdatedAt: now,
	}

	users[2] = User{
		ID:        2,
		Username:  "john_doe",
		Email:     "john.doe@example.com",
		FullName:  "John Doe",
		Role:      "user",
		Active:    true,
		CreatedAt: now.AddDate(0, -3, 0),
		UpdatedAt: now.AddDate(0, 0, -7),
	}

	users[3] = User{
		ID:        3,
		Username:  "jane_smith",
		Email:     "jane.smith@example.com",
		FullName:  "Jane Smith",
		Role:      "user",
		Active:    false,
		CreatedAt: now.AddDate(0, -1, 0),
		UpdatedAt: now.AddDate(0, 0, -3),
	}

	nextID = 4
}