package swagger

import (
	"time"
)

// DocumentAllEndpoints documents all API endpoints with comprehensive examples
func DocumentAllEndpoints(swaggerMW *SwaggerMiddleware) {
	// Authentication endpoints
	documentAuthEndpoints(swaggerMW)
	
	// User management endpoints
	documentUserEndpoints(swaggerMW)
	
	// Product management endpoints
	documentProductEndpoints(swaggerMW)
	
	// Order management endpoints
	documentOrderEndpoints(swaggerMW)
	
	// File management endpoints
	documentFileEndpoints(swaggerMW)
	
	// System endpoints
	documentSystemEndpoints(swaggerMW)
	
	// Notification endpoints
	documentNotificationEndpoints(swaggerMW)
	
	// Search endpoints
	documentSearchEndpoints(swaggerMW)
	
	// Bulk operation endpoints
	documentBulkEndpoints(swaggerMW)
}

// documentAuthEndpoints documents authentication-related endpoints
func documentAuthEndpoints(swaggerMW *SwaggerMiddleware) {
	// POST /auth/login - User login
	loginOp := CreateOperation(
		"User Login",
		"Authenticate user with username/email and password. Returns JWT token for subsequent API calls.",
		[]string{"Authentication"},
	)
	loginOp.AddRequestBody("Login credentials", true, &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"username": {Type: "string", Example: "john_doe", Description: "Username or email address"},
			"password": {Type: "string", Example: "securePassword123", Description: "User password"},
		},
		Required: []string{"username", "password"},
	})
	loginOp.AddResponse("200", "Login successful", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"success": {Type: "boolean", Example: true},
			"message": {Type: "string", Example: "Login successful"},
			"data": {
				Type: "object",
				Properties: map[string]Schema{
					"token": {Type: "string", Example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."},
					"expires_at": {Type: "string", Format: "date-time", Example: time.Now().Add(24 * time.Hour).Format(time.RFC3339)},
					"user": {
						Type: "object",
						Properties: map[string]Schema{
							"id": {Type: "integer", Example: 2},
							"username": {Type: "string", Example: "john_doe"},
							"email": {Type: "string", Example: "john.doe@example.com"},
							"full_name": {Type: "string", Example: "John Doe"},
							"role": {Type: "string", Example: "user"},
						},
					},
				},
			},
		},
	})
	loginOp.AddResponse("401", "Invalid credentials", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"success": {Type: "boolean", Example: false},
			"message": {Type: "string", Example: "Invalid username or password"},
			"error": {
				Type: "object",
				Properties: map[string]Schema{
					"code": {Type: "integer", Example: 401},
					"message": {Type: "string", Example: "Authentication failed"},
				},
			},
		},
	})
	swaggerMW.DocumentEndpoint("POST", "/auth/login", nil, func(op *Operation) {
		*op = *loginOp
	})
	
	// POST /auth/logout - User logout
	logoutOp := CreateOperation(
		"User Logout",
		"Logout user and invalidate JWT token. Requires valid authentication token.",
		[]string{"Authentication"},
	)
	logoutOp.AddSecurity("bearerAuth")
	logoutOp.AddResponse("200", "Logout successful", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"success": {Type: "boolean", Example: true},
			"message": {Type: "string", Example: "Logout successful"},
		},
	})
	logoutOp.AddResponse("401", "Unauthorized", nil)
	swaggerMW.DocumentEndpoint("POST", "/auth/logout", nil, func(op *Operation) {
		*op = *logoutOp
	})
	
	// POST /auth/refresh - Refresh JWT token
	refreshOp := CreateOperation(
		"Refresh Token",
		"Refresh JWT token to extend session. Requires valid authentication token.",
		[]string{"Authentication"},
	)
	refreshOp.AddSecurity("bearerAuth")
	refreshOp.AddResponse("200", "Token refreshed successfully", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"success": {Type: "boolean", Example: true},
			"message": {Type: "string", Example: "Token refreshed successfully"},
			"data": {
				Type: "object",
				Properties: map[string]Schema{
					"token": {Type: "string", Example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."},
					"expires_at": {Type: "string", Format: "date-time"},
				},
			},
		},
	})
	swaggerMW.DocumentEndpoint("POST", "/auth/refresh", nil, func(op *Operation) {
		*op = *refreshOp
	})
}

// documentUserEndpoints documents user management endpoints
func documentUserEndpoints(swaggerMW *SwaggerMiddleware) {
	// GET /users - List all users with pagination
	listUsersOp := CreateOperation(
		"List Users",
		"Retrieve a paginated list of users. Supports filtering and sorting.",
		[]string{"Users"},
	)
	listUsersOp.AddSecurity("bearerAuth")
	listUsersOp.AddParameter("page", "query", "Page number (1-based)", false, &Schema{Type: "integer", Example: 1, Minimum: 1})
	listUsersOp.AddParameter("page_size", "query", "Number of items per page", false, &Schema{Type: "integer", Example: 10, Minimum: 1, Maximum: 100})
	listUsersOp.AddParameter("role", "query", "Filter by user role", false, &Schema{Type: "string", Enum: []interface{}{"admin", "user", "guest"}})
	listUsersOp.AddParameter("active", "query", "Filter by active status", false, &Schema{Type: "boolean"})
	listUsersOp.AddParameter("sort_by", "query", "Sort field", false, &Schema{Type: "string", Enum: []interface{}{"id", "username", "email", "created_at"}})
	listUsersOp.AddParameter("sort_order", "query", "Sort order", false, &Schema{Type: "string", Enum: []interface{}{"asc", "desc"}})
	listUsersOp.AddResponse("200", "Users retrieved successfully", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"success": {Type: "boolean", Example: true},
			"message": {Type: "string", Example: "Users retrieved successfully"},
			"data": {
				Type: "array",
				Items: &Schema{
					Type: "object",
					Properties: map[string]Schema{
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
			"pagination": {
				Type: "object",
				Properties: map[string]Schema{
					"page": {Type: "integer", Example: 1},
					"page_size": {Type: "integer", Example: 10},
					"total_items": {Type: "integer", Example: 25},
					"total_pages": {Type: "integer", Example: 3},
				},
			},
		},
	})
	swaggerMW.DocumentEndpoint("GET", "/users", nil, func(op *Operation) {
		*op = *listUsersOp
	})
	
	// GET /users/{id} - Get user by ID
	getUserOp := CreateOperation(
		"Get User",
		"Retrieve a specific user by their ID. Returns detailed user information.",
		[]string{"Users"},
	)
	getUserOp.AddSecurity("bearerAuth")
	getUserOp.AddParameter("id", "path", "User ID", true, &Schema{Type: "integer", Example: 1})
	getUserOp.AddResponse("200", "User retrieved successfully", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"success": {Type: "boolean", Example: true},
			"message": {Type: "string", Example: "User retrieved successfully"},
			"data": {
				Type: "object",
				Properties: map[string]Schema{
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
	getUserOp.AddResponse("404", "User not found", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"success": {Type: "boolean", Example: false},
			"message": {Type: "string", Example: "User not found"},
			"error": {
				Type: "object",
				Properties: map[string]Schema{
					"code": {Type: "integer", Example: 404},
					"message": {Type: "string", Example: "User with ID 1 not found"},
				},
			},
		},
	})
	swaggerMW.DocumentEndpoint("GET", "/users/{id}", nil, func(op *Operation) {
		*op = *getUserOp
	})
	
	// POST /users - Create new user
	createUserOp := CreateOperation(
		"Create User",
		"Create a new user account. Requires admin privileges.",
		[]string{"Users"},
	)
	createUserOp.AddSecurity("bearerAuth")
	createUserOp.AddRequestBody("User data", true, &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"username": {Type: "string", Example: "new_user", Description: "Unique username (3-50 characters)"},
			"email": {Type: "string", Example: "new.user@example.com", Description: "Valid email address"},
			"full_name": {Type: "string", Example: "New User", Description: "Full name of the user"},
			"password": {Type: "string", Example: "securePassword123", Description: "Password (minimum 8 characters)"},
			"role": {Type: "string", Example: "user", Enum: []interface{}{"admin", "user", "guest"}},
		},
		Required: []string{"username", "email", "full_name", "password", "role"},
	})
	createUserOp.AddResponse("201", "User created successfully", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"success": {Type: "boolean", Example: true},
			"message": {Type: "string", Example: "User created successfully"},
			"data": {
				Type: "object",
				Properties: map[string]Schema{
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
	createUserOp.AddResponse("409", "Username or email already exists", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"success": {Type: "boolean", Example: false},
			"message": {Type: "string", Example: "Username or email already exists"},
			"error": {
				Type: "object",
				Properties: map[string]Schema{
					"code": {Type: "integer", Example: 409},
					"message": {Type: "string", Example: "Conflict: Username 'new_user' already exists"},
				},
			},
		},
	})
	swaggerMW.DocumentEndpoint("POST", "/users", nil, func(op *Operation) {
		*op = *createUserOp
	})
	
	// PUT /users/{id} - Update user
	updateUserOp := CreateOperation(
		"Update User",
		"Update an existing user. Users can update their own profile, admins can update any user.",
		[]string{"Users"},
	)
	updateUserOp.AddSecurity("bearerAuth")
	updateUserOp.AddParameter("id", "path", "User ID", true, &Schema{Type: "integer", Example: 1})
	updateUserOp.AddRequestBody("Updated user data", true, &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"username": {Type: "string", Example: "updated_username", Description: "New username (optional)"},
			"email": {Type: "string", Example: "updated.email@example.com", Description: "New email address (optional)"},
			"full_name": {Type: "string", Example: "Updated Name", Description: "New full name (optional)"},
			"role": {Type: "string", Example: "admin", Enum: []interface{}{"admin", "user", "guest"}, Description: "New role (admin only)"},
			"active": {Type: "boolean", Example: false, Description: "New active status (admin only)"},
		},
	})
	updateUserOp.AddResponse("200", "User updated successfully", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"success": {Type: "boolean", Example: true},
			"message": {Type: "string", Example: "User updated successfully"},
			"data": {
				Type: "object",
				Properties: map[string]Schema{
					"id": {Type: "integer", Example: 1},
					"username": {Type: "string", Example: "updated_username"},
					"email": {Type: "string", Example: "updated.email@example.com"},
					"full_name": {Type: "string", Example: "Updated Name"},
					"role": {Type: "string", Example: "admin"},
					"active": {Type: "boolean", Example: false},
					"updated_at": {Type: "string", Format: "date-time"},
				},
			},
		},
	})
	swaggerMW.DocumentEndpoint("PUT", "/users/{id}", nil, func(op *Operation) {
		*op = *updateUserOp
	})
	
	// DELETE /users/{id} - Delete user
	deleteUserOp := CreateOperation(
		"Delete User",
		"Delete a user account. Requires admin privileges. This action is irreversible.",
		[]string{"Users"},
	)
	deleteUserOp.AddSecurity("bearerAuth")
	deleteUserOp.AddParameter("id", "path", "User ID", true, &Schema{Type: "integer", Example: 1})
	deleteUserOp.AddResponse("200", "User deleted successfully", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"success": {Type: "boolean", Example: true},
			"message": {Type: "string", Example: "User deleted successfully"},
		},
	})
	deleteUserOp.AddResponse("403", "Insufficient permissions", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"success": {Type: "boolean", Example: false},
			"message": {Type: "string", Example: "Insufficient permissions"},
			"error": {
				Type: "object",
				Properties: map[string]Schema{
					"code": {Type: "integer", Example: 403},
					"message": {Type: "string", Example: "Admin privileges required"},
				},
			},
		},
	})
	swaggerMW.DocumentEndpoint("DELETE", "/users/{id}", nil, func(op *Operation) {
		*op = *deleteUserOp
	})
}

// documentProductEndpoints documents product management endpoints
func documentProductEndpoints(swaggerMW *SwaggerMiddleware) {
	// GET /products - List all products
	listProductsOp := CreateOperation(
		"List Products",
		"Retrieve a paginated list of products with filtering and sorting options.",
		[]string{"Products"},
	)
	listProductsOp.AddParameter("page", "query", "Page number", false, &Schema{Type: "integer", Example: 1})
	listProductsOp.AddParameter("page_size", "query", "Items per page", false, &Schema{Type: "integer", Example: 10})
	listProductsOp.AddParameter("category", "query", "Filter by category", false, &Schema{Type: "string", Example: "Electronics"})
	listProductsOp.AddParameter("min_price", "query", "Minimum price filter", false, &Schema{Type: "number", Example: 10.0})
	listProductsOp.AddParameter("max_price", "query", "Maximum price filter", false, &Schema{Type: "number", Example: 1000.0})
	listProductsOp.AddParameter("active", "query", "Filter by active status", false, &Schema{Type: "boolean"})
	listProductsOp.AddResponse("200", "Products retrieved successfully", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"success": {Type: "boolean", Example: true},
			"data": {
				Type: "array",
				Items: &Schema{
					Type: "object",
					Properties: map[string]Schema{
						"id": {Type: "integer", Example: 1},
						"name": {Type: "string", Example: "Laptop Computer"},
						"description": {Type: "string", Example: "High-performance laptop"},
						"price": {Type: "number", Example: 1299.99},
						"stock": {Type: "integer", Example: 25},
						"category": {Type: "string", Example: "Electronics"},
						"active": {Type: "boolean", Example: true},
					},
				},
			},
			"pagination": {
				Type: "object",
				Properties: map[string]Schema{
					"page": {Type: "integer", Example: 1},
					"total_pages": {Type: "integer", Example: 5},
					"total_items": {Type: "integer", Example: 50},
				},
			},
		},
	})
	swaggerMW.DocumentEndpoint("GET", "/products", nil, func(op *Operation) {
		*op = *listProductsOp
	})
	
	// POST /products - Create new product
	createProductOp := CreateOperation(
		"Create Product",
		"Create a new product. Requires admin privileges.",
		[]string{"Products"},
	)
	createProductOp.AddSecurity("bearerAuth")
	createProductOp.AddRequestBody("Product data", true, &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"name": {Type: "string", Example: "New Product"},
			"description": {Type: "string", Example: "Product description"},
			"price": {Type: "number", Example: 99.99},
			"stock": {Type: "integer", Example: 100},
			"category": {Type: "string", Example: "Electronics"},
		},
		Required: []string{"name", "price", "category"},
	})
	createProductOp.AddResponse("201", "Product created successfully", nil)
	swaggerMW.DocumentEndpoint("POST", "/products", nil, func(op *Operation) {
		*op = *createProductOp
	})
}

// documentOrderEndpoints documents order management endpoints
func documentOrderEndpoints(swaggerMW *SwaggerMiddleware) {
	// GET /orders - List orders
	listOrdersOp := CreateOperation(
		"List Orders",
		"Retrieve orders. Users see their own orders, admins see all orders.",
		[]string{"Orders"},
	)
	listOrdersOp.AddSecurity("bearerAuth")
	listOrdersOp.AddParameter("status", "query", "Filter by order status", false, &Schema{
		Type: "string",
		Enum: []interface{}{"pending", "processing", "shipped", "delivered", "cancelled"},
	})
	listOrdersOp.AddResponse("200", "Orders retrieved successfully", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"success": {Type: "boolean", Example: true},
			"data": {
				Type: "array",
				Items: &Schema{
					Type: "object",
					Properties: map[string]Schema{
						"id": {Type: "integer", Example: 1},
						"user_id": {Type: "integer", Example: 2},
						"total": {Type: "number", Example: 1359.97},
						"status": {Type: "string", Example: "delivered"},
						"items": {
							Type: "array",
							Items: &Schema{
								Type: "object",
								Properties: map[string]Schema{
									"product_id": {Type: "integer", Example: 1},
									"quantity": {Type: "integer", Example: 1},
									"price": {Type: "number", Example: 1299.99},
									"subtotal": {Type: "number", Example: 1299.99},
								},
							},
						},
						"created_at": {Type: "string", Format: "date-time"},
					},
				},
			},
		},
	})
	swaggerMW.DocumentEndpoint("GET", "/orders", nil, func(op *Operation) {
		*op = *listOrdersOp
	})
	
	// POST /orders - Create new order
	createOrderOp := CreateOperation(
		"Create Order",
		"Create a new order with specified products and quantities.",
		[]string{"Orders"},
	)
	createOrderOp.AddSecurity("bearerAuth")
	createOrderOp.AddRequestBody("Order data", true, &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"items": {
				Type: "array",
				Items: &Schema{
					Type: "object",
					Properties: map[string]Schema{
						"product_id": {Type: "integer", Example: 1},
						"quantity": {Type: "integer", Example: 2},
					},
					Required: []string{"product_id", "quantity"},
				},
			},
		},
		Required: []string{"items"},
	})
	createOrderOp.AddResponse("201", "Order created successfully", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"success": {Type: "boolean", Example: true},
			"message": {Type: "string", Example: "Order created successfully"},
			"data": {
				Type: "object",
				Properties: map[string]Schema{
					"id": {Type: "integer", Example: 3},
					"total": {Type: "number", Example: 2599.98},
					"status": {Type: "string", Example: "pending"},
					"created_at": {Type: "string", Format: "date-time"},
				},
			},
		},
	})
	swaggerMW.DocumentEndpoint("POST", "/orders", nil, func(op *Operation) {
		*op = *createOrderOp
	})
}

// documentFileEndpoints documents file management endpoints
func documentFileEndpoints(swaggerMW *SwaggerMiddleware) {
	// POST /files/upload - Upload file
	uploadOp := CreateOperation(
		"Upload File",
		"Upload a file to the server. Supports various file types with size limits.",
		[]string{"Files"},
	)
	uploadOp.AddSecurity("bearerAuth")
	uploadOp.AddRequestBody("File upload", true, &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"file": {Type: "string", Format: "binary", Description: "File to upload"},
			"description": {Type: "string", Example: "Profile picture", Description: "Optional file description"},
		},
		Required: []string{"file"},
	})
	uploadOp.AddResponse("200", "File uploaded successfully", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"success": {Type: "boolean", Example: true},
			"data": {
				Type: "object",
				Properties: map[string]Schema{
					"file_id": {Type: "string", Example: "f47ac10b-58cc-4372-a567-0e02b2c3d479"},
					"filename": {Type: "string", Example: "profile.jpg"},
					"size": {Type: "integer", Example: 1024000},
					"content_type": {Type: "string", Example: "image/jpeg"},
					"url": {Type: "string", Example: "/files/f47ac10b-58cc-4372-a567-0e02b2c3d479"},
					"uploaded_at": {Type: "string", Format: "date-time"},
				},
			},
		},
	})
	swaggerMW.DocumentEndpoint("POST", "/files/upload", nil, func(op *Operation) {
		*op = *uploadOp
	})
}

// documentSystemEndpoints documents system-related endpoints
func documentSystemEndpoints(swaggerMW *SwaggerMiddleware) {
	// Already documented in AddCommonEndpoints, but we can add more detailed examples here
	
	// GET /health - Enhanced health check
	healthOp := CreateOperation(
		"Health Check",
		"Comprehensive health check including database, cache, and external service status.",
		[]string{"System"},
	)
	healthOp.AddResponse("200", "System is healthy", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"status": {Type: "string", Example: "healthy", Enum: []interface{}{"healthy", "unhealthy", "degraded"}},
			"timestamp": {Type: "string", Format: "date-time", Example: time.Now().Format(time.RFC3339)},
			"version": {Type: "string", Example: "1.0.0"},
			"uptime": {Type: "string", Example: "2h30m15s"},
			"services": {
				Type: "object",
				Properties: map[string]Schema{
					"database": {Type: "string", Example: "healthy"},
					"cache": {Type: "string", Example: "healthy"},
					"external_api": {Type: "string", Example: "degraded"},
				},
			},
		},
		Required: []string{"status", "timestamp"},
	})
	swaggerMW.DocumentEndpoint("GET", "/health", nil, func(op *Operation) {
		*op = *healthOp
	})
}

// documentNotificationEndpoints documents notification endpoints
func documentNotificationEndpoints(swaggerMW *SwaggerMiddleware) {
	// POST /notifications - Send notification
	sendNotificationOp := CreateOperation(
		"Send Notification",
		"Send notifications to one or more users. Supports immediate and scheduled delivery.",
		[]string{"Notifications"},
	)
	sendNotificationOp.AddSecurity("bearerAuth")
	sendNotificationOp.AddRequestBody("Notification data", true, &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"recipients": {
				Type: "array",
				Items: &Schema{Type: "string"},
				Example: []interface{}{"user1", "user2"},
				Description: "List of recipient user IDs",
			},
			"title": {Type: "string", Example: "New Order Received"},
			"message": {Type: "string", Example: "You have received a new order #12345"},
			"type": {Type: "string", Example: "info", Enum: []interface{}{"info", "warning", "error", "success"}},
			"data": {
				Type: "object",
				Example: map[string]interface{}{"order_id": 12345, "amount": 99.99},
				Description: "Additional notification data",
			},
			"schedule_at": {Type: "string", Format: "date-time", Description: "Schedule for later delivery (optional)"},
		},
		Required: []string{"recipients", "title", "message", "type"},
	})
	sendNotificationOp.AddResponse("200", "Notification sent successfully", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"success": {Type: "boolean", Example: true},
			"data": {
				Type: "object",
				Properties: map[string]Schema{
					"notification_id": {Type: "string", Example: "notif_123456789"},
					"status": {Type: "string", Example: "sent"},
					"recipient_count": {Type: "integer", Example: 2},
					"sent_at": {Type: "string", Format: "date-time"},
				},
			},
		},
	})
	swaggerMW.DocumentEndpoint("POST", "/notifications", nil, func(op *Operation) {
		*op = *sendNotificationOp
	})
}

// documentSearchEndpoints documents search endpoints
func documentSearchEndpoints(swaggerMW *SwaggerMiddleware) {
	// GET /search - Global search
	searchOp := CreateOperation(
		"Global Search",
		"Search across products, users, and orders with advanced filtering options.",
		[]string{"Search"},
	)
	searchOp.AddParameter("q", "query", "Search query", true, &Schema{Type: "string", Example: "laptop"})
	searchOp.AddParameter("type", "query", "Search type", false, &Schema{
		Type: "string",
		Enum: []interface{}{"products", "users", "orders", "all"},
		Example: "products",
	})
	searchOp.AddParameter("page", "query", "Page number", false, &Schema{Type: "integer", Example: 1})
	searchOp.AddParameter("page_size", "query", "Items per page", false, &Schema{Type: "integer", Example: 10})
	searchOp.AddResponse("200", "Search results", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"success": {Type: "boolean", Example: true},
			"data": {
				Type: "object",
				Properties: map[string]Schema{
					"query": {Type: "string", Example: "laptop"},
					"total_results": {Type: "integer", Example: 15},
					"results": {
						Type: "array",
						Items: &Schema{
							Type: "object",
							Properties: map[string]Schema{
								"type": {Type: "string", Example: "product"},
								"id": {Type: "integer", Example: 1},
								"title": {Type: "string", Example: "Laptop Computer"},
								"description": {Type: "string", Example: "High-performance laptop"},
								"relevance_score": {Type: "number", Example: 0.95},
							},
						},
					},
				},
			},
			"pagination": {
				Type: "object",
				Properties: map[string]Schema{
					"page": {Type: "integer", Example: 1},
					"total_pages": {Type: "integer", Example: 2},
				},
			},
		},
	})
	swaggerMW.DocumentEndpoint("GET", "/search", nil, func(op *Operation) {
		*op = *searchOp
	})
}

// documentBulkEndpoints documents bulk operation endpoints
func documentBulkEndpoints(swaggerMW *SwaggerMiddleware) {
	// POST /bulk/users - Bulk user operations
	bulkUsersOp := CreateOperation(
		"Bulk User Operations",
		"Perform bulk operations on multiple users (create, update, delete). Requires admin privileges.",
		[]string{"Users", "Bulk Operations"},
	)
	bulkUsersOp.AddSecurity("bearerAuth")
	bulkUsersOp.AddRequestBody("Bulk operation data", true, &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"operation": {Type: "string", Example: "create", Enum: []interface{}{"create", "update", "delete"}},
			"items": {
				Type: "array",
				Items: &Schema{
					Type: "object",
					Description: "User data (structure depends on operation type)",
				},
				Example: []interface{}{
					map[string]interface{}{
						"username": "bulk_user1",
						"email": "bulk1@example.com",
						"full_name": "Bulk User 1",
						"password": "password123",
						"role": "user",
					},
					map[string]interface{}{
						"username": "bulk_user2",
						"email": "bulk2@example.com",
						"full_name": "Bulk User 2",
						"password": "password123",
						"role": "user",
					},
				},
			},
		},
		Required: []string{"operation", "items"},
	})
	bulkUsersOp.AddResponse("200", "Bulk operation completed", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"success": {Type: "boolean", Example: true},
			"data": {
				Type: "object",
				Properties: map[string]Schema{
					"total_items": {Type: "integer", Example: 2},
					"success_count": {Type: "integer", Example: 2},
					"failure_count": {Type: "integer", Example: 0},
					"results": {
						Type: "array",
						Items: &Schema{
							Type: "object",
							Properties: map[string]Schema{
								"index": {Type: "integer", Example: 0},
								"success": {Type: "boolean", Example: true},
								"data": {
									Type: "object",
									Description: "Created/updated user data",
								},
							},
						},
					},
					"errors": {
						Type: "array",
						Items: &Schema{
							Type: "object",
							Properties: map[string]Schema{
								"index": {Type: "integer"},
								"code": {Type: "string"},
								"message": {Type: "string"},
							},
						},
						Description: "Errors that occurred during processing",
					},
				},
			},
		},
	})
	swaggerMW.DocumentEndpoint("POST", "/bulk/users", nil, func(op *Operation) {
		*op = *bulkUsersOp
	})
}