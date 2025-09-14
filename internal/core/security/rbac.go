package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Permission represents a permission in the RBAC system
type Permission struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
}

// Role represents a role in the RBAC system
type Role struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions"`
}

// User represents a user in the RBAC system
type User struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Roles    []Role   `json:"roles"`
	Active   bool     `json:"active"`
}

// HasPermission checks if the user has a specific permission
func (u *User) HasPermission(resource, action string) bool {
	if !u.Active {
		return false
	}

	for _, role := range u.Roles {
		for _, permission := range role.Permissions {
			if (permission.Resource == "*" || permission.Resource == resource) &&
				(permission.Action == "*" || permission.Action == action) {
				return true
			}
		}
	}
	return false
}

// HasRole checks if the user has a specific role
func (u *User) HasRole(roleName string) bool {
	if !u.Active {
		return false
	}

	for _, role := range u.Roles {
		if role.Name == roleName {
			return true
		}
	}
	return false
}

// HasAnyRole checks if the user has any of the specified roles
func (u *User) HasAnyRole(roleNames ...string) bool {
	if !u.Active {
		return false
	}

	for _, roleName := range roleNames {
		if u.HasRole(roleName) {
			return true
		}
	}
	return false
}

// HasAllRoles checks if the user has all of the specified roles
func (u *User) HasAllRoles(roleNames ...string) bool {
	if !u.Active {
		return false
	}

	for _, roleName := range roleNames {
		if !u.HasRole(roleName) {
			return false
		}
	}
	return true
}

// GetPermissions returns all permissions for the user
func (u *User) GetPermissions() []Permission {
	if !u.Active {
		return nil
	}

	permissionMap := make(map[string]Permission)
	for _, role := range u.Roles {
		for _, permission := range role.Permissions {
			permissionMap[permission.ID] = permission
		}
	}

	permissions := make([]Permission, 0, len(permissionMap))
	for _, permission := range permissionMap {
		permissions = append(permissions, permission)
	}
	return permissions
}

// UserProvider defines the interface for user retrieval
type UserProvider interface {
	GetUser(ctx context.Context, userID string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
}

// MemoryUserProvider is an in-memory implementation of UserProvider
type MemoryUserProvider struct {
	users map[string]*User
}

// NewMemoryUserProvider creates a new memory user provider
func NewMemoryUserProvider() *MemoryUserProvider {
	return &MemoryUserProvider{
		users: make(map[string]*User),
	}
}

// AddUser adds a user to the memory provider
func (mup *MemoryUserProvider) AddUser(user *User) {
	mup.users[user.ID] = user
}

// GetUser retrieves a user by ID
func (mup *MemoryUserProvider) GetUser(ctx context.Context, userID string) (*User, error) {
	user, exists := mup.users[userID]
	if !exists {
		return nil, fmt.Errorf("user not found: %s", userID)
	}
	return user, nil
}

// GetUserByUsername retrieves a user by username
func (mup *MemoryUserProvider) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	for _, user := range mup.users {
		if user.Username == username {
			return user, nil
		}
	}
	return nil, fmt.Errorf("user not found: %s", username)
}

// GetUserByEmail retrieves a user by email
func (mup *MemoryUserProvider) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	for _, user := range mup.users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, fmt.Errorf("user not found: %s", email)
}

// RBACConfig holds RBAC configuration
type RBACConfig struct {
	// Enabled enables RBAC middleware
	Enabled bool `json:"enabled" yaml:"enabled" env:"RBAC_ENABLED" default:"true"`
	// UserProvider provides user information
	UserProvider UserProvider `json:"-" yaml:"-"`
	// SkipFunc determines if RBAC should be skipped
	SkipFunc SkipFunc `json:"-" yaml:"-"`
	// ErrorHandler handles RBAC errors
	ErrorHandler RBACErrorHandler `json:"-" yaml:"-"`
	// UnauthorizedHandler handles unauthorized access
	UnauthorizedHandler http.Handler `json:"-" yaml:"-"`
	// ForbiddenHandler handles forbidden access
	ForbiddenHandler http.Handler `json:"-" yaml:"-"`
}

// RBACErrorHandler handles RBAC errors
type RBACErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// DefaultRBACConfig returns default RBAC configuration
func DefaultRBACConfig() RBACConfig {
	return RBACConfig{
		Enabled:      true,
		UserProvider: NewMemoryUserProvider(),
		ErrorHandler: DefaultRBACErrorHandler,
	}
}

// DefaultRBACErrorHandler is the default RBAC error handler
func DefaultRBACErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":   "forbidden",
		"message": err.Error(),
	})
}

// Context keys for RBAC
const (
	RBACUserKey contextKey = "rbac_user"
)

// RBACMiddleware creates an RBAC middleware that loads user information
func RBACMiddleware(config RBACConfig) func(http.Handler) http.Handler {
	if !config.Enabled {
		return func(next http.Handler) http.Handler {
			return next // Pass through if disabled
		}
	}

	if config.ErrorHandler == nil {
		config.ErrorHandler = DefaultRBACErrorHandler
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip RBAC if skip function returns true
			if config.SkipFunc != nil && config.SkipFunc(r) {
				next.ServeHTTP(w, r)
				return
			}

			// Get user ID from JWT claims
			userID, ok := GetJWTUser(r)
			if !ok {
				if config.UnauthorizedHandler != nil {
					config.UnauthorizedHandler.ServeHTTP(w, r)
				} else {
					config.ErrorHandler(w, r, fmt.Errorf("user not authenticated"))
				}
				return
			}

			// Load user information
			user, err := config.UserProvider.GetUser(r.Context(), userID)
			if err != nil {
				config.ErrorHandler(w, r, fmt.Errorf("failed to load user: %w", err))
				return
			}

			// Add user to context
			ctx := context.WithValue(r.Context(), RBACUserKey, user)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// GetRBACUser extracts RBAC user from request context
func GetRBACUser(r *http.Request) (*User, bool) {
	user, ok := r.Context().Value(RBACUserKey).(*User)
	return user, ok
}

// RequirePermission creates middleware that requires specific permission
func RequirePermission(resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := GetRBACUser(r)
			if !ok {
				http.Error(w, "User not found in context", http.StatusUnauthorized)
				return
			}

			if !user.HasPermission(resource, action) {
				http.Error(w, fmt.Sprintf("Permission denied: %s:%s", resource, action), http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole creates middleware that requires specific role
func RequireRole(roleName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := GetRBACUser(r)
			if !ok {
				http.Error(w, "User not found in context", http.StatusUnauthorized)
				return
			}

			if !user.HasRole(roleName) {
				http.Error(w, fmt.Sprintf("Role required: %s", roleName), http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyRole creates middleware that requires any of the specified roles
func RequireAnyRole(roleNames ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := GetRBACUser(r)
			if !ok {
				http.Error(w, "User not found in context", http.StatusUnauthorized)
				return
			}

			if !user.HasAnyRole(roleNames...) {
				http.Error(w, fmt.Sprintf("One of these roles required: %s", strings.Join(roleNames, ", ")), http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAllRoles creates middleware that requires all of the specified roles
func RequireAllRoles(roleNames ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := GetRBACUser(r)
			if !ok {
				http.Error(w, "User not found in context", http.StatusUnauthorized)
				return
			}

			if !user.HasAllRoles(roleNames...) {
				http.Error(w, fmt.Sprintf("All of these roles required: %s", strings.Join(roleNames, ", ")), http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// PermissionChecker is a function that checks permissions dynamically
type PermissionChecker func(user *User, r *http.Request) bool

// RequireCustomPermission creates middleware with custom permission logic
func RequireCustomPermission(checker PermissionChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := GetRBACUser(r)
			if !ok {
				http.Error(w, "User not found in context", http.StatusUnauthorized)
				return
			}

			if !checker(user, r) {
				http.Error(w, "Permission denied", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ResourceOwnershipChecker checks if user owns a resource
type ResourceOwnershipChecker func(user *User, r *http.Request) (bool, error)

// RequireResourceOwnership creates middleware that checks resource ownership
func RequireResourceOwnership(checker ResourceOwnershipChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := GetRBACUser(r)
			if !ok {
				http.Error(w, "User not found in context", http.StatusUnauthorized)
				return
			}

			owns, err := checker(user, r)
			if err != nil {
				http.Error(w, fmt.Sprintf("Error checking ownership: %v", err), http.StatusInternalServerError)
				return
			}

			if !owns {
				http.Error(w, "Access denied: resource ownership required", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CreateDefaultRoles creates a set of default roles
func CreateDefaultRoles() []Role {
	return []Role{
		{
			ID:          "admin",
			Name:        "Administrator",
			Description: "Full system access",
			Permissions: []Permission{
				{ID: "admin_all", Name: "Admin All", Resource: "*", Action: "*"},
			},
		},
		{
			ID:          "user",
			Name:        "User",
			Description: "Basic user access",
			Permissions: []Permission{
				{ID: "user_read", Name: "User Read", Resource: "user", Action: "read"},
				{ID: "user_update", Name: "User Update", Resource: "user", Action: "update"},
			},
		},
		{
			ID:          "moderator",
			Name:        "Moderator",
			Description: "Content moderation access",
			Permissions: []Permission{
				{ID: "content_read", Name: "Content Read", Resource: "content", Action: "read"},
				{ID: "content_update", Name: "Content Update", Resource: "content", Action: "update"},
				{ID: "content_delete", Name: "Content Delete", Resource: "content", Action: "delete"},
				{ID: "user_read", Name: "User Read", Resource: "user", Action: "read"},
			},
		},
	}
}