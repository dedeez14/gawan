package router

import (
	"fmt"
	"net/http"
	"strings"
)

// RouterType represents the type of router to use
type RouterType string

const (
	// TrieRouter uses our custom trie-based implementation
	TrieRouter RouterType = "trie"
	// ChiRouter uses go-chi router
	ChiRouter RouterType = "chi"
	// HttpRouter uses httprouter
	HttpRouter RouterType = "httprouter"
)

// Config holds router configuration
type Config struct {
	// Type specifies which router implementation to use
	Type RouterType `json:"type" yaml:"type" env:"ROUTER_TYPE" default:"trie"`
	// StrictSlash enables strict slash handling
	StrictSlash bool `json:"strict_slash" yaml:"strict_slash" env:"ROUTER_STRICT_SLASH" default:"false"`
	// CaseSensitive enables case-sensitive routing
	CaseSensitive bool `json:"case_sensitive" yaml:"case_sensitive" env:"ROUTER_CASE_SENSITIVE" default:"true"`
	// HandleMethodNotAllowed enables method not allowed handling
	HandleMethodNotAllowed bool `json:"handle_method_not_allowed" yaml:"handle_method_not_allowed" env:"ROUTER_HANDLE_METHOD_NOT_ALLOWED" default:"true"`
	// HandleOPTIONS enables automatic OPTIONS handling
	HandleOPTIONS bool `json:"handle_options" yaml:"handle_options" env:"ROUTER_HANDLE_OPTIONS" default:"true"`
}

// DefaultConfig returns default router configuration
func DefaultConfig() Config {
	return Config{
		Type:                   TrieRouter,
		StrictSlash:            false,
		CaseSensitive:          true,
		HandleMethodNotAllowed: true,
		HandleOPTIONS:          true,
	}
}

// NewRouter creates a new router based on the configuration
func NewRouter(config Config) (RouterInterface, error) {
	switch strings.ToLower(string(config.Type)) {
	case "trie":
		return NewTrieRouter(), nil
	case "chi":
		return NewChiAdapter(), nil
	case "httprouter":
		return NewHttpRouterAdapter(), nil
	default:
		return nil, fmt.Errorf("unsupported router type: %s", config.Type)
	}
}

// MustNewRouter creates a new router and panics on error
func MustNewRouter(config Config) RouterInterface {
	router, err := NewRouter(config)
	if err != nil {
		panic(fmt.Sprintf("failed to create router: %v", err))
	}
	return router
}

// NewTrieRouterWithConfig creates a trie router with specific configuration
func NewTrieRouterWithConfig(config Config) *TrieRouter {
	router := NewTrieRouter()
	// Apply configuration specific to trie router
	// (Additional configuration can be added here)
	return router
}

// NewChiAdapterWithConfig creates a chi adapter with specific configuration
func NewChiAdapterWithConfig(config Config) *ChiAdapter {
	adapter := NewChiAdapter()
	// Apply configuration specific to chi router
	// (Additional configuration can be added here)
	return adapter
}

// NewHttpRouterAdapterWithConfig creates an httprouter adapter with specific configuration
func NewHttpRouterAdapterWithConfig(config Config) *HttpRouterAdapter {
	adapter := NewHttpRouterAdapter()
	// Apply configuration specific to httprouter
	// (Additional configuration can be added here)
	return adapter
}

// RouterGroup provides route grouping functionality
type RouterGroup struct {
	router     RouterInterface
	prefix     string
	middleware []Middleware
}

// NewRouterGroup creates a new router group
func NewRouterGroup(router RouterInterface, prefix string, middleware ...Middleware) *RouterGroup {
	return &RouterGroup{
		router:     router,
		prefix:     strings.TrimSuffix(prefix, "/"),
		middleware: middleware,
	}
}

// Group creates a sub-group with additional prefix and middleware
func (rg *RouterGroup) Group(prefix string, middleware ...Middleware) *RouterGroup {
	newPrefix := rg.prefix + "/" + strings.Trim(prefix, "/")
	newMiddleware := append(rg.middleware, middleware...)
	return NewRouterGroup(rg.router, newPrefix, newMiddleware...)
}

// Use adds middleware to the group
func (rg *RouterGroup) Use(middleware ...Middleware) {
	rg.middleware = append(rg.middleware, middleware...)
}

// GET adds a GET route to the group
func (rg *RouterGroup) GET(path string, handler http.Handler, middleware ...Middleware) {
	fullPath := rg.prefix + path
	allMiddleware := append(rg.middleware, middleware...)
	rg.router.GET(fullPath, handler, allMiddleware...)
}

// POST adds a POST route to the group
func (rg *RouterGroup) POST(path string, handler http.Handler, middleware ...Middleware) {
	fullPath := rg.prefix + path
	allMiddleware := append(rg.middleware, middleware...)
	rg.router.POST(fullPath, handler, allMiddleware...)
}

// PUT adds a PUT route to the group
func (rg *RouterGroup) PUT(path string, handler http.Handler, middleware ...Middleware) {
	fullPath := rg.prefix + path
	allMiddleware := append(rg.middleware, middleware...)
	rg.router.PUT(fullPath, handler, allMiddleware...)
}

// DELETE adds a DELETE route to the group
func (rg *RouterGroup) DELETE(path string, handler http.Handler, middleware ...Middleware) {
	fullPath := rg.prefix + path
	allMiddleware := append(rg.middleware, middleware...)
	rg.router.DELETE(fullPath, handler, allMiddleware...)
}

// PATCH adds a PATCH route to the group
func (rg *RouterGroup) PATCH(path string, handler http.Handler, middleware ...Middleware) {
	fullPath := rg.prefix + path
	allMiddleware := append(rg.middleware, middleware...)
	rg.router.PATCH(fullPath, handler, allMiddleware...)
}

// OPTIONS adds an OPTIONS route to the group
func (rg *RouterGroup) OPTIONS(path string, handler http.Handler, middleware ...Middleware) {
	fullPath := rg.prefix + path
	allMiddleware := append(rg.middleware, middleware...)
	rg.router.OPTIONS(fullPath, handler, allMiddleware...)
}

// HEAD adds a HEAD route to the group
func (rg *RouterGroup) HEAD(path string, handler http.Handler, middleware ...Middleware) {
	fullPath := rg.prefix + path
	allMiddleware := append(rg.middleware, middleware...)
	rg.router.HEAD(fullPath, handler, allMiddleware...)
}

// Any adds a route that matches any HTTP method to the group
func (rg *RouterGroup) Any(path string, handler http.Handler, middleware ...Middleware) {
	fullPath := rg.prefix + path
	allMiddleware := append(rg.middleware, middleware...)
	rg.router.Any(fullPath, handler, allMiddleware...)
}