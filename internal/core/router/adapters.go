package router

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/julienschmidt/httprouter"
)

// ChiAdapter provides compatibility with go-chi router
type ChiAdapter struct {
	router chi.Router
}

// NewChiAdapter creates a new chi router adapter
func NewChiAdapter() *ChiAdapter {
	return &ChiAdapter{
		router: chi.NewRouter(),
	}
}

// Use adds middleware to the chi router
func (ca *ChiAdapter) Use(middleware ...Middleware) {
	for _, mw := range middleware {
		ca.router.Use(mw)
	}
}

// GET adds a GET route to chi router
func (ca *ChiAdapter) GET(path string, handler http.Handler, middleware ...Middleware) {
	ca.addRoute(http.MethodGet, path, handler, middleware...)
}

// POST adds a POST route to chi router
func (ca *ChiAdapter) POST(path string, handler http.Handler, middleware ...Middleware) {
	ca.addRoute(http.MethodPost, path, handler, middleware...)
}

// PUT adds a PUT route to chi router
func (ca *ChiAdapter) PUT(path string, handler http.Handler, middleware ...Middleware) {
	ca.addRoute(http.MethodPut, path, handler, middleware...)
}

// DELETE adds a DELETE route to chi router
func (ca *ChiAdapter) DELETE(path string, handler http.Handler, middleware ...Middleware) {
	ca.addRoute(http.MethodDelete, path, handler, middleware...)
}

// PATCH adds a PATCH route to chi router
func (ca *ChiAdapter) PATCH(path string, handler http.Handler, middleware ...Middleware) {
	ca.addRoute(http.MethodPatch, path, handler, middleware...)
}

// OPTIONS adds an OPTIONS route to chi router
func (ca *ChiAdapter) OPTIONS(path string, handler http.Handler, middleware ...Middleware) {
	ca.addRoute(http.MethodOptions, path, handler, middleware...)
}

// HEAD adds a HEAD route to chi router
func (ca *ChiAdapter) HEAD(path string, handler http.Handler, middleware ...Middleware) {
	ca.addRoute(http.MethodHead, path, handler, middleware...)
}

// Any adds a route that matches any HTTP method to chi router
func (ca *ChiAdapter) Any(path string, handler http.Handler, middleware ...Middleware) {
	methods := []string{
		http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete,
		http.MethodPatch, http.MethodOptions, http.MethodHead,
	}

	for _, method := range methods {
		ca.addRoute(method, path, handler, middleware...)
	}
}

// addRoute adds a route with middleware to chi router
func (ca *ChiAdapter) addRoute(method, path string, handler http.Handler, middleware ...Middleware) {
	// Convert path from our format to chi format
	chiPath := convertToChiPath(path)
	
	// Apply middleware
	for i := len(middleware) - 1; i >= 0; i-- {
		handler = middleware[i](handler)
	}

	// Add route parameter extraction middleware
	handler = chiParamMiddleware(handler)

	ca.router.Method(method, chiPath, handler)
}

// ServeHTTP implements http.Handler interface
func (ca *ChiAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ca.router.ServeHTTP(w, r)
}

// convertToChiPath converts our path format to chi format
func convertToChiPath(path string) string {
	// Convert :param to {param}
	result := strings.ReplaceAll(path, ":", "{")
	
	// Add closing braces for parameters
	parts := strings.Split(result, "/")
	for i, part := range parts {
		if strings.HasPrefix(part, "{") && !strings.HasSuffix(part, "}") {
			parts[i] = part + "}"
		}
		// Handle wildcards
		if strings.HasPrefix(part, "*") {
			parts[i] = "{" + part[1:] + ":*}"
		}
	}
	
	return strings.Join(parts, "/")
}

// chiParamMiddleware extracts chi route parameters and sets them in our context format
func chiParamMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract chi route context
		rctx := chi.RouteContext(r.Context())
		if rctx == nil {
			next.ServeHTTP(w, r)
			return
		}

		// Convert chi params to our format
		params := make(map[string]string)
		for i, key := range rctx.URLParams.Keys {
			if i < len(rctx.URLParams.Values) {
				params[key] = rctx.URLParams.Values[i]
			}
		}

		// Set params in our context format
		ctx := SetRouteParams(r.Context(), params)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

// HttpRouterAdapter provides compatibility with httprouter
type HttpRouterAdapter struct {
	router *httprouter.Router
	middleware []Middleware
}

// NewHttpRouterAdapter creates a new httprouter adapter
func NewHttpRouterAdapter() *HttpRouterAdapter {
	return &HttpRouterAdapter{
		router: httprouter.New(),
	}
}

// Use adds middleware to the httprouter adapter
func (hra *HttpRouterAdapter) Use(middleware ...Middleware) {
	hra.middleware = append(hra.middleware, middleware...)
}

// GET adds a GET route to httprouter
func (hra *HttpRouterAdapter) GET(path string, handler http.Handler, middleware ...Middleware) {
	hra.addRoute(http.MethodGet, path, handler, middleware...)
}

// POST adds a POST route to httprouter
func (hra *HttpRouterAdapter) POST(path string, handler http.Handler, middleware ...Middleware) {
	hra.addRoute(http.MethodPost, path, handler, middleware...)
}

// PUT adds a PUT route to httprouter
func (hra *HttpRouterAdapter) PUT(path string, handler http.Handler, middleware ...Middleware) {
	hra.addRoute(http.MethodPut, path, handler, middleware...)
}

// DELETE adds a DELETE route to httprouter
func (hra *HttpRouterAdapter) DELETE(path string, handler http.Handler, middleware ...Middleware) {
	hra.addRoute(http.MethodDelete, path, handler, middleware...)
}

// PATCH adds a PATCH route to httprouter
func (hra *HttpRouterAdapter) PATCH(path string, handler http.Handler, middleware ...Middleware) {
	hra.addRoute(http.MethodPatch, path, handler, middleware...)
}

// OPTIONS adds an OPTIONS route to httprouter
func (hra *HttpRouterAdapter) OPTIONS(path string, handler http.Handler, middleware ...Middleware) {
	hra.addRoute(http.MethodOptions, path, handler, middleware...)
}

// HEAD adds a HEAD route to httprouter
func (hra *HttpRouterAdapter) HEAD(path string, handler http.Handler, middleware ...Middleware) {
	hra.addRoute(http.MethodHead, path, handler, middleware...)
}

// Any adds a route that matches any HTTP method to httprouter
func (hra *HttpRouterAdapter) Any(path string, handler http.Handler, middleware ...Middleware) {
	methods := []string{
		http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete,
		http.MethodPatch, http.MethodOptions, http.MethodHead,
	}

	for _, method := range methods {
		hra.addRoute(method, path, handler, middleware...)
	}
}

// addRoute adds a route with middleware to httprouter
func (hra *HttpRouterAdapter) addRoute(method, path string, handler http.Handler, middleware ...Middleware) {
	// Convert path from our format to httprouter format
	httprouterPath := convertToHttpRouterPath(path)
	
	// Create httprouter handle
	handle := func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		// Convert httprouter params to our format
		params := make(map[string]string)
		for _, param := range ps {
			params[param.Key] = param.Value
		}

		// Set params in context
		ctx := SetRouteParams(r.Context(), params)
		r = r.WithContext(ctx)

		// Build middleware chain
		finalHandler := handler

		// Apply route-specific middleware (in reverse order)
		for i := len(middleware) - 1; i >= 0; i-- {
			finalHandler = middleware[i](finalHandler)
		}

		// Apply global middleware (in reverse order)
		for i := len(hra.middleware) - 1; i >= 0; i-- {
			finalHandler = hra.middleware[i](finalHandler)
		}

		finalHandler.ServeHTTP(w, r)
	}

	switch method {
	case http.MethodGet:
		hra.router.GET(httprouterPath, handle)
	case http.MethodPost:
		hra.router.POST(httprouterPath, handle)
	case http.MethodPut:
		hra.router.PUT(httprouterPath, handle)
	case http.MethodDelete:
		hra.router.DELETE(httprouterPath, handle)
	case http.MethodPatch:
		hra.router.PATCH(httprouterPath, handle)
	case http.MethodOptions:
		hra.router.OPTIONS(httprouterPath, handle)
	case http.MethodHead:
		hra.router.HEAD(httprouterPath, handle)
	}
}

// convertToHttpRouterPath converts our path format to httprouter format
func convertToHttpRouterPath(path string) string {
	// httprouter uses the same format as our trie router
	// Just handle wildcards differently
	if strings.Contains(path, "*") {
		// httprouter wildcards must be at the end and use *filepath format
		parts := strings.Split(path, "*")
		if len(parts) == 2 {
			return parts[0] + "*" + parts[1]
		}
	}
	return path
}

// ServeHTTP implements http.Handler interface
func (hra *HttpRouterAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hra.router.ServeHTTP(w, r)
}

// RouterInterface defines the common interface for all router adapters
type RouterInterface interface {
	Use(middleware ...Middleware)
	GET(path string, handler http.Handler, middleware ...Middleware)
	POST(path string, handler http.Handler, middleware ...Middleware)
	PUT(path string, handler http.Handler, middleware ...Middleware)
	DELETE(path string, handler http.Handler, middleware ...Middleware)
	PATCH(path string, handler http.Handler, middleware ...Middleware)
	OPTIONS(path string, handler http.Handler, middleware ...Middleware)
	HEAD(path string, handler http.Handler, middleware ...Middleware)
	Any(path string, handler http.Handler, middleware ...Middleware)
	http.Handler
}