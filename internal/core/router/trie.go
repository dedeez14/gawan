package router

import (
	"net/http"
	"strings"
)

// TrieNode represents a node in the trie structure
type TrieNode struct {
	// children maps static path segments to child nodes
	children map[string]*TrieNode
	// paramChild holds the parameter child node (e.g., :id)
	paramChild *TrieNode
	// paramName is the name of the parameter (without the colon)
	paramName string
	// wildcardChild holds the wildcard child node (e.g., *filepath)
	wildcardChild *TrieNode
	// wildcardName is the name of the wildcard parameter
	wildcardName string
	// handlers maps HTTP methods to their handlers
	handlers map[string]http.Handler
	// middleware stores middleware for this specific route
	middleware []Middleware
	// isEnd indicates if this node represents a complete route
	isEnd bool
}

// NewTrieNode creates a new trie node
func NewTrieNode() *TrieNode {
	return &TrieNode{
		children: make(map[string]*TrieNode),
		handlers: make(map[string]http.Handler),
	}
}

// TrieRouter implements a trie-based router for parametric routes
type TrieRouter struct {
	root       *TrieNode
	middleware []Middleware
	notFound   http.Handler
}

// NewTrieRouter creates a new trie-based router
func NewTrieRouter() *TrieRouter {
	return &TrieRouter{
		root:     NewTrieNode(),
		notFound: http.NotFoundHandler(),
	}
}

// RouteMatch represents a matched route with parameters
type RouteMatch struct {
	Handler    http.Handler
	Params     map[string]string
	Middleware []Middleware
}

// Insert adds a route to the trie
func (tr *TrieRouter) Insert(method, path string, handler http.Handler, middleware ...Middleware) {
	if path == "" || path[0] != '/' {
		path = "/" + path
	}

	// Clean and split the path
	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) == 1 && segments[0] == "" {
		segments = []string{} // Root path
	}

	current := tr.root

	for _, segment := range segments {
		if segment == "" {
			continue
		}

		if strings.HasPrefix(segment, ":") {
			// Parameter segment
			paramName := segment[1:]
			if current.paramChild == nil {
				current.paramChild = NewTrieNode()
				current.paramName = paramName
			}
			current = current.paramChild
		} else if strings.HasPrefix(segment, "*") {
			// Wildcard segment
			wildcardName := segment[1:]
			if current.wildcardChild == nil {
				current.wildcardChild = NewTrieNode()
				current.wildcardName = wildcardName
			}
			current = current.wildcardChild
			break // Wildcard must be the last segment
		} else {
			// Static segment
			if current.children[segment] == nil {
				current.children[segment] = NewTrieNode()
			}
			current = current.children[segment]
		}
	}

	// Set handler and middleware for the final node
	current.handlers[method] = handler
	current.middleware = middleware
	current.isEnd = true
}

// Search finds a route match for the given method and path
func (tr *TrieRouter) Search(method, path string) *RouteMatch {
	if path == "" || path[0] != '/' {
		path = "/" + path
	}

	// Clean and split the path
	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) == 1 && segments[0] == "" {
		segments = []string{} // Root path
	}

	params := make(map[string]string)
	node := tr.searchNode(tr.root, segments, 0, params)

	if node == nil || !node.isEnd {
		return nil
	}

	handler := node.handlers[method]
	if handler == nil {
		return nil
	}

	return &RouteMatch{
		Handler:    handler,
		Params:     params,
		Middleware: node.middleware,
	}
}

// searchNode recursively searches for a matching node
func (tr *TrieRouter) searchNode(node *TrieNode, segments []string, index int, params map[string]string) *TrieNode {
	// If we've processed all segments, return current node
	if index >= len(segments) {
		return node
	}

	segment := segments[index]

	// Try static match first
	if child := node.children[segment]; child != nil {
		if result := tr.searchNode(child, segments, index+1, params); result != nil {
			return result
		}
	}

	// Try parameter match
	if node.paramChild != nil {
		params[node.paramName] = segment
		if result := tr.searchNode(node.paramChild, segments, index+1, params); result != nil {
			return result
		}
		delete(params, node.paramName) // Backtrack
	}

	// Try wildcard match (captures remaining path)
	if node.wildcardChild != nil {
		remainingPath := strings.Join(segments[index:], "/")
		params[node.wildcardName] = remainingPath
		return node.wildcardChild
	}

	return nil
}

// Use adds middleware to the router
func (tr *TrieRouter) Use(middleware ...Middleware) {
	tr.middleware = append(tr.middleware, middleware...)
}

// SetNotFound sets the not found handler
func (tr *TrieRouter) SetNotFound(handler http.Handler) {
	tr.notFound = handler
}

// ServeHTTP implements http.Handler interface
func (tr *TrieRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	match := tr.Search(r.Method, r.URL.Path)
	if match == nil {
		tr.notFound.ServeHTTP(w, r)
		return
	}

	// Set route parameters in context
	ctx := SetRouteParams(r.Context(), match.Params)
	r = r.WithContext(ctx)

	// Build middleware chain
	handler := match.Handler

	// Apply route-specific middleware (in reverse order)
	for i := len(match.Middleware) - 1; i >= 0; i-- {
		handler = match.Middleware[i](handler)
	}

	// Apply global middleware (in reverse order)
	for i := len(tr.middleware) - 1; i >= 0; i-- {
		handler = tr.middleware[i](handler)
	}

	handler.ServeHTTP(w, r)
}

// GET adds a GET route
func (tr *TrieRouter) GET(path string, handler http.Handler, middleware ...Middleware) {
	tr.Insert(http.MethodGet, path, handler, middleware...)
}

// POST adds a POST route
func (tr *TrieRouter) POST(path string, handler http.Handler, middleware ...Middleware) {
	tr.Insert(http.MethodPost, path, handler, middleware...)
}

// PUT adds a PUT route
func (tr *TrieRouter) PUT(path string, handler http.Handler, middleware ...Middleware) {
	tr.Insert(http.MethodPut, path, handler, middleware...)
}

// DELETE adds a DELETE route
func (tr *TrieRouter) DELETE(path string, handler http.Handler, middleware ...Middleware) {
	tr.Insert(http.MethodDelete, path, handler, middleware...)
}

// PATCH adds a PATCH route
func (tr *TrieRouter) PATCH(path string, handler http.Handler, middleware ...Middleware) {
	tr.Insert(http.MethodPatch, path, handler, middleware...)
}

// OPTIONS adds an OPTIONS route
func (tr *TrieRouter) OPTIONS(path string, handler http.Handler, middleware ...Middleware) {
	tr.Insert(http.MethodOptions, path, handler, middleware...)
}

// HEAD adds a HEAD route
func (tr *TrieRouter) HEAD(path string, handler http.Handler, middleware ...Middleware) {
	tr.Insert(http.MethodHead, path, handler, middleware...)
}

// Any adds a route that matches any HTTP method
func (tr *TrieRouter) Any(path string, handler http.Handler, middleware ...Middleware) {
	methods := []string{
		http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete,
		http.MethodPatch, http.MethodOptions, http.MethodHead,
	}

	for _, method := range methods {
		tr.Insert(method, path, handler, middleware...)
	}
}