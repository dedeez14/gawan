package httpx

import (
	"net/http"

	"github.com/gorilla/mux"
)

// MuxWrapper wraps gorilla/mux with additional functionality
type MuxWrapper struct {
	*mux.Router
}

// NewMux creates a new mux wrapper
func NewMux() *MuxWrapper {
	return &MuxWrapper{
		Router: mux.NewRouter(),
	}
}

// Group creates a new route group with common prefix
func (m *MuxWrapper) Group(prefix string) *RouteGroup {
	return &RouteGroup{
		router: m.Router,
		prefix: prefix,
	}
}

// RouteGroup represents a group of routes with common prefix
type RouteGroup struct {
	router *mux.Router
	prefix string
}

// GET adds a GET route to the group
func (rg *RouteGroup) GET(path string, handler http.HandlerFunc) *mux.Route {
	return rg.router.HandleFunc(rg.prefix+path, handler).Methods("GET")
}

// POST adds a POST route to the group
func (rg *RouteGroup) POST(path string, handler http.HandlerFunc) *mux.Route {
	return rg.router.HandleFunc(rg.prefix+path, handler).Methods("POST")
}

// PUT adds a PUT route to the group
func (rg *RouteGroup) PUT(path string, handler http.HandlerFunc) *mux.Route {
	return rg.router.HandleFunc(rg.prefix+path, handler).Methods("PUT")
}

// DELETE adds a DELETE route to the group
func (rg *RouteGroup) DELETE(path string, handler http.HandlerFunc) *mux.Route {
	return rg.router.HandleFunc(rg.prefix+path, handler).Methods("DELETE")
}

// PATCH adds a PATCH route to the group
func (rg *RouteGroup) PATCH(path string, handler http.HandlerFunc) *mux.Route {
	return rg.router.HandleFunc(rg.prefix+path, handler).Methods("PATCH")
}

// Use adds middleware to the route group
func (rg *RouteGroup) Use(middleware ...mux.MiddlewareFunc) {
	subrouter := rg.router.PathPrefix(rg.prefix).Subrouter()
	subrouter.Use(middleware...)
}