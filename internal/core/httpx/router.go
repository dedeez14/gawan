package httpx

import (
	"net/http"

	"Gawan/internal/core/logx"
	"github.com/gorilla/mux"
)

// Router wraps gorilla/mux router with additional functionality
type Router struct {
	*mux.Router
	logger *logx.Logger
}

// NewRouter creates a new HTTP router
func NewRouter(logger *logx.Logger) *Router {
	r := mux.NewRouter()
	router := &Router{
		Router: r,
		logger: logger,
	}

	// Apply global middlewares
	router.Use(RequestIDMiddleware())
	router.Use(LoggerMiddleware(logger))
	router.Use(ErrorHandlerMiddleware(logger))

	return router
}

// GET adds a GET route
func (r *Router) GET(path string, handler http.HandlerFunc) *mux.Route {
	return r.HandleFunc(path, handler).Methods("GET")
}

// POST adds a POST route
func (r *Router) POST(path string, handler http.HandlerFunc) *mux.Route {
	return r.HandleFunc(path, handler).Methods("POST")
}

// PUT adds a PUT route
func (r *Router) PUT(path string, handler http.HandlerFunc) *mux.Route {
	return r.HandleFunc(path, handler).Methods("PUT")
}

// DELETE adds a DELETE route
func (r *Router) DELETE(path string, handler http.HandlerFunc) *mux.Route {
	return r.HandleFunc(path, handler).Methods("DELETE")
}

// PATCH adds a PATCH route
func (r *Router) PATCH(path string, handler http.HandlerFunc) *mux.Route {
	return r.HandleFunc(path, handler).Methods("PATCH")
}