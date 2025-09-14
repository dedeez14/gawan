package app

import (
	"net/http"

	"Gawan/internal/core/httpx"
)

// SetupRoutes configures all application routes
func SetupRoutes(router *httpx.Router) {
	// Health check endpoint
	router.GET("/health", healthHandler)

	// API v1 routes
	api := router.PathPrefix("/api/v1").Subrouter()
	setupAPIRoutes(api)
}

// setupAPIRoutes configures API routes
func setupAPIRoutes(router *http.ServeMux) {
	// Add your API routes here
	// Example:
	// router.HandleFunc("/users", usersHandler).Methods("GET")
	// router.HandleFunc("/users", createUserHandler).Methods("POST")
}

// healthHandler handles health check requests
func healthHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":  "ok",
		"service": "Gawan",
		"version": "1.0.0",
	}

	httpx.WriteSuccess(w, r, response, "Service is healthy")
}