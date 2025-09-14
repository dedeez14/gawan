package main

import (
	"log"
	"net/http"

	"Gawan/internal/app"
	"Gawan/internal/core/config"
	"Gawan/internal/core/httpx"
	"Gawan/internal/core/logx"
)

func main() {
	// Initialize logger
	logger := logx.NewLogger()

	// Load configuration
	cfg := config.Load()

	// Initialize HTTP router
	router := httpx.NewRouter(logger)

	// Setup routes
	app.SetupRoutes(router)

	// Start server
	log.Printf("Server starting on port %s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, router); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}