package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"runtime"
	"strconv"
	"time"
)

// Response represents a JSON response
type Response struct {
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	RequestID string    `json:"request_id"`
	Delay     int       `json:"delay_ms"`
}

// HealthResponse represents health check response
type HealthResponse struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	Uptime    string    `json:"uptime"`
}

var startTime = time.Now()

// rootHandler handles root endpoint (optimized for high load)
func rootHandler(w http.ResponseWriter, r *http.Request) {
	// Minimal delay for high-load testing
	delay := rand.Intn(10) + 5 // 5-15ms random delay
	time.Sleep(time.Duration(delay) * time.Millisecond)
	
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Connection", "keep-alive")
	
	// Pre-allocated response for better performance
	response := Response{
		Message:   "OK",
		Timestamp: time.Now(),
		RequestID: generateRequestID(),
		Delay:     delay,
	}
	
	json.NewEncoder(w).Encode(response)
}

// healthHandler handles health check endpoint
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	uptime := time.Since(startTime)
	response := HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now(),
		Uptime:    uptime.String(),
	}
	
	json.NewEncoder(w).Encode(response)
}

// slowHandler simulates a slow endpoint
func slowHandler(w http.ResponseWriter, r *http.Request) {
	// Parse delay parameter
	delayParam := r.URL.Query().Get("delay")
	delay := 1000 // default 1 second
	
	if delayParam != "" {
		if d, err := strconv.Atoi(delayParam); err == nil {
			delay = d
		}
	}
	
	time.Sleep(time.Duration(delay) * time.Millisecond)
	
	w.Header().Set("Content-Type", "application/json")
	response := Response{
		Message:   "Slow response completed",
		Timestamp: time.Now(),
		RequestID: generateRequestID(),
		Delay:     delay,
	}
	
	json.NewEncoder(w).Encode(response)
}

// errorHandler simulates random errors
func errorHandler(w http.ResponseWriter, r *http.Request) {
	// 20% chance of error
	if rand.Float32() < 0.2 {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Simulated server error",
			"timestamp": time.Now().Format(time.RFC3339),
		})
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	response := Response{
		Message:   "Success response",
		Timestamp: time.Now(),
		RequestID: generateRequestID(),
		Delay:     rand.Intn(30) + 5,
	}
	
	json.NewEncoder(w).Encode(response)
}

// cpuIntensiveHandler simulates CPU-intensive work
func cpuIntensiveHandler(w http.ResponseWriter, r *http.Request) {
	// Simulate CPU work
	start := time.Now()
	sum := 0
	for i := 0; i < 1000000; i++ {
		sum += i
	}
	processingTime := time.Since(start)
	
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"message": "CPU intensive task completed",
		"timestamp": time.Now(),
		"request_id": generateRequestID(),
		"processing_time_ms": processingTime.Milliseconds(),
		"result": sum,
	}
	
	json.NewEncoder(w).Encode(response)
}

// generateRequestID generates a simple request ID
func generateRequestID() string {
	return fmt.Sprintf("req_%d_%d", time.Now().UnixNano(), rand.Intn(1000))
}

// loggingMiddleware logs all requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		duration := time.Since(start)
		
		log.Printf("%s %s %s %v", r.Method, r.URL.Path, r.RemoteAddr, duration)
	})
}

func main() {
	rand.Seed(time.Now().UnixNano())
	
	// Set GOMAXPROCS for better performance
	runtime.GOMAXPROCS(runtime.NumCPU())
	
	mux := http.NewServeMux()
	
	// Register handlers
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/slow", slowHandler)
	mux.HandleFunc("/error", errorHandler)
	mux.HandleFunc("/cpu", cpuIntensiveHandler)
	
	// Wrap with logging middleware (disable for high load)
	// handler := loggingMiddleware(mux)
	handler := mux // Direct handler for better performance
	
	port := ":8080"
	log.Printf("🚀 High-Performance Test Server starting on port %s", port)
	log.Printf("Optimized for high-load testing (logging disabled)")
	log.Printf("Available endpoints:")
	log.Printf("  GET /         - Basic endpoint with random delay")
	log.Printf("  GET /health   - Health check endpoint")
	log.Printf("  GET /slow     - Slow endpoint (default 1s delay)")
	log.Printf("  GET /error    - Random error endpoint (20%% error rate)")
	log.Printf("  GET /cpu      - CPU intensive endpoint")
	log.Printf("")
	log.Printf("Ready for high-load testing! 🎯")
	
	server := &http.Server{
		Addr:         port,
		Handler:      handler,
		ReadTimeout:  5 * time.Second,  // Reduced for high load
		WriteTimeout: 5 * time.Second,  // Reduced for high load
		IdleTimeout:  120 * time.Second, // Increased for connection reuse
		MaxHeaderBytes: 1 << 20, // 1MB
	}
	
	log.Fatal(server.ListenAndServe())
}