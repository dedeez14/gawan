package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"Gawan/internal/app"
	"Gawan/internal/core/httpx"
	"Gawan/internal/core/logx"
)

func TestHealthEndpoint(t *testing.T) {
	// Setup
	logger := logx.NewLogger()
	router := httpx.NewRouter(logger)
	app.SetupRoutes(router)

	// Create test request
	req, err := http.NewRequest("GET", "/health", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create response recorder
	rr := httptest.NewRecorder()

	// Execute request
	router.ServeHTTP(rr, req)

	// Check status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check content type
	expectedContentType := "application/json"
	if contentType := rr.Header().Get("Content-Type"); contentType != expectedContentType {
		t.Errorf("handler returned wrong content type: got %v want %v",
			contentType, expectedContentType)
	}

	// Check response body
	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	// Verify response structure
	if success, ok := response["success"].(bool); !ok || !success {
		t.Errorf("Expected success to be true, got %v", response["success"])
	}

	if data, ok := response["data"].(map[string]interface{}); ok {
		if status, ok := data["status"].(string); !ok || status != "ok" {
			t.Errorf("Expected status to be 'ok', got %v", data["status"])
		}

		if service, ok := data["service"].(string); !ok || service != "Gawan" {
			t.Errorf("Expected service to be 'Gawan', got %v", data["service"])
		}

		if version, ok := data["version"].(string); !ok || version != "1.0.0" {
			t.Errorf("Expected version to be '1.0.0', got %v", data["version"])
		}
	} else {
		t.Errorf("Expected data to be a map, got %v", response["data"])
	}

	// Check for request ID header
	if requestID := rr.Header().Get("X-Request-ID"); requestID == "" {
		t.Error("Expected X-Request-ID header to be present")
	}
}

func TestHealthEndpointWithRequestID(t *testing.T) {
	// Setup
	logger := logx.NewLogger()
	router := httpx.NewRouter(logger)
	app.SetupRoutes(router)

	// Create test request with custom request ID
	req, err := http.NewRequest("GET", "/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	customRequestID := "test-request-id-123"
	req.Header.Set("X-Request-ID", customRequestID)

	// Create response recorder
	rr := httptest.NewRecorder()

	// Execute request
	router.ServeHTTP(rr, req)

	// Check that the same request ID is returned
	if requestID := rr.Header().Get("X-Request-ID"); requestID != customRequestID {
		t.Errorf("Expected request ID to be %s, got %s", customRequestID, requestID)
	}

	// Check response body contains the request ID
	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	if responseRequestID, ok := response["request_id"].(string); ok {
		if responseRequestID != customRequestID {
			t.Errorf("Expected response request_id to be %s, got %s", customRequestID, responseRequestID)
		}
	}
}