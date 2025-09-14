package httpx

import (
	"encoding/json"
	"net/http"
)

// WriteJSON writes JSON response
func WriteJSON(w http.ResponseWriter, data interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(data)
}

// WriteJSONWithStatus writes JSON response with custom status code
func WriteJSONWithStatus(w http.ResponseWriter, status int, data interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(data)
}

// ReadJSON reads JSON from request body
func ReadJSON(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// SuccessResponse represents a successful API response
type SuccessResponse struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Message   string      `json:"message,omitempty"`
	RequestID string      `json:"request_id,omitempty"`
}

// ErrorResponse represents an error API response
type ErrorResponse struct {
	Success   bool   `json:"success"`
	Error     Error  `json:"error"`
	RequestID string `json:"request_id,omitempty"`
}

// Error represents error details
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// WriteSuccess writes a successful JSON response
func WriteSuccess(w http.ResponseWriter, r *http.Request, data interface{}, message string) error {
	response := SuccessResponse{
		Success:   true,
		Data:      data,
		Message:   message,
		RequestID: GetRequestIDFromRequest(r),
	}
	return WriteJSON(w, response)
}

// WriteError writes an error JSON response
func WriteError(w http.ResponseWriter, r *http.Request, code int, message string) error {
	w.WriteHeader(code)
	response := ErrorResponse{
		Success: false,
		Error: Error{
			Code:    code,
			Message: message,
		},
		RequestID: GetRequestIDFromRequest(r),
	}
	return WriteJSON(w, response)
}