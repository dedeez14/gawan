package swagger

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
)

// GawanIntegration provides integration between Swagger and Gawan framework
type GawanIntegration struct {
	swaggerMW *SwaggerMiddleware
	config    IntegrationConfig
}

// IntegrationConfig holds configuration for Gawan integration
type IntegrationConfig struct {
	AutoDocument     bool     `json:"auto_document"`     // Automatically document endpoints
	IncludePaths     []string `json:"include_paths"`     // Paths to include in auto-documentation
	ExcludePaths     []string `json:"exclude_paths"`     // Paths to exclude from auto-documentation
	RequireAuth      bool     `json:"require_auth"`      // Require authentication for Swagger UI
	CustomCSS        string   `json:"custom_css"`        // Custom CSS for Swagger UI
	CustomJS         string   `json:"custom_js"`         // Custom JavaScript for Swagger UI
	EnableValidator  bool     `json:"enable_validator"`  // Enable request/response validation
	EnableCORS       bool     `json:"enable_cors"`       // Enable CORS for Swagger endpoints
	Theme            string   `json:"theme"`             // Swagger UI theme (light, dark)
	DefaultExpanded  bool     `json:"default_expanded"`  // Expand operations by default
	ShowExtensions   bool     `json:"show_extensions"`   // Show vendor extensions
	MaxDisplayedTags int      `json:"max_displayed_tags"` // Maximum number of tags to display
}

// DefaultIntegrationConfig returns default integration configuration
func DefaultIntegrationConfig() IntegrationConfig {
	return IntegrationConfig{
		AutoDocument:     true,
		IncludePaths:     []string{"/api/"},
		ExcludePaths:     []string{"/docs/", "/swagger/", "/health", "/metrics"},
		RequireAuth:      false,
		EnableValidator:  true,
		EnableCORS:       true,
		Theme:            "light",
		DefaultExpanded:  false,
		ShowExtensions:   false,
		MaxDisplayedTags: 20,
	}
}

// NewGawanIntegration creates a new Gawan integration
func NewGawanIntegration(swaggerMW *SwaggerMiddleware, config IntegrationConfig) *GawanIntegration {
	return &GawanIntegration{
		swaggerMW: swaggerMW,
		config:    config,
	}
}

// RegisterRoutes registers Swagger routes with the Gawan router
func (gi *GawanIntegration) RegisterRoutes(router interface{}) error {
	// This is a generic interface - in real implementation, you would type assert
	// to the specific router type (Gin, Chi, etc.) and register routes accordingly
	
	// Example for different router types:
	switch r := router.(type) {
	case *http.ServeMux:
		return gi.registerServeMuxRoutes(r)
	default:
		return fmt.Errorf("unsupported router type: %T", router)
	}
}

// registerServeMuxRoutes registers routes for http.ServeMux
func (gi *GawanIntegration) registerServeMuxRoutes(mux *http.ServeMux) error {
	basePath := gi.swaggerMW.config.Path
	
	// Swagger UI endpoint
	mux.HandleFunc(basePath+"/", gi.handleSwaggerUI)
	mux.HandleFunc(basePath+"/index.html", gi.handleSwaggerUI)
	
	// OpenAPI JSON endpoint
	mux.HandleFunc(basePath+"/swagger.json", gi.handleOpenAPIJSON)
	mux.HandleFunc(basePath+"/openapi.json", gi.handleOpenAPIJSON)
	
	// Static assets
	mux.HandleFunc(basePath+"/swagger-ui-bundle.js", gi.handleStaticAsset)
	mux.HandleFunc(basePath+"/swagger-ui-standalone-preset.js", gi.handleStaticAsset)
	mux.HandleFunc(basePath+"/swagger-ui.css", gi.handleStaticAsset)
	
	// Custom assets
	if gi.config.CustomCSS != "" {
		mux.HandleFunc(basePath+"/custom.css", gi.handleCustomCSS)
	}
	if gi.config.CustomJS != "" {
		mux.HandleFunc(basePath+"/custom.js", gi.handleCustomJS)
	}
	
	// API validation endpoint
	if gi.config.EnableValidator {
		mux.HandleFunc(basePath+"/validate", gi.handleValidation)
	}
	
	return nil
}

// handleSwaggerUI serves the Swagger UI
func (gi *GawanIntegration) handleSwaggerUI(w http.ResponseWriter, r *http.Request) {
	if gi.config.RequireAuth && !gi.isAuthenticated(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	if gi.config.EnableCORS {
		gi.setCORSHeaders(w)
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	
	html := gi.generateSwaggerHTML()
	w.Write([]byte(html))
}

// handleOpenAPIJSON serves the OpenAPI JSON specification
func (gi *GawanIntegration) handleOpenAPIJSON(w http.ResponseWriter, r *http.Request) {
	if gi.config.EnableCORS {
		gi.setCORSHeaders(w)
	}
	
	w.Header().Set("Content-Type", "application/json")
	
	spec, err := gi.swaggerMW.GetOpenAPISpec()
	if err != nil {
		http.Error(w, "Failed to generate OpenAPI spec", http.StatusInternalServerError)
		return
	}
	
	w.Write(spec)
}

// handleStaticAsset serves static Swagger UI assets
func (gi *GawanIntegration) handleStaticAsset(w http.ResponseWriter, r *http.Request) {
	if gi.config.EnableCORS {
		gi.setCORSHeaders(w)
	}
	
	filename := filepath.Base(r.URL.Path)
	var content string
	var contentType string
	
	switch filename {
	case "swagger-ui-bundle.js":
		content = getSwaggerUIBundleJS()
		contentType = "application/javascript"
	case "swagger-ui-standalone-preset.js":
		content = getSwaggerUIPresetJS()
		contentType = "application/javascript"
	case "swagger-ui.css":
		content = getSwaggerUICSS()
		contentType = "text/css"
	default:
		http.NotFound(w, r)
		return
	}
	
	w.Header().Set("Content-Type", contentType)
	w.Write([]byte(content))
}

// handleCustomCSS serves custom CSS
func (gi *GawanIntegration) handleCustomCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css")
	w.Write([]byte(gi.config.CustomCSS))
}

// handleCustomJS serves custom JavaScript
func (gi *GawanIntegration) handleCustomJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	w.Write([]byte(gi.config.CustomJS))
}

// handleValidation handles API request/response validation
func (gi *GawanIntegration) handleValidation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req ValidationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	result := gi.validateRequest(req)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// ValidationRequest represents a validation request
type ValidationRequest struct {
	Method   string                 `json:"method"`
	Path     string                 `json:"path"`
	Headers  map[string]string      `json:"headers"`
	Query    map[string]string      `json:"query"`
	Body     interface{}            `json:"body"`
	Response interface{}            `json:"response"`
}

// ValidationResult represents a validation result
type ValidationResult struct {
	Valid   bool     `json:"valid"`
	Errors  []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// validateRequest validates a request against the OpenAPI specification
func (gi *GawanIntegration) validateRequest(req ValidationRequest) ValidationResult {
	result := ValidationResult{
		Valid:    true,
		Errors:   []string{},
		Warnings: []string{},
	}
	
	// Basic validation logic - in a real implementation, you would use
	// a proper OpenAPI validator library
	spec := gi.swaggerMW.GetGenerator().Generate()
	
	// Check if path exists
	pathItem, exists := spec.Paths[req.Path]
	if !exists {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Path '%s' not found in specification", req.Path))
		return result
	}
	
	// Check if method exists
	var operation *Operation
	switch strings.ToUpper(req.Method) {
	case "GET":
		operation = pathItem.Get
	case "POST":
		operation = pathItem.Post
	case "PUT":
		operation = pathItem.Put
	case "DELETE":
		operation = pathItem.Delete
	case "PATCH":
		operation = pathItem.Patch
	case "OPTIONS":
		operation = pathItem.Options
	case "HEAD":
		operation = pathItem.Head
	case "TRACE":
		operation = pathItem.Trace
	}
	
	if operation == nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Method '%s' not allowed for path '%s'", req.Method, req.Path))
		return result
	}
	
	// Validate required parameters
	for _, param := range operation.Parameters {
		if param.Required {
			switch param.In {
			case "query":
				if _, exists := req.Query[param.Name]; !exists {
					result.Valid = false
					result.Errors = append(result.Errors, fmt.Sprintf("Required query parameter '%s' is missing", param.Name))
				}
			case "header":
				if _, exists := req.Headers[param.Name]; !exists {
					result.Valid = false
					result.Errors = append(result.Errors, fmt.Sprintf("Required header '%s' is missing", param.Name))
				}
			}
		}
	}
	
	// Validate request body if required
	if operation.RequestBody != nil && operation.RequestBody.Required && req.Body == nil {
		result.Valid = false
		result.Errors = append(result.Errors, "Request body is required")
	}
	
	return result
}

// isAuthenticated checks if the request is authenticated
func (gi *GawanIntegration) isAuthenticated(r *http.Request) bool {
	// Basic authentication check - implement your own logic
	auth := r.Header.Get("Authorization")
	return auth != "" && strings.HasPrefix(auth, "Bearer ")
}

// setCORSHeaders sets CORS headers
func (gi *GawanIntegration) setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}

// generateSwaggerHTML generates the Swagger UI HTML
func (gi *GawanIntegration) generateSwaggerHTML() string {
	theme := gi.config.Theme
	if theme == "" {
		theme = "light"
	}
	
	customCSS := ""
	if gi.config.CustomCSS != "" {
		customCSS = fmt.Sprintf(`<link rel="stylesheet" type="text/css" href="%s/custom.css" />`, gi.swaggerMW.config.Path)
	}
	
	customJS := ""
	if gi.config.CustomJS != "" {
		customJS = fmt.Sprintf(`<script src="%s/custom.js"></script>`, gi.swaggerMW.config.Path)
	}
	
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s - Swagger UI</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui.css" />
    %s
    <style>
        html {
            box-sizing: border-box;
            overflow: -moz-scrollbars-vertical;
            overflow-y: scroll;
        }
        *, *:before, *:after {
            box-sizing: inherit;
        }
        body {
            margin: 0;
            background: %s;
        }
        .swagger-ui .topbar {
            background-color: #1b1b1b;
            border-bottom: 1px solid #3b4151;
        }
        .swagger-ui .topbar .download-url-wrapper {
            display: none;
        }
        %s
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            const ui = SwaggerUIBundle({
                url: '%s/swagger.json',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout",
                defaultModelsExpandDepth: %d,
                defaultModelExpandDepth: 1,
                defaultModelRendering: 'example',
                displayOperationId: false,
                tryItOutEnabled: true,
                requestInterceptor: function(request) {
                    // Add custom request interceptor logic here
                    return request;
                },
                responseInterceptor: function(response) {
                    // Add custom response interceptor logic here
                    return response;
                },
                onComplete: function() {
                    console.log('Swagger UI loaded successfully');
                },
                onFailure: function(data) {
                    console.error('Failed to load Swagger UI:', data);
                },
                docExpansion: '%s',
                apisSorter: 'alpha',
                operationsSorter: 'alpha',
                maxDisplayedTags: %d,
                showExtensions: %t,
                showCommonExtensions: true,
                useUnsafeMarkdown: false
            });
            
            // Custom initialization code
            %s
        };
    </script>
    %s
</body>
</html>`,
		gi.swaggerMW.config.Title,
		customCSS,
		gi.getThemeBackground(theme),
		gi.getThemeCSS(theme),
		gi.swaggerMW.config.Path,
		gi.getDefaultExpansion(),
		gi.getDocExpansion(),
		gi.config.MaxDisplayedTags,
		gi.config.ShowExtensions,
		gi.getCustomInitJS(),
		customJS,
	)
}

// getThemeBackground returns the background color for the theme
func (gi *GawanIntegration) getThemeBackground(theme string) string {
	if theme == "dark" {
		return "#1a1a1a"
	}
	return "#fafafa"
}

// getThemeCSS returns theme-specific CSS
func (gi *GawanIntegration) getThemeCSS(theme string) string {
	if theme == "dark" {
		return `
        .swagger-ui {
            filter: invert(1) hue-rotate(180deg);
        }
        .swagger-ui img {
            filter: invert(1) hue-rotate(180deg);
        }
        `
	}
	return ""
}

// getDefaultExpansion returns the default expansion level
func (gi *GawanIntegration) getDefaultExpansion() int {
	if gi.config.DefaultExpanded {
		return 2
	}
	return 0
}

// getDocExpansion returns the document expansion setting
func (gi *GawanIntegration) getDocExpansion() string {
	if gi.config.DefaultExpanded {
		return "full"
	}
	return "list"
}

// getCustomInitJS returns custom initialization JavaScript
func (gi *GawanIntegration) getCustomInitJS() string {
	return `
            // Add authentication header if available
            const token = localStorage.getItem('auth_token');
            if (token) {
                ui.preauthorizeApiKey('bearerAuth', 'Bearer ' + token);
            }
            
            // Add custom styling
            const style = document.createElement('style');
            style.textContent = ` + "`" + `
                .swagger-ui .info .title {
                    color: #3b4151;
                }
                .swagger-ui .scheme-container {
                    background: #fff;
                    border-radius: 4px;
                    border: 1px solid #d3d3d3;
                }
            ` + "`" + `;
            document.head.appendChild(style);
        `
}

// AutoDocumentationMiddleware returns middleware for automatic endpoint documentation
func (gi *GawanIntegration) AutoDocumentationMiddleware() func(http.Handler) http.Handler {
	if !gi.config.AutoDocument {
		return func(next http.Handler) http.Handler {
			return next
		}
	}
	
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip documentation for excluded paths
			if gi.shouldExcludePath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			
			// Check if path should be included
			if !gi.shouldIncludePath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			
			// Auto-document the endpoint
			gi.autoDocumentEndpoint(r.Method, r.URL.Path, r)
			
			next.ServeHTTP(w, r)
		})
	}
}

// shouldExcludePath checks if a path should be excluded from documentation
func (gi *GawanIntegration) shouldExcludePath(path string) bool {
	for _, excludePath := range gi.config.ExcludePaths {
		if strings.HasPrefix(path, excludePath) {
			return true
		}
	}
	return false
}

// shouldIncludePath checks if a path should be included in documentation
func (gi *GawanIntegration) shouldIncludePath(path string) bool {
	if len(gi.config.IncludePaths) == 0 {
		return true
	}
	
	for _, includePath := range gi.config.IncludePaths {
		if strings.HasPrefix(path, includePath) {
			return true
		}
	}
	return false
}

// autoDocumentEndpoint automatically documents an endpoint
func (gi *GawanIntegration) autoDocumentEndpoint(method, path string, r *http.Request) {
	// Use the swagger middleware's auto-documentation feature
	gi.swaggerMW.autoDocumentEndpoint(method, path, r)
}

// GetSwaggerMiddleware returns the underlying Swagger middleware
func (gi *GawanIntegration) GetSwaggerMiddleware() *SwaggerMiddleware {
	return gi.swaggerMW
}

// UpdateConfig updates the integration configuration
func (gi *GawanIntegration) UpdateConfig(config IntegrationConfig) {
	gi.config = config
}

// GetConfig returns the current integration configuration
func (gi *GawanIntegration) GetConfig() IntegrationConfig {
	return gi.config
}

// Static asset content (in a real implementation, these would be embedded files)
func getSwaggerUIBundleJS() string {
	return `/* Swagger UI Bundle JS - This would contain the actual Swagger UI bundle */
console.log('Swagger UI Bundle loaded');`
}

func getSwaggerUIPresetJS() string {
	return `/* Swagger UI Standalone Preset JS - This would contain the actual preset */
console.log('Swagger UI Preset loaded');`
}

func getSwaggerUICSS() string {
	return `/* Swagger UI CSS - This would contain the actual Swagger UI styles */
body { font-family: Arial, sans-serif; }`
}