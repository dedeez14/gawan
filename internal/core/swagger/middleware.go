package swagger

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
)

// SwaggerMiddleware provides automatic API documentation generation
type SwaggerMiddleware struct {
	generator *SwaggerGenerator
	config    Config
}

// NewSwaggerMiddleware creates a new Swagger middleware
func NewSwaggerMiddleware(config Config) *SwaggerMiddleware {
	return &SwaggerMiddleware{
		generator: NewSwaggerGenerator(config),
		config:    config,
	}
}

// Handler returns the HTTP handler for Swagger documentation
func (sm *SwaggerMiddleware) Handler() http.HandlerFunc {
	return sm.generator.ServeHTTP
}

// DocumentEndpoint documents an API endpoint
func (sm *SwaggerMiddleware) DocumentEndpoint(method, path string, handler interface{}, options ...EndpointOption) {
	operation := sm.analyzeHandler(handler)
	
	// Apply options
	for _, option := range options {
		option(operation)
	}
	
	// Set default operation ID if not provided
	if operation.OperationID == "" {
		operation.OperationID = generateOperationID(method, path)
	}
	
	sm.generator.AddEndpoint(method, path, operation)
}

// EndpointOption represents an option for configuring an endpoint
type EndpointOption func(*Operation)

// WithSummary sets the operation summary
func WithSummary(summary string) EndpointOption {
	return func(op *Operation) {
		op.Summary = summary
	}
}

// WithDescription sets the operation description
func WithDescription(description string) EndpointOption {
	return func(op *Operation) {
		op.Description = description
	}
}

// WithTags sets the operation tags
func WithTags(tags ...string) EndpointOption {
	return func(op *Operation) {
		op.Tags = tags
	}
}

// WithSecurity adds security requirements
func WithSecurity(schemes ...string) EndpointOption {
	return func(op *Operation) {
		for _, scheme := range schemes {
			secReq := SecurityRequirement{
				scheme: []string{},
			}
			op.Security = append(op.Security, secReq)
		}
	}
}

// WithDeprecated marks the operation as deprecated
func WithDeprecated() EndpointOption {
	return func(op *Operation) {
		op.Deprecated = true
	}
}

// WithRequestBody adds a request body schema
func WithRequestBody(description string, required bool, example interface{}) EndpointOption {
	return func(op *Operation) {
		schema := generateSchemaFromExample(example)
		op.AddRequestBody(description, required, &schema)
	}
}

// WithResponse adds a response schema
func WithResponse(code string, description string, example interface{}) EndpointOption {
	return func(op *Operation) {
		var schema *Schema
		if example != nil {
			s := generateSchemaFromExample(example)
			schema = &s
		}
		op.AddResponse(code, description, schema)
	}
}

// WithParameter adds a parameter
func WithParameter(name, in, description string, required bool, example interface{}) EndpointOption {
	return func(op *Operation) {
		schema := generateSchemaFromExample(example)
		op.AddParameter(name, in, description, required, &schema)
	}
}

// analyzeHandler analyzes a handler function to generate documentation
func (sm *SwaggerMiddleware) analyzeHandler(handler interface{}) *Operation {
	operation := &Operation{
		Responses:  make(map[string]Response),
		Parameters: make([]Parameter, 0),
	}
	
	// Add default responses
	operation.AddResponse("200", "Successful response", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"message": {Type: "string", Example: "Success"},
			"data": {Type: "object"},
		},
	})
	
	operation.AddResponse("400", "Bad Request", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"error": {Type: "string", Example: "Invalid request"},
			"code": {Type: "integer", Example: 400},
		},
	})
	
	operation.AddResponse("401", "Unauthorized", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"error": {Type: "string", Example: "Unauthorized"},
			"code": {Type: "integer", Example: 401},
		},
	})
	
	operation.AddResponse("500", "Internal Server Error", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"error": {Type: "string", Example: "Internal server error"},
			"code": {Type: "integer", Example: 500},
		},
	})
	
	return operation
}

// generateSchemaFromExample generates a schema from an example value
func generateSchemaFromExample(example interface{}) Schema {
	if example == nil {
		return Schema{Type: "object"}
	}
	
	t := reflect.TypeOf(example)
	v := reflect.ValueOf(example)
	
	if t.Kind() == reflect.Ptr {
		if v.IsNil() {
			return Schema{Type: "object"}
		}
		t = t.Elem()
		v = v.Elem()
	}
	
	// Check if value is valid
	if !v.IsValid() {
		return Schema{Type: "object"}
	}
	
	schema := Schema{}
	
	switch t.Kind() {
	case reflect.String:
		schema.Type = "string"
		schema.Example = v.String()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		schema.Type = "integer"
		schema.Example = v.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		schema.Type = "integer"
		schema.Example = v.Uint()
	case reflect.Float32, reflect.Float64:
		schema.Type = "number"
		schema.Example = v.Float()
	case reflect.Bool:
		schema.Type = "boolean"
		schema.Example = v.Bool()
	case reflect.Slice, reflect.Array:
		schema.Type = "array"
		if v.Len() > 0 {
			itemSchema := generateSchemaFromExample(v.Index(0).Interface())
			schema.Items = &itemSchema
		}
		schema.Example = example
	case reflect.Map:
		schema.Type = "object"
		schema.Example = example
	case reflect.Struct:
		schema.Type = "object"
		schema.Properties = make(map[string]Schema)
		var required []string
		
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			if !field.IsExported() {
				continue
			}
			
			jsonTag := field.Tag.Get("json")
			if jsonTag == "-" {
				continue
			}
			
			fieldName := field.Name
			if jsonTag != "" {
				parts := strings.Split(jsonTag, ",")
				if parts[0] != "" {
					fieldName = parts[0]
				}
			}
			
			fieldValue := v.Field(i)
			fieldSchema := generateSchemaFromExample(fieldValue.Interface())
			
			// Add description from tag
			if desc := field.Tag.Get("description"); desc != "" {
				fieldSchema.Description = desc
			}
			
			// Check if field is required
			if validate := field.Tag.Get("validate"); strings.Contains(validate, "required") {
				required = append(required, fieldName)
			}
			
			schema.Properties[fieldName] = fieldSchema
		}
		
		if len(required) > 0 {
			schema.Required = required
		}
		schema.Example = example
	default:
		schema.Type = "object"
		schema.Example = example
	}
	
	return schema
}

// generateOperationID generates an operation ID from method and path
func generateOperationID(method, path string) string {
	// Convert path to camelCase
	parts := strings.Split(strings.Trim(path, "/"), "/")
	var operationParts []string
	
	for _, part := range parts {
		if strings.HasPrefix(part, ":") || strings.HasPrefix(part, "{") {
			// Skip path parameters
			continue
		}
		
		// Convert to camelCase
		if len(part) > 0 {
			operationParts = append(operationParts, strings.Title(part))
		}
	}
	
	operationName := strings.Join(operationParts, "")
	if operationName == "" {
		operationName = "Root"
	}
	
	return strings.ToLower(method) + operationName
}

// AutoDocumentMiddleware creates middleware that automatically documents endpoints
func (sm *SwaggerMiddleware) AutoDocumentMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip documentation paths
			if strings.HasPrefix(r.URL.Path, sm.config.Path) {
				next.ServeHTTP(w, r)
				return
			}
			
			// Auto-document this endpoint if not already documented
			method := strings.ToUpper(r.Method)
			path := r.URL.Path
			
			// Check if endpoint is already documented
			if !sm.isEndpointDocumented(method, path) {
				sm.autoDocumentEndpoint(method, path, r)
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// isEndpointDocumented checks if an endpoint is already documented
func (sm *SwaggerMiddleware) isEndpointDocumented(method, path string) bool {
	if pathMethods, exists := sm.generator.handlers[path]; exists {
		_, methodExists := pathMethods[strings.ToLower(method)]
		return methodExists
	}
	return false
}

// autoDocumentEndpoint automatically documents an endpoint
func (sm *SwaggerMiddleware) autoDocumentEndpoint(method, path string, r *http.Request) {
	operation := CreateOperation(
		fmt.Sprintf("%s %s", method, path),
		fmt.Sprintf("Auto-generated documentation for %s %s", method, path),
		[]string{"Auto-generated"},
	)
	
	// Add path parameters
	pathParams := extractPathParameters(path)
	for _, param := range pathParams {
		operation.AddParameter(param, "path", fmt.Sprintf("Path parameter: %s", param), true, &Schema{
			Type: "string",
		})
	}
	
	// Add query parameters from request
	for key := range r.URL.Query() {
		operation.AddParameter(key, "query", fmt.Sprintf("Query parameter: %s", key), false, &Schema{
			Type: "string",
		})
	}
	
	// Add common responses
	operation.AddResponse("200", "Successful response", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"message": {Type: "string", Example: "Success"},
		},
	})
	
	operation.AddResponse("400", "Bad Request", nil)
	operation.AddResponse("500", "Internal Server Error", nil)
	
	// Add request body for POST/PUT/PATCH methods
	if method == "POST" || method == "PUT" || method == "PATCH" {
		operation.AddRequestBody("Request body", true, &Schema{
			Type: "object",
		})
	}
	
	sm.generator.AddEndpoint(method, path, operation)
}

// extractPathParameters extracts parameter names from a path
func extractPathParameters(path string) []string {
	var params []string
	parts := strings.Split(path, "/")
	
	for _, part := range parts {
		if strings.HasPrefix(part, ":") {
			// Gin-style parameter
			params = append(params, part[1:])
		} else if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			// OpenAPI-style parameter
			params = append(params, part[1:len(part)-1])
		}
	}
	
	return params
}

// AddCommonEndpoints adds common endpoints to the documentation
func (sm *SwaggerMiddleware) AddCommonEndpoints() {
	// Health check endpoint
	healthOp := CreateOperation(
		"Health Check",
		"Returns the health status of the application",
		[]string{"Health"},
	)
	healthOp.AddResponse("200", "Health status", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"status": {Type: "string", Example: "healthy", Enum: []interface{}{"healthy", "unhealthy", "degraded"}},
			"timestamp": {Type: "string", Format: "date-time"},
			"version": {Type: "string", Example: "1.0.0"},
			"uptime": {Type: "string", Example: "2h30m15s"},
		},
		Required: []string{"status", "timestamp"},
	})
	sm.generator.AddEndpoint("GET", "/health", healthOp)
	
	// Metrics endpoint
	metricsOp := CreateOperation(
		"Application Metrics",
		"Returns application metrics and statistics",
		[]string{"Monitoring"},
	)
	metricsOp.AddResponse("200", "Application metrics", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"requests_total": {Type: "integer", Example: 1000},
			"requests_per_second": {Type: "number", Example: 10.5},
			"response_time_avg": {Type: "number", Example: 150.5},
			"memory_usage": {Type: "integer", Example: 67108864},
			"cpu_usage": {Type: "number", Example: 25.5},
		},
	})
	metricsOp.AddSecurity("bearerAuth")
	sm.generator.AddEndpoint("GET", "/metrics", metricsOp)
	
	// Version endpoint
	versionOp := CreateOperation(
		"Application Version",
		"Returns the application version information",
		[]string{"System"},
	)
	versionOp.AddResponse("200", "Version information", &Schema{
		Type: "object",
		Properties: map[string]Schema{
			"version": {Type: "string", Example: "1.0.0"},
			"build_date": {Type: "string", Format: "date-time"},
			"commit_hash": {Type: "string", Example: "abc123def456"},
			"go_version": {Type: "string", Example: "go1.21.0"},
		},
		Required: []string{"version"},
	})
	sm.generator.AddEndpoint("GET", "/version", versionOp)
}

// GetGenerator returns the Swagger generator instance
func (sm *SwaggerMiddleware) GetGenerator() *SwaggerGenerator {
	return sm.generator
}

// RegisterCustomSchema registers a custom schema
func (sm *SwaggerMiddleware) RegisterCustomSchema(name string, example interface{}) {
	schema := generateSchemaFromExample(example)
	sm.generator.AddSchema(name, schema)
}

// SetGlobalSecurity sets global security requirements
func (sm *SwaggerMiddleware) SetGlobalSecurity(schemes ...string) {
	var security []SecurityRequirement
	for _, scheme := range schemes {
		secReq := SecurityRequirement{
			scheme: []string{},
		}
		security = append(security, secReq)
	}
	sm.generator.openAPI.Security = security
}

// AddTag adds a tag to the documentation
func (sm *SwaggerMiddleware) AddTag(name, description string) {
	tag := Tag{
		Name:        name,
		Description: description,
	}
	sm.generator.openAPI.Tags = append(sm.generator.openAPI.Tags, tag)
}

// SetInfo updates the API information
func (sm *SwaggerMiddleware) SetInfo(title, description, version string) {
	sm.generator.openAPI.Info.Title = title
	sm.generator.openAPI.Info.Description = description
	sm.generator.openAPI.Info.Version = version
}

// AddServer adds a server to the documentation
func (sm *SwaggerMiddleware) AddServer(url, description string) {
	server := Server{
		URL:         url,
		Description: description,
	}
	sm.generator.openAPI.Servers = append(sm.generator.openAPI.Servers, server)
}

// GetOpenAPISpec returns the generated OpenAPI specification as JSON
func (sm *SwaggerMiddleware) GetOpenAPISpec() ([]byte, error) {
	spec := sm.generator.Generate()
	return json.MarshalIndent(spec, "", "  ")
}

// ValidateSpec validates the generated OpenAPI specification
func (sm *SwaggerMiddleware) ValidateSpec() []string {
	var errors []string
	spec := sm.generator.Generate()
	
	// Basic validation
	if spec.Info.Title == "" {
		errors = append(errors, "API title is required")
	}
	
	if spec.Info.Version == "" {
		errors = append(errors, "API version is required")
	}
	
	if len(spec.Paths) == 0 {
		errors = append(errors, "At least one path is required")
	}
	
	// Validate paths
	for path, pathItem := range spec.Paths {
		if !strings.HasPrefix(path, "/") {
			errors = append(errors, fmt.Sprintf("Path '%s' must start with '/'", path))
		}
		
		// Check if path has at least one operation
		hasOperation := pathItem.Get != nil || pathItem.Post != nil || pathItem.Put != nil ||
			pathItem.Delete != nil || pathItem.Patch != nil || pathItem.Options != nil ||
			pathItem.Head != nil || pathItem.Trace != nil
		
		if !hasOperation {
			errors = append(errors, fmt.Sprintf("Path '%s' has no operations", path))
		}
	}
	
	return errors
}