package swagger

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"
)

// OpenAPI represents the root OpenAPI specification
type OpenAPI struct {
	OpenAPI      string                 `json:"openapi"`
	Info         Info                   `json:"info"`
	Servers      []Server               `json:"servers,omitempty"`
	Paths        map[string]PathItem    `json:"paths"`
	Components   *Components            `json:"components,omitempty"`
	Security     []SecurityRequirement  `json:"security,omitempty"`
	Tags         []Tag                  `json:"tags,omitempty"`
	ExternalDocs *ExternalDocumentation `json:"externalDocs,omitempty"`
}

// Info provides metadata about the API
type Info struct {
	Title          string   `json:"title"`
	Description    string   `json:"description,omitempty"`
	TermsOfService string   `json:"termsOfService,omitempty"`
	Contact        *Contact `json:"contact,omitempty"`
	License        *License `json:"license,omitempty"`
	Version        string   `json:"version"`
}

// Contact information for the exposed API
type Contact struct {
	Name  string `json:"name,omitempty"`
	URL   string `json:"url,omitempty"`
	Email string `json:"email,omitempty"`
}

// License information for the exposed API
type License struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

// Server represents a server
type Server struct {
	URL         string                     `json:"url"`
	Description string                     `json:"description,omitempty"`
	Variables   map[string]ServerVariable  `json:"variables,omitempty"`
}

// ServerVariable represents a server variable for server URL template substitution
type ServerVariable struct {
	Enum        []string `json:"enum,omitempty"`
	Default     string   `json:"default"`
	Description string   `json:"description,omitempty"`
}

// PathItem describes the operations available on a single path
type PathItem struct {
	Ref         string     `json:"$ref,omitempty"`
	Summary     string     `json:"summary,omitempty"`
	Description string     `json:"description,omitempty"`
	Get         *Operation `json:"get,omitempty"`
	Put         *Operation `json:"put,omitempty"`
	Post        *Operation `json:"post,omitempty"`
	Delete      *Operation `json:"delete,omitempty"`
	Options     *Operation `json:"options,omitempty"`
	Head        *Operation `json:"head,omitempty"`
	Patch       *Operation `json:"patch,omitempty"`
	Trace       *Operation `json:"trace,omitempty"`
	Servers     []Server   `json:"servers,omitempty"`
	Parameters  []Parameter `json:"parameters,omitempty"`
}

// Operation describes a single API operation on a path
type Operation struct {
	Tags         []string               `json:"tags,omitempty"`
	Summary      string                 `json:"summary,omitempty"`
	Description  string                 `json:"description,omitempty"`
	ExternalDocs *ExternalDocumentation `json:"externalDocs,omitempty"`
	OperationID  string                 `json:"operationId,omitempty"`
	Parameters   []Parameter            `json:"parameters,omitempty"`
	RequestBody  *RequestBody           `json:"requestBody,omitempty"`
	Responses    map[string]Response    `json:"responses"`
	Callbacks    map[string]Callback    `json:"callbacks,omitempty"`
	Deprecated   bool                   `json:"deprecated,omitempty"`
	Security     []SecurityRequirement  `json:"security,omitempty"`
	Servers      []Server               `json:"servers,omitempty"`
}

// Parameter describes a single operation parameter
type Parameter struct {
	Name            string      `json:"name"`
	In              string      `json:"in"`
	Description     string      `json:"description,omitempty"`
	Required        bool        `json:"required,omitempty"`
	Deprecated      bool        `json:"deprecated,omitempty"`
	AllowEmptyValue bool        `json:"allowEmptyValue,omitempty"`
	Style           string      `json:"style,omitempty"`
	Explode         bool        `json:"explode,omitempty"`
	AllowReserved   bool        `json:"allowReserved,omitempty"`
	Schema          *Schema     `json:"schema,omitempty"`
	Example         interface{} `json:"example,omitempty"`
	Examples        map[string]Example `json:"examples,omitempty"`
}

// RequestBody describes a single request body
type RequestBody struct {
	Description string                `json:"description,omitempty"`
	Content     map[string]MediaType  `json:"content"`
	Required    bool                  `json:"required,omitempty"`
}

// MediaType provides schema and examples for the media type identified by its key
type MediaType struct {
	Schema   *Schema            `json:"schema,omitempty"`
	Example  interface{}        `json:"example,omitempty"`
	Examples map[string]Example `json:"examples,omitempty"`
	Encoding map[string]Encoding `json:"encoding,omitempty"`
}

// Encoding defines encoding definition applied to a single schema property
type Encoding struct {
	ContentType   string             `json:"contentType,omitempty"`
	Headers       map[string]Header  `json:"headers,omitempty"`
	Style         string             `json:"style,omitempty"`
	Explode       bool               `json:"explode,omitempty"`
	AllowReserved bool               `json:"allowReserved,omitempty"`
}

// Response describes a single response from an API Operation
type Response struct {
	Description string                `json:"description"`
	Headers     map[string]Header     `json:"headers,omitempty"`
	Content     map[string]MediaType  `json:"content,omitempty"`
	Links       map[string]Link       `json:"links,omitempty"`
}

// Header follows the structure of the Parameter Object
type Header struct {
	Description     string      `json:"description,omitempty"`
	Required        bool        `json:"required,omitempty"`
	Deprecated      bool        `json:"deprecated,omitempty"`
	AllowEmptyValue bool        `json:"allowEmptyValue,omitempty"`
	Style           string      `json:"style,omitempty"`
	Explode         bool        `json:"explode,omitempty"`
	AllowReserved   bool        `json:"allowReserved,omitempty"`
	Schema          *Schema     `json:"schema,omitempty"`
	Example         interface{} `json:"example,omitempty"`
	Examples        map[string]Example `json:"examples,omitempty"`
}

// Link represents a possible design-time link for a response
type Link struct {
	OperationRef string                 `json:"operationRef,omitempty"`
	OperationID  string                 `json:"operationId,omitempty"`
	Parameters   map[string]interface{} `json:"parameters,omitempty"`
	RequestBody  interface{}            `json:"requestBody,omitempty"`
	Description  string                 `json:"description,omitempty"`
	Server       *Server                `json:"server,omitempty"`
}

// Callback is a map of possible out-of band callbacks related to the parent operation
type Callback map[string]PathItem

// Example object
type Example struct {
	Summary       string      `json:"summary,omitempty"`
	Description   string      `json:"description,omitempty"`
	Value         interface{} `json:"value,omitempty"`
	ExternalValue string      `json:"externalValue,omitempty"`
}

// Tag adds metadata to a single tag that is used by the Operation Object
type Tag struct {
	Name         string                 `json:"name"`
	Description  string                 `json:"description,omitempty"`
	ExternalDocs *ExternalDocumentation `json:"externalDocs,omitempty"`
}

// ExternalDocumentation allows referencing an external resource for extended documentation
type ExternalDocumentation struct {
	Description string `json:"description,omitempty"`
	URL         string `json:"url"`
}

// Components holds a set of reusable objects for different aspects of the OAS
type Components struct {
	Schemas         map[string]Schema         `json:"schemas,omitempty"`
	Responses       map[string]Response       `json:"responses,omitempty"`
	Parameters      map[string]Parameter      `json:"parameters,omitempty"`
	Examples        map[string]Example        `json:"examples,omitempty"`
	RequestBodies   map[string]RequestBody    `json:"requestBodies,omitempty"`
	Headers         map[string]Header         `json:"headers,omitempty"`
	SecuritySchemes map[string]SecurityScheme `json:"securitySchemes,omitempty"`
	Links           map[string]Link           `json:"links,omitempty"`
	Callbacks       map[string]Callback       `json:"callbacks,omitempty"`
}

// Schema represents a schema object
type Schema struct {
	Type                 string             `json:"type,omitempty"`
	AllOf                []Schema           `json:"allOf,omitempty"`
	OneOf                []Schema           `json:"oneOf,omitempty"`
	AnyOf                []Schema           `json:"anyOf,omitempty"`
	Not                  *Schema            `json:"not,omitempty"`
	Items                *Schema            `json:"items,omitempty"`
	Properties           map[string]Schema  `json:"properties,omitempty"`
	AdditionalProperties interface{}        `json:"additionalProperties,omitempty"`
	Description          string             `json:"description,omitempty"`
	Format               string             `json:"format,omitempty"`
	Default              interface{}        `json:"default,omitempty"`
	Title                string             `json:"title,omitempty"`
	MultipleOf           float64            `json:"multipleOf,omitempty"`
	Maximum              float64            `json:"maximum,omitempty"`
	ExclusiveMaximum     bool               `json:"exclusiveMaximum,omitempty"`
	Minimum              float64            `json:"minimum,omitempty"`
	ExclusiveMinimum     bool               `json:"exclusiveMinimum,omitempty"`
	MaxLength            int                `json:"maxLength,omitempty"`
	MinLength            int                `json:"minLength,omitempty"`
	Pattern              string             `json:"pattern,omitempty"`
	MaxItems             int                `json:"maxItems,omitempty"`
	MinItems             int                `json:"minItems,omitempty"`
	UniqueItems          bool               `json:"uniqueItems,omitempty"`
	MaxProperties        int                `json:"maxProperties,omitempty"`
	MinProperties        int                `json:"minProperties,omitempty"`
	Required             []string           `json:"required,omitempty"`
	Enum                 []interface{}      `json:"enum,omitempty"`
	Example              interface{}        `json:"example,omitempty"`
	Nullable             bool               `json:"nullable,omitempty"`
	Discriminator        *Discriminator     `json:"discriminator,omitempty"`
	ReadOnly             bool               `json:"readOnly,omitempty"`
	WriteOnly            bool               `json:"writeOnly,omitempty"`
	XML                  *XML               `json:"xml,omitempty"`
	ExternalDocs         *ExternalDocumentation `json:"externalDocs,omitempty"`
	Deprecated           bool               `json:"deprecated,omitempty"`
}

// Discriminator object is used to differentiate between the schemas which may satisfy the payload description
type Discriminator struct {
	PropertyName string            `json:"propertyName"`
	Mapping      map[string]string `json:"mapping,omitempty"`
}

// XML object provides additional metadata when translating the JSON Schema to XML
type XML struct {
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Prefix    string `json:"prefix,omitempty"`
	Attribute bool   `json:"attribute,omitempty"`
	Wrapped   bool   `json:"wrapped,omitempty"`
}

// SecurityScheme defines a security scheme that can be used by the operations
type SecurityScheme struct {
	Type             string      `json:"type"`
	Description      string      `json:"description,omitempty"`
	Name             string      `json:"name,omitempty"`
	In               string      `json:"in,omitempty"`
	Scheme           string      `json:"scheme,omitempty"`
	BearerFormat     string      `json:"bearerFormat,omitempty"`
	Flows            *OAuthFlows `json:"flows,omitempty"`
	OpenIDConnectURL string      `json:"openIdConnectUrl,omitempty"`
}

// OAuthFlows allows configuration of the supported OAuth Flows
type OAuthFlows struct {
	Implicit          *OAuthFlow `json:"implicit,omitempty"`
	Password          *OAuthFlow `json:"password,omitempty"`
	ClientCredentials *OAuthFlow `json:"clientCredentials,omitempty"`
	AuthorizationCode *OAuthFlow `json:"authorizationCode,omitempty"`
}

// OAuthFlow configuration details for a supported OAuth Flow
type OAuthFlow struct {
	AuthorizationURL string            `json:"authorizationUrl,omitempty"`
	TokenURL         string            `json:"tokenUrl,omitempty"`
	RefreshURL       string            `json:"refreshUrl,omitempty"`
	Scopes           map[string]string `json:"scopes"`
}

// SecurityRequirement lists the required security schemes to execute this operation
type SecurityRequirement map[string][]string

// Config holds Swagger configuration
type Config struct {
	Enabled     bool   `json:"enabled" yaml:"enabled" env:"SWAGGER_ENABLED" default:"true"`
	Path        string `json:"path" yaml:"path" env:"SWAGGER_PATH" default:"/swagger"`
	JSONPath    string `json:"json_path" yaml:"json_path" env:"SWAGGER_JSON_PATH" default:"/swagger/doc.json"`
	Title       string `json:"title" yaml:"title" env:"SWAGGER_TITLE" default:"Gawan API"`
	Description string `json:"description" yaml:"description" env:"SWAGGER_DESCRIPTION" default:"Gawan Framework API Documentation"`
	Version     string `json:"version" yaml:"version" env:"SWAGGER_VERSION" default:"1.0.0"`
	Host        string `json:"host" yaml:"host" env:"SWAGGER_HOST" default:"localhost:8080"`
	BasePath    string `json:"base_path" yaml:"base_path" env:"SWAGGER_BASE_PATH" default:"/api/v1"`
	Schemes     []string `json:"schemes" yaml:"schemes" env:"SWAGGER_SCHEMES" default:"[\"http\", \"https\"]"`
}

// SwaggerGenerator generates OpenAPI documentation
type SwaggerGenerator struct {
	config    Config
	openAPI   *OpenAPI
	handlers  map[string]map[string]*Operation
	schemas   map[string]Schema
}

// NewSwaggerGenerator creates a new Swagger generator
func NewSwaggerGenerator(config Config) *SwaggerGenerator {
	sg := &SwaggerGenerator{
		config:   config,
		handlers: make(map[string]map[string]*Operation),
		schemas:  make(map[string]Schema),
	}

	// Initialize OpenAPI specification
	sg.openAPI = &OpenAPI{
		OpenAPI: "3.0.3",
		Info: Info{
			Title:       config.Title,
			Description: config.Description,
			Version:     config.Version,
			Contact: &Contact{
				Name:  "Gawan Framework",
				Email: "support@gawan.dev",
			},
			License: &License{
				Name: "MIT",
				URL:  "https://opensource.org/licenses/MIT",
			},
		},
		Servers: []Server{
			{
				URL:         fmt.Sprintf("http://%s%s", config.Host, config.BasePath),
				Description: "Development server",
			},
		},
		Paths: make(map[string]PathItem),
		Components: &Components{
			Schemas:         make(map[string]Schema),
			SecuritySchemes: make(map[string]SecurityScheme),
		},
		Tags: []Tag{
			{
				Name:        "Authentication",
				Description: "Authentication and authorization endpoints",
			},
			{
				Name:        "Users",
				Description: "User management endpoints",
			},
			{
				Name:        "Health",
				Description: "Health check endpoints",
			},
		},
	}

	// Add default security schemes
	sg.AddSecurityScheme("bearerAuth", SecurityScheme{
		Type:         "http",
		Scheme:       "bearer",
		BearerFormat: "JWT",
		Description:  "JWT Bearer token authentication",
	})

	sg.AddSecurityScheme("apiKey", SecurityScheme{
		Type:        "apiKey",
		In:          "header",
		Name:        "X-API-Key",
		Description: "API key authentication",
	})

	// Add common schemas
	sg.addCommonSchemas()

	return sg
}

// AddEndpoint adds an endpoint to the documentation
func (sg *SwaggerGenerator) AddEndpoint(method, path string, operation *Operation) {
	if sg.handlers[path] == nil {
		sg.handlers[path] = make(map[string]*Operation)
	}
	sg.handlers[path][strings.ToLower(method)] = operation
}

// AddSchema adds a schema to the components
func (sg *SwaggerGenerator) AddSchema(name string, schema Schema) {
	sg.schemas[name] = schema
	sg.openAPI.Components.Schemas[name] = schema
}

// AddSecurityScheme adds a security scheme to the components
func (sg *SwaggerGenerator) AddSecurityScheme(name string, scheme SecurityScheme) {
	sg.openAPI.Components.SecuritySchemes[name] = scheme
}

// GenerateFromStruct generates schema from Go struct
func (sg *SwaggerGenerator) GenerateFromStruct(v interface{}) Schema {
	t := reflect.TypeOf(v)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	return sg.generateSchemaFromType(t)
}

// generateSchemaFromType generates schema from reflect.Type
func (sg *SwaggerGenerator) generateSchemaFromType(t reflect.Type) Schema {
	schema := Schema{}

	switch t.Kind() {
	case reflect.String:
		schema.Type = "string"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		schema.Type = "integer"
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		schema.Type = "integer"
	case reflect.Float32, reflect.Float64:
		schema.Type = "number"
	case reflect.Bool:
		schema.Type = "boolean"
	case reflect.Slice, reflect.Array:
		schema.Type = "array"
		itemSchema := sg.generateSchemaFromType(t.Elem())
		schema.Items = &itemSchema
	case reflect.Map:
		schema.Type = "object"
		valueSchema := sg.generateSchemaFromType(t.Elem())
		schema.AdditionalProperties = valueSchema
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

			fieldSchema := sg.generateSchemaFromType(field.Type)

			// Add description from tag
			if desc := field.Tag.Get("description"); desc != "" {
				fieldSchema.Description = desc
			}

			// Add example from tag
			if example := field.Tag.Get("example"); example != "" {
				fieldSchema.Example = example
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
	default:
		schema.Type = "object"
	}

	return schema
}

// Generate generates the complete OpenAPI specification
func (sg *SwaggerGenerator) Generate() *OpenAPI {
	// Convert handlers to paths
	for path, methods := range sg.handlers {
		pathItem := PathItem{}

		for method, operation := range methods {
			switch method {
			case "get":
				pathItem.Get = operation
			case "post":
				pathItem.Post = operation
			case "put":
				pathItem.Put = operation
			case "delete":
				pathItem.Delete = operation
			case "patch":
				pathItem.Patch = operation
			case "options":
				pathItem.Options = operation
			case "head":
				pathItem.Head = operation
			}
		}

		sg.openAPI.Paths[path] = pathItem
	}

	return sg.openAPI
}

// ServeHTTP serves the Swagger UI and JSON documentation
func (sg *SwaggerGenerator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch {
	case path == sg.config.JSONPath:
		// Serve OpenAPI JSON
		w.Header().Set("Content-Type", "application/json")
		spec := sg.Generate()
		json.NewEncoder(w).Encode(spec)

	case path == sg.config.Path || path == sg.config.Path+"/":
		// Serve Swagger UI
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(sg.generateSwaggerUI()))

	default:
		http.NotFound(w, r)
	}
}

// generateSwaggerUI generates the Swagger UI HTML
func (sg *SwaggerGenerator) generateSwaggerUI() string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>%s</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui.css" />
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
            margin:0;
            background: #fafafa;
        }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            const ui = SwaggerUIBundle({
                url: '%s',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout"
            });
        };
    </script>
</body>
</html>
`, sg.config.Title, sg.config.JSONPath)
}

// addCommonSchemas adds common schemas used across the API
func (sg *SwaggerGenerator) addCommonSchemas() {
	// Error response schema
	sg.AddSchema("Error", Schema{
		Type: "object",
		Properties: map[string]Schema{
			"error": {
				Type:        "string",
				Description: "Error message",
				Example:     "Invalid request",
			},
			"code": {
				Type:        "integer",
				Description: "Error code",
				Example:     400,
			},
			"details": {
				Type:        "object",
				Description: "Additional error details",
			},
		},
		Required: []string{"error", "code"},
	})

	// Success response schema
	sg.AddSchema("Success", Schema{
		Type: "object",
		Properties: map[string]Schema{
			"message": {
				Type:        "string",
				Description: "Success message",
				Example:     "Operation completed successfully",
			},
			"data": {
				Type:        "object",
				Description: "Response data",
			},
		},
		Required: []string{"message"},
	})

	// Pagination schema
	sg.AddSchema("Pagination", Schema{
		Type: "object",
		Properties: map[string]Schema{
			"page": {
				Type:        "integer",
				Description: "Current page number",
				Example:     1,
				Minimum:     1,
			},
			"limit": {
				Type:        "integer",
				Description: "Number of items per page",
				Example:     10,
				Minimum:     1,
				Maximum:     100,
			},
			"total": {
				Type:        "integer",
				Description: "Total number of items",
				Example:     100,
			},
			"pages": {
				Type:        "integer",
				Description: "Total number of pages",
				Example:     10,
			},
		},
		Required: []string{"page", "limit", "total", "pages"},
	})

	// Health check schema
	sg.AddSchema("Health", Schema{
		Type: "object",
		Properties: map[string]Schema{
			"status": {
				Type:        "string",
				Description: "Health status",
				Example:     "healthy",
				Enum:        []interface{}{"healthy", "unhealthy", "degraded"},
			},
			"timestamp": {
				Type:        "string",
				Format:      "date-time",
				Description: "Health check timestamp",
				Example:     time.Now().Format(time.RFC3339),
			},
			"version": {
				Type:        "string",
				Description: "Application version",
				Example:     "1.0.0",
			},
			"uptime": {
				Type:        "string",
				Description: "Application uptime",
				Example:     "2h30m15s",
			},
		},
		Required: []string{"status", "timestamp"},
	})
}

// CreateOperation creates a new operation with common defaults
func CreateOperation(summary, description string, tags []string) *Operation {
	return &Operation{
		Summary:     summary,
		Description: description,
		Tags:        tags,
		Responses:   make(map[string]Response),
		Parameters:  make([]Parameter, 0),
	}
}

// AddResponse adds a response to an operation
func (op *Operation) AddResponse(code string, description string, schema *Schema) {
	response := Response{
		Description: description,
	}

	if schema != nil {
		response.Content = map[string]MediaType{
			"application/json": {
				Schema: schema,
			},
		}
	}

	op.Responses[code] = response
}

// AddParameter adds a parameter to an operation
func (op *Operation) AddParameter(name, in, description string, required bool, schema *Schema) {
	param := Parameter{
		Name:        name,
		In:          in,
		Description: description,
		Required:    required,
		Schema:      schema,
	}

	op.Parameters = append(op.Parameters, param)
}

// AddRequestBody adds a request body to an operation
func (op *Operation) AddRequestBody(description string, required bool, schema *Schema) {
	op.RequestBody = &RequestBody{
		Description: description,
		Required:    required,
		Content: map[string]MediaType{
			"application/json": {
				Schema: schema,
			},
		},
	}
}

// AddSecurity adds security requirements to an operation
func (op *Operation) AddSecurity(schemes ...string) {
	for _, scheme := range schemes {
		secReq := SecurityRequirement{
			scheme: []string{},
		}
		op.Security = append(op.Security, secReq)
	}
}