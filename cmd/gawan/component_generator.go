package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

// ComponentGenerator generates individual components
type ComponentGenerator struct {
	Type          string
	Name          string
	PackageName   string
	OutputDir     string
	Force         bool
	WithTests     bool
	WithInterface bool
	Fields        []string
}

// Generate creates the component files
func (cg *ComponentGenerator) Generate() ([]string, error) {
	var generatedFiles []string

	// Generate main component file
	mainFile, err := cg.generateMainFile()
	if err != nil {
		return nil, fmt.Errorf("failed to generate main file: %w", err)
	}
	generatedFiles = append(generatedFiles, mainFile)

	// Generate interface file if requested
	if cg.WithInterface && (cg.Type == "service" || cg.Type == "repository") {
		interfaceFile, err := cg.generateInterfaceFile()
		if err != nil {
			return nil, fmt.Errorf("failed to generate interface file: %w", err)
		}
		generatedFiles = append(generatedFiles, interfaceFile)
	}

	// Generate test file if requested
	if cg.WithTests {
		testFile, err := cg.generateTestFile()
		if err != nil {
			return nil, fmt.Errorf("failed to generate test file: %w", err)
		}
		generatedFiles = append(generatedFiles, testFile)
	}

	return generatedFiles, nil
}

func (cg *ComponentGenerator) generateMainFile() (string, error) {
	filename := fmt.Sprintf("%s.go", toSnakeCase(cg.Name))
	filePath := filepath.Join(cg.OutputDir, filename)

	// Check if file exists and force is not set
	if _, err := os.Stat(filePath); err == nil && !cg.Force {
		return "", fmt.Errorf("file %s already exists (use --force to overwrite)", filePath)
	}

	tmplContent := cg.getMainTemplate()
	if tmplContent == "" {
		return "", fmt.Errorf("no template found for component type: %s", cg.Type)
	}

	return cg.generateFileFromTemplate(filePath, tmplContent)
}

func (cg *ComponentGenerator) generateInterfaceFile() (string, error) {
	filename := fmt.Sprintf("%s_interface.go", toSnakeCase(cg.Name))
	filePath := filepath.Join(cg.OutputDir, filename)

	// Check if file exists and force is not set
	if _, err := os.Stat(filePath); err == nil && !cg.Force {
		return "", fmt.Errorf("file %s already exists (use --force to overwrite)", filePath)
	}

	tmplContent := cg.getInterfaceTemplate()
	if tmplContent == "" {
		return "", fmt.Errorf("no interface template found for component type: %s", cg.Type)
	}

	return cg.generateFileFromTemplate(filePath, tmplContent)
}

func (cg *ComponentGenerator) generateTestFile() (string, error) {
	filename := fmt.Sprintf("%s_test.go", toSnakeCase(cg.Name))
	filePath := filepath.Join(cg.OutputDir, filename)

	// Check if file exists and force is not set
	if _, err := os.Stat(filePath); err == nil && !cg.Force {
		return "", fmt.Errorf("file %s already exists (use --force to overwrite)", filePath)
	}

	tmplContent := cg.getTestTemplate()
	if tmplContent == "" {
		return "", fmt.Errorf("no test template found for component type: %s", cg.Type)
	}

	return cg.generateFileFromTemplate(filePath, tmplContent)
}

func (cg *ComponentGenerator) generateFileFromTemplate(filePath, tmplContent string) (string, error) {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}

	// Parse and execute template with function map
	tmpl, err := template.New(filepath.Base(filePath)).Funcs(funcMap()).Parse(tmplContent)
	if err != nil {
		return "", err
	}

	f, err := os.Create(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	data := cg.getTemplateData()
	if err := tmpl.Execute(f, data); err != nil {
		return "", err
	}

	return filePath, nil
}

func (cg *ComponentGenerator) getTemplateData() map[string]interface{} {
	return map[string]interface{}{
		"PackageName":    cg.PackageName,
		"ComponentName":  toPascalCase(cg.Name),
		"ComponentType":  cg.Type,
		"VariableName":   toCamelCase(cg.Name),
		"SnakeCaseName":  toSnakeCase(cg.Name),
		"Fields":         cg.parseFields(),
		"Actions":        cg.Fields, // For controllers
		"Methods":        cg.Fields, // For handlers
	}
}

func (cg *ComponentGenerator) parseFields() []Field {
	var fields []Field
	for _, fieldStr := range cg.Fields {
		parts := strings.Split(fieldStr, ":")
		if len(parts) >= 2 {
			field := Field{
				Name: toPascalCase(parts[0]),
				Type: parts[1],
			}
			if len(parts) >= 3 {
				field.Tag = parts[2]
			}
			fields = append(fields, field)
		}
	}
	return fields
}

type Field struct {
	Name string
	Type string
	Tag  string
}

func (cg *ComponentGenerator) getMainTemplate() string {
	switch cg.Type {
	case "controller":
		return controllerTemplate
	case "service":
		return serviceTemplate
	case "model":
		return modelTemplate
	case "middleware":
		return middlewareTemplate
	case "repository":
		return repositoryTemplate
	case "handler":
		return handlerTemplate
	default:
		return ""
	}
}

func (cg *ComponentGenerator) getInterfaceTemplate() string {
	switch cg.Type {
	case "service":
		return serviceInterfaceTemplate
	case "repository":
		return repositoryInterfaceTemplate
	default:
		return ""
	}
}

func (cg *ComponentGenerator) getTestTemplate() string {
	switch cg.Type {
	case "controller":
		return controllerTestTemplate
	case "service":
		return serviceTestTemplate
	case "model":
		return modelTestTemplate
	case "middleware":
		return middlewareTestTemplate
	case "repository":
		return repositoryTestTemplate
	case "handler":
		return handlerTestTemplate
	default:
		return ""
	}
}

// Component templates
const controllerTemplate = `package {{.PackageName}}

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// {{.ComponentName}}Controller handles {{.ComponentName}} requests
type {{.ComponentName}}Controller struct {
	// Add dependencies here (services, repositories, etc.)
}

// New{{.ComponentName}}Controller creates a new {{.ComponentName}} controller
func New{{.ComponentName}}Controller() *{{.ComponentName}}Controller {
	return &{{.ComponentName}}Controller{}
}

{{range .Actions}}
// {{.}} handles {{.}} requests for {{$.ComponentName}}
func (c *{{$.ComponentName}}Controller) {{.}}(ctx *gin.Context) {
	{{if eq . "Create"}}
	// TODO: Implement create logic
	ctx.JSON(http.StatusCreated, gin.H{
		"message": "{{$.ComponentName}} created successfully",
	})
	{{else if eq . "Read"}}
	// Get ID from URL parameter
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "ID is required",
		})
		return
	}
	
	// TODO: Implement read logic
	ctx.JSON(http.StatusOK, gin.H{
		"id": id,
		"message": "{{$.ComponentName}} retrieved successfully",
	})
	{{else if eq . "Update"}}
	// Get ID from URL parameter
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "ID is required",
		})
		return
	}
	
	// TODO: Implement update logic
	ctx.JSON(http.StatusOK, gin.H{
		"id": id,
		"message": "{{$.ComponentName}} updated successfully",
	})
	{{else if eq . "Delete"}}
	// Get ID from URL parameter
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "ID is required",
		})
		return
	}
	
	// TODO: Implement delete logic
	ctx.JSON(http.StatusOK, gin.H{
		"message": "{{$.ComponentName}} deleted successfully",
	})
	{{else}}
	// TODO: Implement {{.}} logic
	ctx.JSON(http.StatusOK, gin.H{
		"message": "{{$.ComponentName}} {{.}} executed successfully",
	})
	{{end}}
}

{{end}}
`

const serviceTemplate = `package {{.PackageName}}

import (
	"context"
	"fmt"
)

// {{.ComponentName}}Service provides {{.ComponentName}} business logic
type {{.ComponentName}}Service struct {
	// Add dependencies here (repositories, external services, etc.)
}

// New{{.ComponentName}}Service creates a new {{.ComponentName}} service
func New{{.ComponentName}}Service() *{{.ComponentName}}Service {
	return &{{.ComponentName}}Service{}
}

// Create creates a new {{.ComponentName}}
func (s *{{.ComponentName}}Service) Create(ctx context.Context, data interface{}) error {
	// TODO: Implement create logic
	return fmt.Errorf("not implemented")
}

// GetByID retrieves a {{.ComponentName}} by ID
func (s *{{.ComponentName}}Service) GetByID(ctx context.Context, id string) (interface{}, error) {
	// TODO: Implement get by ID logic
	return nil, fmt.Errorf("not implemented")
}

// Update updates a {{.ComponentName}}
func (s *{{.ComponentName}}Service) Update(ctx context.Context, id string, data interface{}) error {
	// TODO: Implement update logic
	return fmt.Errorf("not implemented")
}

// Delete deletes a {{.ComponentName}}
func (s *{{.ComponentName}}Service) Delete(ctx context.Context, id string) error {
	// TODO: Implement delete logic
	return fmt.Errorf("not implemented")
}

// List retrieves all {{.ComponentName}}s
func (s *{{.ComponentName}}Service) List(ctx context.Context) ([]interface{}, error) {
	// TODO: Implement list logic
	return nil, fmt.Errorf("not implemented")
}
`

const modelTemplate = `package {{.PackageName}}

import (
	"time"
)

// {{.ComponentName}} represents a {{.ComponentName}} entity
type {{.ComponentName}} struct {
	ID        uint      ` + "`" + `json:"id" gorm:"primaryKey"` + "`" + `
	CreatedAt time.Time ` + "`" + `json:"created_at"` + "`" + `
	UpdatedAt time.Time ` + "`" + `json:"updated_at"` + "`" + `
{{range .Fields}}
	{{.Name}} {{.Type}} ` + "`" + `json:"{{$.SnakeCaseName}}_{{.Name | ToSnakeCase}}"{{if .Tag}} {{.Tag}}{{end}}` + "`" + `
{{end}}
}

// TableName returns the table name for the {{.ComponentName}} model
func ({{.ComponentName}}) TableName() string {
	return "{{.SnakeCaseName}}s"
}

// Validate validates the {{.ComponentName}} model
func (m *{{.ComponentName}}) Validate() error {
	// TODO: Add validation logic
	return nil
}

// BeforeCreate is called before creating a {{.ComponentName}}
func (m *{{.ComponentName}}) BeforeCreate() error {
	// TODO: Add pre-creation logic
	return nil
}

// AfterCreate is called after creating a {{.ComponentName}}
func (m *{{.ComponentName}}) AfterCreate() error {
	// TODO: Add post-creation logic
	return nil
}
`

const middlewareTemplate = `package {{.PackageName}}

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// {{.ComponentName}}Middleware provides {{.ComponentName}} middleware functionality
func {{.ComponentName}}Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Implement middleware logic
		
		// Example: Add custom header
		c.Header("X-{{.ComponentName}}-Middleware", "active")
		
		// Continue to next handler
		c.Next()
		
		// TODO: Add post-processing logic if needed
	}
}

// {{.ComponentName}}MiddlewareWithConfig provides configurable {{.ComponentName}} middleware
func {{.ComponentName}}MiddlewareWithConfig(config {{.ComponentName}}Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Implement configurable middleware logic
		
		// Example: Check configuration
		if !config.Enabled {
			c.Next()
			return
		}
		
		// TODO: Add your middleware logic here
		
		c.Next()
	}
}

// {{.ComponentName}}Config holds configuration for {{.ComponentName}} middleware
type {{.ComponentName}}Config struct {
	Enabled bool
	// TODO: Add more configuration options
}

// Default{{.ComponentName}}Config returns default configuration
func Default{{.ComponentName}}Config() {{.ComponentName}}Config {
	return {{.ComponentName}}Config{
		Enabled: true,
	}
}
`

const repositoryTemplate = `package {{.PackageName}}

import (
	"context"
	"fmt"
)

// {{.ComponentName}}Repository handles {{.ComponentName}} data access
type {{.ComponentName}}Repository struct {
	// Add database connection or other dependencies here
}

// New{{.ComponentName}}Repository creates a new {{.ComponentName}} repository
func New{{.ComponentName}}Repository() *{{.ComponentName}}Repository {
	return &{{.ComponentName}}Repository{}
}

// Create creates a new {{.ComponentName}} in the database
func (r *{{.ComponentName}}Repository) Create(ctx context.Context, entity interface{}) error {
	// TODO: Implement database create logic
	return fmt.Errorf("not implemented")
}

// GetByID retrieves a {{.ComponentName}} by ID from the database
func (r *{{.ComponentName}}Repository) GetByID(ctx context.Context, id string) (interface{}, error) {
	// TODO: Implement database get by ID logic
	return nil, fmt.Errorf("not implemented")
}

// Update updates a {{.ComponentName}} in the database
func (r *{{.ComponentName}}Repository) Update(ctx context.Context, id string, entity interface{}) error {
	// TODO: Implement database update logic
	return fmt.Errorf("not implemented")
}

// Delete deletes a {{.ComponentName}} from the database
func (r *{{.ComponentName}}Repository) Delete(ctx context.Context, id string) error {
	// TODO: Implement database delete logic
	return fmt.Errorf("not implemented")
}

// List retrieves all {{.ComponentName}}s from the database
func (r *{{.ComponentName}}Repository) List(ctx context.Context) ([]interface{}, error) {
	// TODO: Implement database list logic
	return nil, fmt.Errorf("not implemented")
}

// FindBy finds {{.ComponentName}}s by specific criteria
func (r *{{.ComponentName}}Repository) FindBy(ctx context.Context, criteria map[string]interface{}) ([]interface{}, error) {
	// TODO: Implement database find by criteria logic
	return nil, fmt.Errorf("not implemented")
}
`

const handlerTemplate = `package {{.PackageName}}

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// {{.ComponentName}}Handler handles {{.ComponentName}} HTTP requests
type {{.ComponentName}}Handler struct {
	// Add dependencies here (services, etc.)
}

// New{{.ComponentName}}Handler creates a new {{.ComponentName}} handler
func New{{.ComponentName}}Handler() *{{.ComponentName}}Handler {
	return &{{.ComponentName}}Handler{}
}

{{range .Methods}}
// Handle{{.}} handles {{.}} requests for {{$.ComponentName}}
func (h *{{$.ComponentName}}Handler) Handle{{.}}(c *gin.Context) {
	{{if eq . "GET"}}
	// TODO: Implement GET logic
	c.JSON(http.StatusOK, gin.H{
		"message": "{{$.ComponentName}} GET request handled",
		"method": "{{.}}",
	})
	{{else if eq . "POST"}}
	// TODO: Implement POST logic
	c.JSON(http.StatusCreated, gin.H{
		"message": "{{$.ComponentName}} POST request handled",
		"method": "{{.}}",
	})
	{{else if eq . "PUT"}}
	// TODO: Implement PUT logic
	c.JSON(http.StatusOK, gin.H{
		"message": "{{$.ComponentName}} PUT request handled",
		"method": "{{.}}",
	})
	{{else if eq . "DELETE"}}
	// TODO: Implement DELETE logic
	c.JSON(http.StatusOK, gin.H{
		"message": "{{$.ComponentName}} DELETE request handled",
		"method": "{{.}}",
	})
	{{else}}
	// TODO: Implement {{.}} logic
	c.JSON(http.StatusOK, gin.H{
		"message": "{{$.ComponentName}} {{.}} request handled",
		"method": "{{.}}",
	})
	{{end}}
}

{{end}}
`

// Interface templates
const serviceInterfaceTemplate = `package {{.PackageName}}

import "context"

// {{.ComponentName}}ServiceInterface defines the contract for {{.ComponentName}} service
type {{.ComponentName}}ServiceInterface interface {
	Create(ctx context.Context, data interface{}) error
	GetByID(ctx context.Context, id string) (interface{}, error)
	Update(ctx context.Context, id string, data interface{}) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context) ([]interface{}, error)
}
`

const repositoryInterfaceTemplate = `package {{.PackageName}}

import "context"

// {{.ComponentName}}RepositoryInterface defines the contract for {{.ComponentName}} repository
type {{.ComponentName}}RepositoryInterface interface {
	Create(ctx context.Context, entity interface{}) error
	GetByID(ctx context.Context, id string) (interface{}, error)
	Update(ctx context.Context, id string, entity interface{}) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context) ([]interface{}, error)
	FindBy(ctx context.Context, criteria map[string]interface{}) ([]interface{}, error)
}
`

// Test templates
const controllerTestTemplate = `package {{.PackageName}}

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func Test{{.ComponentName}}Controller_Create(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	router := gin.New()
	controller := New{{.ComponentName}}Controller()
	
	// TODO: Setup routes
	// router.POST("/{{.SnakeCaseName}}", controller.Create)
	
	// Test cases
	t.Run("should create {{.ComponentName}} successfully", func(t *testing.T) {
		// TODO: Implement test
		t.Skip("Test not implemented yet")
	})
}

func Test{{.ComponentName}}Controller_Read(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	router := gin.New()
	controller := New{{.ComponentName}}Controller()
	
	// TODO: Setup routes
	// router.GET("/{{.SnakeCaseName}}/:id", controller.Read)
	
	// Test cases
	t.Run("should read {{.ComponentName}} successfully", func(t *testing.T) {
		// TODO: Implement test
		t.Skip("Test not implemented yet")
	})
}
`

const serviceTestTemplate = `package {{.PackageName}}

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test{{.ComponentName}}Service_Create(t *testing.T) {
	// Setup
	service := New{{.ComponentName}}Service()
	ctx := context.Background()
	
	// Test cases
	t.Run("should create {{.ComponentName}} successfully", func(t *testing.T) {
		// TODO: Implement test
		err := service.Create(ctx, nil)
		assert.Error(t, err) // Currently returns "not implemented"
	})
}

func Test{{.ComponentName}}Service_GetByID(t *testing.T) {
	// Setup
	service := New{{.ComponentName}}Service()
	ctx := context.Background()
	
	// Test cases
	t.Run("should get {{.ComponentName}} by ID successfully", func(t *testing.T) {
		// TODO: Implement test
		result, err := service.GetByID(ctx, "1")
		assert.Error(t, err) // Currently returns "not implemented"
		assert.Nil(t, result)
	})
}
`

const modelTestTemplate = `package {{.PackageName}}

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test{{.ComponentName}}_TableName(t *testing.T) {
	model := {{.ComponentName}}{}
	expected := "{{.SnakeCaseName}}s"
	actual := model.TableName()
	assert.Equal(t, expected, actual)
}

func Test{{.ComponentName}}_Validate(t *testing.T) {
	t.Run("should validate {{.ComponentName}} successfully", func(t *testing.T) {
		model := {{.ComponentName}}{}
		err := model.Validate()
		assert.NoError(t, err)
	})
}
`

const middlewareTestTemplate = `package {{.PackageName}}

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func Test{{.ComponentName}}Middleware(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use({{.ComponentName}}Middleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "test"})
	})
	
	// Test
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)
	
	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "active", w.Header().Get("X-{{.ComponentName}}-Middleware"))
}

func Test{{.ComponentName}}MiddlewareWithConfig(t *testing.T) {
	t.Run("should work when enabled", func(t *testing.T) {
		// Setup
		gin.SetMode(gin.TestMode)
		router := gin.New()
		config := {{.ComponentName}}Config{Enabled: true}
		router.Use({{.ComponentName}}MiddlewareWithConfig(config))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "test"})
		})
		
		// Test
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)
		
		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)
	})
	
	t.Run("should skip when disabled", func(t *testing.T) {
		// Setup
		gin.SetMode(gin.TestMode)
		router := gin.New()
		config := {{.ComponentName}}Config{Enabled: false}
		router.Use({{.ComponentName}}MiddlewareWithConfig(config))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "test"})
		})
		
		// Test
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)
		
		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)
	})
}
`

const repositoryTestTemplate = `package {{.PackageName}}

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test{{.ComponentName}}Repository_Create(t *testing.T) {
	// Setup
	repo := New{{.ComponentName}}Repository()
	ctx := context.Background()
	
	// Test cases
	t.Run("should create {{.ComponentName}} successfully", func(t *testing.T) {
		// TODO: Implement test
		err := repo.Create(ctx, nil)
		assert.Error(t, err) // Currently returns "not implemented"
	})
}

func Test{{.ComponentName}}Repository_GetByID(t *testing.T) {
	// Setup
	repo := New{{.ComponentName}}Repository()
	ctx := context.Background()
	
	// Test cases
	t.Run("should get {{.ComponentName}} by ID successfully", func(t *testing.T) {
		// TODO: Implement test
		result, err := repo.GetByID(ctx, "1")
		assert.Error(t, err) // Currently returns "not implemented"
		assert.Nil(t, result)
	})
}
`

const handlerTestTemplate = `package {{.PackageName}}

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

{{range .Methods}}
func Test{{$.ComponentName}}Handler_Handle{{.}}(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := New{{$.ComponentName}}Handler()
	
	// TODO: Setup routes
	// router.{{. | ToUpper}}("/{{$.SnakeCaseName}}", handler.Handle{{.}})
	
	// Test cases
	t.Run("should handle {{.}} request successfully", func(t *testing.T) {
		// TODO: Implement test
		t.Skip("Test not implemented yet")
	})
}

{{end}}
`