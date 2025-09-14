package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// String manipulation utilities

// toPascalCase converts a string to PascalCase
func toPascalCase(s string) string {
	if s == "" {
		return s
	}
	
	// Split by common delimiters
	words := splitWords(s)
	var result strings.Builder
	
	for _, word := range words {
		if len(word) > 0 {
			result.WriteString(strings.ToUpper(string(word[0])))
			if len(word) > 1 {
				result.WriteString(strings.ToLower(word[1:]))
			}
		}
	}
	
	return result.String()
}

// toCamelCase converts a string to camelCase
func toCamelCase(s string) string {
	if s == "" {
		return s
	}
	
	pascal := toPascalCase(s)
	if len(pascal) == 0 {
		return pascal
	}
	
	return strings.ToLower(string(pascal[0])) + pascal[1:]
}

// toSnakeCase converts a string to snake_case
func toSnakeCase(s string) string {
	if s == "" {
		return s
	}
	
	// Handle camelCase and PascalCase
	re := regexp.MustCompile(`([a-z0-9])([A-Z])`)
	s = re.ReplaceAllString(s, `${1}_${2}`)
	
	// Replace common delimiters with underscores
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, ".", "_")
	
	// Remove multiple underscores
	re = regexp.MustCompile(`_+`)
	s = re.ReplaceAllString(s, "_")
	
	// Trim underscores from start and end
	s = strings.Trim(s, "_")
	
	return strings.ToLower(s)
}

// toKebabCase converts a string to kebab-case
func toKebabCase(s string) string {
	return strings.ReplaceAll(toSnakeCase(s), "_", "-")
}

// splitWords splits a string into words by common delimiters
func splitWords(s string) []string {
	if s == "" {
		return []string{}
	}
	
	// Split by common delimiters
	re := regexp.MustCompile(`[\s\-_\.]+`)
	words := re.Split(s, -1)
	
	// Handle camelCase/PascalCase
	var result []string
	for _, word := range words {
		if word == "" {
			continue
		}
		
		// Split camelCase/PascalCase
		camelWords := splitCamelCase(word)
		result = append(result, camelWords...)
	}
	
	return result
}

// splitCamelCase splits camelCase or PascalCase strings
func splitCamelCase(s string) []string {
	if s == "" {
		return []string{}
	}
	
	var words []string
	var currentWord strings.Builder
	
	for i, r := range s {
		if i > 0 && unicode.IsUpper(r) && (i == len(s)-1 || unicode.IsLower(rune(s[i+1])) || unicode.IsLower(rune(s[i-1]))) {
			if currentWord.Len() > 0 {
				words = append(words, currentWord.String())
				currentWord.Reset()
			}
		}
		currentWord.WriteRune(r)
	}
	
	if currentWord.Len() > 0 {
		words = append(words, currentWord.String())
	}
	
	return words
}

// File and directory utilities

// ensureDir creates a directory if it doesn't exist
func ensureDir(path string) error {
	return os.MkdirAll(path, 0755)
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// dirExists checks if a directory exists
func dirExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

// isEmptyDir checks if a directory is empty
func isEmptyDir(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	
	_, err = f.Readdirnames(1)
	if err != nil {
		if err.Error() == "EOF" {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

// getProjectRoot finds the project root directory by looking for go.mod
func getProjectRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	
	dir := cwd
	for {
		goModPath := filepath.Join(dir, "go.mod")
		if fileExists(goModPath) {
			return dir, nil
		}
		
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached root directory
			break
		}
		dir = parent
	}
	
	return "", fmt.Errorf("go.mod not found in current directory or any parent directory")
}

// getModuleName extracts the module name from go.mod file
func getModuleName(projectRoot string) (string, error) {
	goModPath := filepath.Join(projectRoot, "go.mod")
	content, err := os.ReadFile(goModPath)
	if err != nil {
		return "", err
	}
	
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module")), nil
		}
	}
	
	return "", fmt.Errorf("module declaration not found in go.mod")
}

// Validation utilities

// isValidProjectName validates a project name
func isValidProjectName(name string) bool {
	if name == "" {
		return false
	}
	
	// Check for valid Go identifier characters
	re := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]*$`)
	return re.MatchString(name)
}

// isValidComponentName validates a component name
func isValidComponentName(name string) bool {
	if name == "" {
		return false
	}
	
	// Check for valid Go identifier characters
	re := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*$`)
	return re.MatchString(name)
}

// isValidPackageName validates a package name
func isValidPackageName(name string) bool {
	if name == "" {
		return false
	}
	
	// Package names should be lowercase and contain only letters, numbers, and underscores
	re := regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	return re.MatchString(name)
}

// Path utilities

// resolveOutputDir resolves the output directory for generated files
func resolveOutputDir(outputDir, componentType string) (string, error) {
	if outputDir != "" {
		// Use provided output directory
		if filepath.IsAbs(outputDir) {
			return outputDir, nil
		}
		
		// Make relative to current directory
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		return filepath.Join(cwd, outputDir), nil
	}
	
	// Auto-detect based on component type and project structure
	projectRoot, err := getProjectRoot()
	if err != nil {
		return "", err
	}
	
	// Default directory mappings
	var defaultDir string
	switch componentType {
	case "controller":
		defaultDir = "internal/controllers"
	case "service":
		defaultDir = "internal/services"
	case "model":
		defaultDir = "internal/models"
	case "middleware":
		defaultDir = "internal/middleware"
	case "repository":
		defaultDir = "internal/repositories"
	case "handler":
		defaultDir = "internal/handlers"
	default:
		defaultDir = "internal"
	}
	
	return filepath.Join(projectRoot, defaultDir), nil
}

// inferPackageName infers the package name from the output directory
func inferPackageName(outputDir string) string {
	// Get the last directory name
	packageName := filepath.Base(outputDir)
	
	// Convert to valid package name
	packageName = strings.ToLower(packageName)
	packageName = strings.ReplaceAll(packageName, "-", "")
	packageName = strings.ReplaceAll(packageName, "_", "")
	
	// Ensure it starts with a letter
	if len(packageName) > 0 && !unicode.IsLetter(rune(packageName[0])) {
		packageName = "pkg" + packageName
	}
	
	// Fallback to "main" if empty or invalid
	if packageName == "" || !isValidPackageName(packageName) {
		return "main"
	}
	
	return packageName
}

// Template utilities

// funcMap returns template functions for use in templates
func funcMap() map[string]interface{} {
	return map[string]interface{}{
		"ToSnakeCase":  toSnakeCase,
		"ToCamelCase":  toCamelCase,
		"ToPascalCase": toPascalCase,
		"ToKebabCase":  toKebabCase,
		"ToUpper":      strings.ToUpper,
		"ToLower":      strings.ToLower,
		"Title":        strings.Title,
	}
}

// Color utilities for CLI output

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
	ColorBold   = "\033[1m"
)

// colorize adds color to text
func colorize(color, text string) string {
	return color + text + ColorReset
}

// success prints a success message
func success(msg string) {
	fmt.Println(colorize(ColorGreen, "✓ "+msg))
}

// warning prints a warning message
func warning(msg string) {
	fmt.Println(colorize(ColorYellow, "⚠ "+msg))
}

// errorMsg prints an error message
func errorMsg(msg string) {
	fmt.Println(colorize(ColorRed, "✗ "+msg))
}

// info prints an info message
func info(msg string) {
	fmt.Println(colorize(ColorBlue, "ℹ "+msg))
}

// header prints a header message
func header(msg string) {
	fmt.Println(colorize(ColorBold+ColorCyan, msg))
}

// Progress utilities

// ProgressBar represents a simple progress bar
type ProgressBar struct {
	total   int
	current int
	width   int
}

// NewProgressBar creates a new progress bar
func NewProgressBar(total int) *ProgressBar {
	return &ProgressBar{
		total: total,
		width: 50,
	}
}

// Update updates the progress bar
func (pb *ProgressBar) Update(current int) {
	pb.current = current
	pb.render()
}

// Increment increments the progress bar
func (pb *ProgressBar) Increment() {
	pb.current++
	pb.render()
}

// Finish completes the progress bar
func (pb *ProgressBar) Finish() {
	pb.current = pb.total
	pb.render()
	fmt.Println()
}

// render renders the progress bar
func (pb *ProgressBar) render() {
	percentage := float64(pb.current) / float64(pb.total)
	filledWidth := int(percentage * float64(pb.width))
	
	bar := strings.Repeat("█", filledWidth) + strings.Repeat("░", pb.width-filledWidth)
	percentStr := fmt.Sprintf("%.1f%%", percentage*100)
	
	fmt.Printf("\r[%s] %s (%d/%d)", bar, percentStr, pb.current, pb.total)
}