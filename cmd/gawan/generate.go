package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

type generateOptions struct {
	componentType string
	name          string
	packageName   string
	outputDir     string
	force         bool
	withTests     bool
	withInterface bool
	fields        []string
}

func newGenerateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "generate",
		Aliases: []string{"gen", "g"},
		Short:   "Generate code components",
		Long:    `Generate various code components like controllers, services, models, etc.`,
	}

	// Add subcommands for different component types
	cmd.AddCommand(newGenerateControllerCmd())
	cmd.AddCommand(newGenerateServiceCmd())
	cmd.AddCommand(newGenerateModelCmd())
	cmd.AddCommand(newGenerateMiddlewareCmd())
	cmd.AddCommand(newGenerateRepositoryCmd())
	cmd.AddCommand(newGenerateHandlerCmd())

	return cmd
}

func newGenerateControllerCmd() *cobra.Command {
	opts := &generateOptions{componentType: "controller"}

	cmd := &cobra.Command{
		Use:   "controller [name]",
		Short: "Generate a new controller",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.name = args[0]
			return runGenerate(opts)
		},
	}

	addCommonFlags(cmd, opts)
	cmd.Flags().StringSliceVar(&opts.fields, "actions", []string{"Create", "Read", "Update", "Delete"}, "Controller actions to generate")

	return cmd
}

func newGenerateServiceCmd() *cobra.Command {
	opts := &generateOptions{componentType: "service"}

	cmd := &cobra.Command{
		Use:   "service [name]",
		Short: "Generate a new service",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.name = args[0]
			return runGenerate(opts)
		},
	}

	addCommonFlags(cmd, opts)
	cmd.Flags().BoolVar(&opts.withInterface, "with-interface", true, "Generate interface along with implementation")

	return cmd
}

func newGenerateModelCmd() *cobra.Command {
	opts := &generateOptions{componentType: "model"}

	cmd := &cobra.Command{
		Use:   "model [name]",
		Short: "Generate a new model",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.name = args[0]
			return runGenerate(opts)
		},
	}

	addCommonFlags(cmd, opts)
	cmd.Flags().StringSliceVar(&opts.fields, "fields", nil, "Model fields (format: name:type:tag)")

	return cmd
}

func newGenerateMiddlewareCmd() *cobra.Command {
	opts := &generateOptions{componentType: "middleware"}

	cmd := &cobra.Command{
		Use:   "middleware [name]",
		Short: "Generate a new middleware",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.name = args[0]
			return runGenerate(opts)
		},
	}

	addCommonFlags(cmd, opts)

	return cmd
}

func newGenerateRepositoryCmd() *cobra.Command {
	opts := &generateOptions{componentType: "repository"}

	cmd := &cobra.Command{
		Use:   "repository [name]",
		Short: "Generate a new repository",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.name = args[0]
			return runGenerate(opts)
		},
	}

	addCommonFlags(cmd, opts)
	cmd.Flags().BoolVar(&opts.withInterface, "with-interface", true, "Generate interface along with implementation")

	return cmd
}

func newGenerateHandlerCmd() *cobra.Command {
	opts := &generateOptions{componentType: "handler"}

	cmd := &cobra.Command{
		Use:   "handler [name]",
		Short: "Generate a new HTTP handler",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.name = args[0]
			return runGenerate(opts)
		},
	}

	addCommonFlags(cmd, opts)
	cmd.Flags().StringSliceVar(&opts.fields, "methods", []string{"GET", "POST", "PUT", "DELETE"}, "HTTP methods to generate")

	return cmd
}

func addCommonFlags(cmd *cobra.Command, opts *generateOptions) {
	cmd.Flags().StringVarP(&opts.packageName, "package", "p", "", "Package name (default: component type)")
	cmd.Flags().StringVarP(&opts.outputDir, "output", "o", "", "Output directory (default: inferred from component type)")
	cmd.Flags().BoolVarP(&opts.force, "force", "f", false, "Force overwrite existing files")
	cmd.Flags().BoolVar(&opts.withTests, "with-tests", true, "Generate test files")
}

func runGenerate(opts *generateOptions) error {
	// Validate component name
	if !isValidComponentName(opts.name) {
		return fmt.Errorf("invalid component name: %s", opts.name)
	}

	// Set default package name
	if opts.packageName == "" {
		opts.packageName = opts.componentType
	}

	// Set default output directory
	if opts.outputDir == "" {
		opts.outputDir = getDefaultOutputDir(opts.componentType)
	}

	// Check if we're in a Gawan project
	if !isGawanProject() {
		return fmt.Errorf("not in a Gawan project directory (no go.mod found with gawan dependency)")
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(opts.outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	fmt.Printf("Generating %s '%s' in %s\n", opts.componentType, opts.name, opts.outputDir)

	// Generate component based on type
	generator := &ComponentGenerator{
		Type:          opts.componentType,
		Name:          opts.name,
		PackageName:   opts.packageName,
		OutputDir:     opts.outputDir,
		Force:         opts.force,
		WithTests:     opts.withTests,
		WithInterface: opts.withInterface,
		Fields:        opts.fields,
	}

	files, err := generator.Generate()
	if err != nil {
		return fmt.Errorf("failed to generate %s: %w", opts.componentType, err)
	}

	fmt.Printf("\n✅ Generated %s '%s' successfully!\n", opts.componentType, opts.name)
	fmt.Printf("Files created:\n")
	for _, file := range files {
		fmt.Printf("  %s\n", file)
	}

	return nil
}



func getDefaultOutputDir(componentType string) string {
	switch componentType {
	case "controller":
		return "internal/app/controllers"
	case "service":
		return "internal/app/services"
	case "model":
		return "internal/app/models"
	case "middleware":
		return "internal/app/middleware"
	case "repository":
		return "internal/app/repositories"
	case "handler":
		return "internal/app/handlers"
	default:
		return "internal/app"
	}
}



// findProjectRoot finds the root of the Gawan project by looking for go.mod
func findProjectRoot() (string, error) {
	currentDir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	dir := currentDir
	for {
		goModPath := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
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