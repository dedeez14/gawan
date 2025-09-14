package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

type newOptions struct {
	name        string
	modulePath  string
	directory   string
	template    string
	force       bool
	noGit       bool
	noMod       bool
}

func newNewCmd() *cobra.Command {
	opts := &newOptions{}

	cmd := &cobra.Command{
		Use:   "new [project-name]",
		Short: "Create a new Gawan project",
		Long: `Create a new Gawan project with the specified name.
This will generate a complete project structure with all necessary files.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.name = args[0]
			return runNew(opts)
		},
	}

	cmd.Flags().StringVarP(&opts.modulePath, "module", "m", "", "Go module path (default: project name)")
	cmd.Flags().StringVarP(&opts.directory, "dir", "d", "", "Directory to create project in (default: current directory)")
	cmd.Flags().StringVarP(&opts.template, "template", "t", "basic", "Project template (basic, api, web, microservice)")
	cmd.Flags().BoolVarP(&opts.force, "force", "f", false, "Force creation even if directory exists")
	cmd.Flags().BoolVar(&opts.noGit, "no-git", false, "Skip git repository initialization")
	cmd.Flags().BoolVar(&opts.noMod, "no-mod", false, "Skip go.mod initialization")

	return cmd
}

func runNew(opts *newOptions) error {
	// Validate project name
	if !isValidProjectName(opts.name) {
		return fmt.Errorf("invalid project name: %s (must be a valid Go module name)", opts.name)
	}

	// Set default module path
	if opts.modulePath == "" {
		opts.modulePath = opts.name
	}

	// Determine project directory
	projectDir := opts.name
	if opts.directory != "" {
		projectDir = filepath.Join(opts.directory, opts.name)
	}

	// Check if directory exists
	if _, err := os.Stat(projectDir); err == nil && !opts.force {
		return fmt.Errorf("directory %s already exists (use --force to overwrite)", projectDir)
	}

	// Create project directory
	if err := os.MkdirAll(projectDir, 0755); err != nil {
		return fmt.Errorf("failed to create project directory: %w", err)
	}

	fmt.Printf("Creating new Gawan project '%s' in %s\n", opts.name, projectDir)

	// Generate project structure based on template
	generator := &ProjectGenerator{
		Name:       opts.name,
		ModulePath: opts.modulePath,
		Directory:  projectDir,
		Template:   opts.template,
		NoGit:      opts.noGit,
		NoMod:      opts.noMod,
	}

	if err := generator.Generate(); err != nil {
		return fmt.Errorf("failed to generate project: %w", err)
	}

	fmt.Printf("\n✅ Project '%s' created successfully!\n", opts.name)
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("  cd %s\n", projectDir)
	if !opts.noMod {
		fmt.Printf("  go mod tidy\n")
	}
	fmt.Printf("  go run cmd/server/main.go\n")

	return nil
}