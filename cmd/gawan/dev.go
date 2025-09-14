package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"Gawan/internal/core/hotreload"
)

type devOptions struct {
	port     string
	host     string
	watch    []string
	ignore   []string
	verbose  bool
	noReload bool
}

func newDevCmd() *cobra.Command {
	opts := &devOptions{}

	cmd := &cobra.Command{
		Use:   "dev",
		Short: "Start development server with hot reload",
		Long: `Start development server with hot reload functionality.
This command will watch for file changes and automatically restart the server.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check if air is available
			if !opts.noReload {
				if hasAir() {
					return runWithAir(opts)
				}
				return runWithWatcher(opts)
			}
			return runSimpleServer(opts)
		},
	}

	cmd.Flags().StringVarP(&opts.port, "port", "p", "8080", "Port to run the server on")
	cmd.Flags().StringVarP(&opts.host, "host", "H", "localhost", "Host to bind the server to")
	cmd.Flags().StringSliceVarP(&opts.watch, "watch", "w", []string{".", "internal", "cmd", "pkg"}, "Directories to watch for changes")
	cmd.Flags().StringSliceVar(&opts.ignore, "ignore", []string{"tmp", "vendor", ".git", "node_modules", "*.log"}, "Patterns to ignore")
	cmd.Flags().BoolVarP(&opts.verbose, "verbose", "v", false, "Enable verbose logging")
	cmd.Flags().BoolVar(&opts.noReload, "no-reload", false, "Disable hot reload functionality")

	return cmd
}

// runDev function removed - logic moved to newDevCmd RunE

func isGawanProject() bool {
	// Check for go.mod
	if _, err := os.Stat("go.mod"); err != nil {
		return false
	}

	// Check for cmd/server/main.go
	if _, err := os.Stat(filepath.Join("cmd", "server", "main.go")); err != nil {
		return false
	}

	return true
}

func hasAir() bool {
	return hotreload.CheckAirInstallation()
}

func runWithAir(opts *devOptions) error {
	fmt.Println("🚀 Starting development server with Air...")
	fmt.Printf("📡 Server will be available at http://%s:%s\n", opts.host, opts.port)
	fmt.Println("👀 Watching for file changes...")
	fmt.Println("")

	// Create .air.toml config if it doesn't exist
	if _, err := os.Stat(".air.toml"); os.IsNotExist(err) {
		if err := hotreload.CreateAirConfig(); err != nil {
			return fmt.Errorf("failed to create air config: %w", err)
		}
		fmt.Println("Created .air.toml configuration file")
	}

	cmd := exec.Command("air")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	return cmd.Run()
}

func runWithWatcher(opts *devOptions) error {
	fmt.Printf("🚀 Starting development server on %s:%s\n", opts.host, opts.port)
	fmt.Printf("📁 Watching directories: %v\n", opts.watch)
	fmt.Printf("🚫 Ignoring patterns: %v\n", opts.ignore)
	fmt.Println("💡 Tip: Install 'air' for better hot reload experience: go install github.com/cosmtrek/air@latest")

	// Create watcher configuration
	config := hotreload.Config{
		WatchDirs:      opts.watch,
		IgnorePatterns: opts.ignore,
		Verbose:        opts.verbose,
		Debounce:       100 * time.Millisecond,
	}

	// Create watcher
	watcher, err := hotreload.NewWatcher(config)
	if err != nil {
		return fmt.Errorf("failed to create watcher: %w", err)
	}
	defer watcher.Stop()

	// Build command with environment variables
	buildCmd := []string{"./tmp/main.exe"}
	os.Setenv("HOST", opts.host)
	os.Setenv("PORT", opts.port)
	os.Setenv("ENV", "development")

	// Start watcher
	if err := watcher.Start(buildCmd); err != nil {
		return fmt.Errorf("failed to start watcher: %w", err)
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("\n✅ Development server started with hot reload")
	fmt.Println("Press Ctrl+C to stop")

	// Wait for shutdown signal
	<-sigChan
	fmt.Println("\n🛑 Shutting down development server...")

	return nil
}

func runSimpleServer(opts *devOptions) error {
	fmt.Println("🚀 Starting development server...")
	fmt.Printf("📡 Server will be available at http://%s:%s\n", opts.host, opts.port)
	fmt.Println("")

	// Set environment variables
	os.Setenv("PORT", opts.port)
	os.Setenv("HOST", opts.host)
	os.Setenv("ENV", "development")

	cmd := exec.Command("go", "run", "cmd/server/main.go")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	return cmd.Run()
}

// createAirConfig moved to hotreload package