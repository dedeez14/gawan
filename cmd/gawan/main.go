package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	// Version information
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gawan",
		Short: "Gawan CLI - Go web framework scaffolding tool",
		Long: `Gawan CLI is a scaffolding tool for the Gawan Go web framework.
It helps you generate boilerplate code for controllers, services, models, and more.`,
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
	}

	// Add subcommands
	cmd.AddCommand(newGenerateCmd())
	cmd.AddCommand(newNewCmd())
	cmd.AddCommand(newDevCmd())
	cmd.AddCommand(newVersionCmd())

	return cmd
}