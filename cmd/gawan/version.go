package main

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// Version information - these will be set during build
var (
	Version   = "dev"
	Commit    = "unknown"
	Date      = "unknown"
	GoVersion = runtime.Version()
)

// newVersionCmd creates the version command
func newVersionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Long:  `Display version information for the Gawan CLI tool.`,
		Run:   runVersion,
	}

	cmd.Flags().BoolP("short", "s", false, "Show only the version number")
	cmd.Flags().BoolP("json", "j", false, "Output version information in JSON format")

	return cmd
}

// runVersion executes the version command
func runVersion(cmd *cobra.Command, args []string) {
	short, _ := cmd.Flags().GetBool("short")
	jsonOutput, _ := cmd.Flags().GetBool("json")

	if short {
		fmt.Println(Version)
		return
	}

	if jsonOutput {
		printVersionJSON()
		return
	}

	printVersionInfo()
}

// printVersionInfo prints formatted version information
func printVersionInfo() {
	header("Gawan CLI Tool")
	fmt.Printf("Version:    %s\n", colorize(ColorGreen, Version))
	fmt.Printf("Commit:     %s\n", colorize(ColorBlue, Commit))
	fmt.Printf("Build Date: %s\n", colorize(ColorYellow, Date))
	fmt.Printf("Go Version: %s\n", colorize(ColorPurple, GoVersion))
	fmt.Printf("OS/Arch:    %s/%s\n", colorize(ColorCyan, runtime.GOOS), colorize(ColorCyan, runtime.GOARCH))
}

// printVersionJSON prints version information in JSON format
func printVersionJSON() {
	fmt.Printf(`{
`)
	fmt.Printf(`  "version": "%s",
`, Version)
	fmt.Printf(`  "commit": "%s",
`, Commit)
	fmt.Printf(`  "buildDate": "%s",
`, Date)
	fmt.Printf(`  "goVersion": "%s",
`, GoVersion)
	fmt.Printf(`  "os": "%s",
`, runtime.GOOS)
	fmt.Printf(`  "arch": "%s"
`, runtime.GOARCH)
	fmt.Printf(`}
`)
}

// GetVersion returns the current version
func GetVersion() string {
	return Version
}

// GetFullVersion returns the full version string
func GetFullVersion() string {
	return fmt.Sprintf("%s (commit: %s, built: %s)", Version, Commit, Date)
}

// IsDevVersion checks if this is a development version
func IsDevVersion() bool {
	return Version == "dev" || Version == "unknown"
}