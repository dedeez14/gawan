package hotreload

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Watcher represents a file watcher with hot reload functionality
type Watcher struct {
	watcher    *fsnotify.Watcher
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.RWMutex
	watchDirs  []string
	ignorePatterns []string
	cmd        *exec.Cmd
	cmdMu      sync.Mutex
	verbose    bool
	debounce   time.Duration
	lastEvent  time.Time
	eventMu    sync.Mutex
}

// Config holds configuration for the watcher
type Config struct {
	WatchDirs      []string
	IgnorePatterns []string
	Verbose        bool
	Debounce       time.Duration
}

// NewWatcher creates a new file watcher
func NewWatcher(config Config) (*Watcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create watcher: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	w := &Watcher{
		watcher:        watcher,
		ctx:            ctx,
		cancel:         cancel,
		watchDirs:      config.WatchDirs,
		ignorePatterns: config.IgnorePatterns,
		verbose:        config.Verbose,
		debounce:       config.Debounce,
	}

	if w.debounce == 0 {
		w.debounce = 100 * time.Millisecond
	}

	// Add directories to watch
	for _, dir := range w.watchDirs {
		if err := w.addDirRecursive(dir); err != nil {
			w.Stop()
			return nil, fmt.Errorf("failed to add directory %s: %w", dir, err)
		}
	}

	if w.verbose {
		log.Printf("Watching %d directories", len(w.watchDirs))
	}

	return w, nil
}

// Start begins watching for file changes
func (w *Watcher) Start(buildCmd []string) error {
	if w.verbose {
		log.Println("Starting file watcher...")
	}

	go w.watchEvents(buildCmd)

	// Initial build
	if err := w.rebuild(buildCmd); err != nil {
		log.Printf("Initial build failed: %v", err)
		return err
	}

	return nil
}

// Stop stops the watcher
func (w *Watcher) Stop() error {
	w.cancel()
	w.stopCurrentProcess()
	return w.watcher.Close()
}

// addDirRecursive adds a directory and all its subdirectories to the watcher
func (w *Watcher) addDirRecursive(root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			return nil
		}

		if w.shouldIgnore(path) {
			return filepath.SkipDir
		}

		if w.verbose {
			log.Printf("Adding directory to watch: %s", path)
		}

		return w.watcher.Add(path)
	})
}

// shouldIgnore checks if a path should be ignored
func (w *Watcher) shouldIgnore(path string) bool {
	for _, pattern := range w.ignorePatterns {
		if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
			return true
		}
		if strings.Contains(path, pattern) {
			return true
		}
	}
	return false
}

// watchEvents watches for file system events
func (w *Watcher) watchEvents(buildCmd []string) {
	for {
		select {
		case <-w.ctx.Done():
			return
		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}

			if w.verbose {
				log.Printf("File event: %s %s", event.Op, event.Name)
			}

			// Check if we should ignore this file
			if w.shouldIgnore(event.Name) {
				continue
			}

			// Only rebuild for relevant files
			if !w.isRelevantFile(event.Name) {
				continue
			}

			// Debounce events
			w.eventMu.Lock()
			now := time.Now()
			if now.Sub(w.lastEvent) < w.debounce {
				w.lastEvent = now
				w.eventMu.Unlock()
				continue
			}
			w.lastEvent = now
			w.eventMu.Unlock()

			// Rebuild after a short delay to catch multiple rapid changes
			go func() {
				time.Sleep(w.debounce)
				if err := w.rebuild(buildCmd); err != nil {
					log.Printf("Rebuild failed: %v", err)
				}
			}()

		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Watcher error: %v", err)
		}
	}
}

// isRelevantFile checks if a file change should trigger a rebuild
func (w *Watcher) isRelevantFile(filename string) bool {
	ext := filepath.Ext(filename)
	relevantExts := []string{".go", ".yaml", ".yml", ".json", ".toml"}
	for _, relevantExt := range relevantExts {
		if ext == relevantExt {
			return true
		}
	}
	return false
}

// rebuild stops the current process and starts a new one
func (w *Watcher) rebuild(buildCmd []string) error {
	if w.verbose {
		log.Println("Rebuilding...")
	}

	// Stop current process
	w.stopCurrentProcess()

	// Build
	if err := w.build(); err != nil {
		return fmt.Errorf("build failed: %w", err)
	}

	// Start new process
	if err := w.startProcess(buildCmd); err != nil {
		return fmt.Errorf("failed to start process: %w", err)
	}

	if w.verbose {
		log.Println("Rebuild completed successfully")
	}

	return nil
}

// build compiles the application
func (w *Watcher) build() error {
	cmd := exec.Command("go", "build", "-o", "./tmp/main.exe", "./cmd/server")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// startProcess starts the built application
func (w *Watcher) startProcess(buildCmd []string) error {
	w.cmdMu.Lock()
	defer w.cmdMu.Unlock()

	if len(buildCmd) == 0 {
		buildCmd = []string{"./tmp/main"}
	}

	w.cmd = exec.Command(buildCmd[0], buildCmd[1:]...)
	w.cmd.Stdout = os.Stdout
	w.cmd.Stderr = os.Stderr

	if err := w.cmd.Start(); err != nil {
		return err
	}

	if w.verbose {
		log.Printf("Started process with PID: %d", w.cmd.Process.Pid)
	}

	return nil
}

// stopCurrentProcess stops the currently running process
func (w *Watcher) stopCurrentProcess() {
	w.cmdMu.Lock()
	defer w.cmdMu.Unlock()

	if w.cmd != nil && w.cmd.Process != nil {
		if w.verbose {
			log.Printf("Stopping process with PID: %d", w.cmd.Process.Pid)
		}

		if err := w.cmd.Process.Kill(); err != nil {
			log.Printf("Failed to kill process: %v", err)
		}

		w.cmd.Wait() // Wait for process to exit
		w.cmd = nil
	}
}

// CheckAirInstallation checks if air is installed
func CheckAirInstallation() bool {
	_, err := exec.LookPath("air")
	return err == nil
}

// InstallAir installs the air tool
func InstallAir() error {
	cmd := exec.Command("go", "install", "github.com/cosmtrek/air@latest")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// CreateAirConfig creates a default .air.toml configuration file
func CreateAirConfig() error {
	config := `# Config file for [Air](https://github.com/cosmtrek/air) in TOML format

# Working directory
# . or absolute path, please note that the directories following must be under root.
root = "."
tmp_dir = "tmp"

[build]
# Just plain old shell command. You could use ` + "`make`" + ` as well.
cmd = "go build -o ./tmp/main ./cmd/server"
# Binary file yields from ` + "`cmd`" + `.
bin = "tmp/main"
# Customize binary, can setup environment variables when run your app.
full_bin = "APP_ENV=dev APP_USER=air ./tmp/main"
# Watch these filename extensions.
include_ext = ["go", "tpl", "tmpl", "html", "yaml", "yml", "json"]
# Ignore these filename extensions or directories.
exclude_dir = ["assets", "tmp", "vendor", "frontend/node_modules"]
# Watch these directories if you specified.
include_dir = []
# Watch these files.
include_file = []
# Exclude files.
exclude_file = []
# Exclude specific regular expressions.
exclude_regex = ["_test\\.go"]
# Exclude unchanged files.
exclude_unchanged = true
# Follow symlink for directories
follow_symlink = true
# This log file places in your tmp_dir.
log = "errors.log"
# Poll files for changes instead of using fsnotify.
poll = false
# Poll interval (defaults to the minimum interval of 500ms).
poll_interval = 500 # ms
# It's not necessary to trigger build each time file changes if it's too frequent.
delay = 0 # ms
# Stop running old binary when build errors occur.
stop_on_error = false
# Send Interrupt signal before killing process (windows does not support this feature)
send_interrupt = true
# Delay after sending Interrupt signal
kill_delay = 0 # nanosecond
# Rerun binary or not
rerun = true
# Delay after each executions
rerun_delay = 500
# Add additional arguments when running binary (bin/full_bin). Will run './tmp/main hello world'.
args_bin = []

[log]
# Show log time
time = false
# Only show main log (hide build log)
main_only = false

[color]
# Customize each part's color. If no color found, use the raw app log.
main = "magenta"
watcher = "cyan"
build = "yellow"
runner = "green"

[misc]
# Delete tmp directory on exit
clean_on_exit = false

[screen]
clear_on_rebuild = false
keep_scroll = true
`

	return os.WriteFile(".air.toml", []byte(config), 0644)
}