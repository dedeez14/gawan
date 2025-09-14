package di

import (
	"context"
	"fmt"
	"time"
)

// Config holds the configuration for the DI system
type Config struct {
	// Services configuration
	Database     map[string]DatabaseConfig     `json:"database" yaml:"database"`
	MessageQueue map[string]MessageQueueConfig `json:"message_queue" yaml:"message_queue"`
	Cache        map[string]CacheConfig        `json:"cache" yaml:"cache"`
	Scheduler    SchedulerConfig               `json:"scheduler" yaml:"scheduler"`

	// Container configuration
	StartTimeout time.Duration `json:"start_timeout" yaml:"start_timeout" env:"DI_START_TIMEOUT" default:"30s"`
	StopTimeout  time.Duration `json:"stop_timeout" yaml:"stop_timeout" env:"DI_STOP_TIMEOUT" default:"30s"`
	LogLevel     string        `json:"log_level" yaml:"log_level" env:"DI_LOG_LEVEL" default:"info"`
}

// SchedulerConfig holds scheduler configuration
type SchedulerConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled" env:"SCHEDULER_ENABLED" default:"true"`
}

// DefaultConfig returns default DI configuration
func DefaultConfig() Config {
	return Config{
		Database:     make(map[string]DatabaseConfig),
		MessageQueue: make(map[string]MessageQueueConfig),
		Cache:        make(map[string]CacheConfig),
		Scheduler: SchedulerConfig{
			Enabled: true,
		},
		StartTimeout: 30 * time.Second,
		StopTimeout:  30 * time.Second,
		LogLevel:     "info",
	}
}

// Builder helps build and configure the DI container
type Builder struct {
	config    Config
	container *Container
	logger    Logger
}

// NewBuilder creates a new DI builder
func NewBuilder(config Config, logger Logger) *Builder {
	if logger == nil {
		logger = NoopLogger{}
	}

	registry := NewServiceRegistry(logger)
	container := NewContainer(registry)

	return &Builder{
		config:    config,
		container: container,
		logger:    logger,
	}
}

// WithDatabaseServices adds database services to the container
func (b *Builder) WithDatabaseServices() *Builder {
	for name, dbConfig := range b.config.Database {
		service := NewDatabaseService(name, dbConfig)
		b.container.Registry().MustRegister(service)
		b.container.Register(service)
		b.logger.Info("Database service registered", "name", name, "driver", dbConfig.Driver)
	}
	return b
}

// WithMessageQueueServices adds message queue services to the container
func (b *Builder) WithMessageQueueServices() *Builder {
	for name, mqConfig := range b.config.MessageQueue {
		service := NewMessageQueueService(name, mqConfig)
		b.container.Registry().MustRegister(service)
		b.container.Register(service)
		b.logger.Info("Message queue service registered", "name", name, "provider", mqConfig.Provider)
	}
	return b
}

// WithCacheServices adds cache services to the container
func (b *Builder) WithCacheServices() *Builder {
	for name, cacheConfig := range b.config.Cache {
		service := NewCacheService(name, cacheConfig)
		b.container.Registry().MustRegister(service)
		b.container.Register(service)
		b.logger.Info("Cache service registered", "name", name, "provider", cacheConfig.Provider)
	}
	return b
}

// WithSchedulerService adds scheduler service to the container
func (b *Builder) WithSchedulerService() *Builder {
	if !b.config.Scheduler.Enabled {
		b.logger.Info("Scheduler service disabled")
		return b
	}

	service := NewSchedulerService("scheduler")
	b.container.Registry().MustRegister(service)
	b.container.Register(service)
	b.logger.Info("Scheduler service registered")
	return b
}

// WithCustomService adds a custom service to the container
func (b *Builder) WithCustomService(service Service, dependencies ...string) *Builder {
	b.container.Registry().MustRegister(service, dependencies...)
	b.container.Register(service)
	b.logger.Info("Custom service registered", "name", service.Name())
	return b
}

// WithFactory registers a factory function for a service type
func (b *Builder) WithFactory(serviceType interface{}, factory Factory, singleton bool) *Builder {
	b.container.RegisterFactory(serviceType, factory, singleton)
	return b
}

// WithInterface registers a service that implements an interface
func (b *Builder) WithInterface(interfaceType interface{}, implementation interface{}) *Builder {
	if err := b.container.RegisterInterface(interfaceType, implementation); err != nil {
		panic(fmt.Sprintf("failed to register interface: %v", err))
	}
	return b
}

// Build returns the configured container
func (b *Builder) Build() *Container {
	return b.container
}

// BuildAndStart builds the container and starts all services
func (b *Builder) BuildAndStart(ctx context.Context) (*Container, error) {
	container := b.Build()

	// Create context with timeout for starting services
	startCtx, cancel := context.WithTimeout(ctx, b.config.StartTimeout)
	defer cancel()

	if err := container.Start(startCtx); err != nil {
		return nil, fmt.Errorf("failed to start services: %w", err)
	}

	return container, nil
}

// Application represents the main application with DI container
type Application struct {
	container *Container
	config    Config
	logger    Logger
	started   bool
}

// NewApplication creates a new application with DI container
func NewApplication(config Config, logger Logger) *Application {
	return &Application{
		config: config,
		logger: logger,
	}
}

// Initialize initializes the application with default services
func (app *Application) Initialize() error {
	builder := NewBuilder(app.config, app.logger)

	// Add default services
	builder.WithDatabaseServices().
		WithMessageQueueServices().
		WithCacheServices().
		WithSchedulerService()

	app.container = builder.Build()
	return nil
}

// Start starts the application and all services
func (app *Application) Start(ctx context.Context) error {
	if app.started {
		return fmt.Errorf("application already started")
	}

	if app.container == nil {
		if err := app.Initialize(); err != nil {
			return fmt.Errorf("failed to initialize application: %w", err)
		}
	}

	startCtx, cancel := context.WithTimeout(ctx, app.config.StartTimeout)
	defer cancel()

	if err := app.container.Start(startCtx); err != nil {
		return fmt.Errorf("failed to start application: %w", err)
	}

	app.started = true
	app.logger.Info("Application started successfully")
	return nil
}

// Stop stops the application and all services
func (app *Application) Stop(ctx context.Context) error {
	if !app.started {
		return nil
	}

	stopCtx, cancel := context.WithTimeout(ctx, app.config.StopTimeout)
	defer cancel()

	if err := app.container.Stop(stopCtx); err != nil {
		app.logger.Error("Failed to stop application gracefully", "error", err)
		return err
	}

	app.started = false
	app.logger.Info("Application stopped successfully")
	return nil
}

// Container returns the DI container
func (app *Application) Container() *Container {
	return app.container
}

// IsStarted returns whether the application is started
func (app *Application) IsStarted() bool {
	return app.started
}

// Shutdown performs graceful shutdown with signal handling
func (app *Application) Shutdown(ctx context.Context) error {
	app.logger.Info("Shutting down application...")

	// Stop all services
	if err := app.Stop(ctx); err != nil {
		app.logger.Error("Error during shutdown", "error", err)
		return err
	}

	app.logger.Info("Application shutdown completed")
	return nil
}

// HealthCheck performs health check on all services
func (app *Application) HealthCheck(ctx context.Context) map[string]error {
	results := make(map[string]error)

	if app.container == nil {
		results["container"] = fmt.Errorf("container not initialized")
		return results
	}

	services := app.container.Registry().ListServices()
	for name, info := range services {
		if !info.Started {
			results[name] = fmt.Errorf("service not started")
			continue
		}

		// For services that implement health check interface
		if healthChecker, ok := info.Service.(interface {
			HealthCheck(ctx context.Context) error
		}); ok {
			results[name] = healthChecker.HealthCheck(ctx)
		} else {
			results[name] = nil // Service is running
		}
	}

	return results
}

// MustNewApplication creates a new application and panics on error
func MustNewApplication(config Config, logger Logger) *Application {
	app := NewApplication(config, logger)
	if err := app.Initialize(); err != nil {
		panic(fmt.Sprintf("failed to create application: %v", err))
	}
	return app
}