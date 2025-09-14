package di

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"
)

// Service represents a service that can be managed by the registry
type Service interface {
	// Start initializes the service
	Start(ctx context.Context) error
	// Stop gracefully shuts down the service
	Stop(ctx context.Context) error
	// Name returns the service name for identification
	Name() string
}

// ServiceInfo holds metadata about a registered service
type ServiceInfo struct {
	Name         string
	Service      Service
	Dependencies []string
	Started      bool
	StartTime    time.Time
	StopTime     time.Time
}

// ServiceRegistry manages the lifecycle of services
type ServiceRegistry struct {
	mu       sync.RWMutex
	services map[string]*ServiceInfo
	started  bool
	logger   Logger
}

// Logger interface for service registry logging
type Logger interface {
	Info(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Debug(msg string, fields ...interface{})
}

// NoopLogger is a no-op logger implementation
type NoopLogger struct{}

func (n NoopLogger) Info(msg string, fields ...interface{})  {}
func (n NoopLogger) Error(msg string, fields ...interface{}) {}
func (n NoopLogger) Warn(msg string, fields ...interface{})  {}
func (n NoopLogger) Debug(msg string, fields ...interface{}) {}

// NewServiceRegistry creates a new service registry
func NewServiceRegistry(logger Logger) *ServiceRegistry {
	if logger == nil {
		logger = NoopLogger{}
	}
	return &ServiceRegistry{
		services: make(map[string]*ServiceInfo),
		logger:   logger,
	}
}

// Register adds a service to the registry
func (sr *ServiceRegistry) Register(service Service, dependencies ...string) error {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	name := service.Name()
	if name == "" {
		return fmt.Errorf("service name cannot be empty")
	}

	if _, exists := sr.services[name]; exists {
		return fmt.Errorf("service %s already registered", name)
	}

	// Validate dependencies exist
	for _, dep := range dependencies {
		if _, exists := sr.services[dep]; !exists {
			return fmt.Errorf("dependency %s not found for service %s", dep, name)
		}
	}

	sr.services[name] = &ServiceInfo{
		Name:         name,
		Service:      service,
		Dependencies: dependencies,
		Started:      false,
	}

	sr.logger.Info("Service registered", "name", name, "dependencies", dependencies)
	return nil
}

// MustRegister registers a service and panics on error
func (sr *ServiceRegistry) MustRegister(service Service, dependencies ...string) {
	if err := sr.Register(service, dependencies...); err != nil {
		panic(fmt.Sprintf("failed to register service %s: %v", service.Name(), err))
	}
}

// Get retrieves a service by name
func (sr *ServiceRegistry) Get(name string) (Service, error) {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	info, exists := sr.services[name]
	if !exists {
		return nil, fmt.Errorf("service %s not found", name)
	}

	return info.Service, nil
}

// MustGet retrieves a service and panics if not found
func (sr *ServiceRegistry) MustGet(name string) Service {
	service, err := sr.Get(name)
	if err != nil {
		panic(fmt.Sprintf("service %s not found: %v", name, err))
	}
	return service
}

// GetTyped retrieves a service by type
func (sr *ServiceRegistry) GetTyped(serviceType interface{}) (interface{}, error) {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	targetType := reflect.TypeOf(serviceType)
	if targetType.Kind() == reflect.Ptr {
		targetType = targetType.Elem()
	}

	for _, info := range sr.services {
		serviceValue := reflect.ValueOf(info.Service)
		serviceType := serviceValue.Type()

		// Check if service implements the target interface
		if serviceType.Implements(targetType) {
			return info.Service, nil
		}

		// Check if service is of the target type
		if serviceType == targetType {
			return info.Service, nil
		}
	}

	return nil, fmt.Errorf("service of type %s not found", targetType.Name())
}

// Start starts all services in dependency order
func (sr *ServiceRegistry) Start(ctx context.Context) error {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	if sr.started {
		return fmt.Errorf("service registry already started")
	}

	// Build dependency graph and start services in order
	startOrder, err := sr.buildStartOrder()
	if err != nil {
		return fmt.Errorf("failed to build start order: %w", err)
	}

	sr.logger.Info("Starting services", "count", len(startOrder))

	for _, name := range startOrder {
		info := sr.services[name]
		sr.logger.Info("Starting service", "name", name)

		startTime := time.Now()
		if err := info.Service.Start(ctx); err != nil {
			sr.logger.Error("Failed to start service", "name", name, "error", err)
			// Stop already started services
			sr.stopStartedServices(ctx, startOrder, name)
			return fmt.Errorf("failed to start service %s: %w", name, err)
		}

		info.Started = true
		info.StartTime = startTime
		sr.logger.Info("Service started", "name", name, "duration", time.Since(startTime))
	}

	sr.started = true
	sr.logger.Info("All services started successfully")
	return nil
}

// Stop stops all services in reverse dependency order
func (sr *ServiceRegistry) Stop(ctx context.Context) error {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	if !sr.started {
		return nil // Already stopped or never started
	}

	// Build stop order (reverse of start order)
	startOrder, err := sr.buildStartOrder()
	if err != nil {
		return fmt.Errorf("failed to build stop order: %w", err)
	}

	// Reverse the order for stopping
	stopOrder := make([]string, len(startOrder))
	for i, name := range startOrder {
		stopOrder[len(startOrder)-1-i] = name
	}

	sr.logger.Info("Stopping services", "count", len(stopOrder))

	var lastErr error
	for _, name := range stopOrder {
		info := sr.services[name]
		if !info.Started {
			continue
		}

		sr.logger.Info("Stopping service", "name", name)
		stopTime := time.Now()

		if err := info.Service.Stop(ctx); err != nil {
			sr.logger.Error("Failed to stop service", "name", name, "error", err)
			lastErr = err
		} else {
			sr.logger.Info("Service stopped", "name", name, "duration", time.Since(stopTime))
		}

		info.Started = false
		info.StopTime = stopTime
	}

	sr.started = false
	sr.logger.Info("All services stopped")
	return lastErr
}

// IsStarted returns whether the registry is started
func (sr *ServiceRegistry) IsStarted() bool {
	sr.mu.RLock()
	defer sr.mu.RUnlock()
	return sr.started
}

// ListServices returns information about all registered services
func (sr *ServiceRegistry) ListServices() map[string]*ServiceInfo {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	result := make(map[string]*ServiceInfo)
	for name, info := range sr.services {
		// Create a copy to avoid external modifications
		result[name] = &ServiceInfo{
			Name:         info.Name,
			Service:      info.Service,
			Dependencies: append([]string{}, info.Dependencies...),
			Started:      info.Started,
			StartTime:    info.StartTime,
			StopTime:     info.StopTime,
		}
	}
	return result
}

// buildStartOrder builds the order in which services should be started
func (sr *ServiceRegistry) buildStartOrder() ([]string, error) {
	var order []string
	visited := make(map[string]bool)
	temp := make(map[string]bool)

	var visit func(string) error
	visit = func(name string) error {
		if temp[name] {
			return fmt.Errorf("circular dependency detected involving service %s", name)
		}
		if visited[name] {
			return nil
		}

		temp[name] = true
		info := sr.services[name]
		for _, dep := range info.Dependencies {
			if err := visit(dep); err != nil {
				return err
			}
		}
		temp[name] = false
		visited[name] = true
		order = append(order, name)
		return nil
	}

	for name := range sr.services {
		if !visited[name] {
			if err := visit(name); err != nil {
				return nil, err
			}
		}
	}

	return order, nil
}

// stopStartedServices stops services that were already started during a failed start
func (sr *ServiceRegistry) stopStartedServices(ctx context.Context, startOrder []string, failedService string) {
	for _, name := range startOrder {
		if name == failedService {
			break
		}
		info := sr.services[name]
		if info.Started {
			sr.logger.Info("Stopping service due to startup failure", "name", name)
			if err := info.Service.Stop(ctx); err != nil {
				sr.logger.Error("Failed to stop service during cleanup", "name", name, "error", err)
			}
			info.Started = false
		}
	}
}