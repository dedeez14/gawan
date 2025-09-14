package di

import (
	"context"
	"fmt"
	"reflect"
	"sync"
)

// Container provides dependency injection capabilities
type Container struct {
	mu        sync.RWMutex
	services  map[reflect.Type]interface{}
	singleton map[reflect.Type]bool
	factories map[reflect.Type]Factory
	registry  *ServiceRegistry
}

// Factory is a function that creates an instance of a service
type Factory func(container *Container) (interface{}, error)

// NewContainer creates a new dependency injection container
func NewContainer(registry *ServiceRegistry) *Container {
	if registry == nil {
		registry = NewServiceRegistry(nil)
	}
	return &Container{
		services:  make(map[reflect.Type]interface{}),
		singleton: make(map[reflect.Type]bool),
		factories: make(map[reflect.Type]Factory),
		registry:  registry,
	}
}

// Register registers a service instance
func (c *Container) Register(service interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	serviceType := reflect.TypeOf(service)
	c.services[serviceType] = service
	c.singleton[serviceType] = true
}

// RegisterFactory registers a factory function for creating services
func (c *Container) RegisterFactory(serviceType interface{}, factory Factory, singleton bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	t := reflect.TypeOf(serviceType)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	c.factories[t] = factory
	c.singleton[t] = singleton
}

// RegisterInterface registers a service that implements an interface
func (c *Container) RegisterInterface(interfaceType interface{}, implementation interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	interfaceT := reflect.TypeOf(interfaceType)
	implT := reflect.TypeOf(implementation)

	// Ensure the interface type is actually an interface
	if interfaceT.Kind() != reflect.Interface {
		return fmt.Errorf("first argument must be an interface type")
	}

	// Ensure the implementation implements the interface
	if !implT.Implements(interfaceT) {
		return fmt.Errorf("implementation does not implement the interface")
	}

	c.services[interfaceT] = implementation
	c.singleton[interfaceT] = true
	return nil
}

// Get retrieves a service by type
func (c *Container) Get(serviceType interface{}) (interface{}, error) {
	t := reflect.TypeOf(serviceType)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	c.mu.RLock()
	service, exists := c.services[t]
	isSingleton := c.singleton[t]
	factory, hasFactory := c.factories[t]
	c.mu.RUnlock()

	if exists {
		return service, nil
	}

	if hasFactory {
		instance, err := factory(c)
		if err != nil {
			return nil, fmt.Errorf("factory failed to create service: %w", err)
		}

		if isSingleton {
			c.mu.Lock()
			c.services[t] = instance
			c.mu.Unlock()
		}

		return instance, nil
	}

	return nil, fmt.Errorf("service of type %s not found", t.Name())
}

// MustGet retrieves a service and panics if not found
func (c *Container) MustGet(serviceType interface{}) interface{} {
	service, err := c.Get(serviceType)
	if err != nil {
		panic(fmt.Sprintf("failed to get service: %v", err))
	}
	return service
}

// Inject performs dependency injection on a struct
func (c *Container) Inject(target interface{}) error {
	value := reflect.ValueOf(target)
	if value.Kind() != reflect.Ptr {
		return fmt.Errorf("target must be a pointer")
	}

	value = value.Elem()
	if value.Kind() != reflect.Struct {
		return fmt.Errorf("target must be a pointer to struct")
	}

	t := value.Type()
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		fieldType := t.Field(i)

		// Check for inject tag
		injectTag := fieldType.Tag.Get("inject")
		if injectTag == "" {
			continue
		}

		if !field.CanSet() {
			return fmt.Errorf("field %s cannot be set", fieldType.Name)
		}

		// Get service by field type
		service, err := c.Get(reflect.New(field.Type()).Interface())
		if err != nil {
			if injectTag == "required" {
				return fmt.Errorf("required dependency %s not found: %w", fieldType.Name, err)
			}
			continue // Optional dependency
		}

		field.Set(reflect.ValueOf(service))
	}

	return nil
}

// Build creates an instance of the specified type with dependency injection
func (c *Container) Build(target interface{}) (interface{}, error) {
	t := reflect.TypeOf(target)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	if t.Kind() != reflect.Struct {
		return nil, fmt.Errorf("target must be a struct type")
	}

	// Create new instance
	instance := reflect.New(t).Interface()

	// Inject dependencies
	if err := c.Inject(instance); err != nil {
		return nil, fmt.Errorf("failed to inject dependencies: %w", err)
	}

	return instance, nil
}

// Start starts the service registry
func (c *Container) Start(ctx context.Context) error {
	return c.registry.Start(ctx)
}

// Stop stops the service registry
func (c *Container) Stop(ctx context.Context) error {
	return c.registry.Stop(ctx)
}

// Registry returns the underlying service registry
func (c *Container) Registry() *ServiceRegistry {
	return c.registry
}

// Provider is a helper interface for services that need to provide themselves to the container
type Provider interface {
	Provide(container *Container) error
}

// AutoRegister automatically registers services that implement the Provider interface
func (c *Container) AutoRegister(services ...interface{}) error {
	for _, service := range services {
		if provider, ok := service.(Provider); ok {
			if err := provider.Provide(c); err != nil {
				return fmt.Errorf("failed to auto-register service: %w", err)
			}
		} else {
			c.Register(service)
		}
	}
	return nil
}

// Scope represents a scoped container for request-specific dependencies
type Scope struct {
	parent   *Container
	services map[reflect.Type]interface{}
	mu       sync.RWMutex
}

// NewScope creates a new scope from the container
func (c *Container) NewScope() *Scope {
	return &Scope{
		parent:   c,
		services: make(map[reflect.Type]interface{}),
	}
}

// Register registers a service in the scope
func (s *Scope) Register(service interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	serviceType := reflect.TypeOf(service)
	s.services[serviceType] = service
}

// Get retrieves a service from the scope or parent container
func (s *Scope) Get(serviceType interface{}) (interface{}, error) {
	t := reflect.TypeOf(serviceType)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	s.mu.RLock()
	service, exists := s.services[t]
	s.mu.RUnlock()

	if exists {
		return service, nil
	}

	// Fallback to parent container
	return s.parent.Get(serviceType)
}

// Inject performs dependency injection using the scope
func (s *Scope) Inject(target interface{}) error {
	value := reflect.ValueOf(target)
	if value.Kind() != reflect.Ptr {
		return fmt.Errorf("target must be a pointer")
	}

	value = value.Elem()
	if value.Kind() != reflect.Struct {
		return fmt.Errorf("target must be a pointer to struct")
	}

	t := value.Type()
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		fieldType := t.Field(i)

		// Check for inject tag
		injectTag := fieldType.Tag.Get("inject")
		if injectTag == "" {
			continue
		}

		if !field.CanSet() {
			return fmt.Errorf("field %s cannot be set", fieldType.Name)
		}

		// Get service by field type
		service, err := s.Get(reflect.New(field.Type()).Interface())
		if err != nil {
			if injectTag == "required" {
				return fmt.Errorf("required dependency %s not found: %w", fieldType.Name, err)
			}
			continue // Optional dependency
		}

		field.Set(reflect.ValueOf(service))
	}

	return nil
}