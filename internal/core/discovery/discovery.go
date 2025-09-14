package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// ServiceStatus represents the status of a service
type ServiceStatus string

const (
	ServiceStatusHealthy   ServiceStatus = "healthy"
	ServiceStatusUnhealthy ServiceStatus = "unhealthy"
	ServiceStatusUnknown   ServiceStatus = "unknown"
)

// Service represents a registered service
type Service struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Address     string            `json:"address"`
	Port        int               `json:"port"`
	Tags        []string          `json:"tags"`
	Metadata    map[string]string `json:"metadata"`
	Status      ServiceStatus     `json:"status"`
	HealthCheck HealthCheck       `json:"health_check"`
	Registered  time.Time         `json:"registered"`
	LastSeen    time.Time         `json:"last_seen"`
	Weight      int               `json:"weight"`
}

// HealthCheck represents health check configuration
type HealthCheck struct {
	Enabled  bool          `json:"enabled"`
	Endpoint string        `json:"endpoint"`
	Interval time.Duration `json:"interval"`
	Timeout  time.Duration `json:"timeout"`
	Method   string        `json:"method"`
}

// Config holds service discovery configuration
type Config struct {
	Enabled             bool          `json:"enabled" yaml:"enabled" env:"DISCOVERY_ENABLED" default:"true"`
	BindAddress         string        `json:"bind_address" yaml:"bind_address" env:"DISCOVERY_BIND_ADDRESS" default:"0.0.0.0"`
	BindPort            int           `json:"bind_port" yaml:"bind_port" env:"DISCOVERY_BIND_PORT" default:"8500"`
	HealthCheckInterval time.Duration `json:"health_check_interval" yaml:"health_check_interval" env:"DISCOVERY_HEALTH_CHECK_INTERVAL" default:"30s"`
	HealthCheckTimeout  time.Duration `json:"health_check_timeout" yaml:"health_check_timeout" env:"DISCOVERY_HEALTH_CHECK_TIMEOUT" default:"5s"`
	TTL                 time.Duration `json:"ttl" yaml:"ttl" env:"DISCOVERY_TTL" default:"60s"`
	CleanupInterval     time.Duration `json:"cleanup_interval" yaml:"cleanup_interval" env:"DISCOVERY_CLEANUP_INTERVAL" default:"120s"`
	MaxRetries          int           `json:"max_retries" yaml:"max_retries" env:"DISCOVERY_MAX_RETRIES" default:"3"`
}

// ServiceDiscovery represents a service discovery instance
type ServiceDiscovery struct {
	config    Config
	services  map[string]*Service
	mu        sync.RWMutex
	stopChan  chan struct{}
	listeners []ServiceEventListener
	client    *http.Client
}

// ServiceEventListener defines an interface for service event listeners
type ServiceEventListener interface {
	OnServiceRegister(service *Service)
	OnServiceDeregister(service *Service)
	OnServiceHealthChange(service *Service, oldStatus, newStatus ServiceStatus)
}

// QueryOptions represents options for service queries
type QueryOptions struct {
	ServiceName string            `json:"service_name,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Healthy     *bool             `json:"healthy,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Limit       int               `json:"limit,omitempty"`
}

// NewServiceDiscovery creates a new service discovery instance
func NewServiceDiscovery(config Config) *ServiceDiscovery {
	return &ServiceDiscovery{
		config:   config,
		services: make(map[string]*Service),
		stopChan: make(chan struct{}),
		client: &http.Client{
			Timeout: config.HealthCheckTimeout,
		},
		listeners: make([]ServiceEventListener, 0),
	}
}

// Start starts the service discovery
func (sd *ServiceDiscovery) Start() error {
	if !sd.config.Enabled {
		return nil
	}

	// Start HTTP server
	go sd.startServer()

	// Start health checking
	go sd.startHealthChecker()

	// Start cleanup routine
	go sd.startCleanup()

	return nil
}

// Stop stops the service discovery
func (sd *ServiceDiscovery) Stop() error {
	close(sd.stopChan)
	return nil
}

// RegisterService registers a new service
func (sd *ServiceDiscovery) RegisterService(service *Service) error {
	if service.ID == "" {
		service.ID = generateServiceID(service.Name, service.Address, service.Port)
	}

	service.Registered = time.Now()
	service.LastSeen = time.Now()
	service.Status = ServiceStatusHealthy

	// Set default health check if not provided
	if service.HealthCheck.Endpoint == "" {
		service.HealthCheck = HealthCheck{
			Enabled:  true,
			Endpoint: "/health",
			Interval: sd.config.HealthCheckInterval,
			Timeout:  sd.config.HealthCheckTimeout,
			Method:   "GET",
		}
	}

	sd.mu.Lock()
	sd.services[service.ID] = service
	sd.mu.Unlock()

	// Notify listeners
	for _, listener := range sd.listeners {
		go listener.OnServiceRegister(service)
	}

	log.Printf("Service registered: %s (%s:%d)", service.Name, service.Address, service.Port)
	return nil
}

// DeregisterService deregisters a service
func (sd *ServiceDiscovery) DeregisterService(serviceID string) error {
	sd.mu.Lock()
	service, exists := sd.services[serviceID]
	if !exists {
		sd.mu.Unlock()
		return errors.New("service not found")
	}
	delete(sd.services, serviceID)
	sd.mu.Unlock()

	// Notify listeners
	for _, listener := range sd.listeners {
		go listener.OnServiceDeregister(service)
	}

	log.Printf("Service deregistered: %s", serviceID)
	return nil
}

// GetService returns a service by ID
func (sd *ServiceDiscovery) GetService(serviceID string) (*Service, error) {
	sd.mu.RLock()
	defer sd.mu.RUnlock()

	service, exists := sd.services[serviceID]
	if !exists {
		return nil, errors.New("service not found")
	}

	return service, nil
}

// GetServices returns all services
func (sd *ServiceDiscovery) GetServices() []*Service {
	sd.mu.RLock()
	defer sd.mu.RUnlock()

	services := make([]*Service, 0, len(sd.services))
	for _, service := range sd.services {
		services = append(services, service)
	}

	return services
}

// QueryServices queries services based on options
func (sd *ServiceDiscovery) QueryServices(options QueryOptions) []*Service {
	sd.mu.RLock()
	defer sd.mu.RUnlock()

	var results []*Service

	for _, service := range sd.services {
		if sd.matchesQuery(service, options) {
			results = append(results, service)
		}

		// Apply limit
		if options.Limit > 0 && len(results) >= options.Limit {
			break
		}
	}

	return results
}

// GetServicesByName returns services by name
func (sd *ServiceDiscovery) GetServicesByName(serviceName string) []*Service {
	return sd.QueryServices(QueryOptions{
		ServiceName: serviceName,
		Healthy:     boolPtr(true),
	})
}

// GetHealthyServices returns only healthy services
func (sd *ServiceDiscovery) GetHealthyServices() []*Service {
	return sd.QueryServices(QueryOptions{
		Healthy: boolPtr(true),
	})
}

// AddListener adds a service event listener
func (sd *ServiceDiscovery) AddListener(listener ServiceEventListener) {
	sd.listeners = append(sd.listeners, listener)
}

// UpdateServiceHealth updates the health status of a service
func (sd *ServiceDiscovery) UpdateServiceHealth(serviceID string, status ServiceStatus) error {
	sd.mu.Lock()
	service, exists := sd.services[serviceID]
	if !exists {
		sd.mu.Unlock()
		return errors.New("service not found")
	}

	oldStatus := service.Status
	service.Status = status
	service.LastSeen = time.Now()
	sd.mu.Unlock()

	// Notify listeners if status changed
	if oldStatus != status {
		for _, listener := range sd.listeners {
			go listener.OnServiceHealthChange(service, oldStatus, status)
		}
	}

	return nil
}

// startServer starts the HTTP server for service discovery API
func (sd *ServiceDiscovery) startServer() {
	mux := http.NewServeMux()

	// Service registration endpoints
	mux.HandleFunc("/v1/agent/service/register", sd.handleServiceRegister)
	mux.HandleFunc("/v1/agent/service/deregister/", sd.handleServiceDeregister)

	// Service query endpoints
	mux.HandleFunc("/v1/health/service/", sd.handleHealthService)
	mux.HandleFunc("/v1/catalog/service/", sd.handleCatalogService)
	mux.HandleFunc("/v1/catalog/services", sd.handleCatalogServices)

	// Health check endpoints
	mux.HandleFunc("/v1/health/checks", sd.handleHealthChecks)
	mux.HandleFunc("/v1/agent/checks", sd.handleAgentChecks)

	// Status endpoints
	mux.HandleFunc("/v1/status/leader", sd.handleStatusLeader)
	mux.HandleFunc("/v1/status/peers", sd.handleStatusPeers)

	addr := fmt.Sprintf("%s:%d", sd.config.BindAddress, sd.config.BindPort)
	log.Printf("Starting service discovery server on %s", addr)

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Printf("Service discovery server error: %v", err)
	}
}

// handleServiceRegister handles service registration requests
func (sd *ServiceDiscovery) handleServiceRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var service Service
	if err := json.NewDecoder(r.Body).Decode(&service); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := sd.RegisterService(&service); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleServiceDeregister handles service deregistration requests
func (sd *ServiceDiscovery) handleServiceDeregister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	serviceID := r.URL.Path[len("/v1/agent/service/deregister/"):]
	if serviceID == "" {
		http.Error(w, "Service ID required", http.StatusBadRequest)
		return
	}

	if err := sd.DeregisterService(serviceID); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleHealthService handles health service queries
func (sd *ServiceDiscovery) handleHealthService(w http.ResponseWriter, r *http.Request) {
	serviceName := r.URL.Path[len("/v1/health/service/"):]
	if serviceName == "" {
		http.Error(w, "Service name required", http.StatusBadRequest)
		return
	}

	services := sd.GetServicesByName(serviceName)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(services)
}

// handleCatalogService handles catalog service queries
func (sd *ServiceDiscovery) handleCatalogService(w http.ResponseWriter, r *http.Request) {
	serviceName := r.URL.Path[len("/v1/catalog/service/"):]
	if serviceName == "" {
		http.Error(w, "Service name required", http.StatusBadRequest)
		return
	}

	services := sd.QueryServices(QueryOptions{
		ServiceName: serviceName,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(services)
}

// handleCatalogServices handles catalog services list
func (sd *ServiceDiscovery) handleCatalogServices(w http.ResponseWriter, r *http.Request) {
	services := sd.GetServices()

	// Group services by name
	serviceMap := make(map[string][]string)
	for _, service := range services {
		serviceMap[service.Name] = service.Tags
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(serviceMap)
}

// handleHealthChecks handles health checks list
func (sd *ServiceDiscovery) handleHealthChecks(w http.ResponseWriter, r *http.Request) {
	services := sd.GetServices()

	checks := make([]map[string]interface{}, 0)
	for _, service := range services {
		check := map[string]interface{}{
			"CheckID":     service.ID + ":health",
			"Name":        "Service Health Check",
			"Status":      string(service.Status),
			"ServiceID":   service.ID,
			"ServiceName": service.Name,
		}
		checks = append(checks, check)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(checks)
}

// handleAgentChecks handles agent checks
func (sd *ServiceDiscovery) handleAgentChecks(w http.ResponseWriter, r *http.Request) {
	// Same as health checks for now
	sd.handleHealthChecks(w, r)
}

// handleStatusLeader handles leader status
func (sd *ServiceDiscovery) handleStatusLeader(w http.ResponseWriter, r *http.Request) {
	leader := fmt.Sprintf("%s:%d", sd.config.BindAddress, sd.config.BindPort)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(leader)
}

// handleStatusPeers handles peers status
func (sd *ServiceDiscovery) handleStatusPeers(w http.ResponseWriter, r *http.Request) {
	peers := []string{fmt.Sprintf("%s:%d", sd.config.BindAddress, sd.config.BindPort)}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(peers)
}

// startHealthChecker starts the health checking routine
func (sd *ServiceDiscovery) startHealthChecker() {
	ticker := time.NewTicker(sd.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sd.performHealthChecks()
		case <-sd.stopChan:
			return
		}
	}
}

// performHealthChecks performs health checks on all services
func (sd *ServiceDiscovery) performHealthChecks() {
	services := sd.GetServices()

	for _, service := range services {
		if service.HealthCheck.Enabled {
			go sd.checkServiceHealth(service)
		}
	}
}

// checkServiceHealth performs health check on a single service
func (sd *ServiceDiscovery) checkServiceHealth(service *Service) {
	ctx, cancel := context.WithTimeout(context.Background(), service.HealthCheck.Timeout)
	defer cancel()

	healthURL := fmt.Sprintf("http://%s:%d%s", service.Address, service.Port, service.HealthCheck.Endpoint)

	req, err := http.NewRequestWithContext(ctx, service.HealthCheck.Method, healthURL, nil)
	if err != nil {
		sd.UpdateServiceHealth(service.ID, ServiceStatusUnhealthy)
		return
	}

	resp, err := sd.client.Do(req)
	if err != nil {
		sd.UpdateServiceHealth(service.ID, ServiceStatusUnhealthy)
		return
	}
	defer resp.Body.Close()

	// Consider 2xx status codes as healthy
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		sd.UpdateServiceHealth(service.ID, ServiceStatusHealthy)
	} else {
		sd.UpdateServiceHealth(service.ID, ServiceStatusUnhealthy)
	}
}

// startCleanup starts the cleanup routine for stale services
func (sd *ServiceDiscovery) startCleanup() {
	ticker := time.NewTicker(sd.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sd.cleanupStaleServices()
		case <-sd.stopChan:
			return
		}
	}
}

// cleanupStaleServices removes stale services
func (sd *ServiceDiscovery) cleanupStaleServices() {
	sd.mu.Lock()
	defer sd.mu.Unlock()

	now := time.Now()
	for serviceID, service := range sd.services {
		if now.Sub(service.LastSeen) > sd.config.TTL {
			delete(sd.services, serviceID)
			log.Printf("Cleaned up stale service: %s", serviceID)

			// Notify listeners
			for _, listener := range sd.listeners {
				go listener.OnServiceDeregister(service)
			}
		}
	}
}

// matchesQuery checks if a service matches the query options
func (sd *ServiceDiscovery) matchesQuery(service *Service, options QueryOptions) bool {
	// Check service name
	if options.ServiceName != "" && service.Name != options.ServiceName {
		return false
	}

	// Check health status
	if options.Healthy != nil {
		isHealthy := service.Status == ServiceStatusHealthy
		if *options.Healthy != isHealthy {
			return false
		}
	}

	// Check tags
	if len(options.Tags) > 0 {
		for _, requiredTag := range options.Tags {
			found := false
			for _, serviceTag := range service.Tags {
				if serviceTag == requiredTag {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}

	// Check metadata
	if len(options.Metadata) > 0 {
		for key, value := range options.Metadata {
			if service.Metadata[key] != value {
				return false
			}
		}
	}

	return true
}

// generateServiceID generates a unique service ID
func generateServiceID(name, address string, port int) string {
	return fmt.Sprintf("%s-%s-%d-%d", name, address, port, time.Now().UnixNano())
}

// boolPtr returns a pointer to a boolean value
func boolPtr(b bool) *bool {
	return &b
}

// GetStats returns service discovery statistics
func (sd *ServiceDiscovery) GetStats() map[string]interface{} {
	sd.mu.RLock()
	defer sd.mu.RUnlock()

	healthyCount := 0
	unhealthyCount := 0
	servicesByName := make(map[string]int)

	for _, service := range sd.services {
		if service.Status == ServiceStatusHealthy {
			healthyCount++
		} else {
			unhealthyCount++
		}

		servicesByName[service.Name]++
	}

	return map[string]interface{}{
		"total_services":     len(sd.services),
		"healthy_services":   healthyCount,
		"unhealthy_services": unhealthyCount,
		"services_by_name":   servicesByName,
		"listeners":          len(sd.listeners),
	}
}