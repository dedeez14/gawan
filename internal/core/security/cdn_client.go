package security

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// CDNClient interface for CDN operations
type CDNClient interface {
	BlockIP(ip string, reason string) error
	UnblockIP(ip string) error
	GetBlockedIPs() ([]string, error)
	CreateFirewallRule(rule FirewallRule) error
	DeleteFirewallRule(ruleID string) error
	GetFirewallRules() ([]FirewallRule, error)
	PurgeCache(urls []string) error
	GetSecurityEvents(limit int) ([]SecurityEvent, error)
}

// FirewallRule represents a CDN firewall rule
type FirewallRule struct {
	ID          string `json:"id,omitempty"`
	Expression  string `json:"expression"`
	Action      string `json:"action"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Priority    int    `json:"priority,omitempty"`
}

// SecurityEvent represents a security event from CDN
type SecurityEvent struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	IP        string    `json:"ip"`
	Country   string    `json:"country"`
	Action    string    `json:"action"`
	Reason    string    `json:"reason"`
	UserAgent string    `json:"user_agent"`
	Path      string    `json:"path"`
}

// CloudflareCDNClient implements CDN operations for Cloudflare
type CloudflareCDNClient struct {
	apiToken string
	zoneID   string
	client   *http.Client
	baseURL  string
}

// NewCloudflareCDNClient creates a new Cloudflare CDN client
func NewCloudflareCDNClient(apiToken, zoneID string) CDNClient {
	return &CloudflareCDNClient{
		apiToken: apiToken,
		zoneID:   zoneID,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: "https://api.cloudflare.com/client/v4",
	}
}

// BlockIP blocks an IP address using Cloudflare firewall rules
func (c *CloudflareCDNClient) BlockIP(ip string, reason string) error {
	rule := FirewallRule{
		Expression:  fmt.Sprintf(`(ip.src eq %s)`, ip),
		Action:      "block",
		Description: fmt.Sprintf("Auto-blocked: %s", reason),
		Enabled:     true,
	}
	
	return c.CreateFirewallRule(rule)
}

// UnblockIP removes IP block by deleting the firewall rule
func (c *CloudflareCDNClient) UnblockIP(ip string) error {
	rules, err := c.GetFirewallRules()
	if err != nil {
		return err
	}
	
	for _, rule := range rules {
		if strings.Contains(rule.Expression, ip) && rule.Action == "block" {
			return c.DeleteFirewallRule(rule.ID)
		}
	}
	
	return fmt.Errorf("no blocking rule found for IP %s", ip)
}

// GetBlockedIPs returns list of blocked IPs
func (c *CloudflareCDNClient) GetBlockedIPs() ([]string, error) {
	rules, err := c.GetFirewallRules()
	if err != nil {
		return nil, err
	}
	
	var blockedIPs []string
	for _, rule := range rules {
		if rule.Action == "block" && strings.Contains(rule.Expression, "ip.src eq") {
			// Extract IP from expression like "(ip.src eq 192.168.1.1)"
			parts := strings.Split(rule.Expression, " ")
			if len(parts) >= 3 {
				ip := strings.Trim(parts[2], "()")
				blockedIPs = append(blockedIPs, ip)
			}
		}
	}
	
	return blockedIPs, nil
}

// CreateFirewallRule creates a new firewall rule
func (c *CloudflareCDNClient) CreateFirewallRule(rule FirewallRule) error {
	url := fmt.Sprintf("%s/zones/%s/firewall/rules", c.baseURL, c.zoneID)
	
	payload := []FirewallRule{rule}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal rule: %w", err)
	}
	
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}
	
	return nil
}

// DeleteFirewallRule deletes a firewall rule
func (c *CloudflareCDNClient) DeleteFirewallRule(ruleID string) error {
	url := fmt.Sprintf("%s/zones/%s/firewall/rules/%s", c.baseURL, c.zoneID, ruleID)
	
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}
	
	return nil
}

// GetFirewallRules retrieves all firewall rules
func (c *CloudflareCDNClient) GetFirewallRules() ([]FirewallRule, error) {
	url := fmt.Sprintf("%s/zones/%s/firewall/rules", c.baseURL, c.zoneID)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}
	
	var response struct {
		Result []FirewallRule `json:"result"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	return response.Result, nil
}

// PurgeCache purges cache for specified URLs
func (c *CloudflareCDNClient) PurgeCache(urls []string) error {
	url := fmt.Sprintf("%s/zones/%s/purge_cache", c.baseURL, c.zoneID)
	
	payload := map[string]interface{}{
		"files": urls,
	}
	
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}
	
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}
	
	return nil
}

// GetSecurityEvents retrieves security events from Cloudflare
func (c *CloudflareCDNClient) GetSecurityEvents(limit int) ([]SecurityEvent, error) {
	// This would typically use Cloudflare Analytics API or Logs API
	// For now, return empty slice as this requires additional setup
	return []SecurityEvent{}, nil
}

// MockCDNClient is a mock implementation for testing
type MockCDNClient struct {
	blockedIPs     map[string]string
	firewallRules  map[string]FirewallRule
	securityEvents []SecurityEvent
	nextRuleID     int
}

// NewMockCDNClient creates a new mock CDN client
func NewMockCDNClient() CDNClient {
	return &MockCDNClient{
		blockedIPs:     make(map[string]string),
		firewallRules:  make(map[string]FirewallRule),
		securityEvents: []SecurityEvent{},
		nextRuleID:     1,
	}
}

// BlockIP blocks an IP in the mock client
func (m *MockCDNClient) BlockIP(ip string, reason string) error {
	m.blockedIPs[ip] = reason
	return nil
}

// UnblockIP unblocks an IP in the mock client
func (m *MockCDNClient) UnblockIP(ip string) error {
	delete(m.blockedIPs, ip)
	return nil
}

// GetBlockedIPs returns blocked IPs from the mock client
func (m *MockCDNClient) GetBlockedIPs() ([]string, error) {
	var ips []string
	for ip := range m.blockedIPs {
		ips = append(ips, ip)
	}
	return ips, nil
}

// CreateFirewallRule creates a firewall rule in the mock client
func (m *MockCDNClient) CreateFirewallRule(rule FirewallRule) error {
	rule.ID = fmt.Sprintf("rule_%d", m.nextRuleID)
	m.nextRuleID++
	m.firewallRules[rule.ID] = rule
	return nil
}

// DeleteFirewallRule deletes a firewall rule from the mock client
func (m *MockCDNClient) DeleteFirewallRule(ruleID string) error {
	delete(m.firewallRules, ruleID)
	return nil
}

// GetFirewallRules returns firewall rules from the mock client
func (m *MockCDNClient) GetFirewallRules() ([]FirewallRule, error) {
	var rules []FirewallRule
	for _, rule := range m.firewallRules {
		rules = append(rules, rule)
	}
	return rules, nil
}

// PurgeCache simulates cache purging in the mock client
func (m *MockCDNClient) PurgeCache(urls []string) error {
	// Mock implementation - just return success
	return nil
}

// GetSecurityEvents returns security events from the mock client
func (m *MockCDNClient) GetSecurityEvents(limit int) ([]SecurityEvent, error) {
	if limit > len(m.securityEvents) {
		limit = len(m.securityEvents)
	}
	return m.securityEvents[:limit], nil
}

// AddSecurityEvent adds a security event to the mock client (for testing)
func (m *MockCDNClient) AddSecurityEvent(event SecurityEvent) {
	m.securityEvents = append(m.securityEvents, event)
}

// CDNConfig holds configuration for CDN integration
type CDNConfig struct {
	Provider    string `json:"provider"`     // "cloudflare", "aws", "azure", etc.
	APIToken    string `json:"api_token"`   // API token for authentication
	ZoneID      string `json:"zone_id"`     // Zone/domain ID
	Enabled     bool   `json:"enabled"`     // Whether CDN integration is enabled
	AutoBlock   bool   `json:"auto_block"`  // Automatically block suspicious IPs
	BlockThreshold int `json:"block_threshold"` // Number of violations before auto-block
}

// CDNManager manages CDN operations and integrations
type CDNManager struct {
	config CDNConfig
	client CDNClient
}

// NewCDNManager creates a new CDN manager
func NewCDNManager(config CDNConfig) (*CDNManager, error) {
	var client CDNClient
	
	switch strings.ToLower(config.Provider) {
	case "cloudflare":
		client = NewCloudflareCDNClient(config.APIToken, config.ZoneID)
	case "mock":
		client = NewMockCDNClient()
	default:
		return nil, fmt.Errorf("unsupported CDN provider: %s", config.Provider)
	}
	
	return &CDNManager{
		config: config,
		client: client,
	}, nil
}

// BlockIPWithReason blocks an IP with a specific reason
func (cm *CDNManager) BlockIPWithReason(ip, reason string) error {
	if !cm.config.Enabled {
		return fmt.Errorf("CDN integration is disabled")
	}
	
	return cm.client.BlockIP(ip, reason)
}

// UnblockIP unblocks an IP
func (cm *CDNManager) UnblockIP(ip string) error {
	if !cm.config.Enabled {
		return fmt.Errorf("CDN integration is disabled")
	}
	
	return cm.client.UnblockIP(ip)
}

// GetBlockedIPs returns list of blocked IPs
func (cm *CDNManager) GetBlockedIPs() ([]string, error) {
	if !cm.config.Enabled {
		return nil, fmt.Errorf("CDN integration is disabled")
	}
	
	return cm.client.GetBlockedIPs()
}

// CreateCustomRule creates a custom firewall rule
func (cm *CDNManager) CreateCustomRule(expression, action, description string) error {
	if !cm.config.Enabled {
		return fmt.Errorf("CDN integration is disabled")
	}
	
	rule := FirewallRule{
		Expression:  expression,
		Action:      action,
		Description: description,
		Enabled:     true,
	}
	
	return cm.client.CreateFirewallRule(rule)
}

// PurgeCache purges cache for specified URLs
func (cm *CDNManager) PurgeCache(urls []string) error {
	if !cm.config.Enabled {
		return fmt.Errorf("CDN integration is disabled")
	}
	
	return cm.client.PurgeCache(urls)
}

// GetSecurityEvents retrieves recent security events
func (cm *CDNManager) GetSecurityEvents(limit int) ([]SecurityEvent, error) {
	if !cm.config.Enabled {
		return nil, fmt.Errorf("CDN integration is disabled")
	}
	
	return cm.client.GetSecurityEvents(limit)
}

// IsEnabled returns whether CDN integration is enabled
func (cm *CDNManager) IsEnabled() bool {
	return cm.config.Enabled
}

// GetConfig returns the CDN configuration
func (cm *CDNManager) GetConfig() CDNConfig {
	return cm.config
}