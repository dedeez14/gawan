package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"Gawan/internal/core/logx"
)

// DDoSProtectionConfig holds DDoS protection configuration
type DDoSProtectionConfig struct {
	// Enabled enables DDoS protection
	Enabled bool `json:"enabled" yaml:"enabled" env:"DDOS_PROTECTION_ENABLED" default:"true"`
	// MaxRequestsPerSecond is the maximum requests per second per IP
	MaxRequestsPerSecond int `json:"max_requests_per_second" yaml:"max_requests_per_second" env:"DDOS_MAX_RPS" default:"10"`
	// MaxRequestsPerMinute is the maximum requests per minute per IP
	MaxRequestsPerMinute int `json:"max_requests_per_minute" yaml:"max_requests_per_minute" env:"DDOS_MAX_RPM" default:"300"`
	// MaxRequestsPerHour is the maximum requests per hour per IP
	MaxRequestsPerHour int `json:"max_requests_per_hour" yaml:"max_requests_per_hour" env:"DDOS_MAX_RPH" default:"5000"`
	// BurstSize is the burst size for token bucket
	BurstSize int `json:"burst_size" yaml:"burst_size" env:"DDOS_BURST_SIZE" default:"20"`
	// BlockDuration is how long to block an IP after detection
	BlockDuration time.Duration `json:"block_duration" yaml:"block_duration" env:"DDOS_BLOCK_DURATION" default:"15m"`
	// WhitelistedIPs are IPs that bypass DDoS protection
	WhitelistedIPs []string `json:"whitelisted_ips" yaml:"whitelisted_ips" env:"DDOS_WHITELIST"`
	// BlacklistedIPs are IPs that are permanently blocked
	BlacklistedIPs []string `json:"blacklisted_ips" yaml:"blacklisted_ips" env:"DDOS_BLACKLIST"`
	// GeoBlocking configuration
	GeoBlocking GeoBlockingConfig `json:"geo_blocking" yaml:"geo_blocking"`
	// CDN configuration for mitigation
	CDN CDNConfig `json:"cdn" yaml:"cdn"`
	// Logger for audit events
	Logger *logx.Logger `json:"-" yaml:"-"`
}

// GeoBlockingConfig holds geolocation blocking configuration
type GeoBlockingConfig struct {
	// Enabled enables geo-blocking
	Enabled bool `json:"enabled" yaml:"enabled" env:"GEO_BLOCKING_ENABLED" default:"false"`
	// BlockedCountries are country codes to block (ISO 3166-1 alpha-2)
	BlockedCountries []string `json:"blocked_countries" yaml:"blocked_countries" env:"GEO_BLOCKED_COUNTRIES"`
	// AllowedCountries are country codes to allow (if set, only these are allowed)
	AllowedCountries []string `json:"allowed_countries" yaml:"allowed_countries" env:"GEO_ALLOWED_COUNTRIES"`
	// GeoIPDatabase path to GeoIP database file
	GeoIPDatabase string `json:"geoip_database" yaml:"geoip_database" env:"GEOIP_DATABASE"`
}

// CDNConfig holds CDN configuration for DDoS mitigation
type CDNConfig struct {
	// Enabled enables CDN integration
	Enabled bool `json:"enabled" yaml:"enabled" env:"CDN_ENABLED" default:"false"`
	// Provider is the CDN provider (cloudflare, aws, etc.)
	Provider string `json:"provider" yaml:"provider" env:"CDN_PROVIDER" default:"cloudflare"`
	// APIKey for CDN provider
	APIKey string `json:"api_key" yaml:"api_key" env:"CDN_API_KEY"`
	// ZoneID for CDN provider
	ZoneID string `json:"zone_id" yaml:"zone_id" env:"CDN_ZONE_ID"`
	// AutoMitigate enables automatic DDoS mitigation
	AutoMitigate bool `json:"auto_mitigate" yaml:"auto_mitigate" env:"CDN_AUTO_MITIGATE" default:"true"`
}

// DDoSProtector implements comprehensive DDoS protection
type DDoSProtector struct {
	config DDoSProtectionConfig
	mu     sync.RWMutex
	
	// Rate limiting per IP
	requestCounts map[string]*RequestCounter
	
	// Blocked IPs with expiration
	blockedIPs map[string]time.Time
	
	// Whitelisted and blacklisted IP networks
	whitelistedNets []*net.IPNet
	blacklistedNets []*net.IPNet
	
	// Cleanup ticker
	cleanupTicker *time.Ticker
	stop          chan struct{}
	
	// GeoIP resolver
	geoResolver GeoIPResolver
	
	// CDN client
	cdnClient CDNClient
}

// RequestCounter tracks requests for different time windows
type RequestCounter struct {
	mu                sync.RWMutex
	requestsPerSecond []time.Time
	requestsPerMinute []time.Time
	requestsPerHour   []time.Time
	lastClean         time.Time
}

// GeoIPResolver interface for geolocation services
type GeoIPResolver interface {
	GetCountryCode(ip string) (string, error)
}

// CDNClient interface for CDN integration
type CDNClient interface {
	EnableDDoSProtection(ctx context.Context) error
	BlockIP(ctx context.Context, ip string, duration time.Duration) error
	UnblockIP(ctx context.Context, ip string) error
}

// NewDDoSProtector creates a new DDoS protector
func NewDDoSProtector(config DDoSProtectionConfig) *DDoSProtector {
	protector := &DDoSProtector{
		config:        config,
		requestCounts: make(map[string]*RequestCounter),
		blockedIPs:    make(map[string]time.Time),
		cleanupTicker: time.NewTicker(time.Minute),
		stop:          make(chan struct{}),
	}
	
	// Parse whitelisted IPs
	for _, ipStr := range config.WhitelistedIPs {
		if _, ipNet, err := net.ParseCIDR(ipStr); err == nil {
			protector.whitelistedNets = append(protector.whitelistedNets, ipNet)
		} else if ip := net.ParseIP(ipStr); ip != nil {
			// Convert single IP to CIDR
			if ip.To4() != nil {
				_, ipNet, _ := net.ParseCIDR(ipStr + "/32")
				protector.whitelistedNets = append(protector.whitelistedNets, ipNet)
			} else {
				_, ipNet, _ := net.ParseCIDR(ipStr + "/128")
				protector.whitelistedNets = append(protector.whitelistedNets, ipNet)
			}
		}
	}
	
	// Parse blacklisted IPs
	for _, ipStr := range config.BlacklistedIPs {
		if _, ipNet, err := net.ParseCIDR(ipStr); err == nil {
			protector.blacklistedNets = append(protector.blacklistedNets, ipNet)
		} else if ip := net.ParseIP(ipStr); ip != nil {
			// Convert single IP to CIDR
			if ip.To4() != nil {
				_, ipNet, _ := net.ParseCIDR(ipStr + "/32")
				protector.blacklistedNets = append(protector.blacklistedNets, ipNet)
			} else {
				_, ipNet, _ := net.ParseCIDR(ipStr + "/128")
				protector.blacklistedNets = append(protector.blacklistedNets, ipNet)
			}
		}
	}
	
	// Initialize GeoIP resolver if geo-blocking is enabled
	if config.GeoBlocking.Enabled {
		protector.geoResolver = NewGeoIPResolver(config.GeoBlocking.GeoIPDatabase)
	}
	
	// Initialize CDN client if CDN is enabled
	if config.CDN.Enabled {
		protector.cdnClient = NewCDNClient(config.CDN)
	}
	
	// Start cleanup goroutine
	go protector.cleanupRoutine()
	
	return protector
}

// IsAllowed checks if a request from the given IP is allowed
func (dp *DDoSProtector) IsAllowed(ip string) (bool, string) {
	if !dp.config.Enabled {
		return true, ""
	}
	
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false, "Invalid IP address"
	}
	
	// Check if IP is blacklisted
	if dp.isBlacklisted(parsedIP) {
		return false, "IP is blacklisted"
	}
	
	// Check if IP is whitelisted (bypass all other checks)
	if dp.isWhitelisted(parsedIP) {
		return true, ""
	}
	
	// Check if IP is currently blocked
	dp.mu.RLock()
	blockUntil, isBlocked := dp.blockedIPs[ip]
	dp.mu.RUnlock()
	
	if isBlocked && time.Now().Before(blockUntil) {
		return false, fmt.Sprintf("IP blocked until %s", blockUntil.Format(time.RFC3339))
	}
	
	// Check geo-blocking
	if dp.config.GeoBlocking.Enabled && dp.geoResolver != nil {
		if allowed, reason := dp.checkGeoBlocking(ip); !allowed {
			return false, reason
		}
	}
	
	// Check rate limits
	if exceeded, reason := dp.checkRateLimits(ip); exceeded {
		// Block the IP
		dp.blockIP(ip, dp.config.BlockDuration)
		return false, reason
	}
	
	return true, ""
}

// RecordRequest records a request from the given IP
func (dp *DDoSProtector) RecordRequest(ip string) {
	if !dp.config.Enabled {
		return
	}
	
	dp.mu.Lock()
	defer dp.mu.Unlock()
	
	counter, exists := dp.requestCounts[ip]
	if !exists {
		counter = &RequestCounter{
			requestsPerSecond: make([]time.Time, 0),
			requestsPerMinute: make([]time.Time, 0),
			requestsPerHour:   make([]time.Time, 0),
			lastClean:         time.Now(),
		}
		dp.requestCounts[ip] = counter
	}
	
	now := time.Now()
	counter.mu.Lock()
	counter.requestsPerSecond = append(counter.requestsPerSecond, now)
	counter.requestsPerMinute = append(counter.requestsPerMinute, now)
	counter.requestsPerHour = append(counter.requestsPerHour, now)
	counter.mu.Unlock()
}

// checkRateLimits checks if the IP has exceeded rate limits
func (dp *DDoSProtector) checkRateLimits(ip string) (bool, string) {
	dp.mu.RLock()
	counter, exists := dp.requestCounts[ip]
	dp.mu.RUnlock()
	
	if !exists {
		return false, ""
	}
	
	now := time.Now()
	counter.mu.Lock()
	defer counter.mu.Unlock()
	
	// Clean old requests
	counter.requestsPerSecond = dp.filterRequests(counter.requestsPerSecond, now.Add(-time.Second))
	counter.requestsPerMinute = dp.filterRequests(counter.requestsPerMinute, now.Add(-time.Minute))
	counter.requestsPerHour = dp.filterRequests(counter.requestsPerHour, now.Add(-time.Hour))
	
	// Check limits
	if len(counter.requestsPerSecond) >= dp.config.MaxRequestsPerSecond {
		return true, fmt.Sprintf("Rate limit exceeded: %d requests per second", len(counter.requestsPerSecond))
	}
	
	if len(counter.requestsPerMinute) >= dp.config.MaxRequestsPerMinute {
		return true, fmt.Sprintf("Rate limit exceeded: %d requests per minute", len(counter.requestsPerMinute))
	}
	
	if len(counter.requestsPerHour) >= dp.config.MaxRequestsPerHour {
		return true, fmt.Sprintf("Rate limit exceeded: %d requests per hour", len(counter.requestsPerHour))
	}
	
	return false, ""
}

// filterRequests filters out requests older than the cutoff time
func (dp *DDoSProtector) filterRequests(requests []time.Time, cutoff time.Time) []time.Time {
	filtered := make([]time.Time, 0, len(requests))
	for _, reqTime := range requests {
		if reqTime.After(cutoff) {
			filtered = append(filtered, reqTime)
		}
	}
	return filtered
}

// isWhitelisted checks if an IP is whitelisted
func (dp *DDoSProtector) isWhitelisted(ip net.IP) bool {
	for _, ipNet := range dp.whitelistedNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// isBlacklisted checks if an IP is blacklisted
func (dp *DDoSProtector) isBlacklisted(ip net.IP) bool {
	for _, ipNet := range dp.blacklistedNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// checkGeoBlocking checks geo-blocking rules
func (dp *DDoSProtector) checkGeoBlocking(ip string) (bool, string) {
	countryCode, err := dp.geoResolver.GetCountryCode(ip)
	if err != nil {
		// If we can't determine country, allow by default
		return true, ""
	}
	
	// If allowed countries are specified, only allow those
	if len(dp.config.GeoBlocking.AllowedCountries) > 0 {
		for _, allowed := range dp.config.GeoBlocking.AllowedCountries {
			if strings.EqualFold(countryCode, allowed) {
				return true, ""
			}
		}
		return false, fmt.Sprintf("Country %s not in allowed list", countryCode)
	}
	
	// Check blocked countries
	for _, blocked := range dp.config.GeoBlocking.BlockedCountries {
		if strings.EqualFold(countryCode, blocked) {
			return false, fmt.Sprintf("Country %s is blocked", countryCode)
		}
	}
	
	return true, ""
}

// blockIP blocks an IP for the specified duration
func (dp *DDoSProtector) blockIP(ip string, duration time.Duration) {
	dp.mu.Lock()
	dp.blockedIPs[ip] = time.Now().Add(duration)
	dp.mu.Unlock()
	
	// Log the block
	if dp.config.Logger != nil {
		dp.config.Logger.Warn("IP blocked for DDoS protection", 
			logx.String("ip", ip),
			logx.Duration("duration", duration),
		)
	}
	
	// Block on CDN if enabled
	if dp.cdnClient != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := dp.cdnClient.BlockIP(ctx, ip, duration); err != nil && dp.config.Logger != nil {
				dp.config.Logger.Error("Failed to block IP on CDN", 
					logx.String("ip", ip),
					logx.Error(err),
				)
			}
		}()
	}
}

// UnblockIP manually unblocks an IP
func (dp *DDoSProtector) UnblockIP(ip string) {
	dp.mu.Lock()
	delete(dp.blockedIPs, ip)
	dp.mu.Unlock()
	
	// Unblock on CDN if enabled
	if dp.cdnClient != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := dp.cdnClient.UnblockIP(ctx, ip); err != nil && dp.config.Logger != nil {
				dp.config.Logger.Error("Failed to unblock IP on CDN", 
					logx.String("ip", ip),
					logx.Error(err),
				)
			}
		}()
	}
}

// GetBlockedIPs returns currently blocked IPs
func (dp *DDoSProtector) GetBlockedIPs() map[string]time.Time {
	dp.mu.RLock()
	defer dp.mu.RUnlock()
	
	blocked := make(map[string]time.Time)
	for ip, blockUntil := range dp.blockedIPs {
		if time.Now().Before(blockUntil) {
			blocked[ip] = blockUntil
		}
	}
	return blocked
}

// GetStats returns DDoS protection statistics
func (dp *DDoSProtector) GetStats() map[string]interface{} {
	dp.mu.RLock()
	defer dp.mu.RUnlock()
	
	stats := map[string]interface{}{
		"total_ips_tracked":    len(dp.requestCounts),
		"currently_blocked":    len(dp.blockedIPs),
		"whitelisted_networks": len(dp.whitelistedNets),
		"blacklisted_networks": len(dp.blacklistedNets),
		"geo_blocking_enabled": dp.config.GeoBlocking.Enabled,
		"cdn_enabled":          dp.config.CDN.Enabled,
	}
	
	// Count active blocks
	activeBlocks := 0
	now := time.Now()
	for _, blockUntil := range dp.blockedIPs {
		if now.Before(blockUntil) {
			activeBlocks++
		}
	}
	stats["active_blocks"] = activeBlocks
	
	return stats
}

// cleanupRoutine periodically cleans up expired data
func (dp *DDoSProtector) cleanupRoutine() {
	for {
		select {
		case <-dp.cleanupTicker.C:
			dp.cleanup()
		case <-dp.stop:
			return
		}
	}
}

// cleanup removes expired data
func (dp *DDoSProtector) cleanup() {
	now := time.Now()
	
	dp.mu.Lock()
	defer dp.mu.Unlock()
	
	// Clean expired blocked IPs
	for ip, blockUntil := range dp.blockedIPs {
		if now.After(blockUntil) {
			delete(dp.blockedIPs, ip)
		}
	}
	
	// Clean old request counters
	for ip, counter := range dp.requestCounts {
		counter.mu.Lock()
		
		// If no recent requests, remove the counter
		if now.Sub(counter.lastClean) > time.Hour {
			counter.requestsPerSecond = dp.filterRequests(counter.requestsPerSecond, now.Add(-time.Second))
			counter.requestsPerMinute = dp.filterRequests(counter.requestsPerMinute, now.Add(-time.Minute))
			counter.requestsPerHour = dp.filterRequests(counter.requestsPerHour, now.Add(-time.Hour))
			
			if len(counter.requestsPerSecond) == 0 && len(counter.requestsPerMinute) == 0 && len(counter.requestsPerHour) == 0 {
				counter.mu.Unlock()
				delete(dp.requestCounts, ip)
				continue
			}
			
			counter.lastClean = now
		}
		
		counter.mu.Unlock()
	}
}

// Stop stops the DDoS protector
func (dp *DDoSProtector) Stop() {
	close(dp.stop)
	dp.cleanupTicker.Stop()
}

// DDoSProtectionMiddleware creates DDoS protection middleware
func DDoSProtectionMiddleware(config DDoSProtectionConfig) func(http.Handler) http.Handler {
	protector := NewDDoSProtector(config)
	
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract client IP
			clientIP := extractClientIP(r)
			
			// Check if request is allowed
			allowed, reason := protector.IsAllowed(clientIP)
			if !allowed {
				// Log the blocked request
				if config.Logger != nil {
					config.Logger.Warn("DDoS protection blocked request",
						logx.String("ip", clientIP),
						logx.String("reason", reason),
						logx.String("user_agent", r.UserAgent()),
						logx.String("path", r.URL.Path),
					)
				}
				
				// Return 429 Too Many Requests
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "900") // 15 minutes
				w.WriteHeader(http.StatusTooManyRequests)
				
				response := map[string]interface{}{
					"error":   "Too Many Requests",
					"message": "Request blocked by DDoS protection",
					"reason":  reason,
					"code":    "DDOS_PROTECTION",
				}
				
				json.NewEncoder(w).Encode(response)
				return
			}
			
			// Record the request
			protector.RecordRequest(clientIP)
			
			// Continue to next handler
			next.ServeHTTP(w, r)
		})
	}
}

// extractClientIP extracts the real client IP from the request
func extractClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (most common)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		if ips := strings.Split(xff, ","); len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	
	// Check CF-Connecting-IP header (Cloudflare)
	if cfip := r.Header.Get("CF-Connecting-IP"); cfip != "" {
		return cfip
	}
	
	// Check X-Forwarded header
	if xf := r.Header.Get("X-Forwarded"); xf != "" {
		return xf
	}
	
	// Fall back to RemoteAddr
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return ip
	}
	
	return r.RemoteAddr
}