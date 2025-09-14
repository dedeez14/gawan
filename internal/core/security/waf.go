package security

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"Gawan/internal/core/logx"
)

// WAFConfig configuration for Web Application Firewall
type WAFConfig struct {
	Enabled                bool                    `json:"enabled"`
	StrictMode             bool                    `json:"strict_mode"`
	LogBlocked             bool                    `json:"log_blocked"`
	LogSuspicious          bool                    `json:"log_suspicious"`
	MaxRequestSize         int64                   `json:"max_request_size"`         // Maximum request body size
	MaxHeaderSize          int                     `json:"max_header_size"`          // Maximum header value size
	MaxURLLength           int                     `json:"max_url_length"`           // Maximum URL length
	MaxParameterCount      int                     `json:"max_parameter_count"`      // Maximum number of parameters
	MaxParameterLength     int                     `json:"max_parameter_length"`     // Maximum parameter value length
	BlockedUserAgents      []string                `json:"blocked_user_agents"`      // Blocked user agent patterns
	BlockedReferers        []string                `json:"blocked_referers"`         // Blocked referer patterns
	AllowedMethods         []string                `json:"allowed_methods"`          // Allowed HTTP methods
	AllowedContentTypes    []string                `json:"allowed_content_types"`    // Allowed content types
	BlockedExtensions      []string                `json:"blocked_extensions"`       // Blocked file extensions
	BlockedPaths           []string                `json:"blocked_paths"`            // Blocked URL paths
	WhitelistedIPs         []string                `json:"whitelisted_ips"`          // Whitelisted IP addresses
	BlacklistedIPs         []string                `json:"blacklisted_ips"`          // Blacklisted IP addresses
	RateLimitEnabled       bool                    `json:"rate_limit_enabled"`
	RateLimitRules         []WAFRateLimitRule      `json:"rate_limit_rules"`
	CustomRules            []WAFCustomRule         `json:"custom_rules"`
	GeoBlocking            WAFGeoBlockingConfig    `json:"geo_blocking"`
	AntiAutomation         WAFAntiAutomationConfig `json:"anti_automation"`
	ContentFiltering       WAFContentFilterConfig  `json:"content_filtering"`
	ResponseFiltering      WAFResponseFilterConfig `json:"response_filtering"`
}

// WAFRateLimitRule defines rate limiting rules
type WAFRateLimitRule struct {
	Name        string        `json:"name"`
	Path        string        `json:"path"`         // Path pattern (regex)
	Method      string        `json:"method"`       // HTTP method
	Limit       int           `json:"limit"`        // Requests per window
	Window      time.Duration `json:"window"`       // Time window
	BurstLimit  int           `json:"burst_limit"`  // Burst allowance
	BlockTime   time.Duration `json:"block_time"`   // Block duration after limit exceeded
}

// WAFCustomRule defines custom filtering rules
type WAFCustomRule struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Pattern     string   `json:"pattern"`     // Regex pattern
	Target      string   `json:"target"`      // header, body, url, parameter
	Action      string   `json:"action"`      // block, log, challenge
	Severity    string   `json:"severity"`    // low, medium, high, critical
	Enabled     bool     `json:"enabled"`
}

// WAFGeoBlockingConfig configuration for geo-blocking
type WAFGeoBlockingConfig struct {
	Enabled           bool     `json:"enabled"`
	BlockedCountries  []string `json:"blocked_countries"`  // Country codes to block
	AllowedCountries  []string `json:"allowed_countries"`  // Only allow these countries
	BlockTor          bool     `json:"block_tor"`          // Block Tor exit nodes
	BlockVPN          bool     `json:"block_vpn"`          // Block known VPN IPs
	BlockDatacenters  bool     `json:"block_datacenters"`  // Block datacenter IPs
}

// WAFAntiAutomationConfig configuration for anti-automation
type WAFAntiAutomationConfig struct {
	Enabled                bool     `json:"enabled"`
	BlockBots              bool     `json:"block_bots"`
	BlockScrapers          bool     `json:"block_scrapers"`
	RequireCaptcha         bool     `json:"require_captcha"`
	BotUserAgents          []string `json:"bot_user_agents"`
	SuspiciousBehaviors    []string `json:"suspicious_behaviors"`
	MaxRequestsPerSecond   int      `json:"max_requests_per_second"`
	MaxConcurrentRequests  int      `json:"max_concurrent_requests"`
}

// WAFContentFilterConfig configuration for content filtering
type WAFContentFilterConfig struct {
	Enabled              bool     `json:"enabled"`
	ScanUploads          bool     `json:"scan_uploads"`
	MaxUploadSize        int64    `json:"max_upload_size"`
	AllowedFileTypes     []string `json:"allowed_file_types"`
	BlockedFileTypes     []string `json:"blocked_file_types"`
	ScanForMalware       bool     `json:"scan_for_malware"`
	BlockExecutables     bool     `json:"block_executables"`
	BlockScripts         bool     `json:"block_scripts"`
}

// WAFResponseFilterConfig configuration for response filtering
type WAFResponseFilterConfig struct {
	Enabled              bool     `json:"enabled"`
	HideServerInfo       bool     `json:"hide_server_info"`
	RemoveDebugHeaders   bool     `json:"remove_debug_headers"`
	SanitizeErrors       bool     `json:"sanitize_errors"`
	BlockedResponseWords []string `json:"blocked_response_words"`
	MaxResponseSize      int64    `json:"max_response_size"`
}

// WAFEngine main WAF engine
type WAFEngine struct {
	config           WAFConfig
	rules            []*WAFRule
	rateLimiters     map[string]*WAFRateLimiter
	blacklistedIPs   map[string]time.Time
	whitelistedIPs   map[string]bool
	geoIPResolver    GeoIPResolver
	sqlDetector      *SQLInjectionDetector
	xssDetector      *XSSDetector
	mu               sync.RWMutex
	logger           *logx.Logger
	cleanup          *time.Ticker
	stop             chan struct{}
	stats            *WAFStats
}

// WAFRule represents a compiled WAF rule
type WAFRule struct {
	Name        string
	Description string
	Pattern     *regexp.Regexp
	Target      string
	Action      string
	Severity    string
	Enabled     bool
}

// WAFRateLimiter implements rate limiting for WAF
type WAFRateLimiter struct {
	Rule      WAFRateLimitRule
	Requests  map[string]*WAFRequestTracker
	mu        sync.RWMutex
}

// WAFRequestTracker tracks requests for rate limiting
type WAFRequestTracker struct {
	Count       int
	LastRequest time.Time
	Blocked     bool
	BlockUntil  time.Time
}

// WAFStats tracks WAF statistics
type WAFStats struct {
	TotalRequests    int64 `json:"total_requests"`
	BlockedRequests  int64 `json:"blocked_requests"`
	SuspiciousRequests int64 `json:"suspicious_requests"`
	BypassedRequests int64 `json:"bypassed_requests"`
	RateLimitHits    int64 `json:"rate_limit_hits"`
	GeoBlocks        int64 `json:"geo_blocks"`
	BotBlocks        int64 `json:"bot_blocks"`
	SQLInjectionBlocks int64 `json:"sql_injection_blocks"`
	XSSBlocks        int64 `json:"xss_blocks"`
	mu               sync.RWMutex
}

// WAFResult represents the result of WAF processing
type WAFResult struct {
	Allowed       bool     `json:"allowed"`
	Blocked       bool     `json:"blocked"`
	Reason        string   `json:"reason"`
	RuleTriggered string   `json:"rule_triggered,omitempty"`
	Severity      string   `json:"severity,omitempty"`
	Action        string   `json:"action"`
	Score         int      `json:"score"`
	Details       []string `json:"details,omitempty"`
	Challenge     bool     `json:"challenge,omitempty"`
}

// XSSDetector detects XSS attacks
type XSSDetector struct {
	patterns []*regexp.Regexp
	logger   *logx.Logger
}

// NewWAFEngine creates a new WAF engine
func NewWAFEngine(config WAFConfig, geoIPResolver GeoIPResolver, sqlDetector *SQLInjectionDetector, logger *logx.Logger) *WAFEngine {
	waf := &WAFEngine{
		config:         config,
		rateLimiters:   make(map[string]*WAFRateLimiter),
		blacklistedIPs: make(map[string]time.Time),
		whitelistedIPs: make(map[string]bool),
		geoIPResolver:  geoIPResolver,
		sqlDetector:    sqlDetector,
		xssDetector:    NewXSSDetector(logger),
		logger:         logger,
		cleanup:        time.NewTicker(5 * time.Minute),
		stop:           make(chan struct{}),
		stats:          &WAFStats{},
	}

	// Initialize whitelisted IPs
	for _, ip := range config.WhitelistedIPs {
		waf.whitelistedIPs[ip] = true
	}

	// Initialize blacklisted IPs
	for _, ip := range config.BlacklistedIPs {
		waf.blacklistedIPs[ip] = time.Now().Add(24 * time.Hour)
	}

	// Compile custom rules
	waf.compileRules()

	// Initialize rate limiters
	waf.initializeRateLimiters()

	// Start cleanup routine
	go waf.cleanupRoutine()

	return waf
}

// compileRules compiles custom WAF rules
func (waf *WAFEngine) compileRules() {
	for _, rule := range waf.config.CustomRules {
		if !rule.Enabled {
			continue
		}

		pattern, err := regexp.Compile(rule.Pattern)
		if err != nil {
			if waf.logger != nil {
				waf.logger.Error("WAF_RULE_COMPILE_ERROR",
					"rule", rule.Name,
					"pattern", rule.Pattern,
					"error", err.Error(),
				)
			}
			continue
		}

		waf.rules = append(waf.rules, &WAFRule{
			Name:        rule.Name,
			Description: rule.Description,
			Pattern:     pattern,
			Target:      rule.Target,
			Action:      rule.Action,
			Severity:    rule.Severity,
			Enabled:     rule.Enabled,
		})
	}
}

// initializeRateLimiters initializes rate limiters
func (waf *WAFEngine) initializeRateLimiters() {
	for _, rule := range waf.config.RateLimitRules {
		waf.rateLimiters[rule.Name] = &WAFRateLimiter{
			Rule:     rule,
			Requests: make(map[string]*WAFRequestTracker),
		}
	}
}

// ProcessRequest processes an incoming HTTP request through WAF
func (waf *WAFEngine) ProcessRequest(r *http.Request) *WAFResult {
	if !waf.config.Enabled {
		return &WAFResult{Allowed: true, Action: "allow"}
	}

	waf.stats.mu.Lock()
	waf.stats.TotalRequests++
	waf.stats.mu.Unlock()

	clientIP := getClientIP(r)
	result := &WAFResult{
		Allowed: true,
		Action:  "allow",
		Score:   0,
	}

	// Check whitelist first
	if waf.whitelistedIPs[clientIP] {
		return result
	}

	// Check blacklist
	if blockUntil, blocked := waf.blacklistedIPs[clientIP]; blocked {
		if time.Now().Before(blockUntil) {
			result.Allowed = false
			result.Blocked = true
			result.Reason = "IP blacklisted"
			result.Action = "block"
			result.Severity = "high"
			waf.incrementStat("blocked")
			return result
		} else {
			// Remove expired blacklist entry
			delete(waf.blacklistedIPs, clientIP)
		}
	}

	// Basic request validation
	if validationResult := waf.validateBasicRequest(r); !validationResult.Allowed {
		return validationResult
	}

	// Geo-blocking
	if geoResult := waf.checkGeoBlocking(r, clientIP); !geoResult.Allowed {
		return geoResult
	}

	// Anti-automation checks
	if botResult := waf.checkAntiAutomation(r, clientIP); !botResult.Allowed {
		return botResult
	}

	// Rate limiting
	if rateLimitResult := waf.checkRateLimits(r, clientIP); !rateLimitResult.Allowed {
		return rateLimitResult
	}

	// Content filtering
	if contentResult := waf.checkContentFiltering(r); !contentResult.Allowed {
		return contentResult
	}

	// SQL injection detection
	if sqlResult := waf.checkSQLInjection(r, clientIP); !sqlResult.Allowed {
		return sqlResult
	}

	// XSS detection
	if xssResult := waf.checkXSS(r, clientIP); !xssResult.Allowed {
		return xssResult
	}

	// Custom rules
	if customResult := waf.checkCustomRules(r); !customResult.Allowed {
		return customResult
	}

	// Log suspicious activity if score is high
	if result.Score > 50 {
		waf.incrementStat("suspicious")
		if waf.config.LogSuspicious && waf.logger != nil {
			waf.logSuspiciousRequest(r, result)
		}
	}

	return result
}

// validateBasicRequest performs basic request validation
func (waf *WAFEngine) validateBasicRequest(r *http.Request) *WAFResult {
	result := &WAFResult{Allowed: true, Action: "allow"}

	// Check request size
	if r.ContentLength > waf.config.MaxRequestSize {
		result.Allowed = false
		result.Blocked = true
		result.Reason = "Request too large"
		result.Action = "block"
		result.Severity = "medium"
		waf.incrementStat("blocked")
		return result
	}

	// Check URL length
	if len(r.URL.String()) > waf.config.MaxURLLength {
		result.Allowed = false
		result.Blocked = true
		result.Reason = "URL too long"
		result.Action = "block"
		result.Severity = "medium"
		waf.incrementStat("blocked")
		return result
	}

	// Check HTTP method
	if len(waf.config.AllowedMethods) > 0 {
		allowed := false
		for _, method := range waf.config.AllowedMethods {
			if r.Method == method {
				allowed = true
				break
			}
		}
		if !allowed {
			result.Allowed = false
			result.Blocked = true
			result.Reason = "HTTP method not allowed"
			result.Action = "block"
			result.Severity = "medium"
			waf.incrementStat("blocked")
			return result
		}
	}

	// Check content type
	contentType := r.Header.Get("Content-Type")
	if contentType != "" && len(waf.config.AllowedContentTypes) > 0 {
		allowed := false
		for _, ct := range waf.config.AllowedContentTypes {
			if strings.Contains(contentType, ct) {
				allowed = true
				break
			}
		}
		if !allowed {
			result.Allowed = false
			result.Blocked = true
			result.Reason = "Content type not allowed"
			result.Action = "block"
			result.Severity = "medium"
			waf.incrementStat("blocked")
			return result
		}
	}

	// Check blocked paths
	for _, blockedPath := range waf.config.BlockedPaths {
		if matched, _ := regexp.MatchString(blockedPath, r.URL.Path); matched {
			result.Allowed = false
			result.Blocked = true
			result.Reason = "Path blocked"
			result.Action = "block"
			result.Severity = "high"
			waf.incrementStat("blocked")
			return result
		}
	}

	// Check blocked extensions
	for _, ext := range waf.config.BlockedExtensions {
		if strings.HasSuffix(strings.ToLower(r.URL.Path), strings.ToLower(ext)) {
			result.Allowed = false
			result.Blocked = true
			result.Reason = "File extension blocked"
			result.Action = "block"
			result.Severity = "medium"
			waf.incrementStat("blocked")
			return result
		}
	}

	// Check user agent
	userAgent := r.Header.Get("User-Agent")
	for _, blockedUA := range waf.config.BlockedUserAgents {
		if matched, _ := regexp.MatchString(blockedUA, userAgent); matched {
			result.Allowed = false
			result.Blocked = true
			result.Reason = "User agent blocked"
			result.Action = "block"
			result.Severity = "medium"
			waf.incrementStat("blocked")
			return result
		}
	}

	// Check referer
	referer := r.Header.Get("Referer")
	for _, blockedRef := range waf.config.BlockedReferers {
		if matched, _ := regexp.MatchString(blockedRef, referer); matched {
			result.Allowed = false
			result.Blocked = true
			result.Reason = "Referer blocked"
			result.Action = "block"
			result.Severity = "medium"
			waf.incrementStat("blocked")
			return result
		}
	}

	return result
}

// checkGeoBlocking performs geo-blocking checks
func (waf *WAFEngine) checkGeoBlocking(r *http.Request, clientIP string) *WAFResult {
	result := &WAFResult{Allowed: true, Action: "allow"}

	if !waf.config.GeoBlocking.Enabled || waf.geoIPResolver == nil {
		return result
	}

	countryCode, err := waf.geoIPResolver.GetCountryCode(clientIP)
	if err != nil {
		return result // Allow if we can't determine country
	}

	// Check blocked countries
	for _, blocked := range waf.config.GeoBlocking.BlockedCountries {
		if strings.EqualFold(countryCode, blocked) {
			result.Allowed = false
			result.Blocked = true
			result.Reason = fmt.Sprintf("Country blocked: %s", countryCode)
			result.Action = "block"
			result.Severity = "medium"
			waf.incrementStat("geo_blocks")
			return result
		}
	}

	// Check allowed countries (whitelist)
	if len(waf.config.GeoBlocking.AllowedCountries) > 0 {
		allowed := false
		for _, allowedCountry := range waf.config.GeoBlocking.AllowedCountries {
			if strings.EqualFold(countryCode, allowedCountry) {
				allowed = true
				break
			}
		}
		if !allowed {
			result.Allowed = false
			result.Blocked = true
			result.Reason = fmt.Sprintf("Country not in whitelist: %s", countryCode)
			result.Action = "block"
			result.Severity = "medium"
			waf.incrementStat("geo_blocks")
			return result
		}
	}

	return result
}

// checkAntiAutomation performs anti-automation checks
func (waf *WAFEngine) checkAntiAutomation(r *http.Request, clientIP string) *WAFResult {
	result := &WAFResult{Allowed: true, Action: "allow"}

	if !waf.config.AntiAutomation.Enabled {
		return result
	}

	userAgent := strings.ToLower(r.Header.Get("User-Agent"))

	// Check for bot user agents
	if waf.config.AntiAutomation.BlockBots {
		for _, botUA := range waf.config.AntiAutomation.BotUserAgents {
			if strings.Contains(userAgent, strings.ToLower(botUA)) {
				result.Allowed = false
				result.Blocked = true
				result.Reason = "Bot detected"
				result.Action = "block"
				result.Severity = "medium"
				waf.incrementStat("bot_blocks")
				return result
			}
		}
	}

	// Check for common bot patterns
	botPatterns := []string{
		"bot", "crawler", "spider", "scraper", "curl", "wget", "python",
		"requests", "scrapy", "selenium", "phantomjs", "headless",
	}

	for _, pattern := range botPatterns {
		if strings.Contains(userAgent, pattern) {
			result.Score += 20
			if waf.config.AntiAutomation.BlockBots {
				result.Allowed = false
				result.Blocked = true
				result.Reason = "Automated tool detected"
				result.Action = "block"
				result.Severity = "medium"
				waf.incrementStat("bot_blocks")
				return result
			}
		}
	}

	// Check for missing common headers (suspicious)
	if r.Header.Get("Accept") == "" || r.Header.Get("Accept-Language") == "" {
		result.Score += 15
	}

	return result
}

// checkRateLimits performs rate limiting checks
func (waf *WAFEngine) checkRateLimits(r *http.Request, clientIP string) *WAFResult {
	result := &WAFResult{Allowed: true, Action: "allow"}

	if !waf.config.RateLimitEnabled {
		return result
	}

	for _, limiter := range waf.rateLimiters {
		if waf.matchesRateLimitRule(r, limiter.Rule) {
			if !waf.checkRateLimit(limiter, clientIP) {
				result.Allowed = false
				result.Blocked = true
				result.Reason = fmt.Sprintf("Rate limit exceeded: %s", limiter.Rule.Name)
				result.Action = "block"
				result.Severity = "medium"
				result.RuleTriggered = limiter.Rule.Name
				waf.incrementStat("rate_limit_hits")
				return result
			}
		}
	}

	return result
}

// checkContentFiltering performs content filtering
func (waf *WAFEngine) checkContentFiltering(r *http.Request) *WAFResult {
	result := &WAFResult{Allowed: true, Action: "allow"}

	if !waf.config.ContentFiltering.Enabled {
		return result
	}

	// Check upload size
	if r.ContentLength > waf.config.ContentFiltering.MaxUploadSize {
		result.Allowed = false
		result.Blocked = true
		result.Reason = "Upload too large"
		result.Action = "block"
		result.Severity = "medium"
		waf.incrementStat("blocked")
		return result
	}

	// Check file types in multipart uploads
	if strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") {
		// This would require parsing the multipart form
		// For now, we'll do basic checks
		result.Score += 10
	}

	return result
}

// checkSQLInjection performs SQL injection detection
func (waf *WAFEngine) checkSQLInjection(r *http.Request, clientIP string) *WAFResult {
	result := &WAFResult{Allowed: true, Action: "allow"}

	if waf.sqlDetector == nil {
		return result
	}

	// Check query parameters
	for key, values := range r.URL.Query() {
		for _, value := range values {
			validationResult := waf.sqlDetector.ValidateInput(value, key, clientIP)
			if !validationResult.Valid {
				result.Allowed = false
				result.Blocked = true
				result.Reason = "SQL injection detected"
				result.Action = "block"
				result.Severity = "high"
				waf.incrementStat("sql_injection_blocks")
				return result
			}
			result.Score += validationResult.SuspiciousLevel / 10
		}
	}

	// Check form data
	if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
		if err := r.ParseForm(); err == nil {
			for key, values := range r.PostForm {
				for _, value := range values {
					validationResult := waf.sqlDetector.ValidateInput(value, key, clientIP)
					if !validationResult.Valid {
						result.Allowed = false
						result.Blocked = true
						result.Reason = "SQL injection detected"
						result.Action = "block"
						result.Severity = "high"
						waf.incrementStat("sql_injection_blocks")
						return result
					}
					result.Score += validationResult.SuspiciousLevel / 10
				}
			}
		}
	}

	return result
}

// checkXSS performs XSS detection
func (waf *WAFEngine) checkXSS(r *http.Request, clientIP string) *WAFResult {
	result := &WAFResult{Allowed: true, Action: "allow"}

	if waf.xssDetector == nil {
		return result
	}

	// Check query parameters
	for _, values := range r.URL.Query() {
		for _, value := range values {
			if waf.xssDetector.DetectXSS(value) {
				result.Allowed = false
				result.Blocked = true
				result.Reason = "XSS attack detected"
				result.Action = "block"
				result.Severity = "high"
				waf.incrementStat("xss_blocks")
				return result
			}
		}
	}

	// Check form data
	if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
		if err := r.ParseForm(); err == nil {
			for _, values := range r.PostForm {
				for _, value := range values {
					if waf.xssDetector.DetectXSS(value) {
						result.Allowed = false
						result.Blocked = true
						result.Reason = "XSS attack detected"
						result.Action = "block"
						result.Severity = "high"
						waf.incrementStat("xss_blocks")
						return result
					}
				}
			}
		}
	}

	return result
}

// checkCustomRules checks custom WAF rules
func (waf *WAFEngine) checkCustomRules(r *http.Request) *WAFResult {
	result := &WAFResult{Allowed: true, Action: "allow"}

	for _, rule := range waf.rules {
		if !rule.Enabled {
			continue
		}

		var target string
		switch rule.Target {
		case "url":
			target = r.URL.String()
		case "body":
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewBuffer(body))
			target = string(body)
		case "header":
			for key, values := range r.Header {
				target += key + ": " + strings.Join(values, ", ") + "\n"
			}
		case "parameter":
			for key, values := range r.URL.Query() {
				target += key + "=" + strings.Join(values, ",") + "&"
			}
		default:
			continue
		}

		if rule.Pattern.MatchString(target) {
			switch rule.Action {
			case "block":
				result.Allowed = false
				result.Blocked = true
				result.Reason = fmt.Sprintf("Custom rule triggered: %s", rule.Name)
				result.Action = "block"
				result.Severity = rule.Severity
				result.RuleTriggered = rule.Name
				waf.incrementStat("blocked")
				return result
			case "challenge":
				result.Challenge = true
				result.Reason = fmt.Sprintf("Challenge required: %s", rule.Name)
				result.Action = "challenge"
				result.RuleTriggered = rule.Name
			case "log":
				result.Score += 25
				result.Details = append(result.Details, fmt.Sprintf("Rule matched: %s", rule.Name))
			}
		}
	}

	return result
}

// Helper methods

func (waf *WAFEngine) matchesRateLimitRule(r *http.Request, rule WAFRateLimitRule) bool {
	if rule.Method != "" && r.Method != rule.Method {
		return false
	}
	if rule.Path != "" {
		matched, _ := regexp.MatchString(rule.Path, r.URL.Path)
		return matched
	}
	return true
}

func (waf *WAFEngine) checkRateLimit(limiter *WAFRateLimiter, clientIP string) bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	tracker, exists := limiter.Requests[clientIP]
	if !exists {
		tracker = &WAFRequestTracker{}
		limiter.Requests[clientIP] = tracker
	}

	now := time.Now()

	// Check if still blocked
	if tracker.Blocked && now.Before(tracker.BlockUntil) {
		return false
	}

	// Reset if block period expired
	if tracker.Blocked && now.After(tracker.BlockUntil) {
		tracker.Blocked = false
		tracker.Count = 0
	}

	// Reset count if window expired
	if now.Sub(tracker.LastRequest) > limiter.Rule.Window {
		tracker.Count = 0
	}

	tracker.Count++
	tracker.LastRequest = now

	// Check limit
	if tracker.Count > limiter.Rule.Limit {
		tracker.Blocked = true
		tracker.BlockUntil = now.Add(limiter.Rule.BlockTime)
		return false
	}

	return true
}

func (waf *WAFEngine) incrementStat(statType string) {
	waf.stats.mu.Lock()
	defer waf.stats.mu.Unlock()

	switch statType {
	case "blocked":
		waf.stats.BlockedRequests++
	case "suspicious":
		waf.stats.SuspiciousRequests++
	case "bypassed":
		waf.stats.BypassedRequests++
	case "rate_limit_hits":
		waf.stats.RateLimitHits++
	case "geo_blocks":
		waf.stats.GeoBlocks++
	case "bot_blocks":
		waf.stats.BotBlocks++
	case "sql_injection_blocks":
		waf.stats.SQLInjectionBlocks++
	case "xss_blocks":
		waf.stats.XSSBlocks++
	}
}

func (waf *WAFEngine) logSuspiciousRequest(r *http.Request, result *WAFResult) {
	waf.logger.Warn("WAF_SUSPICIOUS_REQUEST",
		"event", "WAF_SUSPICIOUS_REQUEST",
		"client_ip", getClientIP(r),
		"method", r.Method,
		"url", r.URL.String(),
		"user_agent", r.Header.Get("User-Agent"),
		"referer", r.Header.Get("Referer"),
		"score", result.Score,
		"details", result.Details,
		"timestamp", time.Now().UTC(),
	)
}

func (waf *WAFEngine) cleanupRoutine() {
	for {
		select {
		case <-waf.cleanup.C:
			waf.cleanupExpiredEntries()
		case <-waf.stop:
			return
		}
	}
}

func (waf *WAFEngine) cleanupExpiredEntries() {
	now := time.Now()

	// Cleanup blacklisted IPs
	for ip, expiry := range waf.blacklistedIPs {
		if now.After(expiry) {
			delete(waf.blacklistedIPs, ip)
		}
	}

	// Cleanup rate limiter entries
	for _, limiter := range waf.rateLimiters {
		limiter.mu.Lock()
		for ip, tracker := range limiter.Requests {
			if now.Sub(tracker.LastRequest) > limiter.Rule.Window*2 {
				delete(limiter.Requests, ip)
			}
		}
		limiter.mu.Unlock()
	}
}

// Stop stops the WAF engine
func (waf *WAFEngine) Stop() {
	close(waf.stop)
	waf.cleanup.Stop()
}

// GetStats returns WAF statistics
func (waf *WAFEngine) GetStats() *WAFStats {
	waf.stats.mu.RLock()
	defer waf.stats.mu.RUnlock()

	// Return a copy
	return &WAFStats{
		TotalRequests:      waf.stats.TotalRequests,
		BlockedRequests:    waf.stats.BlockedRequests,
		SuspiciousRequests: waf.stats.SuspiciousRequests,
		BypassedRequests:   waf.stats.BypassedRequests,
		RateLimitHits:      waf.stats.RateLimitHits,
		GeoBlocks:          waf.stats.GeoBlocks,
		BotBlocks:          waf.stats.BotBlocks,
		SQLInjectionBlocks: waf.stats.SQLInjectionBlocks,
		XSSBlocks:          waf.stats.XSSBlocks,
	}
}

// NewXSSDetector creates a new XSS detector
func NewXSSDetector(logger *logx.Logger) *XSSDetector {
	patterns := []string{
		`(?i)<script[^>]*>.*?</script>`,
		`(?i)<iframe[^>]*>.*?</iframe>`,
		`(?i)<object[^>]*>.*?</object>`,
		`(?i)<embed[^>]*>`,
		`(?i)<applet[^>]*>.*?</applet>`,
		`(?i)javascript:`,
		`(?i)vbscript:`,
		`(?i)onload\s*=`,
		`(?i)onerror\s*=`,
		`(?i)onclick\s*=`,
		`(?i)onmouseover\s*=`,
		`(?i)onfocus\s*=`,
		`(?i)onblur\s*=`,
		`(?i)onchange\s*=`,
		`(?i)onsubmit\s*=`,
		`(?i)eval\s*\(`,
		`(?i)expression\s*\(`,
		`(?i)alert\s*\(`,
		`(?i)confirm\s*\(`,
		`(?i)prompt\s*\(`,
		`(?i)document\.cookie`,
		`(?i)document\.write`,
		`(?i)window\.location`,
		`(?i)<svg[^>]*onload`,
		`(?i)<img[^>]*onerror`,
		`(?i)<body[^>]*onload`,
	}

	compiled := make([]*regexp.Regexp, 0)
	for _, pattern := range patterns {
		if re, err := regexp.Compile(pattern); err == nil {
			compiled = append(compiled, re)
		}
	}

	return &XSSDetector{
		patterns: compiled,
		logger:   logger,
	}
}

// DetectXSS detects XSS patterns in input
func (xss *XSSDetector) DetectXSS(input string) bool {
	for _, pattern := range xss.patterns {
		if pattern.MatchString(input) {
			return true
		}
	}
	return false
}

// WAFMiddleware creates WAF middleware
func WAFMiddleware(waf *WAFEngine) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			result := waf.ProcessRequest(r)

			if !result.Allowed {
				w.Header().Set("Content-Type", "application/json")
				if result.Challenge {
					w.WriteHeader(http.StatusUnauthorized)
				} else {
					w.WriteHeader(http.StatusForbidden)
				}
				json.NewEncoder(w).Encode(map[string]interface{}{
					"blocked":        result.Blocked,
					"reason":         result.Reason,
					"rule_triggered": result.RuleTriggered,
					"severity":       result.Severity,
					"challenge":      result.Challenge,
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// DefaultWAFConfig returns default WAF configuration
func DefaultWAFConfig() WAFConfig {
	return WAFConfig{
		Enabled:            true,
		StrictMode:         false,
		LogBlocked:         true,
		LogSuspicious:      true,
		MaxRequestSize:     10 * 1024 * 1024, // 10MB
		MaxHeaderSize:      8192,              // 8KB
		MaxURLLength:       2048,              // 2KB
		MaxParameterCount:  100,
		MaxParameterLength: 1024,
		AllowedMethods:     []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"},
		AllowedContentTypes: []string{"application/json", "application/x-www-form-urlencoded", "multipart/form-data", "text/plain"},
		BlockedExtensions:  []string{".exe", ".bat", ".cmd", ".com", ".pif", ".scr", ".vbs", ".js"},
		BlockedUserAgents:  []string{"(?i)bot", "(?i)crawler", "(?i)spider", "(?i)scraper"},
		RateLimitEnabled:   true,
		GeoBlocking: WAFGeoBlockingConfig{
			Enabled: false,
		},
		AntiAutomation: WAFAntiAutomationConfig{
			Enabled:               true,
			BlockBots:             false,
			MaxRequestsPerSecond:  10,
			MaxConcurrentRequests: 50,
		},
		ContentFiltering: WAFContentFilterConfig{
			Enabled:          true,
			ScanUploads:      true,
			MaxUploadSize:    50 * 1024 * 1024, // 50MB
			BlockExecutables: true,
			BlockScripts:     true,
		},
		ResponseFiltering: WAFResponseFilterConfig{
			Enabled:            true,
			HideServerInfo:     true,
			RemoveDebugHeaders: true,
			SanitizeErrors:     true,
			MaxResponseSize:    100 * 1024 * 1024, // 100MB
		},
	}
}