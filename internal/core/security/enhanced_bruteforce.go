package security

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"Gawan/internal/core/logx"
)

// EnhancedBruteForceConfig extends the basic brute force config with advanced features
type EnhancedBruteForceConfig struct {
	BruteForceConfig
	
	// Captcha integration
	CaptchaEnabled       bool `json:"captcha_enabled"`
	CaptchaAfterAttempts int  `json:"captcha_after_attempts"` // Show captcha after N failed attempts
	
	// Progressive lockout
	ProgressiveLockout bool          `json:"progressive_lockout"`
	LockoutMultiplier  float64       `json:"lockout_multiplier"`  // Multiply lockout duration after each violation
	MaxLockoutDuration time.Duration `json:"max_lockout_duration"` // Maximum lockout duration
	
	// Account lockout
	AccountLockout         bool          `json:"account_lockout"`
	AccountLockoutAttempts int           `json:"account_lockout_attempts"` // Lock account after N violations
	AccountLockoutDuration time.Duration `json:"account_lockout_duration"`
	
	// 2FA integration
	TwoFAEnabled       bool     `json:"twofa_enabled"`
	TwoFAAfterAttempts int      `json:"twofa_after_attempts"` // Require 2FA after N failed attempts
	TwoFARequiredPaths []string `json:"twofa_required_paths"`
	
	// IP reputation
	IPReputationEnabled bool `json:"ip_reputation_enabled"`
	TrustProxies        bool `json:"trust_proxies"`
	
	// Notification
	NotifyOnLockout    bool `json:"notify_on_lockout"`
	NotifyOnSuspicious bool `json:"notify_on_suspicious"`
}

// EnhancedAttemptRecord extends AttemptRecord with additional tracking
type EnhancedAttemptRecord struct {
	*AttemptRecord
	
	// Progressive lockout tracking
	LockoutCount    int       `json:"lockout_count"`
	LastLockout     time.Time `json:"last_lockout"`
	LockoutHistory  []time.Time `json:"lockout_history"`
	
	// Captcha tracking
	CaptchaRequired bool      `json:"captcha_required"`
	CaptchaFailures int       `json:"captcha_failures"`
	LastCaptcha     time.Time `json:"last_captcha"`
	
	// 2FA tracking
	TwoFARequired bool      `json:"twofa_required"`
	TwoFAFailures int       `json:"twofa_failures"`
	LastTwoFA     time.Time `json:"last_twofa"`
	
	// Account lockout
	AccountLocked   bool      `json:"account_locked"`
	AccountLockTime time.Time `json:"account_lock_time"`
	
	// Suspicious activity
	SuspiciousScore int       `json:"suspicious_score"`
	LastActivity    time.Time `json:"last_activity"`
	UserAgents      []string  `json:"user_agents"`
	Countries       []string  `json:"countries"`
}

// EnhancedBruteForceManager manages enhanced brute force protection
type EnhancedBruteForceManager struct {
	config         EnhancedBruteForceConfig
	records        map[string]*EnhancedAttemptRecord
	captchaManager *CaptchaManager
	twoFAManager   *TwoFAManager
	geoIPResolver  GeoIPResolver
	mu             sync.RWMutex
	cleanup        *time.Ticker
	stop           chan struct{}
	logger         *logx.Logger
}

// NewEnhancedBruteForceManager creates a new enhanced brute force manager
func NewEnhancedBruteForceManager(config EnhancedBruteForceConfig, captchaManager *CaptchaManager, twoFAManager *TwoFAManager, geoIPResolver GeoIPResolver, logger *logx.Logger) *EnhancedBruteForceManager {
	// Set defaults
	if config.CaptchaAfterAttempts <= 0 {
		config.CaptchaAfterAttempts = 3
	}
	if config.LockoutMultiplier <= 0 {
		config.LockoutMultiplier = 2.0
	}
	if config.MaxLockoutDuration <= 0 {
		config.MaxLockoutDuration = 24 * time.Hour
	}
	if config.AccountLockoutAttempts <= 0 {
		config.AccountLockoutAttempts = 10
	}
	if config.AccountLockoutDuration <= 0 {
		config.AccountLockoutDuration = 24 * time.Hour
	}
	if config.TwoFAAfterAttempts <= 0 {
		config.TwoFAAfterAttempts = 5
	}

	ebfm := &EnhancedBruteForceManager{
		config:         config,
		records:        make(map[string]*EnhancedAttemptRecord),
		captchaManager: captchaManager,
		twoFAManager:   twoFAManager,
		geoIPResolver:  geoIPResolver,
		cleanup:        time.NewTicker(time.Minute),
		stop:           make(chan struct{}),
		logger:         logger,
	}

	// Start cleanup routine
	go ebfm.cleanupRoutine()

	return ebfm
}

// CheckAccess checks if access should be allowed and what additional verification is needed
func (ebfm *EnhancedBruteForceManager) CheckAccess(r *http.Request) (*AccessCheckResult, error) {
	if !ebfm.config.Enabled {
		return &AccessCheckResult{Allowed: true}, nil
	}

	key := ebfm.config.KeyExtractor(r)
	
	ebfm.mu.Lock()
	defer ebfm.mu.Unlock()

	record := ebfm.getOrCreateRecord(key)
	
	// Check account lockout
	if record.AccountLocked {
		if time.Now().Before(record.AccountLockTime.Add(ebfm.config.AccountLockoutDuration)) {
			return &AccessCheckResult{
				Allowed: false,
				Reason:  "account_locked",
				Message: "Account is locked due to suspicious activity",
				RetryAfter: int(time.Until(record.AccountLockTime.Add(ebfm.config.AccountLockoutDuration)).Seconds()),
			}, nil
		} else {
			// Unlock account
			record.AccountLocked = false
			record.AccountLockTime = time.Time{}
		}
	}

	// Check IP lockout
	if record.LockoutUntil.After(time.Now()) {
		return &AccessCheckResult{
			Allowed: false,
			Reason:  "ip_locked",
			Message: "IP address is temporarily locked",
			RetryAfter: int(time.Until(record.LockoutUntil).Seconds()),
		}, nil
	}

	// Update suspicious activity tracking
	ebfm.updateSuspiciousActivity(record, r)

	// Determine required verifications
	result := &AccessCheckResult{
		Allowed: true,
		IP:      key,
	}

	// Check if captcha is required
	if ebfm.config.CaptchaEnabled && ebfm.captchaManager != nil {
		attemptCount := ebfm.getAttemptCount(record)
		if attemptCount >= ebfm.config.CaptchaAfterAttempts || record.CaptchaRequired {
			result.CaptchaRequired = true
		}
	}

	// Check if 2FA is required
	if ebfm.config.TwoFAEnabled && ebfm.twoFAManager != nil {
		attemptCount := ebfm.getAttemptCount(record)
		if attemptCount >= ebfm.config.TwoFAAfterAttempts || record.TwoFARequired {
			result.TwoFARequired = true
		}
	}

	// Check suspicious score
	if record.SuspiciousScore > 50 {
		result.CaptchaRequired = true
		result.TwoFARequired = true
	}

	return result, nil
}

// RecordAttempt records a login attempt (success or failure)
func (ebfm *EnhancedBruteForceManager) RecordAttempt(r *http.Request, success bool, userID string) error {
	if !ebfm.config.Enabled {
		return nil
	}

	key := ebfm.config.KeyExtractor(r)
	
	ebfm.mu.Lock()
	defer ebfm.mu.Unlock()

	record := ebfm.getOrCreateRecord(key)
	
	if success {
		// Reset on successful login
		record.FailedAttempts = []time.Time{}
		record.CaptchaRequired = false
		record.TwoFARequired = false
		record.CaptchaFailures = 0
		record.TwoFAFailures = 0
		record.SuspiciousScore = max(0, record.SuspiciousScore-10)
		
		if ebfm.logger != nil {
			ebfm.logger.Info("LOGIN_SUCCESS",
				"event", "LOGIN_SUCCESS",
				"ip", key,
				"user_id", userID,
				"user_agent", r.UserAgent(),
				"timestamp", time.Now().UTC(),
			)
		}
	} else {
		// Record failed attempt
		now := time.Now()
		record.LastAttempt = now
		
		// Clean old attempts
		cutoff := now.Add(-ebfm.config.WindowDuration)
		validAttempts := []time.Time{}
		for _, attemptTime := range record.FailedAttempts {
			if attemptTime.After(cutoff) {
				validAttempts = append(validAttempts, attemptTime)
			}
		}
		validAttempts = append(validAttempts, now)
		record.FailedAttempts = validAttempts
		
		// Increase suspicious score
		record.SuspiciousScore += 5
		
		// Check for lockout
		if len(record.FailedAttempts) >= ebfm.config.MaxAttempts {
			ebfm.triggerLockout(record, key, r)
		}
		
		// Update verification requirements
		if len(record.FailedAttempts) >= ebfm.config.CaptchaAfterAttempts {
			record.CaptchaRequired = true
		}
		if len(record.FailedAttempts) >= ebfm.config.TwoFAAfterAttempts {
			record.TwoFARequired = true
		}
		
		if ebfm.logger != nil {
			ebfm.logger.Warn("LOGIN_FAILURE",
				"event", "LOGIN_FAILURE",
				"ip", key,
				"user_id", userID,
				"user_agent", r.UserAgent(),
				"attempt_count", len(record.FailedAttempts),
				"suspicious_score", record.SuspiciousScore,
				"timestamp", time.Now().UTC(),
			)
		}
	}

	return nil
}

// ValidateCaptcha validates a captcha response
func (ebfm *EnhancedBruteForceManager) ValidateCaptcha(challengeID, userAnswer string) (bool, error) {
	if !ebfm.config.CaptchaEnabled || ebfm.captchaManager == nil {
		return true, nil
	}

	return ebfm.captchaManager.ValidateChallenge(challengeID, userAnswer)
}

// ValidateTwoFA validates a 2FA code
func (ebfm *EnhancedBruteForceManager) ValidateTwoFA(userID, code string, isBackupCode bool) (bool, error) {
	if !ebfm.config.TwoFAEnabled || ebfm.twoFAManager == nil {
		return true, nil
	}

	if isBackupCode {
		return ebfm.twoFAManager.VerifyBackupCode(userID, code)
	}
	return ebfm.twoFAManager.VerifyTOTP(userID, code)
}

// triggerLockout triggers IP lockout with progressive duration
func (ebfm *EnhancedBruteForceManager) triggerLockout(record *EnhancedAttemptRecord, key string, r *http.Request) {
	now := time.Now()
	record.LockoutCount++
	record.LastLockout = now
	record.LockoutHistory = append(record.LockoutHistory, now)
	
	// Calculate progressive lockout duration
	lockoutDuration := ebfm.config.LockoutDuration
	if ebfm.config.ProgressiveLockout && record.LockoutCount > 1 {
		multiplier := 1.0
		for i := 1; i < record.LockoutCount; i++ {
			multiplier *= ebfm.config.LockoutMultiplier
		}
		lockoutDuration = time.Duration(float64(lockoutDuration) * multiplier)
		
		// Cap at maximum duration
		if lockoutDuration > ebfm.config.MaxLockoutDuration {
			lockoutDuration = ebfm.config.MaxLockoutDuration
		}
	}
	
	record.LockoutUntil = now.Add(lockoutDuration)
	
	// Check for account lockout
	if ebfm.config.AccountLockout && record.LockoutCount >= ebfm.config.AccountLockoutAttempts {
		record.AccountLocked = true
		record.AccountLockTime = now
	}
	
	if ebfm.logger != nil {
		ebfm.logger.Error("IP_LOCKOUT",
			"event", "IP_LOCKOUT",
			"ip", key,
			"lockout_count", record.LockoutCount,
			"lockout_duration", lockoutDuration.String(),
			"lockout_until", record.LockoutUntil.UTC(),
			"account_locked", record.AccountLocked,
			"user_agent", r.UserAgent(),
			"timestamp", now.UTC(),
		)
	}
}

// updateSuspiciousActivity updates suspicious activity tracking
func (ebfm *EnhancedBruteForceManager) updateSuspiciousActivity(record *EnhancedAttemptRecord, r *http.Request) {
	now := time.Now()
	record.LastActivity = now
	
	// Track user agents
	userAgent := r.UserAgent()
	if userAgent != "" {
		found := false
		for _, ua := range record.UserAgents {
			if ua == userAgent {
				found = true
				break
			}
		}
		if !found {
			record.UserAgents = append(record.UserAgents, userAgent)
			// Multiple user agents increase suspicious score
			if len(record.UserAgents) > 3 {
				record.SuspiciousScore += 10
			}
		}
	}
	
	// Track countries (if GeoIP is available)
	if ebfm.config.IPReputationEnabled && ebfm.geoIPResolver != nil {
		ip := ebfm.config.KeyExtractor(r)
		if countryCode, err := ebfm.geoIPResolver.GetCountryCode(ip); err == nil {
			found := false
			for _, country := range record.Countries {
				if country == countryCode {
					found = true
					break
				}
			}
			if !found {
				record.Countries = append(record.Countries, countryCode)
				// Multiple countries increase suspicious score
				if len(record.Countries) > 2 {
					record.SuspiciousScore += 15
				}
			}
		}
	}
	
	// Decay suspicious score over time
	if time.Since(record.LastActivity) > time.Hour {
		record.SuspiciousScore = max(0, record.SuspiciousScore-1)
	}
}

// getOrCreateRecord gets or creates an enhanced attempt record
func (ebfm *EnhancedBruteForceManager) getOrCreateRecord(key string) *EnhancedAttemptRecord {
	record, exists := ebfm.records[key]
	if !exists {
		record = &EnhancedAttemptRecord{
			AttemptRecord: &AttemptRecord{
				FailedAttempts: make([]time.Time, 0),
			},
			LockoutHistory: make([]time.Time, 0),
			UserAgents:     make([]string, 0),
			Countries:      make([]string, 0),
		}
		ebfm.records[key] = record
	}
	return record
}

// getAttemptCount returns the current attempt count for a record
func (ebfm *EnhancedBruteForceManager) getAttemptCount(record *EnhancedAttemptRecord) int {
	now := time.Now()
	cutoff := now.Add(-ebfm.config.WindowDuration)
	count := 0
	for _, attemptTime := range record.FailedAttempts {
		if attemptTime.After(cutoff) {
			count++
		}
	}
	return count
}

// cleanupRoutine removes expired records
func (ebfm *EnhancedBruteForceManager) cleanupRoutine() {
	for {
		select {
		case <-ebfm.cleanup.C:
			ebfm.cleanupExpired()
		case <-ebfm.stop:
			return
		}
	}
}

// cleanupExpired removes expired records
func (ebfm *EnhancedBruteForceManager) cleanupExpired() {
	ebfm.mu.Lock()
	defer ebfm.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-ebfm.config.WindowDuration * 2)

	for key, record := range ebfm.records {
		// Remove if no recent activity and not locked
		if record.LastAttempt.Before(cutoff) && 
		   record.LockoutUntil.Before(now) && 
		   !record.AccountLocked &&
		   record.LastActivity.Before(cutoff) {
			delete(ebfm.records, key)
		}
	}
}

// Stop stops the enhanced brute force manager
func (ebfm *EnhancedBruteForceManager) Stop() {
	close(ebfm.stop)
	ebfm.cleanup.Stop()
}

// GetStats returns enhanced brute force protection statistics
func (ebfm *EnhancedBruteForceManager) GetStats() map[string]interface{} {
	ebfm.mu.RLock()
	defer ebfm.mu.RUnlock()

	lockedIPs := 0
	lockedAccounts := 0
	captchaRequired := 0
	twoFARequired := 0
	totalSuspiciousScore := 0

	for _, record := range ebfm.records {
		if record.LockoutUntil.After(time.Now()) {
			lockedIPs++
		}
		if record.AccountLocked {
			lockedAccounts++
		}
		if record.CaptchaRequired {
			captchaRequired++
		}
		if record.TwoFARequired {
			twoFARequired++
		}
		totalSuspiciousScore += record.SuspiciousScore
	}

	return map[string]interface{}{
		"total_records":        len(ebfm.records),
		"locked_ips":           lockedIPs,
		"locked_accounts":      lockedAccounts,
		"captcha_required":     captchaRequired,
		"twofa_required":       twoFARequired,
		"avg_suspicious_score": float64(totalSuspiciousScore) / float64(max(1, len(ebfm.records))),
		"config":               ebfm.config,
	}
}

// AccessCheckResult represents the result of an access check
type AccessCheckResult struct {
	Allowed         bool   `json:"allowed"`
	Reason          string `json:"reason,omitempty"`
	Message         string `json:"message,omitempty"`
	RetryAfter      int    `json:"retry_after,omitempty"`
	CaptchaRequired bool   `json:"captcha_required,omitempty"`
	TwoFARequired   bool   `json:"twofa_required,omitempty"`
	IP              string `json:"ip,omitempty"`
}

// EnhancedBruteForceMiddleware creates enhanced brute force protection middleware
func EnhancedBruteForceMiddleware(manager *EnhancedBruteForceManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !manager.config.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Only apply to login paths
			if !matchesLoginPath(r.URL.Path, manager.config.LoginPathPatterns) {
				next.ServeHTTP(w, r)
				return
			}

			// Check access
			result, err := manager.CheckAccess(r)
			if err != nil {
				http.Error(w, "Security check failed", http.StatusInternalServerError)
				return
			}

			if !result.Allowed {
				w.Header().Set("Content-Type", "application/json")
				if result.RetryAfter > 0 {
					w.Header().Set("Retry-After", strconv.Itoa(result.RetryAfter))
				}
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(result)
				return
			}

			// Add security headers
			if result.CaptchaRequired {
				w.Header().Set("X-Captcha-Required", "true")
			}
			if result.TwoFARequired {
				w.Header().Set("X-2FA-Required", "true")
			}

			// Wrap response writer to capture status
			wrapped := &enhancedBruteForceResponseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
				manager:        manager,
				request:        r,
			}

			next.ServeHTTP(wrapped, r)
		})
	}
}

// enhancedBruteForceResponseWriter wraps http.ResponseWriter for enhanced tracking
type enhancedBruteForceResponseWriter struct {
	http.ResponseWriter
	statusCode int
	manager    *EnhancedBruteForceManager
	request    *http.Request
}

// WriteHeader captures status and records attempt
func (ebrw *enhancedBruteForceResponseWriter) WriteHeader(code int) {
	ebrw.statusCode = code

	// Extract user ID from request (you may need to adjust this based on your auth system)
	userID := ebrw.request.Header.Get("X-User-ID")
	if userID == "" {
		userID = ebrw.request.FormValue("username")
	}

	// Record attempt
	success := code >= 200 && code < 300
	ebrw.manager.RecordAttempt(ebrw.request, success, userID)

	ebrw.ResponseWriter.WriteHeader(code)
}

// DefaultEnhancedBruteForceConfig returns default enhanced brute force configuration
func DefaultEnhancedBruteForceConfig() EnhancedBruteForceConfig {
	return EnhancedBruteForceConfig{
		BruteForceConfig:       DefaultBruteForceConfig(),
		CaptchaEnabled:         true,
		CaptchaAfterAttempts:   3,
		ProgressiveLockout:     true,
		LockoutMultiplier:      2.0,
		MaxLockoutDuration:     24 * time.Hour,
		AccountLockout:         true,
		AccountLockoutAttempts: 10,
		AccountLockoutDuration: 24 * time.Hour,
		TwoFAEnabled:           true,
		TwoFAAfterAttempts:     5,
		TwoFARequiredPaths:     []string{"/admin", "/api/admin"},
		IPReputationEnabled:    true,
		TrustProxies:           false,
		NotifyOnLockout:        true,
		NotifyOnSuspicious:     true,
	}
}

// Helper function
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}