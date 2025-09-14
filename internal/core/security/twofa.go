package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TwoFAConfig holds 2FA configuration
type TwoFAConfig struct {
	Enabled        bool          `json:"enabled"`
	Issuer         string        `json:"issuer"`
	SecretLength   int           `json:"secret_length"`
	WindowSize     int           `json:"window_size"`     // Number of time steps to allow
	TimeStep       time.Duration `json:"time_step"`       // TOTP time step (usually 30s)
	BackupCodes    int           `json:"backup_codes"`    // Number of backup codes to generate
	RequiredPaths  []string      `json:"required_paths"`  // Paths that require 2FA
	GracePeriod    time.Duration `json:"grace_period"`    // Grace period after login
	RememberDevice bool          `json:"remember_device"` // Allow device remembering
}

// TwoFASecret represents a 2FA secret for a user
type TwoFASecret struct {
	UserID      string    `json:"user_id"`
	Secret      string    `json:"secret"`
	BackupCodes []string  `json:"backup_codes"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsed    time.Time `json:"last_used"`
	UsedCodes   []string  `json:"used_codes"` // Track used TOTP codes to prevent replay
}

// TwoFASession represents a 2FA session
type TwoFASession struct {
	UserID      string    `json:"user_id"`
	SessionID   string    `json:"session_id"`
	Verified    bool      `json:"verified"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	DeviceID    string    `json:"device_id,omitempty"`
	Remembered  bool      `json:"remembered"`
}

// TwoFAManager manages 2FA operations
type TwoFAManager struct {
	config   TwoFAConfig
	secrets  map[string]*TwoFASecret // userID -> secret
	sessions map[string]*TwoFASession // sessionID -> session
	devices  map[string]time.Time     // deviceID -> last verified time
	mu       sync.RWMutex
	cleanup  *time.Ticker
	stop     chan struct{}
}

// NewTwoFAManager creates a new 2FA manager
func NewTwoFAManager(config TwoFAConfig) *TwoFAManager {
	if config.SecretLength <= 0 {
		config.SecretLength = 32
	}
	if config.WindowSize <= 0 {
		config.WindowSize = 1
	}
	if config.TimeStep <= 0 {
		config.TimeStep = 30 * time.Second
	}
	if config.BackupCodes <= 0 {
		config.BackupCodes = 10
	}
	if config.GracePeriod <= 0 {
		config.GracePeriod = 30 * time.Minute
	}
	if config.Issuer == "" {
		config.Issuer = "Gawan Framework"
	}

	tm := &TwoFAManager{
		config:   config,
		secrets:  make(map[string]*TwoFASecret),
		sessions: make(map[string]*TwoFASession),
		devices:  make(map[string]time.Time),
		cleanup:  time.NewTicker(time.Minute),
		stop:     make(chan struct{}),
	}

	// Start cleanup routine
	go tm.cleanupRoutine()

	return tm
}

// GenerateSecret generates a new 2FA secret for a user
func (tm *TwoFAManager) GenerateSecret(userID string) (*TwoFASecret, error) {
	if !tm.config.Enabled {
		return nil, fmt.Errorf("2FA is disabled")
	}

	// Generate random secret
	secretBytes := make([]byte, tm.config.SecretLength)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, fmt.Errorf("failed to generate secret: %w", err)
	}

	secret := base32.StdEncoding.EncodeToString(secretBytes)
	secret = strings.TrimRight(secret, "=") // Remove padding

	// Generate backup codes
	backupCodes, err := tm.generateBackupCodes(tm.config.BackupCodes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	twoFASecret := &TwoFASecret{
		UserID:      userID,
		Secret:      secret,
		BackupCodes: backupCodes,
		Enabled:     false, // Must be explicitly enabled after verification
		CreatedAt:   time.Now(),
		UsedCodes:   make([]string, 0),
	}

	tm.mu.Lock()
	tm.secrets[userID] = twoFASecret
	tm.mu.Unlock()

	return twoFASecret, nil
}

// EnableTwoFA enables 2FA for a user after verifying a TOTP code
func (tm *TwoFAManager) EnableTwoFA(userID, totpCode string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	secret, exists := tm.secrets[userID]
	if !exists {
		return fmt.Errorf("no 2FA secret found for user")
	}

	// Verify the TOTP code
	if !tm.verifyTOTP(secret.Secret, totpCode, time.Now()) {
		return fmt.Errorf("invalid TOTP code")
	}

	// Enable 2FA
	secret.Enabled = true
	secret.LastUsed = time.Now()

	return nil
}

// DisableTwoFA disables 2FA for a user
func (tm *TwoFAManager) DisableTwoFA(userID string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	secret, exists := tm.secrets[userID]
	if !exists {
		return fmt.Errorf("no 2FA secret found for user")
	}

	secret.Enabled = false
	return nil
}

// VerifyTOTP verifies a TOTP code for a user
func (tm *TwoFAManager) VerifyTOTP(userID, totpCode string) (bool, error) {
	if !tm.config.Enabled {
		return true, nil // Skip if 2FA is disabled
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()

	secret, exists := tm.secrets[userID]
	if !exists || !secret.Enabled {
		return true, nil // No 2FA setup or not enabled
	}

	now := time.Now()

	// Check if code was already used (prevent replay attacks)
	for _, usedCode := range secret.UsedCodes {
		if usedCode == totpCode {
			return false, fmt.Errorf("TOTP code already used")
		}
	}

	// Verify TOTP code
	if tm.verifyTOTP(secret.Secret, totpCode, now) {
		// Add to used codes
		secret.UsedCodes = append(secret.UsedCodes, totpCode)
		// Keep only recent codes (last 5 minutes)
		cutoff := now.Add(-5 * time.Minute)
		var recentCodes []string
		for _, code := range secret.UsedCodes {
			// This is a simple approach; in production, you'd store timestamps
			recentCodes = append(recentCodes, code)
		}
		if len(recentCodes) > 10 { // Keep last 10 codes
			recentCodes = recentCodes[len(recentCodes)-10:]
		}
		secret.UsedCodes = recentCodes
		secret.LastUsed = now
		return true, nil
	}

	return false, fmt.Errorf("invalid TOTP code")
}

// VerifyBackupCode verifies a backup code for a user
func (tm *TwoFAManager) VerifyBackupCode(userID, backupCode string) (bool, error) {
	if !tm.config.Enabled {
		return true, nil
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()

	secret, exists := tm.secrets[userID]
	if !exists || !secret.Enabled {
		return true, nil
	}

	// Find and remove the backup code
	for i, code := range secret.BackupCodes {
		if code == backupCode {
			// Remove the used backup code
			secret.BackupCodes = append(secret.BackupCodes[:i], secret.BackupCodes[i+1:]...)
			secret.LastUsed = time.Now()
			return true, nil
		}
	}

	return false, fmt.Errorf("invalid backup code")
}

// CreateSession creates a new 2FA session
func (tm *TwoFAManager) CreateSession(userID, sessionID, deviceID string) *TwoFASession {
	now := time.Now()
	session := &TwoFASession{
		UserID:    userID,
		SessionID: sessionID,
		Verified:  false,
		CreatedAt: now,
		ExpiresAt: now.Add(tm.config.GracePeriod),
		DeviceID:  deviceID,
	}

	// Check if device is remembered
	if tm.config.RememberDevice && deviceID != "" {
		tm.mu.RLock()
		lastVerified, exists := tm.devices[deviceID]
		tm.mu.RUnlock()

		if exists && time.Since(lastVerified) < 30*24*time.Hour { // 30 days
			session.Verified = true
			session.Remembered = true
		}
	}

	tm.mu.Lock()
	tm.sessions[sessionID] = session
	tm.mu.Unlock()

	return session
}

// VerifySession verifies a 2FA session with TOTP or backup code
func (tm *TwoFAManager) VerifySession(sessionID, code string, isBackupCode bool) (bool, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	session, exists := tm.sessions[sessionID]
	if !exists {
		return false, fmt.Errorf("session not found")
	}

	if time.Now().After(session.ExpiresAt) {
		delete(tm.sessions, sessionID)
		return false, fmt.Errorf("session expired")
	}

	var verified bool
	var err error

	if isBackupCode {
		verified, err = tm.VerifyBackupCode(session.UserID, code)
	} else {
		verified, err = tm.VerifyTOTP(session.UserID, code)
	}

	if err != nil {
		return false, err
	}

	if verified {
		session.Verified = true
		// Remember device if enabled
		if tm.config.RememberDevice && session.DeviceID != "" {
			tm.devices[session.DeviceID] = time.Now()
		}
	}

	return verified, nil
}

// IsSessionVerified checks if a session is verified
func (tm *TwoFAManager) IsSessionVerified(sessionID string) bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	session, exists := tm.sessions[sessionID]
	if !exists {
		return false
	}

	if time.Now().After(session.ExpiresAt) {
		return false
	}

	return session.Verified
}

// GetQRCodeURL generates a QR code URL for Google Authenticator
func (tm *TwoFAManager) GetQRCodeURL(userID, accountName string) (string, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	secret, exists := tm.secrets[userID]
	if !exists {
		return "", fmt.Errorf("no 2FA secret found for user")
	}

	// Create TOTP URL
	u := url.URL{
		Scheme: "otpauth",
		Host:   "totp",
		Path:   fmt.Sprintf("/%s:%s", tm.config.Issuer, accountName),
	}

	q := u.Query()
	q.Set("secret", secret.Secret)
	q.Set("issuer", tm.config.Issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// verifyTOTP verifies a TOTP code against a secret
func (tm *TwoFAManager) verifyTOTP(secret, code string, timestamp time.Time) bool {
	// Convert timestamp to time step
	timeStep := timestamp.Unix() / int64(tm.config.TimeStep.Seconds())

	// Check current time step and adjacent ones (window)
	for i := -tm.config.WindowSize; i <= tm.config.WindowSize; i++ {
		if tm.generateTOTP(secret, timeStep+int64(i)) == code {
			return true
		}
	}

	return false
}

// generateTOTP generates a TOTP code for a given secret and time step
func (tm *TwoFAManager) generateTOTP(secret string, timeStep int64) string {
	// Decode base32 secret
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return ""
	}

	// Convert time step to bytes
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(timeStep))

	// Generate HMAC-SHA1
	h := hmac.New(sha1.New, key)
	h.Write(buf)
	hash := h.Sum(nil)

	// Dynamic truncation
	offset := hash[len(hash)-1] & 0x0F
	code := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7FFFFFFF

	// Generate 6-digit code
	return fmt.Sprintf("%06d", code%1000000)
}

// generateBackupCodes generates backup codes
func (tm *TwoFAManager) generateBackupCodes(count int) ([]string, error) {
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		// Generate 8-character alphanumeric code
		bytes := make([]byte, 6)
		if _, err := rand.Read(bytes); err != nil {
			return nil, err
		}
		
		// Convert to alphanumeric
		code := ""
		for _, b := range bytes {
			code += fmt.Sprintf("%02x", b)
		}
		codes[i] = strings.ToUpper(code[:8])
	}
	return codes, nil
}

// cleanupRoutine removes expired sessions and old used codes
func (tm *TwoFAManager) cleanupRoutine() {
	for {
		select {
		case <-tm.cleanup.C:
			tm.cleanupExpired()
		case <-tm.stop:
			return
		}
	}
}

// cleanupExpired removes expired sessions and old device records
func (tm *TwoFAManager) cleanupExpired() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	now := time.Now()

	// Clean expired sessions
	for sessionID, session := range tm.sessions {
		if now.After(session.ExpiresAt) {
			delete(tm.sessions, sessionID)
		}
	}

	// Clean old device records (older than 30 days)
	cutoff := now.Add(-30 * 24 * time.Hour)
	for deviceID, lastVerified := range tm.devices {
		if lastVerified.Before(cutoff) {
			delete(tm.devices, deviceID)
		}
	}
}

// Stop stops the 2FA manager
func (tm *TwoFAManager) Stop() {
	close(tm.stop)
	tm.cleanup.Stop()
}

// GetUserSecret returns the 2FA secret for a user (for admin purposes)
func (tm *TwoFAManager) GetUserSecret(userID string) (*TwoFASecret, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	secret, exists := tm.secrets[userID]
	if !exists {
		return nil, fmt.Errorf("no 2FA secret found for user")
	}

	// Return a copy without the actual secret for security
	return &TwoFASecret{
		UserID:      secret.UserID,
		Enabled:     secret.Enabled,
		CreatedAt:   secret.CreatedAt,
		LastUsed:    secret.LastUsed,
		BackupCodes: make([]string, len(secret.BackupCodes)), // Empty backup codes
	}, nil
}

// RegenerateBackupCodes generates new backup codes for a user
func (tm *TwoFAManager) RegenerateBackupCodes(userID string) ([]string, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	secret, exists := tm.secrets[userID]
	if !exists {
		return nil, fmt.Errorf("no 2FA secret found for user")
	}

	backupCodes, err := tm.generateBackupCodes(tm.config.BackupCodes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	secret.BackupCodes = backupCodes
	return backupCodes, nil
}

// GetStats returns 2FA statistics
func (tm *TwoFAManager) GetStats() map[string]interface{} {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	enabledUsers := 0
	for _, secret := range tm.secrets {
		if secret.Enabled {
			enabledUsers++
		}
	}

	return map[string]interface{}{
		"total_users":     len(tm.secrets),
		"enabled_users":   enabledUsers,
		"active_sessions": len(tm.sessions),
		"remembered_devices": len(tm.devices),
		"config":          tm.config,
	}
}

// TwoFAMiddleware creates HTTP middleware for 2FA verification
func TwoFAMiddleware(manager *TwoFAManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !manager.config.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Check if this path requires 2FA
			requires2FA := false
			for _, path := range manager.config.RequiredPaths {
				if r.URL.Path == path || strings.HasPrefix(r.URL.Path, path) {
					requires2FA = true
					break
				}
			}

			if !requires2FA {
				next.ServeHTTP(w, r)
				return
			}

			// Get session ID from cookie or header
			sessionID := ""
			if cookie, err := r.Cookie("session_id"); err == nil {
				sessionID = cookie.Value
			} else if sessionID = r.Header.Get("X-Session-ID"); sessionID == "" {
				http.Error(w, "Session required", http.StatusUnauthorized)
				return
			}

			// Check if session is verified
			if !manager.IsSessionVerified(sessionID) {
				http.Error(w, "2FA verification required", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// DefaultTwoFAConfig returns default 2FA configuration
func DefaultTwoFAConfig() TwoFAConfig {
	return TwoFAConfig{
		Enabled:        false, // Disabled by default
		Issuer:         "Gawan Framework",
		SecretLength:   32,
		WindowSize:     1,
		TimeStep:       30 * time.Second,
		BackupCodes:    10,
		RequiredPaths:  []string{"/admin", "/api/admin"},
		GracePeriod:    30 * time.Minute,
		RememberDevice: true,
	}
}

// GenerateDeviceID generates a unique device ID based on request headers
func GenerateDeviceID(r *http.Request) string {
	// Create device fingerprint from headers
	fingerprint := fmt.Sprintf("%s|%s|%s",
		r.UserAgent(),
		r.Header.Get("Accept-Language"),
		r.Header.Get("Accept-Encoding"),
	)

	// Hash the fingerprint
	h := sha256.New()
	h.Write([]byte(fingerprint))
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}