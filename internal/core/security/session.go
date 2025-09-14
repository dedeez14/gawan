package security

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// SessionData represents session data
type SessionData struct {
	ID        string                 `json:"id"`
	UserID    string                 `json:"user_id"`
	CreatedAt time.Time              `json:"created_at"`
	ExpiresAt time.Time              `json:"expires_at"`
	Data      map[string]interface{} `json:"data"`
	IPAddress string                 `json:"ip_address"`
	UserAgent string                 `json:"user_agent"`
}

// IsExpired checks if the session is expired
func (s *SessionData) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// SessionStore defines the interface for session storage
type SessionStore interface {
	Get(ctx context.Context, sessionID string) (*SessionData, error)
	Set(ctx context.Context, sessionID string, data *SessionData) error
	Delete(ctx context.Context, sessionID string) error
	Cleanup(ctx context.Context) error
	Exists(ctx context.Context, sessionID string) (bool, error)
}

// MemorySessionStore is an in-memory implementation of SessionStore
type MemorySessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*SessionData
}

// NewMemorySessionStore creates a new memory session store
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{
		sessions: make(map[string]*SessionData),
	}
}

// Get retrieves a session by ID
func (mss *MemorySessionStore) Get(ctx context.Context, sessionID string) (*SessionData, error) {
	mss.mu.RLock()
	defer mss.mu.RUnlock()

	session, exists := mss.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	if session.IsExpired() {
		delete(mss.sessions, sessionID)
		return nil, fmt.Errorf("session expired")
	}

	return session, nil
}

// Set stores a session
func (mss *MemorySessionStore) Set(ctx context.Context, sessionID string, data *SessionData) error {
	mss.mu.Lock()
	defer mss.mu.Unlock()

	mss.sessions[sessionID] = data
	return nil
}

// Delete removes a session
func (mss *MemorySessionStore) Delete(ctx context.Context, sessionID string) error {
	mss.mu.Lock()
	defer mss.mu.Unlock()

	delete(mss.sessions, sessionID)
	return nil
}

// Exists checks if a session exists
func (mss *MemorySessionStore) Exists(ctx context.Context, sessionID string) (bool, error) {
	mss.mu.RLock()
	defer mss.mu.RUnlock()

	session, exists := mss.sessions[sessionID]
	if !exists {
		return false, nil
	}

	if session.IsExpired() {
		delete(mss.sessions, sessionID)
		return false, nil
	}

	return true, nil
}

// Cleanup removes expired sessions
func (mss *MemorySessionStore) Cleanup(ctx context.Context) error {
	mss.mu.Lock()
	defer mss.mu.Unlock()

	now := time.Now()
	for id, session := range mss.sessions {
		if now.After(session.ExpiresAt) {
			delete(mss.sessions, id)
		}
	}
	return nil
}

// SessionConfig holds session configuration
type SessionConfig struct {
	// Store is the session store implementation
	Store SessionStore `json:"-" yaml:"-"`
	// CookieName is the name of the session cookie
	CookieName string `json:"cookie_name" yaml:"cookie_name" env:"SESSION_COOKIE_NAME" default:"session_id"`
	// CookiePath is the path for the session cookie
	CookiePath string `json:"cookie_path" yaml:"cookie_path" env:"SESSION_COOKIE_PATH" default:"/"`
	// CookieDomain is the domain for the session cookie
	CookieDomain string `json:"cookie_domain" yaml:"cookie_domain" env:"SESSION_COOKIE_DOMAIN"`
	// CookieSecure indicates if the cookie should only be sent over HTTPS
	CookieSecure bool `json:"cookie_secure" yaml:"cookie_secure" env:"SESSION_COOKIE_SECURE" default:"false"`
	// CookieHTTPOnly indicates if the cookie should be HTTP only
	CookieHTTPOnly bool `json:"cookie_http_only" yaml:"cookie_http_only" env:"SESSION_COOKIE_HTTP_ONLY" default:"true"`
	// CookieSameSite sets the SameSite attribute
	CookieSameSite http.SameSite `json:"cookie_same_site" yaml:"cookie_same_site" env:"SESSION_COOKIE_SAME_SITE" default:"1"`
	// MaxAge is the maximum age of the session in seconds
	MaxAge int `json:"max_age" yaml:"max_age" env:"SESSION_MAX_AGE" default:"3600"`
	// CleanupInterval is the interval for cleaning up expired sessions
	CleanupInterval time.Duration `json:"cleanup_interval" yaml:"cleanup_interval" env:"SESSION_CLEANUP_INTERVAL" default:"300s"`
	// SkipFunc determines if session middleware should be skipped
	SkipFunc SkipFunc `json:"-" yaml:"-"`
	// ErrorHandler handles session errors
	ErrorHandler SessionErrorHandler `json:"-" yaml:"-"`
}

// SessionErrorHandler handles session errors
type SessionErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// DefaultSessionConfig returns default session configuration
func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		Store:           NewMemorySessionStore(),
		CookieName:      "session_id",
		CookiePath:      "/",
		CookieSecure:    false,
		CookieHTTPOnly:  true,
		CookieSameSite:  http.SameSiteLaxMode,
		MaxAge:          3600, // 1 hour
		CleanupInterval: 5 * time.Minute,
		ErrorHandler:    DefaultSessionErrorHandler,
	}
}

// DefaultSessionErrorHandler is the default session error handler
func DefaultSessionErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":   "unauthorized",
		"message": err.Error(),
	})
}

// SessionManager manages sessions
type SessionManager struct {
	config SessionConfig
	quit   chan struct{}
}

// NewSessionManager creates a new session manager
func NewSessionManager(config SessionConfig) *SessionManager {
	if config.Store == nil {
		config.Store = NewMemorySessionStore()
	}
	if config.ErrorHandler == nil {
		config.ErrorHandler = DefaultSessionErrorHandler
	}

	sm := &SessionManager{
		config: config,
		quit:   make(chan struct{}),
	}

	// Start cleanup goroutine
	go sm.cleanupLoop()

	return sm
}

// cleanupLoop runs the cleanup process periodically
func (sm *SessionManager) cleanupLoop() {
	ticker := time.NewTicker(sm.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sm.config.Store.Cleanup(context.Background())
		case <-sm.quit:
			return
		}
	}
}

// Stop stops the session manager
func (sm *SessionManager) Stop() {
	close(sm.quit)
}

// GenerateSessionID generates a new session ID
func (sm *SessionManager) GenerateSessionID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// CreateSession creates a new session
func (sm *SessionManager) CreateSession(ctx context.Context, userID string, r *http.Request) (*SessionData, error) {
	sessionID, err := sm.GenerateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	now := time.Now()
	session := &SessionData{
		ID:        sessionID,
		UserID:    userID,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(sm.config.MaxAge) * time.Second),
		Data:      make(map[string]interface{}),
		IPAddress: getClientIP(r),
		UserAgent: r.UserAgent(),
	}

	if err := sm.config.Store.Set(ctx, sessionID, session); err != nil {
		return nil, fmt.Errorf("failed to store session: %w", err)
	}

	return session, nil
}

// GetSession retrieves a session by ID
func (sm *SessionManager) GetSession(ctx context.Context, sessionID string) (*SessionData, error) {
	return sm.config.Store.Get(ctx, sessionID)
}

// UpdateSession updates a session
func (sm *SessionManager) UpdateSession(ctx context.Context, session *SessionData) error {
	return sm.config.Store.Set(ctx, session.ID, session)
}

// DeleteSession deletes a session
func (sm *SessionManager) DeleteSession(ctx context.Context, sessionID string) error {
	return sm.config.Store.Delete(ctx, sessionID)
}

// RefreshSession extends the session expiration
func (sm *SessionManager) RefreshSession(ctx context.Context, sessionID string) (*SessionData, error) {
	session, err := sm.config.Store.Get(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	session.ExpiresAt = time.Now().Add(time.Duration(sm.config.MaxAge) * time.Second)

	if err := sm.config.Store.Set(ctx, sessionID, session); err != nil {
		return nil, fmt.Errorf("failed to refresh session: %w", err)
	}

	return session, nil
}

// SetSessionCookie sets the session cookie
func (sm *SessionManager) SetSessionCookie(w http.ResponseWriter, sessionID string) {
	cookie := &http.Cookie{
		Name:     sm.config.CookieName,
		Value:    sessionID,
		Path:     sm.config.CookiePath,
		Domain:   sm.config.CookieDomain,
		MaxAge:   sm.config.MaxAge,
		Secure:   sm.config.CookieSecure,
		HttpOnly: sm.config.CookieHTTPOnly,
		SameSite: sm.config.CookieSameSite,
	}
	http.SetCookie(w, cookie)
}

// ClearSessionCookie clears the session cookie
func (sm *SessionManager) ClearSessionCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     sm.config.CookieName,
		Value:    "",
		Path:     sm.config.CookiePath,
		Domain:   sm.config.CookieDomain,
		MaxAge:   -1,
		Secure:   sm.config.CookieSecure,
		HttpOnly: sm.config.CookieHTTPOnly,
		SameSite: sm.config.CookieSameSite,
	}
	http.SetCookie(w, cookie)
}

// Context keys for session
const (
	SessionKey     contextKey = "session"
	SessionDataKey contextKey = "session_data"
)

// SessionMiddleware creates session middleware
func SessionMiddleware(manager *SessionManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip session if skip function returns true
			if manager.config.SkipFunc != nil && manager.config.SkipFunc(r) {
				next.ServeHTTP(w, r)
				return
			}

			// Get session ID from cookie
			cookie, err := r.Cookie(manager.config.CookieName)
			if err != nil {
				// No session cookie, continue without session
				next.ServeHTTP(w, r)
				return
			}

			// Get session data
			session, err := manager.GetSession(r.Context(), cookie.Value)
			if err != nil {
				// Invalid or expired session, clear cookie and continue
				manager.ClearSessionCookie(w)
				next.ServeHTTP(w, r)
				return
			}

			// Add session to context
			ctx := context.WithValue(r.Context(), SessionKey, manager)
			ctx = context.WithValue(ctx, SessionDataKey, session)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// RequireSession creates middleware that requires a valid session
func RequireSession() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, ok := GetSession(r)
			if !ok {
				http.Error(w, "Session required", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetSessionManager extracts session manager from request context
func GetSessionManager(r *http.Request) (*SessionManager, bool) {
	manager, ok := r.Context().Value(SessionKey).(*SessionManager)
	return manager, ok
}

// GetSession extracts session data from request context
func GetSession(r *http.Request) (*SessionData, bool) {
	session, ok := r.Context().Value(SessionDataKey).(*SessionData)
	return session, ok
}

// GetSessionUserID extracts user ID from session
func GetSessionUserID(r *http.Request) (string, bool) {
	session, ok := GetSession(r)
	if !ok {
		return "", false
	}
	return session.UserID, true
}

// SetSessionData sets data in the session
func SetSessionData(r *http.Request, key string, value interface{}) error {
	session, ok := GetSession(r)
	if !ok {
		return fmt.Errorf("no session found")
	}

	manager, ok := GetSessionManager(r)
	if !ok {
		return fmt.Errorf("no session manager found")
	}

	session.Data[key] = value
	return manager.UpdateSession(r.Context(), session)
}

// GetSessionData gets data from the session
func GetSessionData(r *http.Request, key string) (interface{}, bool) {
	session, ok := GetSession(r)
	if !ok {
		return nil, false
	}

	value, exists := session.Data[key]
	return value, exists
}

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}