package security

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// JWTClaims represents JWT claims
type JWTClaims struct {
	// Standard claims
	Issuer    string `json:"iss,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Audience  string `json:"aud,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	JWTID     string `json:"jti,omitempty"`

	// Custom claims
	UserID   string   `json:"user_id,omitempty"`
	Username string   `json:"username,omitempty"`
	Email    string   `json:"email,omitempty"`
	Roles    []string `json:"roles,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
}

// Valid validates the JWT claims
func (c *JWTClaims) Valid() error {
	now := time.Now().Unix()

	// Check expiration
	if c.ExpiresAt > 0 && now > c.ExpiresAt {
		return errors.New("token is expired")
	}

	// Check not before
	if c.NotBefore > 0 && now < c.NotBefore {
		return errors.New("token used before valid")
	}

	return nil
}

// HasRole checks if the user has a specific role
func (c *JWTClaims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasScope checks if the token has a specific scope
func (c *JWTClaims) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// JWTConfig holds JWT configuration
type JWTConfig struct {
	// Enabled enables JWT authentication
	Enabled bool `json:"enabled" yaml:"enabled" env:"JWT_ENABLED" default:"true"`
	// Secret is the signing secret
	Secret string `json:"secret" yaml:"secret" env:"JWT_SECRET"`
	// Issuer is the token issuer
	Issuer string `json:"issuer" yaml:"issuer" env:"JWT_ISSUER"`
	// Audience is the token audience
	Audience string `json:"audience" yaml:"audience" env:"JWT_AUDIENCE"`
	// ExpirationTime is the token expiration time
	ExpirationTime time.Duration `json:"expiration_time" yaml:"expiration_time" env:"JWT_EXPIRATION_TIME" default:"24h"`
	// RefreshTime is the refresh token expiration time
	RefreshTime time.Duration `json:"refresh_time" yaml:"refresh_time" env:"JWT_REFRESH_TIME" default:"168h"`
	// TokenLookup specifies where to look for the token
	TokenLookup string `json:"token_lookup" yaml:"token_lookup" env:"JWT_TOKEN_LOOKUP" default:"header:Authorization"`
	// AuthScheme is the authentication scheme (Bearer, JWT, etc.)
	AuthScheme string `json:"auth_scheme" yaml:"auth_scheme" env:"JWT_AUTH_SCHEME" default:"Bearer"`
	// SkipFunc determines if JWT validation should be skipped
	SkipFunc SkipFunc `json:"-" yaml:"-"`
	// ErrorHandler handles JWT errors
	ErrorHandler JWTErrorHandler `json:"-" yaml:"-"`
}

// JWTErrorHandler handles JWT authentication errors
type JWTErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// DefaultJWTConfig returns default JWT configuration
func DefaultJWTConfig() JWTConfig {
	return JWTConfig{
		Enabled:        true,
		Secret:         "", // Must be set
		Issuer:         "tutorial-api",
		Audience:       "tutorial-users",
		ExpirationTime: 24 * time.Hour,
		RefreshTime:    7 * 24 * time.Hour,
		TokenLookup:    "header:Authorization",
		AuthScheme:     "Bearer",
		ErrorHandler:   DefaultJWTErrorHandler,
	}
}

// DefaultJWTErrorHandler is the default JWT error handler
func DefaultJWTErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":   "unauthorized",
		"message": err.Error(),
	})
}

// JWTService provides JWT operations
type JWTService struct {
	config JWTConfig
}

// NewJWTService creates a new JWT service
func NewJWTService(config JWTConfig) *JWTService {
	if config.Secret == "" {
		panic("JWT secret is required")
	}
	return &JWTService{config: config}
}

// GenerateToken generates a JWT token
func (js *JWTService) GenerateToken(claims *JWTClaims) (string, error) {
	// Set standard claims
	now := time.Now()
	if claims.IssuedAt == 0 {
		claims.IssuedAt = now.Unix()
	}
	if claims.ExpiresAt == 0 {
		claims.ExpiresAt = now.Add(js.config.ExpirationTime).Unix()
	}
	if claims.Issuer == "" {
		claims.Issuer = js.config.Issuer
	}
	if claims.Audience == "" {
		claims.Audience = js.config.Audience
	}

	// Create header
	header := map[string]interface{}{
		"typ": "JWT",
		"alg": "HS256",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	// Create payload
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	// Encode header and payload
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create signature
	message := headerEncoded + "." + payloadEncoded
	signature := js.sign(message)

	return message + "." + signature, nil
}

// ValidateToken validates a JWT token
func (js *JWTService) ValidateToken(tokenString string) (*JWTClaims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	headerEncoded, payloadEncoded, signatureEncoded := parts[0], parts[1], parts[2]

	// Verify signature
	message := headerEncoded + "." + payloadEncoded
	expectedSignature := js.sign(message)
	if !hmac.Equal([]byte(signatureEncoded), []byte(expectedSignature)) {
		return nil, errors.New("invalid token signature")
	}

	// Decode payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadEncoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var claims JWTClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	// Validate claims
	if err := claims.Valid(); err != nil {
		return nil, err
	}

	return &claims, nil
}

// RefreshToken generates a new token from an existing one
func (js *JWTService) RefreshToken(tokenString string) (string, error) {
	claims, err := js.ValidateToken(tokenString)
	if err != nil {
		return "", err
	}

	// Create new claims with updated timestamps
	now := time.Now()
	newClaims := *claims
	newClaims.IssuedAt = now.Unix()
	newClaims.ExpiresAt = now.Add(js.config.ExpirationTime).Unix()

	return js.GenerateToken(&newClaims)
}

// sign creates HMAC signature
func (js *JWTService) sign(message string) string {
	h := hmac.New(sha256.New, []byte(js.config.Secret))
	h.Write([]byte(message))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// extractToken extracts token from request based on TokenLookup configuration
func (js *JWTService) extractToken(r *http.Request) (string, error) {
	parts := strings.Split(js.config.TokenLookup, ":")
	if len(parts) != 2 {
		return "", errors.New("invalid token lookup format")
	}

	lookupType, lookupKey := parts[0], parts[1]

	switch lookupType {
	case "header":
		auth := r.Header.Get(lookupKey)
		if auth == "" {
			return "", errors.New("missing authorization header")
		}

		// Handle Bearer scheme
		if js.config.AuthScheme != "" {
			scheme := js.config.AuthScheme + " "
			if !strings.HasPrefix(auth, scheme) {
				return "", fmt.Errorf("invalid authorization scheme, expected %s", js.config.AuthScheme)
			}
			return auth[len(scheme):], nil
		}
		return auth, nil

	case "query":
		token := r.URL.Query().Get(lookupKey)
		if token == "" {
			return "", fmt.Errorf("missing token in query parameter %s", lookupKey)
		}
		return token, nil

	case "cookie":
		cookie, err := r.Cookie(lookupKey)
		if err != nil {
			return "", fmt.Errorf("missing token in cookie %s", lookupKey)
		}
		return cookie.Value, nil

	default:
		return "", fmt.Errorf("unsupported token lookup type: %s", lookupType)
	}
}

// Context keys for JWT claims
type contextKey string

const (
	JWTClaimsKey contextKey = "jwt_claims"
	JWTUserKey   contextKey = "jwt_user"
)

// JWTMiddleware creates a JWT authentication middleware
func JWTMiddleware(config JWTConfig) func(http.Handler) http.Handler {
	if !config.Enabled {
		return func(next http.Handler) http.Handler {
			return next // Pass through if disabled
		}
	}

	if config.ErrorHandler == nil {
		config.ErrorHandler = DefaultJWTErrorHandler
	}

	service := NewJWTService(config)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip JWT validation if skip function returns true
			if config.SkipFunc != nil && config.SkipFunc(r) {
				next.ServeHTTP(w, r)
				return
			}

			// Extract token
			tokenString, err := service.extractToken(r)
			if err != nil {
				config.ErrorHandler(w, r, err)
				return
			}

			// Validate token
			claims, err := service.ValidateToken(tokenString)
			if err != nil {
				config.ErrorHandler(w, r, err)
				return
			}

			// Add claims to context
			ctx := context.WithValue(r.Context(), JWTClaimsKey, claims)
			ctx = context.WithValue(ctx, JWTUserKey, claims.UserID)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// GetJWTClaims extracts JWT claims from request context
func GetJWTClaims(r *http.Request) (*JWTClaims, bool) {
	claims, ok := r.Context().Value(JWTClaimsKey).(*JWTClaims)
	return claims, ok
}

// GetJWTUser extracts user ID from request context
func GetJWTUser(r *http.Request) (string, bool) {
	userID, ok := r.Context().Value(JWTUserKey).(string)
	return userID, ok
}

// RequireJWTClaims is a helper middleware that ensures JWT claims are present
func RequireJWTClaims(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := GetJWTClaims(r); !ok {
			http.Error(w, "JWT claims not found in context", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// OptionalJWTMiddleware creates an optional JWT middleware that doesn't fail on missing tokens
func OptionalJWTMiddleware(config JWTConfig) func(http.Handler) http.Handler {
	service := NewJWTService(config)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try to extract and validate token
			tokenString, err := service.extractToken(r)
			if err == nil {
				if claims, err := service.ValidateToken(tokenString); err == nil {
					// Add claims to context if valid
					ctx := context.WithValue(r.Context(), JWTClaimsKey, claims)
					ctx = context.WithValue(ctx, JWTUserKey, claims.UserID)
					r = r.WithContext(ctx)
				}
			}

			// Continue regardless of token validation result
			next.ServeHTTP(w, r)
		})
	}
}