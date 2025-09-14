package security

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

// CaptchaConfig holds captcha configuration
type CaptchaConfig struct {
	Enabled        bool          `json:"enabled"`
	Width          int           `json:"width"`
	Height         int           `json:"height"`
	Length         int           `json:"length"`
	Expiry         time.Duration `json:"expiry"`
	NoiseCount     int           `json:"noise_count"`
	ShowMathProblem bool         `json:"show_math_problem"`
	Difficulty     string        `json:"difficulty"` // "easy", "medium", "hard"
}

// CaptchaChallenge represents a captcha challenge
type CaptchaChallenge struct {
	ID          string    `json:"id"`
	Answer      string    `json:"-"` // Never expose in JSON
	ImageData   []byte    `json:"-"`
	MathProblem string    `json:"math_problem,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Attempts    int       `json:"attempts"`
	MaxAttempts int       `json:"max_attempts"`
}

// CaptchaManager manages captcha generation and validation
type CaptchaManager struct {
	config     CaptchaConfig
	challenges map[string]*CaptchaChallenge
	mu         sync.RWMutex
	cleanup    *time.Ticker
	stop       chan struct{}
}

// NewCaptchaManager creates a new captcha manager
func NewCaptchaManager(config CaptchaConfig) *CaptchaManager {
	if config.Width <= 0 {
		config.Width = 200
	}
	if config.Height <= 0 {
		config.Height = 80
	}
	if config.Length <= 0 {
		config.Length = 5
	}
	if config.Expiry <= 0 {
		config.Expiry = 5 * time.Minute
	}
	if config.NoiseCount <= 0 {
		config.NoiseCount = 100
	}
	if config.Difficulty == "" {
		config.Difficulty = "medium"
	}

	cm := &CaptchaManager{
		config:     config,
		challenges: make(map[string]*CaptchaChallenge),
		cleanup:    time.NewTicker(time.Minute),
		stop:       make(chan struct{}),
	}

	// Start cleanup routine
	go cm.cleanupRoutine()

	return cm
}

// GenerateChallenge creates a new captcha challenge
func (cm *CaptchaManager) GenerateChallenge() (*CaptchaChallenge, error) {
	if !cm.config.Enabled {
		return nil, fmt.Errorf("captcha is disabled")
	}

	id, err := generateRandomID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate challenge ID: %w", err)
	}

	var answer string
	var mathProblem string
	var imageData []byte

	if cm.config.ShowMathProblem {
		// Generate math problem
		mathProblem, answer = cm.generateMathProblem()
		imageData, err = cm.generateMathImage(mathProblem)
	} else {
		// Generate text captcha
		answer = cm.generateRandomText()
		imageData, err = cm.generateTextImage(answer)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to generate captcha image: %w", err)
	}

	now := time.Now()
	challenge := &CaptchaChallenge{
		ID:          id,
		Answer:      answer,
		ImageData:   imageData,
		MathProblem: mathProblem,
		CreatedAt:   now,
		ExpiresAt:   now.Add(cm.config.Expiry),
		Attempts:    0,
		MaxAttempts: 3,
	}

	cm.mu.Lock()
	cm.challenges[id] = challenge
	cm.mu.Unlock()

	return challenge, nil
}

// ValidateChallenge validates a captcha response
func (cm *CaptchaManager) ValidateChallenge(challengeID, userAnswer string) (bool, error) {
	if !cm.config.Enabled {
		return true, nil // Skip validation if disabled
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	challenge, exists := cm.challenges[challengeID]
	if !exists {
		return false, fmt.Errorf("invalid or expired challenge")
	}

	// Check expiry
	if time.Now().After(challenge.ExpiresAt) {
		delete(cm.challenges, challengeID)
		return false, fmt.Errorf("challenge expired")
	}

	// Increment attempts
	challenge.Attempts++

	// Check max attempts
	if challenge.Attempts > challenge.MaxAttempts {
		delete(cm.challenges, challengeID)
		return false, fmt.Errorf("maximum attempts exceeded")
	}

	// Validate answer (case-insensitive)
	isValid := strings.EqualFold(strings.TrimSpace(userAnswer), strings.TrimSpace(challenge.Answer))

	// Remove challenge if valid or max attempts reached
	if isValid || challenge.Attempts >= challenge.MaxAttempts {
		delete(cm.challenges, challengeID)
	}

	return isValid, nil
}

// GetChallengeImage returns the image data for a challenge
func (cm *CaptchaManager) GetChallengeImage(challengeID string) ([]byte, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	challenge, exists := cm.challenges[challengeID]
	if !exists {
		return nil, fmt.Errorf("challenge not found")
	}

	if time.Now().After(challenge.ExpiresAt) {
		return nil, fmt.Errorf("challenge expired")
	}

	return challenge.ImageData, nil
}

// generateRandomText generates random text for captcha
func (cm *CaptchaManager) generateRandomText() string {
	var chars string
	switch cm.config.Difficulty {
	case "easy":
		chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	case "hard":
		chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	default: // medium
		chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	}

	result := make([]byte, cm.config.Length)
	for i := range result {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		result[i] = chars[n.Int64()]
	}
	return string(result)
}

// generateMathProblem generates a simple math problem
func (cm *CaptchaManager) generateMathProblem() (string, string) {
	var a, b int
	var operator string
	var answer int

	switch cm.config.Difficulty {
	case "easy":
		a, _ = rand.Int(rand.Reader, big.NewInt(10))
		b, _ = rand.Int(rand.Reader, big.NewInt(10))
		operator = "+"
		answer = int(a.Int64()) + int(b.Int64())
	case "hard":
		a, _ = rand.Int(rand.Reader, big.NewInt(20))
		b, _ = rand.Int(rand.Reader, big.NewInt(20))
		ops := []string{"+", "-", "*"}
		opIdx, _ := rand.Int(rand.Reader, big.NewInt(3))
		operator = ops[opIdx.Int64()]
		switch operator {
		case "+":
			answer = int(a.Int64()) + int(b.Int64())
		case "-":
			if a.Int64() < b.Int64() {
				a, b = b, a
			}
			answer = int(a.Int64()) - int(b.Int64())
		case "*":
			a, _ = rand.Int(rand.Reader, big.NewInt(10))
			b, _ = rand.Int(rand.Reader, big.NewInt(10))
			answer = int(a.Int64()) * int(b.Int64())
		}
	default: // medium
		a, _ = rand.Int(rand.Reader, big.NewInt(15))
		b, _ = rand.Int(rand.Reader, big.NewInt(15))
		ops := []string{"+", "-"}
		opIdx, _ := rand.Int(rand.Reader, big.NewInt(2))
		operator = ops[opIdx.Int64()]
		if operator == "+" {
			answer = int(a.Int64()) + int(b.Int64())
		} else {
			if a.Int64() < b.Int64() {
				a, b = b, a
			}
			answer = int(a.Int64()) - int(b.Int64())
		}
	}

	problem := fmt.Sprintf("%d %s %d = ?", a.Int64(), operator, b.Int64())
	return problem, strconv.Itoa(answer)
}

// generateTextImage creates an image with distorted text
func (cm *CaptchaManager) generateTextImage(text string) ([]byte, error) {
	// Create image
	img := image.NewRGBA(image.Rect(0, 0, cm.config.Width, cm.config.Height))

	// Fill background with random color
	bgColor := color.RGBA{
		R: uint8(randomInt(200, 255)),
		G: uint8(randomInt(200, 255)),
		B: uint8(randomInt(200, 255)),
		A: 255,
	}
	draw.Draw(img, img.Bounds(), &image.Uniform{bgColor}, image.Point{}, draw.Src)

	// Add noise
	cm.addNoise(img)

	// Draw text
	cm.drawText(img, text)

	// Add more noise on top
	cm.addNoise(img)

	// Convert to PNG bytes
	return cm.imageToPNG(img)
}

// generateMathImage creates an image with math problem
func (cm *CaptchaManager) generateMathImage(problem string) ([]byte, error) {
	return cm.generateTextImage(problem)
}

// drawText draws text on the image with distortion
func (cm *CaptchaManager) drawText(img *image.RGBA, text string) {
	fontFace := basicfont.Face7x13
	textColor := color.RGBA{
		R: uint8(randomInt(0, 100)),
		G: uint8(randomInt(0, 100)),
		B: uint8(randomInt(0, 100)),
		A: 255,
	}

	d := &font.Drawer{
		Dst:  img,
		Src:  &image.Uniform{textColor},
		Face: fontFace,
	}

	// Calculate text positioning
	textWidth := font.MeasureString(fontFace, text)
	textHeight := fontFace.Metrics().Height

	startX := (cm.config.Width - textWidth.Round()) / 2
	startY := (cm.config.Height + textHeight.Round()) / 2

	// Draw each character with slight random offset
	charWidth := textWidth.Round() / len(text)
	for i, char := range text {
		x := startX + i*charWidth + randomInt(-5, 5)
		y := startY + randomInt(-10, 10)
		d.Dot = fixed.Point26_6{
			X: fixed.Int26_6(x * 64),
			Y: fixed.Int26_6(y * 64),
		}
		d.DrawString(string(char))
	}
}

// addNoise adds random noise to the image
func (cm *CaptchaManager) addNoise(img *image.RGBA) {
	bounds := img.Bounds()
	for i := 0; i < cm.config.NoiseCount; i++ {
		x := randomInt(bounds.Min.X, bounds.Max.X)
		y := randomInt(bounds.Min.Y, bounds.Max.Y)
		noiseColor := color.RGBA{
			R: uint8(randomInt(0, 255)),
			G: uint8(randomInt(0, 255)),
			B: uint8(randomInt(0, 255)),
			A: uint8(randomInt(50, 150)),
		}
		img.Set(x, y, noiseColor)
	}

	// Add some lines
	for i := 0; i < 3; i++ {
		cm.drawRandomLine(img)
	}
}

// drawRandomLine draws a random line on the image
func (cm *CaptchaManager) drawRandomLine(img *image.RGBA) {
	bounds := img.Bounds()
	x1 := randomInt(bounds.Min.X, bounds.Max.X)
	y1 := randomInt(bounds.Min.Y, bounds.Max.Y)
	x2 := randomInt(bounds.Min.X, bounds.Max.X)
	y2 := randomInt(bounds.Min.Y, bounds.Max.Y)

	lineColor := color.RGBA{
		R: uint8(randomInt(0, 150)),
		G: uint8(randomInt(0, 150)),
		B: uint8(randomInt(0, 150)),
		A: 100,
	}

	// Simple line drawing using Bresenham's algorithm
	dx := int(math.Abs(float64(x2 - x1)))
	dy := int(math.Abs(float64(y2 - y1)))
	sx := -1
	sy := -1
	if x1 < x2 {
		sx = 1
	}
	if y1 < y2 {
		sy = 1
	}
	err := dx - dy

	for {
		img.Set(x1, y1, lineColor)
		if x1 == x2 && y1 == y2 {
			break
		}
		e2 := 2 * err
		if e2 > -dy {
			err -= dy
			x1 += sx
		}
		if e2 < dx {
			err += dx
			y1 += sy
		}
	}
}

// imageToPNG converts image to PNG bytes
func (cm *CaptchaManager) imageToPNG(img image.Image) ([]byte, error) {
	var buf strings.Builder
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	if err := png.Encode(encoder, img); err != nil {
		return nil, err
	}
	encoder.Close()
	return []byte(buf.String()), nil
}

// cleanupRoutine removes expired challenges
func (cm *CaptchaManager) cleanupRoutine() {
	for {
		select {
		case <-cm.cleanup.C:
			cm.cleanupExpired()
		case <-cm.stop:
			return
		}
	}
}

// cleanupExpired removes expired challenges
func (cm *CaptchaManager) cleanupExpired() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	now := time.Now()
	for id, challenge := range cm.challenges {
		if now.After(challenge.ExpiresAt) {
			delete(cm.challenges, id)
		}
	}
}

// Stop stops the captcha manager
func (cm *CaptchaManager) Stop() {
	close(cm.stop)
	cm.cleanup.Stop()
}

// GetStats returns captcha statistics
func (cm *CaptchaManager) GetStats() map[string]interface{} {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return map[string]interface{}{
		"active_challenges": len(cm.challenges),
		"config":            cm.config,
	}
}

// CaptchaMiddleware creates HTTP middleware for captcha validation
func CaptchaMiddleware(manager *CaptchaManager, requiredPaths []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if this path requires captcha
			requiresCaptcha := false
			for _, path := range requiredPaths {
				if r.URL.Path == path {
					requiresCaptcha = true
					break
				}
			}

			if !requiresCaptcha {
				next.ServeHTTP(w, r)
				return
			}

			// For POST requests, validate captcha
			if r.Method == "POST" {
				challengeID := r.FormValue("captcha_id")
				userAnswer := r.FormValue("captcha_answer")

				if challengeID == "" || userAnswer == "" {
					http.Error(w, "Captcha validation required", http.StatusBadRequest)
					return
				}

				valid, err := manager.ValidateChallenge(challengeID, userAnswer)
				if err != nil || !valid {
					http.Error(w, "Invalid captcha", http.StatusBadRequest)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Helper functions

func generateRandomID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func randomInt(min, max int) int {
	if min >= max {
		return min
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	return min + int(n.Int64())
}

// DefaultCaptchaConfig returns default captcha configuration
func DefaultCaptchaConfig() CaptchaConfig {
	return CaptchaConfig{
		Enabled:         true,
		Width:           200,
		Height:          80,
		Length:          5,
		Expiry:          5 * time.Minute,
		NoiseCount:      100,
		ShowMathProblem: false,
		Difficulty:      "medium",
	}
}