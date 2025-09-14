package logx

import (
	"context"
)

// SlogAdapter adapts our Logger to work with standard slog interfaces
type SlogAdapter struct {
	logger *Logger
}

// NewSlogAdapter creates a new slog adapter
func NewSlogAdapter(logger *Logger) *SlogAdapter {
	return &SlogAdapter{logger: logger}
}

// Debug logs a debug message
func (s *SlogAdapter) Debug(msg string, args ...any) {
	s.logger.Debug(msg, args...)
}

// DebugContext logs a debug message with context
func (s *SlogAdapter) DebugContext(ctx context.Context, msg string, args ...any) {
	s.logger.DebugContext(ctx, msg, args...)
}

// Info logs an info message
func (s *SlogAdapter) Info(msg string, args ...any) {
	s.logger.Info(msg, args...)
}

// InfoContext logs an info message with context
func (s *SlogAdapter) InfoContext(ctx context.Context, msg string, args ...any) {
	s.logger.InfoContext(ctx, msg, args...)
}

// Warn logs a warning message
func (s *SlogAdapter) Warn(msg string, args ...any) {
	s.logger.Warn(msg, args...)
}

// WarnContext logs a warning message with context
func (s *SlogAdapter) WarnContext(ctx context.Context, msg string, args ...any) {
	s.logger.WarnContext(ctx, msg, args...)
}

// Error logs an error message
func (s *SlogAdapter) Error(msg string, args ...any) {
	s.logger.Error(msg, args...)
}

// ErrorContext logs an error message with context
func (s *SlogAdapter) ErrorContext(ctx context.Context, msg string, args ...any) {
	s.logger.ErrorContext(ctx, msg, args...)
}

// With returns a new adapter with additional attributes
func (s *SlogAdapter) With(args ...any) *SlogAdapter {
	return &SlogAdapter{
		logger: &Logger{Logger: s.logger.With(args...)},
	}
}