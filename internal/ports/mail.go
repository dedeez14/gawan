package ports

import (
	"context"
	"time"
)

// MailPort defines the interface for email operations
type MailPort interface {
	// SendEmail sends a single email
	SendEmail(ctx context.Context, email *Email) error

	// SendBulkEmail sends multiple emails
	SendBulkEmail(ctx context.Context, emails []*Email) error

	// SendTemplateEmail sends an email using a template
	SendTemplateEmail(ctx context.Context, templateEmail *TemplateEmail) error

	// ValidateEmail validates an email address
	ValidateEmail(email string) error

	// GetDeliveryStatus gets the delivery status of an email
	GetDeliveryStatus(ctx context.Context, messageID string) (*DeliveryStatus, error)
}

// Email represents an email message
type Email struct {
	From        string            `json:"from"`
	To          []string          `json:"to"`
	CC          []string          `json:"cc,omitempty"`
	BCC         []string          `json:"bcc,omitempty"`
	Subject     string            `json:"subject"`
	Body        string            `json:"body"`
	HTMLBody    string            `json:"html_body,omitempty"`
	Attachments []*Attachment     `json:"attachments,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Priority    Priority          `json:"priority,omitempty"`
	ScheduledAt *time.Time        `json:"scheduled_at,omitempty"`
}

// TemplateEmail represents an email with template
type TemplateEmail struct {
	From         string            `json:"from"`
	To           []string          `json:"to"`
	CC           []string          `json:"cc,omitempty"`
	BCC          []string          `json:"bcc,omitempty"`
	Subject      string            `json:"subject"`
	TemplateName string            `json:"template_name"`
	TemplateData map[string]interface{} `json:"template_data"`
	Attachments  []*Attachment     `json:"attachments,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Priority     Priority          `json:"priority,omitempty"`
	ScheduledAt  *time.Time        `json:"scheduled_at,omitempty"`
}

// Attachment represents an email attachment
type Attachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Content     []byte `json:"content"`
	Inline      bool   `json:"inline,omitempty"`
}

// Priority represents email priority
type Priority string

const (
	PriorityLow    Priority = "low"
	PriorityNormal Priority = "normal"
	PriorityHigh   Priority = "high"
)

// DeliveryStatus represents email delivery status
type DeliveryStatus struct {
	MessageID   string            `json:"message_id"`
	Status      DeliveryState     `json:"status"`
	DeliveredAt *time.Time        `json:"delivered_at,omitempty"`
	Error       string            `json:"error,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// DeliveryState represents the state of email delivery
type DeliveryState string

const (
	DeliveryStatePending   DeliveryState = "pending"
	DeliveryStateSent      DeliveryState = "sent"
	DeliveryStateDelivered DeliveryState = "delivered"
	DeliveryStateFailed    DeliveryState = "failed"
	DeliveryStateBounced   DeliveryState = "bounced"
)

// MailConfig holds email configuration
type MailConfig struct {
	SMTPHost     string `json:"smtp_host"`
	SMTPPort     int    `json:"smtp_port"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	FromEmail    string `json:"from_email"`
	FromName     string `json:"from_name"`
	UseTLS       bool   `json:"use_tls"`
	UseSSL       bool   `json:"use_ssl"`
	Timeout      int    `json:"timeout"`
	RetryAttempts int   `json:"retry_attempts"`
}