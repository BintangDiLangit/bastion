package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// WebhookEventStatus represents the status of a webhook event.
type WebhookEventStatus string

const (
	WebhookStatusPending   WebhookEventStatus = "pending"
	WebhookStatusProcessed WebhookEventStatus = "processed"
	WebhookStatusFailed    WebhookEventStatus = "failed"
)

// WebhookEvent represents a received webhook event.
type WebhookEvent struct {
	ID           uuid.UUID          `db:"id" json:"id"`
	Provider     string             `db:"provider" json:"provider"` // github, gitlab, etc.
	Event        string             `db:"event" json:"event"`       // push, pull_request, etc.
	Payload      WebhookPayload     `db:"payload" json:"payload"`
	Status       WebhookEventStatus `db:"status" json:"status"`
	ErrorMessage *string            `db:"error_message" json:"error_message,omitempty"`
	CreatedAt    time.Time          `db:"created_at" json:"created_at"`
	ProcessedAt  *time.Time         `db:"processed_at" json:"processed_at,omitempty"`
}

// WebhookPayload holds the JSON payload of the webhook.
type WebhookPayload map[string]interface{}

// Value implements the driver.Valuer interface.
func (p WebhookPayload) Value() (driver.Value, error) {
	return json.Marshal(p)
}

// Scan implements the sql.Scanner interface.
func (p *WebhookPayload) Scan(value interface{}) error {
	if value == nil {
		*p = make(WebhookPayload)
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}

	return json.Unmarshal(bytes, p)
}
