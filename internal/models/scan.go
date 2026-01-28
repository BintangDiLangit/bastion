// Package models provides data models for the application.
package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// ScanStatus represents the status of a scan.
type ScanStatus string

const (
	ScanStatusPending    ScanStatus = "pending"
	ScanStatusRunning    ScanStatus = "running"
	ScanStatusCompleted  ScanStatus = "completed"
	ScanStatusFailed     ScanStatus = "failed"
	ScanStatusCancelled  ScanStatus = "cancelled"
)

// ScanType represents the type of scan.
type ScanType string

const (
	ScanTypeFull        ScanType = "full"
	ScanTypeIncremental ScanType = "incremental"
	ScanTypePR          ScanType = "pull_request"
	ScanTypeManual      ScanType = "manual"
)

// ScanTrigger represents what triggered the scan.
type ScanTrigger string

const (
	ScanTriggerWebhook  ScanTrigger = "webhook"
	ScanTriggerManual   ScanTrigger = "manual"
	ScanTriggerSchedule ScanTrigger = "schedule"
	ScanTriggerCLI      ScanTrigger = "cli"
)

// Scan represents a security scan of a repository.
type Scan struct {
	ID            uuid.UUID      `db:"id" json:"id"`
	RepositoryID  uuid.UUID      `db:"repository_id" json:"repository_id"`
	Status        ScanStatus     `db:"status" json:"status"`
	Type          ScanType       `db:"type" json:"type"`
	Trigger       ScanTrigger    `db:"trigger" json:"trigger"`
	Branch        string         `db:"branch" json:"branch"`
	CommitSHA     string         `db:"commit_sha" json:"commit_sha"`
	PRNumber      *int           `db:"pr_number" json:"pr_number,omitempty"`
	StartedAt     *time.Time     `db:"started_at" json:"started_at,omitempty"`
	CompletedAt   *time.Time     `db:"completed_at" json:"completed_at,omitempty"`
	Duration      *int64         `db:"duration_ms" json:"duration_ms,omitempty"` // in milliseconds
	FilesScanned  int            `db:"files_scanned" json:"files_scanned"`
	LinesScanned  int            `db:"lines_scanned" json:"lines_scanned"`
	ErrorMessage  *string        `db:"error_message" json:"error_message,omitempty"`
	Metadata      ScanMetadata   `db:"metadata" json:"metadata"`
	CreatedAt     time.Time      `db:"created_at" json:"created_at"`
	UpdatedAt     time.Time      `db:"updated_at" json:"updated_at"`
}

// ScanMetadata holds additional scan metadata.
type ScanMetadata struct {
	Languages      []string          `json:"languages,omitempty"`
	EnabledRules   []string          `json:"enabled_rules,omitempty"`
	ExcludedPaths  []string          `json:"excluded_paths,omitempty"`
	ScanOptions    map[string]string `json:"scan_options,omitempty"`
	TriggerInfo    TriggerInfo       `json:"trigger_info,omitempty"`
}

// TriggerInfo holds information about what triggered the scan.
type TriggerInfo struct {
	UserID     string `json:"user_id,omitempty"`
	Username   string `json:"username,omitempty"`
	WebhookID  string `json:"webhook_id,omitempty"`
	ScheduleID string `json:"schedule_id,omitempty"`
}

// Value implements the driver.Valuer interface for ScanMetadata.
func (m ScanMetadata) Value() (driver.Value, error) {
	return json.Marshal(m)
}

// Scan implements the sql.Scanner interface for ScanMetadata.
func (m *ScanMetadata) Scan(value interface{}) error {
	if value == nil {
		*m = ScanMetadata{}
		return nil
	}
	
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}
	
	return json.Unmarshal(bytes, m)
}

// NewScan creates a new Scan with defaults.
func NewScan(repoID uuid.UUID, scanType ScanType, trigger ScanTrigger) *Scan {
	now := time.Now()
	return &Scan{
		ID:           uuid.New(),
		RepositoryID: repoID,
		Status:       ScanStatusPending,
		Type:         scanType,
		Trigger:      trigger,
		CreatedAt:    now,
		UpdatedAt:    now,
		Metadata:     ScanMetadata{},
	}
}

// Start marks the scan as started.
func (s *Scan) Start() {
	now := time.Now()
	s.Status = ScanStatusRunning
	s.StartedAt = &now
	s.UpdatedAt = now
}

// Complete marks the scan as completed.
func (s *Scan) Complete(filesScanned, linesScanned int) {
	now := time.Now()
	s.Status = ScanStatusCompleted
	s.CompletedAt = &now
	s.FilesScanned = filesScanned
	s.LinesScanned = linesScanned
	s.UpdatedAt = now
	
	if s.StartedAt != nil {
		duration := now.Sub(*s.StartedAt).Milliseconds()
		s.Duration = &duration
	}
}

// Fail marks the scan as failed.
func (s *Scan) Fail(errMsg string) {
	now := time.Now()
	s.Status = ScanStatusFailed
	s.CompletedAt = &now
	s.ErrorMessage = &errMsg
	s.UpdatedAt = now
	
	if s.StartedAt != nil {
		duration := now.Sub(*s.StartedAt).Milliseconds()
		s.Duration = &duration
	}
}

// Cancel marks the scan as cancelled.
func (s *Scan) Cancel() {
	now := time.Now()
	s.Status = ScanStatusCancelled
	s.CompletedAt = &now
	s.UpdatedAt = now
	
	if s.StartedAt != nil {
		duration := now.Sub(*s.StartedAt).Milliseconds()
		s.Duration = &duration
	}
}

// IsFinished returns true if the scan is in a terminal state.
func (s *Scan) IsFinished() bool {
	return s.Status == ScanStatusCompleted ||
		s.Status == ScanStatusFailed ||
		s.Status == ScanStatusCancelled
}

// ScanSummary represents a summary of scan results.
type ScanSummary struct {
	ScanID              uuid.UUID `json:"scan_id"`
	TotalVulnerabilities int      `json:"total_vulnerabilities"`
	Critical            int       `json:"critical"`
	High                int       `json:"high"`
	Medium              int       `json:"medium"`
	Low                 int       `json:"low"`
	Info                int       `json:"info"`
	FilesScanned        int       `json:"files_scanned"`
	LinesScanned        int       `json:"lines_scanned"`
	Duration            int64     `json:"duration_ms"`
}

// ScanRequest represents a request to start a new scan.
type ScanRequest struct {
	RepositoryURL string            `json:"repository_url" binding:"required"`
	Branch        string            `json:"branch"`
	CommitSHA     string            `json:"commit_sha"`
	ScanType      ScanType          `json:"scan_type"`
	Options       map[string]string `json:"options"`
}

// ScanResponse represents the response for a scan request.
type ScanResponse struct {
	ScanID  uuid.UUID  `json:"scan_id"`
	Status  ScanStatus `json:"status"`
	Message string     `json:"message"`
}

// ScanListFilter represents filters for listing scans.
type ScanListFilter struct {
	RepositoryID *uuid.UUID  `form:"repository_id"`
	Status       *ScanStatus `form:"status"`
	Type         *ScanType   `form:"type"`
	Branch       string      `form:"branch"`
	FromDate     *time.Time  `form:"from_date"`
	ToDate       *time.Time  `form:"to_date"`
	Limit        int         `form:"limit"`
	Offset       int         `form:"offset"`
}

// ScanProgress represents the progress of an ongoing scan.
type ScanProgress struct {
	ScanID         uuid.UUID `json:"scan_id"`
	Status         ScanStatus `json:"status"`
	Phase          string    `json:"phase"` // cloning, parsing, analyzing, reporting
	Progress       float64   `json:"progress"` // 0-100
	FilesProcessed int       `json:"files_processed"`
	TotalFiles     int       `json:"total_files"`
	CurrentFile    string    `json:"current_file,omitempty"`
	Message        string    `json:"message,omitempty"`
}
