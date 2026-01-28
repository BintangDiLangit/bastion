package queue

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
)

// Queue names
const (
	QueueCritical = "critical"
	QueueDefault  = "default"
	QueueLow      = "low"
)

// Task types
const (
	TaskTypeScanRepository     = "scan:repository"
	TaskTypeScanPullRequest    = "scan:pull_request"
	TaskTypeGenerateReport     = "report:generate"
	TaskTypeSendNotification   = "notification:send"
	TaskTypeCleanupRepository  = "cleanup:repository"
	TaskTypeProcessWebhook     = "webhook:process"
	TaskTypeAIAnalysis         = "ai:analysis"
)

// ScanRepositoryPayload represents the payload for repository scan task.
type ScanRepositoryPayload struct {
	ScanID       uuid.UUID         `json:"scan_id"`
	RepositoryID uuid.UUID         `json:"repository_id"`
	Branch       string            `json:"branch"`
	CommitSHA    string            `json:"commit_sha,omitempty"`
	Options      map[string]string `json:"options,omitempty"`
}

// NewScanRepositoryTask creates a new scan repository task.
func NewScanRepositoryTask(payload ScanRepositoryPayload) (*asynq.Task, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(TaskTypeScanRepository, data), nil
}

// ParseScanRepositoryPayload parses the scan repository payload from a task.
func ParseScanRepositoryPayload(task *asynq.Task) (*ScanRepositoryPayload, error) {
	var payload ScanRepositoryPayload
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		return nil, fmt.Errorf("failed to parse payload: %w", err)
	}
	return &payload, nil
}

// ScanPullRequestPayload represents the payload for PR scan task.
type ScanPullRequestPayload struct {
	ScanID       uuid.UUID `json:"scan_id"`
	RepositoryID uuid.UUID `json:"repository_id"`
	PRNumber     int       `json:"pr_number"`
	BaseBranch   string    `json:"base_branch"`
	HeadBranch   string    `json:"head_branch"`
	HeadSHA      string    `json:"head_sha"`
}

// NewScanPullRequestTask creates a new PR scan task.
func NewScanPullRequestTask(payload ScanPullRequestPayload) (*asynq.Task, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(TaskTypeScanPullRequest, data, asynq.Queue(QueueCritical)), nil
}

// ParseScanPullRequestPayload parses the PR scan payload from a task.
func ParseScanPullRequestPayload(task *asynq.Task) (*ScanPullRequestPayload, error) {
	var payload ScanPullRequestPayload
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		return nil, fmt.Errorf("failed to parse payload: %w", err)
	}
	return &payload, nil
}

// GenerateReportPayload represents the payload for report generation task.
type GenerateReportPayload struct {
	ReportID     uuid.UUID `json:"report_id"`
	ScanID       uuid.UUID `json:"scan_id"`
	RepositoryID uuid.UUID `json:"repository_id"`
	Format       string    `json:"format"`
	IncludeAI    bool      `json:"include_ai"`
	SendToGitHub bool      `json:"send_to_github"`
	Email        string    `json:"email,omitempty"`
}

// NewGenerateReportTask creates a new report generation task.
func NewGenerateReportTask(payload GenerateReportPayload) (*asynq.Task, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(TaskTypeGenerateReport, data), nil
}

// ParseGenerateReportPayload parses the report generation payload from a task.
func ParseGenerateReportPayload(task *asynq.Task) (*GenerateReportPayload, error) {
	var payload GenerateReportPayload
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		return nil, fmt.Errorf("failed to parse payload: %w", err)
	}
	return &payload, nil
}

// SendNotificationPayload represents the payload for notification task.
type SendNotificationPayload struct {
	Type       string            `json:"type"` // email, slack, webhook
	Recipient  string            `json:"recipient"`
	Subject    string            `json:"subject"`
	Message    string            `json:"message"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// NewSendNotificationTask creates a new notification task.
func NewSendNotificationTask(payload SendNotificationPayload) (*asynq.Task, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(TaskTypeSendNotification, data, asynq.Queue(QueueLow)), nil
}

// ParseSendNotificationPayload parses the notification payload from a task.
func ParseSendNotificationPayload(task *asynq.Task) (*SendNotificationPayload, error) {
	var payload SendNotificationPayload
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		return nil, fmt.Errorf("failed to parse payload: %w", err)
	}
	return &payload, nil
}

// CleanupRepositoryPayload represents the payload for repository cleanup task.
type CleanupRepositoryPayload struct {
	RepositoryID uuid.UUID `json:"repository_id"`
	ClonePath    string    `json:"clone_path"`
}

// NewCleanupRepositoryTask creates a new cleanup task.
func NewCleanupRepositoryTask(payload CleanupRepositoryPayload) (*asynq.Task, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(TaskTypeCleanupRepository, data, asynq.Queue(QueueLow)), nil
}

// ParseCleanupRepositoryPayload parses the cleanup payload from a task.
func ParseCleanupRepositoryPayload(task *asynq.Task) (*CleanupRepositoryPayload, error) {
	var payload CleanupRepositoryPayload
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		return nil, fmt.Errorf("failed to parse payload: %w", err)
	}
	return &payload, nil
}

// ProcessWebhookPayload represents the payload for webhook processing task.
type ProcessWebhookPayload struct {
	WebhookID    uuid.UUID       `json:"webhook_id"`
	Provider     string          `json:"provider"`
	EventType    string          `json:"event_type"`
	Payload      json.RawMessage `json:"payload"`
	RepositoryID *uuid.UUID      `json:"repository_id,omitempty"`
}

// NewProcessWebhookTask creates a new webhook processing task.
func NewProcessWebhookTask(payload ProcessWebhookPayload) (*asynq.Task, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(TaskTypeProcessWebhook, data, asynq.Queue(QueueCritical)), nil
}

// ParseProcessWebhookPayload parses the webhook payload from a task.
func ParseProcessWebhookPayload(task *asynq.Task) (*ProcessWebhookPayload, error) {
	var payload ProcessWebhookPayload
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		return nil, fmt.Errorf("failed to parse payload: %w", err)
	}
	return &payload, nil
}

// AIAnalysisPayload represents the payload for AI analysis task.
type AIAnalysisPayload struct {
	ScanID           uuid.UUID   `json:"scan_id"`
	VulnerabilityIDs []uuid.UUID `json:"vulnerability_ids"`
	AnalysisType     string      `json:"analysis_type"` // vulnerability, code_review, summary
}

// NewAIAnalysisTask creates a new AI analysis task.
func NewAIAnalysisTask(payload AIAnalysisPayload) (*asynq.Task, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(TaskTypeAIAnalysis, data), nil
}

// ParseAIAnalysisPayload parses the AI analysis payload from a task.
func ParseAIAnalysisPayload(task *asynq.Task) (*AIAnalysisPayload, error) {
	var payload AIAnalysisPayload
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		return nil, fmt.Errorf("failed to parse payload: %w", err)
	}
	return &payload, nil
}

// TaskHandler is an interface for handling tasks.
type TaskHandler interface {
	Handle(ctx context.Context, task *asynq.Task) error
}

// TaskMiddleware is a function that wraps a task handler.
type TaskMiddleware func(TaskHandler) TaskHandler

// WithLogging adds logging to a task handler.
func WithLogging(handler asynq.HandlerFunc) asynq.HandlerFunc {
	return func(ctx context.Context, task *asynq.Task) error {
		// Logging is handled by the worker's error handler
		return handler(ctx, task)
	}
}

// WithRecovery adds panic recovery to a task handler.
func WithRecovery(handler asynq.HandlerFunc) asynq.HandlerFunc {
	return func(ctx context.Context, task *asynq.Task) (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic recovered: %v", r)
			}
		}()
		return handler(ctx, task)
	}
}
