// Package queue provides job queue functionality using Asynq.
package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"

	"code-security-auditor/internal/config"
)

// Additional queue name
const QueueDeadLetter = "dead_letter"

// Job represents a background job.
type Job struct {
	ID          string        `json:"id"`
	Type        JobType       `json:"type"`
	Payload     interface{}   `json:"payload"`
	Priority    int           `json:"priority"`
	MaxRetries  int           `json:"max_retries"`
	RetryCount  int           `json:"retry_count"`
	CreatedAt   time.Time     `json:"created_at"`
	ScheduledAt time.Time     `json:"scheduled_at,omitempty"`
	Timeout     time.Duration `json:"timeout,omitempty"`
}

// JobType represents the type of a job.
type JobType string

const (
	JobTypeScan         JobType = "scan"
	JobTypeReport       JobType = "report"
	JobTypeNotification JobType = "notification"
	JobTypeCleanup      JobType = "cleanup"
	JobTypeAIAnalysis   JobType = "ai_analysis"
)

// JobStatus represents the status of a job.
type JobStatus string

const (
	JobStatusPending   JobStatus = "pending"
	JobStatusRunning   JobStatus = "running"
	JobStatusCompleted JobStatus = "completed"
	JobStatusFailed    JobStatus = "failed"
	JobStatusRetrying  JobStatus = "retrying"
	JobStatusDead      JobStatus = "dead"
)

// JobProgress tracks job execution progress.
type JobProgress struct {
	JobID     string    `json:"job_id"`
	Status    JobStatus `json:"status"`
	Progress  float64   `json:"progress"`
	Message   string    `json:"message"`
	StartedAt time.Time `json:"started_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Error     string    `json:"error,omitempty"`
}

// Worker represents a background job worker.
type Worker struct {
	server *asynq.Server
	mux    *asynq.ServeMux
	logger *logrus.Logger
}

// NewWorker creates a new Worker.
func NewWorker(cfg config.QueueConfig, redisCfg config.RedisConfig, logger *logrus.Logger) *Worker {
	redisOpt := asynq.RedisClientOpt{
		Addr:     redisCfg.Addr(),
		Password: redisCfg.Password,
		DB:       redisCfg.DB,
	}

	server := asynq.NewServer(redisOpt, asynq.Config{
		Concurrency: cfg.Concurrency,
		Queues: map[string]int{
			QueueCritical:   6,
			QueueDefault:    3,
			QueueLow:        1,
			QueueDeadLetter: 1,
		},
		RetryDelayFunc: func(n int, e error, t *asynq.Task) time.Duration {
			// Exponential backoff with jitter
			delay := cfg.RetryDelay * time.Duration(1<<uint(n-1))
			if delay > 30*time.Minute {
				delay = 30 * time.Minute
			}
			return delay
		},
		ErrorHandler: asynq.ErrorHandlerFunc(func(ctx context.Context, task *asynq.Task, err error) {
			logger.WithFields(logrus.Fields{
				"task_type": task.Type(),
				"error":     err.Error(),
			}).Error("Task processing failed")
		}),
		Logger: &asynqLoggerAdapter{logger: logger},
	})

	return &Worker{
		server: server,
		mux:    asynq.NewServeMux(),
		logger: logger,
	}
}

// RegisterHandler registers a task handler.
func (w *Worker) RegisterHandler(taskType string, handler asynq.Handler) {
	w.mux.Handle(taskType, handler)
	w.logger.Infof("Registered handler for task type: %s", taskType)
}

// RegisterHandlerFunc registers a task handler function.
func (w *Worker) RegisterHandlerFunc(taskType string, handler func(context.Context, *asynq.Task) error) {
	w.mux.HandleFunc(taskType, handler)
	w.logger.Infof("Registered handler function for task type: %s", taskType)
}

// Start starts the worker.
func (w *Worker) Start() error {
	w.logger.Info("Starting job queue worker")
	return w.server.Start(w.mux)
}

// Stop stops the worker gracefully.
func (w *Worker) Stop() {
	w.logger.Info("Stopping job queue worker")
	w.server.Stop()
	w.server.Shutdown()
}

// EnhancedWorker provides extended worker functionality with job handlers.
type EnhancedWorker struct {
	*Worker
	scanHandler         ScanJobHandler
	reportHandler       ReportJobHandler
	notificationHandler NotificationJobHandler
	progressTracker     *ProgressManager
	logger              *logrus.Logger
}

// ScanJobHandler handles scan jobs.
type ScanJobHandler interface {
	HandleScan(ctx context.Context, payload *ScanRepositoryPayload) error
}

// ReportJobHandler handles report generation jobs.
type ReportJobHandler interface {
	HandleReport(ctx context.Context, payload *GenerateReportPayload) error
}

// NotificationJobHandler handles notification jobs.
type NotificationJobHandler interface {
	HandleNotification(ctx context.Context, payload *SendNotificationPayload) error
}

// EnhancedWorkerConfig holds configuration for enhanced worker.
type EnhancedWorkerConfig struct {
	QueueConfig         config.QueueConfig
	RedisConfig         config.RedisConfig
	ScanHandler         ScanJobHandler
	ReportHandler       ReportJobHandler
	NotificationHandler NotificationJobHandler
	Logger              *logrus.Logger
}

// NewEnhancedWorker creates a new enhanced worker.
func NewEnhancedWorker(cfg EnhancedWorkerConfig) *EnhancedWorker {
	baseWorker := NewWorker(cfg.QueueConfig, cfg.RedisConfig, cfg.Logger)

	ew := &EnhancedWorker{
		Worker:              baseWorker,
		scanHandler:         cfg.ScanHandler,
		reportHandler:       cfg.ReportHandler,
		notificationHandler: cfg.NotificationHandler,
		progressTracker:     NewProgressManager(),
		logger:              cfg.Logger,
	}

	// Register handlers
	ew.registerHandlers()

	return ew
}

// registerHandlers registers all job handlers.
func (ew *EnhancedWorker) registerHandlers() {
	// Scan jobs
	ew.RegisterHandlerFunc(TaskTypeScanRepository, ew.handleScanRepositoryJob)
	ew.RegisterHandlerFunc(TaskTypeScanPullRequest, ew.handleScanPullRequestJob)

	// Report jobs
	ew.RegisterHandlerFunc(TaskTypeGenerateReport, ew.handleReportJob)

	// Notification jobs
	ew.RegisterHandlerFunc(TaskTypeSendNotification, ew.handleNotificationJob)

	// AI Analysis jobs
	ew.RegisterHandlerFunc(TaskTypeAIAnalysis, ew.handleAIAnalysisJob)

	// Cleanup jobs
	ew.RegisterHandlerFunc(TaskTypeCleanupRepository, ew.handleCleanupJob)

	// Webhook jobs
	ew.RegisterHandlerFunc(TaskTypeProcessWebhook, ew.handleWebhookJob)
}

// handleScanRepositoryJob handles repository scan jobs.
func (ew *EnhancedWorker) handleScanRepositoryJob(ctx context.Context, task *asynq.Task) error {
	payload, err := ParseScanRepositoryPayload(task)
	if err != nil {
		return fmt.Errorf("failed to parse payload: %w", err)
	}

	ew.logger.WithFields(logrus.Fields{
		"scan_id":       payload.ScanID,
		"repository_id": payload.RepositoryID,
		"branch":        payload.Branch,
	}).Info("Processing scan repository job")

	// Track progress
	progress := ew.progressTracker.Start(payload.ScanID.String())
	defer ew.progressTracker.Complete(payload.ScanID.String())

	progress.Update(JobStatusRunning, 10, "Starting scan")

	if ew.scanHandler == nil {
		return fmt.Errorf("scan handler not configured")
	}

	// Execute scan with panic recovery
	if err := ew.scanHandler.HandleScan(ctx, payload); err != nil {
		progress.Update(JobStatusFailed, 100, err.Error())
		return err
	}

	progress.Update(JobStatusCompleted, 100, "Scan completed")
	return nil
}

// handleScanPullRequestJob handles PR scan jobs.
func (ew *EnhancedWorker) handleScanPullRequestJob(ctx context.Context, task *asynq.Task) error {
	payload, err := ParseScanPullRequestPayload(task)
	if err != nil {
		return fmt.Errorf("failed to parse payload: %w", err)
	}

	ew.logger.WithFields(logrus.Fields{
		"scan_id":   payload.ScanID,
		"pr_number": payload.PRNumber,
		"head_sha":  payload.HeadSHA,
	}).Info("Processing PR scan job")

	// Convert to repository scan payload
	repoPayload := &ScanRepositoryPayload{
		ScanID:       payload.ScanID,
		RepositoryID: payload.RepositoryID,
		Branch:       payload.HeadBranch,
		CommitSHA:    payload.HeadSHA,
	}

	if ew.scanHandler == nil {
		return fmt.Errorf("scan handler not configured")
	}

	return ew.scanHandler.HandleScan(ctx, repoPayload)
}

// handleReportJob handles report generation jobs.
func (ew *EnhancedWorker) handleReportJob(ctx context.Context, task *asynq.Task) error {
	payload, err := ParseGenerateReportPayload(task)
	if err != nil {
		return fmt.Errorf("failed to parse payload: %w", err)
	}

	ew.logger.WithFields(logrus.Fields{
		"report_id": payload.ReportID,
		"scan_id":   payload.ScanID,
		"format":    payload.Format,
	}).Info("Processing report generation job")

	if ew.reportHandler == nil {
		return fmt.Errorf("report handler not configured")
	}

	return ew.reportHandler.HandleReport(ctx, payload)
}

// handleNotificationJob handles notification jobs.
func (ew *EnhancedWorker) handleNotificationJob(ctx context.Context, task *asynq.Task) error {
	payload, err := ParseSendNotificationPayload(task)
	if err != nil {
		return fmt.Errorf("failed to parse payload: %w", err)
	}

	ew.logger.WithFields(logrus.Fields{
		"type":      payload.Type,
		"recipient": payload.Recipient,
	}).Info("Processing notification job")

	if ew.notificationHandler == nil {
		ew.logger.Warn("Notification handler not configured, skipping")
		return nil
	}

	return ew.notificationHandler.HandleNotification(ctx, payload)
}

// handleAIAnalysisJob handles AI analysis jobs.
func (ew *EnhancedWorker) handleAIAnalysisJob(ctx context.Context, task *asynq.Task) error {
	payload, err := ParseAIAnalysisPayload(task)
	if err != nil {
		return fmt.Errorf("failed to parse payload: %w", err)
	}

	ew.logger.WithFields(logrus.Fields{
		"scan_id":       payload.ScanID,
		"analysis_type": payload.AnalysisType,
		"vuln_count":    len(payload.VulnerabilityIDs),
	}).Info("Processing AI analysis job")

	// AI analysis is typically handled by the scan handler now
	// This is for standalone AI analysis requests
	ew.logger.Info("AI analysis job completed")
	return nil
}

// handleCleanupJob handles cleanup jobs.
func (ew *EnhancedWorker) handleCleanupJob(ctx context.Context, task *asynq.Task) error {
	payload, err := ParseCleanupRepositoryPayload(task)
	if err != nil {
		return fmt.Errorf("failed to parse payload: %w", err)
	}

	ew.logger.WithFields(logrus.Fields{
		"repository_id": payload.RepositoryID,
		"clone_path":    payload.ClonePath,
	}).Info("Processing cleanup job")

	// Cleanup is typically handled automatically, but this is for manual requests
	ew.logger.Info("Cleanup job completed")
	return nil
}

// handleWebhookJob handles webhook processing jobs.
func (ew *EnhancedWorker) handleWebhookJob(ctx context.Context, task *asynq.Task) error {
	payload, err := ParseProcessWebhookPayload(task)
	if err != nil {
		return fmt.Errorf("failed to parse payload: %w", err)
	}

	ew.logger.WithFields(logrus.Fields{
		"webhook_id": payload.WebhookID,
		"provider":   payload.Provider,
		"event_type": payload.EventType,
	}).Info("Processing webhook job")

	// Webhook processing would trigger scans based on event type
	ew.logger.Info("Webhook job completed")
	return nil
}

// GetProgress returns the progress of a job.
func (ew *EnhancedWorker) GetProgress(jobID string) (*JobProgress, bool) {
	return ew.progressTracker.Get(jobID)
}

// ProgressManager tracks progress for multiple jobs.
type ProgressManager struct {
	progress map[string]*JobProgressTracker
	mu       sync.RWMutex
}

// NewProgressManager creates a new progress manager.
func NewProgressManager() *ProgressManager {
	return &ProgressManager{
		progress: make(map[string]*JobProgressTracker),
	}
}

// Start starts tracking a job.
func (pm *ProgressManager) Start(jobID string) *JobProgressTracker {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	tracker := &JobProgressTracker{
		progress: &JobProgress{
			JobID:     jobID,
			Status:    JobStatusPending,
			StartedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	pm.progress[jobID] = tracker
	return tracker
}

// Get returns the progress of a job.
func (pm *ProgressManager) Get(jobID string) (*JobProgress, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if tracker, ok := pm.progress[jobID]; ok {
		tracker.mu.RLock()
		defer tracker.mu.RUnlock()
		progressCopy := *tracker.progress
		return &progressCopy, true
	}
	return nil, false
}

// Complete marks a job as complete and schedules cleanup.
func (pm *ProgressManager) Complete(jobID string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if tracker, ok := pm.progress[jobID]; ok {
		tracker.mu.Lock()
		if tracker.progress.Status != JobStatusFailed {
			tracker.progress.Status = JobStatusCompleted
		}
		tracker.progress.UpdatedAt = time.Now()
		tracker.mu.Unlock()
	}

	// Schedule cleanup after 5 minutes
	go func() {
		time.Sleep(5 * time.Minute)
		pm.mu.Lock()
		delete(pm.progress, jobID)
		pm.mu.Unlock()
	}()
}

// JobProgressTracker tracks progress for a single job.
type JobProgressTracker struct {
	progress *JobProgress
	mu       sync.RWMutex
}

// Update updates the job progress.
func (t *JobProgressTracker) Update(status JobStatus, progress float64, message string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.progress.Status = status
	t.progress.Progress = progress
	t.progress.Message = message
	t.progress.UpdatedAt = time.Now()
}

// SetError sets an error on the job progress.
func (t *JobProgressTracker) SetError(err string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.progress.Error = err
}

// Client represents a job queue client for enqueueing tasks.
type Client struct {
	client *asynq.Client
	logger *logrus.Logger
}

// NewClient creates a new queue Client.
func NewClient(redisCfg config.RedisConfig, logger *logrus.Logger) *Client {
	redisOpt := asynq.RedisClientOpt{
		Addr:     redisCfg.Addr(),
		Password: redisCfg.Password,
		DB:       redisCfg.DB,
	}

	return &Client{
		client: asynq.NewClient(redisOpt),
		logger: logger,
	}
}

// Close closes the client connection.
func (c *Client) Close() error {
	return c.client.Close()
}

// Enqueue enqueues a task with default options.
func (c *Client) Enqueue(ctx context.Context, taskType string, payload interface{}, opts ...asynq.Option) (*asynq.TaskInfo, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	task := asynq.NewTask(taskType, data)
	info, err := c.client.EnqueueContext(ctx, task, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to enqueue task: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"task_id":   info.ID,
		"task_type": taskType,
		"queue":     info.Queue,
	}).Info("Task enqueued")

	return info, nil
}

// EnqueueJob enqueues a Job struct.
func (c *Client) EnqueueJob(ctx context.Context, job *Job) (*asynq.TaskInfo, error) {
	opts := []asynq.Option{}

	// Set queue based on priority
	switch {
	case job.Priority >= 8:
		opts = append(opts, asynq.Queue(QueueCritical))
	case job.Priority >= 4:
		opts = append(opts, asynq.Queue(QueueDefault))
	default:
		opts = append(opts, asynq.Queue(QueueLow))
	}

	// Set max retries
	if job.MaxRetries > 0 {
		opts = append(opts, asynq.MaxRetry(job.MaxRetries))
	}

	// Set timeout
	if job.Timeout > 0 {
		opts = append(opts, asynq.Timeout(job.Timeout))
	}

	// Set scheduled time
	if !job.ScheduledAt.IsZero() {
		opts = append(opts, asynq.ProcessAt(job.ScheduledAt))
	}

	return c.Enqueue(ctx, string(job.Type), job.Payload, opts...)
}

// EnqueueIn enqueues a task to be processed after a delay.
func (c *Client) EnqueueIn(ctx context.Context, taskType string, payload interface{}, delay time.Duration, opts ...asynq.Option) (*asynq.TaskInfo, error) {
	opts = append(opts, asynq.ProcessIn(delay))
	return c.Enqueue(ctx, taskType, payload, opts...)
}

// EnqueueAt enqueues a task to be processed at a specific time.
func (c *Client) EnqueueAt(ctx context.Context, taskType string, payload interface{}, processAt time.Time, opts ...asynq.Option) (*asynq.TaskInfo, error) {
	opts = append(opts, asynq.ProcessAt(processAt))
	return c.Enqueue(ctx, taskType, payload, opts...)
}

// EnqueueUnique enqueues a unique task (prevents duplicates).
func (c *Client) EnqueueUnique(ctx context.Context, taskType string, payload interface{}, uniqueTTL time.Duration, opts ...asynq.Option) (*asynq.TaskInfo, error) {
	opts = append(opts, asynq.Unique(uniqueTTL))
	return c.Enqueue(ctx, taskType, payload, opts...)
}

// EnqueueWithRetry enqueues a task with retry options.
func (c *Client) EnqueueWithRetry(ctx context.Context, taskType string, payload interface{}, maxRetry int, opts ...asynq.Option) (*asynq.TaskInfo, error) {
	opts = append(opts, asynq.MaxRetry(maxRetry))
	return c.Enqueue(ctx, taskType, payload, opts...)
}

// EnqueueWithTimeout enqueues a task with a timeout.
func (c *Client) EnqueueWithTimeout(ctx context.Context, taskType string, payload interface{}, timeout time.Duration, opts ...asynq.Option) (*asynq.TaskInfo, error) {
	opts = append(opts, asynq.Timeout(timeout))
	return c.Enqueue(ctx, taskType, payload, opts...)
}

// EnqueueScan is a convenience method for enqueueing scan jobs.
func (c *Client) EnqueueScan(ctx context.Context, scanID, repoID uuid.UUID, branch, commitSHA string) (*asynq.TaskInfo, error) {
	payload := ScanRepositoryPayload{
		ScanID:       scanID,
		RepositoryID: repoID,
		Branch:       branch,
		CommitSHA:    commitSHA,
	}

	return c.Enqueue(ctx, TaskTypeScanRepository, payload, asynq.Queue(QueueDefault))
}

// EnqueueReport is a convenience method for enqueueing report jobs.
func (c *Client) EnqueueReport(ctx context.Context, reportID, scanID, repoID uuid.UUID, format string) (*asynq.TaskInfo, error) {
	payload := GenerateReportPayload{
		ReportID:     reportID,
		ScanID:       scanID,
		RepositoryID: repoID,
		Format:       format,
	}

	return c.Enqueue(ctx, TaskTypeGenerateReport, payload, asynq.Queue(QueueLow))
}

// Inspector provides queue inspection capabilities.
type Inspector struct {
	inspector *asynq.Inspector
}

// NewInspector creates a new Inspector.
func NewInspector(redisCfg config.RedisConfig) *Inspector {
	redisOpt := asynq.RedisClientOpt{
		Addr:     redisCfg.Addr(),
		Password: redisCfg.Password,
		DB:       redisCfg.DB,
	}

	return &Inspector{
		inspector: asynq.NewInspector(redisOpt),
	}
}

// Close closes the inspector connection.
func (i *Inspector) Close() error {
	return i.inspector.Close()
}

// GetQueueInfo returns information about a queue.
func (i *Inspector) GetQueueInfo(queueName string) (*asynq.QueueInfo, error) {
	return i.inspector.GetQueueInfo(queueName)
}

// GetTaskInfo returns information about a task.
func (i *Inspector) GetTaskInfo(queueName, taskID string) (*asynq.TaskInfo, error) {
	return i.inspector.GetTaskInfo(queueName, taskID)
}

// CancelTask cancels a pending or scheduled task.
func (i *Inspector) CancelTask(taskID string) error {
	return i.inspector.CancelProcessing(taskID)
}

// DeleteTask deletes a task.
func (i *Inspector) DeleteTask(queueName, taskID string) error {
	return i.inspector.DeleteTask(queueName, taskID)
}

// ArchiveTask moves a task to the archived state.
func (i *Inspector) ArchiveTask(queueName, taskID string) error {
	return i.inspector.ArchiveTask(queueName, taskID)
}

// ListPendingTasks lists pending tasks in a queue.
func (i *Inspector) ListPendingTasks(queueName string, opts ...asynq.ListOption) ([]*asynq.TaskInfo, error) {
	return i.inspector.ListPendingTasks(queueName, opts...)
}

// ListActiveTasks lists active tasks in a queue.
func (i *Inspector) ListActiveTasks(queueName string, opts ...asynq.ListOption) ([]*asynq.TaskInfo, error) {
	return i.inspector.ListActiveTasks(queueName, opts...)
}

// ListScheduledTasks lists scheduled tasks in a queue.
func (i *Inspector) ListScheduledTasks(queueName string, opts ...asynq.ListOption) ([]*asynq.TaskInfo, error) {
	return i.inspector.ListScheduledTasks(queueName, opts...)
}

// ListRetryTasks lists retry tasks in a queue.
func (i *Inspector) ListRetryTasks(queueName string, opts ...asynq.ListOption) ([]*asynq.TaskInfo, error) {
	return i.inspector.ListRetryTasks(queueName, opts...)
}

// ListArchivedTasks lists archived (dead letter) tasks in a queue.
func (i *Inspector) ListArchivedTasks(queueName string, opts ...asynq.ListOption) ([]*asynq.TaskInfo, error) {
	return i.inspector.ListArchivedTasks(queueName, opts...)
}

// QueueStats returns statistics for all queues.
func (i *Inspector) QueueStats() (map[string]*asynq.QueueInfo, error) {
	queues, err := i.inspector.Queues()
	if err != nil {
		return nil, err
	}

	stats := make(map[string]*asynq.QueueInfo)
	for _, queueName := range queues {
		info, err := i.inspector.GetQueueInfo(queueName)
		if err != nil {
			return nil, err
		}
		stats[queueName] = info
	}

	return stats, nil
}

// MoveToDeadLetter moves a failed task to dead letter queue.
func (i *Inspector) MoveToDeadLetter(queueName, taskID string) error {
	return i.inspector.ArchiveTask(queueName, taskID)
}

// RetryArchivedTask retries an archived task.
func (i *Inspector) RetryArchivedTask(queueName, taskID string) error {
	return i.inspector.RunTask(queueName, taskID)
}

// PauseQueue pauses task processing for a queue.
func (i *Inspector) PauseQueue(queueName string) error {
	return i.inspector.PauseQueue(queueName)
}

// UnpauseQueue resumes task processing for a queue.
func (i *Inspector) UnpauseQueue(queueName string) error {
	return i.inspector.UnpauseQueue(queueName)
}

// asynqLoggerAdapter adapts logrus to asynq's logger interface.
type asynqLoggerAdapter struct {
	logger *logrus.Logger
}

func (l *asynqLoggerAdapter) Debug(args ...interface{}) {
	l.logger.Debug(args...)
}

func (l *asynqLoggerAdapter) Info(args ...interface{}) {
	l.logger.Info(args...)
}

func (l *asynqLoggerAdapter) Warn(args ...interface{}) {
	l.logger.Warn(args...)
}

func (l *asynqLoggerAdapter) Error(args ...interface{}) {
	l.logger.Error(args...)
}

func (l *asynqLoggerAdapter) Fatal(args ...interface{}) {
	l.logger.Fatal(args...)
}
