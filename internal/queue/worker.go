// Package queue provides job queue functionality using Asynq.
package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"

	"github.com/code-security-auditor/internal/config"
)

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
			QueueCritical: 6,
			QueueDefault:  3,
			QueueLow:      1,
		},
		RetryDelayFunc: func(n int, e error, t *asynq.Task) time.Duration {
			return cfg.RetryDelay * time.Duration(n)
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

// ListPendingTasks lists pending tasks in a queue.
func (i *Inspector) ListPendingTasks(queueName string, opts ...asynq.ListOption) ([]*asynq.TaskInfo, error) {
	return i.inspector.ListPendingTasks(queueName, opts...)
}

// ListActiveTasks lists active tasks in a queue.
func (i *Inspector) ListActiveTasks(queueName string, opts ...asynq.ListOption) ([]*asynq.TaskInfo, error) {
	return i.inspector.ListActiveTasks(queueName, opts...)
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
