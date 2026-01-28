package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// WebhookService defines the interface for webhook operations.
type WebhookService interface {
	ProcessGitHubWebhook(ctx context.Context, eventType string, payload []byte) error
	ProcessGitLabWebhook(ctx context.Context, eventType string, payload []byte) error
}

// WebhookHandler handles webhook endpoints.
type WebhookHandler struct {
	service WebhookService
	logger  *logrus.Logger
}

// NewWebhookHandler creates a new WebhookHandler.
func NewWebhookHandler(service WebhookService, logger *logrus.Logger) *WebhookHandler {
	return &WebhookHandler{
		service: service,
		logger:  logger,
	}
}

// HandleGitHub handles GitHub webhook events.
func (h *WebhookHandler) HandleGitHub(c *gin.Context) {
	// Get event type
	eventType := c.GetHeader("X-GitHub-Event")
	if eventType == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Missing X-GitHub-Event header",
		})
		return
	}

	// Read payload
	payload, err := io.ReadAll(c.Request.Body)
	if err != nil {
		h.logger.WithError(err).Error("Failed to read webhook payload")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Failed to read payload",
		})
		return
	}

	// Log webhook receipt
	h.logger.WithFields(logrus.Fields{
		"event_type":  eventType,
		"delivery_id": c.GetHeader("X-GitHub-Delivery"),
	}).Info("Received GitHub webhook")

	// Handle ping event
	if eventType == "ping" {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
		return
	}

	// Process webhook
	if err := h.service.ProcessGitHubWebhook(c.Request.Context(), eventType, payload); err != nil {
		h.logger.WithError(err).Error("Failed to process GitHub webhook")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to process webhook",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Webhook processed",
	})
}

// HandleGitLab handles GitLab webhook events.
func (h *WebhookHandler) HandleGitLab(c *gin.Context) {
	// Get event type
	eventType := c.GetHeader("X-Gitlab-Event")
	if eventType == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Missing X-Gitlab-Event header",
		})
		return
	}

	// Read payload
	payload, err := io.ReadAll(c.Request.Body)
	if err != nil {
		h.logger.WithError(err).Error("Failed to read webhook payload")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Failed to read payload",
		})
		return
	}

	// Log webhook receipt
	h.logger.WithFields(logrus.Fields{
		"event_type": eventType,
	}).Info("Received GitLab webhook")

	// Process webhook
	if err := h.service.ProcessGitLabWebhook(c.Request.Context(), eventType, payload); err != nil {
		h.logger.WithError(err).Error("Failed to process GitLab webhook")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to process webhook",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Webhook processed",
	})
}

// GitHubPushPayload represents a GitHub push event payload.
type GitHubPushPayload struct {
	Ref        string `json:"ref"`
	Before     string `json:"before"`
	After      string `json:"after"`
	Repository struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		FullName string `json:"full_name"`
		CloneURL string `json:"clone_url"`
		HTMLURL  string `json:"html_url"`
		Private  bool   `json:"private"`
	} `json:"repository"`
	Pusher struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"pusher"`
	Sender struct {
		Login string `json:"login"`
		ID    int64  `json:"id"`
	} `json:"sender"`
	HeadCommit struct {
		ID      string `json:"id"`
		Message string `json:"message"`
		Author  struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"author"`
	} `json:"head_commit"`
}

// GitHubPullRequestPayload represents a GitHub pull request event payload.
type GitHubPullRequestPayload struct {
	Action      string `json:"action"`
	Number      int    `json:"number"`
	PullRequest struct {
		ID     int64  `json:"id"`
		Number int    `json:"number"`
		State  string `json:"state"`
		Title  string `json:"title"`
		Head   struct {
			Ref string `json:"ref"`
			SHA string `json:"sha"`
		} `json:"head"`
		Base struct {
			Ref string `json:"ref"`
			SHA string `json:"sha"`
		} `json:"base"`
	} `json:"pull_request"`
	Repository struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		FullName string `json:"full_name"`
		CloneURL string `json:"clone_url"`
	} `json:"repository"`
}

// GitLabPushPayload represents a GitLab push event payload.
type GitLabPushPayload struct {
	ObjectKind   string `json:"object_kind"`
	EventName    string `json:"event_name"`
	Before       string `json:"before"`
	After        string `json:"after"`
	Ref          string `json:"ref"`
	CheckoutSHA  string `json:"checkout_sha"`
	UserID       int64  `json:"user_id"`
	UserName     string `json:"user_name"`
	UserEmail    string `json:"user_email"`
	UserUsername string `json:"user_username"`
	Project      struct {
		ID                int64  `json:"id"`
		Name              string `json:"name"`
		PathWithNamespace string `json:"path_with_namespace"`
		GitHTTPURL        string `json:"git_http_url"`
		GitSSHURL         string `json:"git_ssh_url"`
	} `json:"project"`
}

// GitLabMergeRequestPayload represents a GitLab merge request event payload.
type GitLabMergeRequestPayload struct {
	ObjectKind string `json:"object_kind"`
	EventType  string `json:"event_type"`
	User       struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		Username string `json:"username"`
		Email    string `json:"email"`
	} `json:"user"`
	Project struct {
		ID                int64  `json:"id"`
		Name              string `json:"name"`
		PathWithNamespace string `json:"path_with_namespace"`
		GitHTTPURL        string `json:"git_http_url"`
	} `json:"project"`
	ObjectAttributes struct {
		ID           int64  `json:"id"`
		IID          int64  `json:"iid"`
		Title        string `json:"title"`
		State        string `json:"state"`
		Action       string `json:"action"`
		SourceBranch string `json:"source_branch"`
		TargetBranch string `json:"target_branch"`
		LastCommit   struct {
			ID string `json:"id"`
		} `json:"last_commit"`
	} `json:"object_attributes"`
}

// ParseGitHubPushPayload parses a GitHub push payload.
func ParseGitHubPushPayload(payload []byte) (*GitHubPushPayload, error) {
	var p GitHubPushPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ParseGitHubPullRequestPayload parses a GitHub pull request payload.
func ParseGitHubPullRequestPayload(payload []byte) (*GitHubPullRequestPayload, error) {
	var p GitHubPullRequestPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ParseGitLabPushPayload parses a GitLab push payload.
func ParseGitLabPushPayload(payload []byte) (*GitLabPushPayload, error) {
	var p GitLabPushPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ParseGitLabMergeRequestPayload parses a GitLab merge request payload.
func ParseGitLabMergeRequestPayload(payload []byte) (*GitLabMergeRequestPayload, error) {
	var p GitLabMergeRequestPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// WebhookEvent represents a stored webhook event.
type WebhookEvent struct {
	ID           uuid.UUID       `json:"id"`
	RepositoryID *uuid.UUID      `json:"repository_id,omitempty"`
	Provider     string          `json:"provider"`
	EventType    string          `json:"event_type"`
	Payload      json.RawMessage `json:"payload"`
	Processed    bool            `json:"processed"`
}
