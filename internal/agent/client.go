// Package agent provides integration with Google ADK for AI-powered analysis.
package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/genai"

	"code-security-auditor/internal/config"
)

// Client wraps the Google Generative AI client.
type Client struct {
	client *genai.Client
	model  *genai.GenerativeModel
	config config.AgentConfig
	logger *logrus.Logger
}

// NewClient creates a new Agent Client.
func NewClient(cfg config.AgentConfig, logger *logrus.Logger) (*Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create the client
	client, err := genai.NewClient(ctx, &genai.ClientConfig{
		APIKey: cfg.APIKey,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create genai client: %w", err)
	}

	// Configure the model
	model := client.GenerativeModel(cfg.Model)
	model.SetMaxOutputTokens(int32(cfg.MaxTokens))
	model.SetTemperature(cfg.Temperature)

	// Set safety settings
	model.SafetySettings = []*genai.SafetySetting{
		{
			Category:  genai.HarmCategoryHarassment,
			Threshold: genai.HarmBlockThresholdBlockOnlyHigh,
		},
		{
			Category:  genai.HarmCategoryHateSpeech,
			Threshold: genai.HarmBlockThresholdBlockOnlyHigh,
		},
	}

	logger.WithFields(logrus.Fields{
		"model":      cfg.Model,
		"max_tokens": cfg.MaxTokens,
	}).Info("Initialized Google GenAI client")

	return &Client{
		client: client,
		model:  model,
		config: cfg,
		logger: logger,
	}, nil
}

// Close closes the client connection.
func (c *Client) Close() error {
	// Client cleanup if needed
	return nil
}

// GenerateContent generates content using the AI model.
func (c *Client) GenerateContent(ctx context.Context, prompt string) (*Response, error) {
	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	c.logger.WithField("prompt_length", len(prompt)).Debug("Generating content")

	resp, err := c.model.GenerateContent(ctx, genai.Text(prompt))
	if err != nil {
		return nil, fmt.Errorf("failed to generate content: %w", err)
	}

	if len(resp.Candidates) == 0 {
		return nil, fmt.Errorf("no response candidates returned")
	}

	candidate := resp.Candidates[0]
	if candidate.Content == nil || len(candidate.Content.Parts) == 0 {
		return nil, fmt.Errorf("empty response content")
	}

	// Extract text from parts
	var text string
	for _, part := range candidate.Content.Parts {
		if textPart, ok := part.(genai.Text); ok {
			text += string(textPart)
		}
	}

	return &Response{
		Text:         text,
		FinishReason: string(candidate.FinishReason),
		TokenCount:   int(resp.UsageMetadata.TotalTokenCount),
	}, nil
}

// Response represents an AI response.
type Response struct {
	Text         string `json:"text"`
	FinishReason string `json:"finish_reason"`
	TokenCount   int    `json:"token_count"`
}

// Chat represents a multi-turn conversation.
type Chat struct {
	client  *Client
	session *genai.ChatSession
}

// StartChat starts a new chat session.
func (c *Client) StartChat(systemPrompt string) *Chat {
	session := c.model.StartChat()

	// Send system prompt as first message to establish context
	if systemPrompt != "" {
		session.History = append(session.History, &genai.Content{
			Role: "user",
			Parts: []genai.Part{
				genai.Text("System: " + systemPrompt),
			},
		})
		session.History = append(session.History, &genai.Content{
			Role: "model",
			Parts: []genai.Part{
				genai.Text("I understand. I will follow the system instructions."),
			},
		})
	}

	return &Chat{
		client:  c,
		session: session,
	}
}

// Send sends a message in the chat session.
func (chat *Chat) Send(ctx context.Context, message string) (*Response, error) {
	ctx, cancel := context.WithTimeout(ctx, chat.client.config.Timeout)
	defer cancel()

	resp, err := chat.session.SendMessage(ctx, genai.Text(message))
	if err != nil {
		return nil, fmt.Errorf("failed to send message: %w", err)
	}

	if len(resp.Candidates) == 0 {
		return nil, fmt.Errorf("no response candidates")
	}

	candidate := resp.Candidates[0]
	if candidate.Content == nil || len(candidate.Content.Parts) == 0 {
		return nil, fmt.Errorf("empty response")
	}

	var text string
	for _, part := range candidate.Content.Parts {
		if textPart, ok := part.(genai.Text); ok {
			text += string(textPart)
		}
	}

	return &Response{
		Text:         text,
		FinishReason: string(candidate.FinishReason),
		TokenCount:   int(resp.UsageMetadata.TotalTokenCount),
	}, nil
}

// GetHistory returns the chat history.
func (chat *Chat) GetHistory() []*genai.Content {
	return chat.session.History
}

// AnalyzeVulnerability analyzes a vulnerability using AI.
func (c *Client) AnalyzeVulnerability(ctx context.Context, req VulnerabilityAnalysisRequest) (*VulnerabilityAnalysis, error) {
	prompt := BuildVulnerabilityAnalysisPrompt(req)

	resp, err := c.GenerateContent(ctx, prompt)
	if err != nil {
		return nil, err
	}

	return ParseVulnerabilityAnalysis(resp.Text)
}

// GenerateSecuritySummary generates a security summary for a scan.
func (c *Client) GenerateSecuritySummary(ctx context.Context, req SummaryRequest) (*SecuritySummary, error) {
	prompt := BuildSummaryPrompt(req)

	resp, err := c.GenerateContent(ctx, prompt)
	if err != nil {
		return nil, err
	}

	return ParseSecuritySummary(resp.Text)
}

// SuggestRemediation suggests remediation for vulnerabilities.
func (c *Client) SuggestRemediation(ctx context.Context, req RemediationRequest) (*RemediationSuggestion, error) {
	prompt := BuildRemediationPrompt(req)

	resp, err := c.GenerateContent(ctx, prompt)
	if err != nil {
		return nil, err
	}

	return ParseRemediationSuggestion(resp.Text)
}

// ReviewCode performs an AI code review.
func (c *Client) ReviewCode(ctx context.Context, req CodeReviewRequest) (*CodeReview, error) {
	prompt := BuildCodeReviewPrompt(req)

	resp, err := c.GenerateContent(ctx, prompt)
	if err != nil {
		return nil, err
	}

	return ParseCodeReview(resp.Text)
}

// Health checks the AI service health.
func (c *Client) Health(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Simple health check prompt
	_, err := c.GenerateContent(ctx, "Return 'OK' if you are working correctly.")
	return err
}
