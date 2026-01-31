// Package agent provides integration with Google ADK for AI-powered analysis.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/genai"

	"code-security-auditor/internal/config"
	"code-security-auditor/internal/models"
)

// Client wraps the Google Generative AI client.
type Client struct {
	client    *genai.Client
	modelName string
	config    config.ADKConfig
	logger    *logrus.Logger
}

// ADKClient provides comprehensive AI-powered security analysis.
// It wraps the base Client with enhanced functionality for vulnerability
// analysis, fix generation, prioritization, and reporting.
type ADKClient struct {
	*Client
	projectID   string
	location    string
	credentials string
	tools       *ToolRegistry
}

// RepositoryInfo holds metadata about the repository being scanned.
type RepositoryInfo struct {
	Name      string            `json:"name"`
	Owner     string            `json:"owner"`
	URL       string            `json:"url"`
	Language  string            `json:"language"`
	Framework string            `json:"framework,omitempty"`
	HasORM    bool              `json:"has_orm"`
	Database  string            `json:"database,omitempty"`
	Branch    string            `json:"branch"`
	CommitSHA string            `json:"commit_sha"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// Rule represents a custom security rule.
type Rule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	Pattern     string   `json:"pattern,omitempty"`
	Languages   []string `json:"languages,omitempty"`
}

// AnalysisInput holds all data needed for comprehensive vulnerability analysis.
type AnalysisInput struct {
	Findings      []models.Finding     `json:"findings"`
	CodeContext   map[string]string    `json:"code_context"` // filepath -> code
	RepoMetadata  *RepositoryInfo      `json:"repo_metadata"`
	PreviousScans []models.ScanSummary `json:"previous_scans"`
	CustomRules   []Rule               `json:"custom_rules"`
}

// ValidatedFinding represents a finding that has been validated by AI.
type ValidatedFinding struct {
	models.Finding
	IsValid            bool    `json:"is_valid_vulnerability"`
	Confidence         float64 `json:"confidence"`
	ActualSeverity     string  `json:"actual_severity"`
	Reasoning          string  `json:"reasoning"`
	Exploitability     string  `json:"exploitability"`
	AttackVector       string  `json:"attack_vector"`
	CWEMapping         string  `json:"cwe_mapping"`
	CVSSScore          float64 `json:"cvss_score"`
	MitigationPriority int     `json:"mitigation_priority"`
}

// RiskAssessment provides overall risk evaluation.
type RiskAssessment struct {
	OverallRisk      string  `json:"overall_risk"` // Critical, High, Medium, Low
	Exploitability   string  `json:"exploitability"`
	Impact           string  `json:"impact"`
	AttackSurface    string  `json:"attack_surface"`
	Summary          string  `json:"summary"`
	Score            float64 `json:"score"` // 0-10
	ComplianceImpact string  `json:"compliance_impact,omitempty"`
}

// AgentResponse contains the full AI analysis response.
type AgentResponse struct {
	ValidatedFindings []ValidatedFinding `json:"validated_findings"`
	FalsePositives    []string           `json:"false_positives"`
	PriorityOrder     []string           `json:"priority_order"`
	RiskAssessment    *RiskAssessment    `json:"risk_assessment"`
	Recommendations   []string           `json:"recommendations"`
	ProcessedAt       time.Time          `json:"processed_at"`
}

// FixSuggestion contains AI-generated code fix.
type FixSuggestion struct {
	OriginalCode   string   `json:"original_code"`
	FixedCode      string   `json:"code"`
	Explanation    string   `json:"explanation"`
	BestPractices  []string `json:"best_practices"`
	References     []string `json:"references"`
	Confidence     float64  `json:"confidence"`
	BreakingChange bool     `json:"breaking_change"`
}

// Report represents a comprehensive security report.
type Report struct {
	ID               string                 `json:"id"`
	Title            string                 `json:"title"`
	ExecutiveSummary string                 `json:"executive_summary"`
	RiskAssessment   *RiskAssessment        `json:"risk_assessment"`
	Findings         []ValidatedFinding     `json:"findings"`
	Recommendations  []ReportRecommendation `json:"recommendations"`
	ComplianceNotes  []string               `json:"compliance_notes"`
	Metrics          *ReportMetrics         `json:"metrics"`
	GeneratedAt      time.Time              `json:"generated_at"`
}

// ReportRecommendation is a prioritized recommendation in a report.
type ReportRecommendation struct {
	Priority    int    `json:"priority"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Effort      string `json:"effort"` // Low, Medium, High
	Impact      string `json:"impact"` // Low, Medium, High
}

// ReportMetrics contains scan metrics for reporting.
type ReportMetrics struct {
	TotalFindings     int            `json:"total_findings"`
	BySeverity        map[string]int `json:"by_severity"`
	ByCategory        map[string]int `json:"by_category"`
	FalsePositiveRate float64        `json:"false_positive_rate"`
	FilesScanned      int            `json:"files_scanned"`
	LinesScanned      int            `json:"lines_scanned"`
	ScanDuration      time.Duration  `json:"scan_duration"`
}

// ScanResult holds complete scan results for report generation.
type ScanResult struct {
	Scan            *models.Scan           `json:"scan"`
	Vulnerabilities []models.Vulnerability `json:"vulnerabilities"`
	Repository      *RepositoryInfo        `json:"repository"`
	Summary         *models.ScanSummary    `json:"summary"`
}

// Response represents an AI response.
type Response struct {
	Text         string `json:"text"`
	FinishReason string `json:"finish_reason"`
	TokenCount   int    `json:"token_count"`
}

// NewClient creates a new Agent Client.
func NewClient(cfg config.ADKConfig, logger *logrus.Logger) (*Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create the client
	client, err := genai.NewClient(ctx, &genai.ClientConfig{
		APIKey: cfg.APIKey,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create genai client: %w", err)
	}

	logger.WithFields(logrus.Fields{
		"model":      cfg.Model,
		"max_tokens": cfg.MaxTokens,
	}).Info("Initialized Google GenAI client")

	return &Client{
		client:    client,
		modelName: cfg.Model,
		config:    cfg,
		logger:    logger,
	}, nil
}

// NewADKClient creates a new ADK client with enhanced capabilities.
func NewADKClient(cfg *config.Config, logger *logrus.Logger) (*ADKClient, error) {
	// Create base client
	baseClient, err := NewClient(cfg.ADK, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create base client: %w", err)
	}

	// Initialize tool registry
	toolRegistry := NewToolRegistry()
	RegisterDefaultTools(toolRegistry)

	logger.WithFields(logrus.Fields{
		"project_id": cfg.ADK.ProjectID,
		"location":   cfg.ADK.Location,
		"model":      cfg.ADK.Model,
	}).Info("Initialized ADK client with enhanced capabilities")

	return &ADKClient{
		Client:      baseClient,
		projectID:   cfg.ADK.ProjectID,
		location:    cfg.ADK.Location,
		credentials: cfg.ADK.APIKey,
		tools:       toolRegistry,
	}, nil
}

// Close closes the client connection.
func (c *Client) Close() error {
	// Client cleanup if needed
	return nil
}

// getGenerateConfig returns a GenerateContentConfig with the configured settings.
func (c *Client) getGenerateConfig(systemPrompt string) *genai.GenerateContentConfig {
	temperature := c.config.Temperature
	maxTokens := int64(c.config.MaxTokens)

	cfg := &genai.GenerateContentConfig{
		Temperature:     &temperature,
		MaxOutputTokens: &maxTokens,
		SafetySettings: []*genai.SafetySetting{
			{
				Category:  genai.HarmCategoryHarassment,
				Threshold: genai.HarmBlockThresholdBlockOnlyHigh,
			},
			{
				Category:  genai.HarmCategoryHateSpeech,
				Threshold: genai.HarmBlockThresholdBlockOnlyHigh,
			},
		},
	}

	// Add system instruction if provided
	if systemPrompt != "" {
		cfg.SystemInstruction = &genai.Content{
			Parts: []*genai.Part{
				{Text: systemPrompt},
			},
		}
	}

	return cfg
}

// GenerateContent generates content using the AI model.
func (c *Client) GenerateContent(ctx context.Context, prompt string) (*Response, error) {
	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	c.logger.WithField("prompt_length", len(prompt)).Debug("Generating content")

	// Create content from text
	contents := genai.Text(prompt)

	// Generate content
	resp, err := c.client.Models.GenerateContent(ctx, c.modelName, contents, c.getGenerateConfig(""))
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
		if part.Text != "" {
			text += part.Text
		}
	}

	tokenCount := 0
	if resp.UsageMetadata != nil {
		tokenCount = int(resp.UsageMetadata.TotalTokenCount)
	}

	return &Response{
		Text:         text,
		FinishReason: string(candidate.FinishReason),
		TokenCount:   tokenCount,
	}, nil
}

// GenerateContentWithSystem generates content with a system prompt.
func (c *Client) GenerateContentWithSystem(ctx context.Context, systemPrompt, userPrompt string) (*Response, error) {
	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	c.logger.WithFields(logrus.Fields{
		"prompt_length": len(userPrompt),
		"has_system":    systemPrompt != "",
	}).Debug("Generating content with system prompt")

	// Create content from text
	contents := genai.Text(userPrompt)

	// Generate content with system instruction
	resp, err := c.client.Models.GenerateContent(ctx, c.modelName, contents, c.getGenerateConfig(systemPrompt))
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
		if part.Text != "" {
			text += part.Text
		}
	}

	tokenCount := 0
	if resp.UsageMetadata != nil {
		tokenCount = int(resp.UsageMetadata.TotalTokenCount)
	}

	return &Response{
		Text:         text,
		FinishReason: string(candidate.FinishReason),
		TokenCount:   tokenCount,
	}, nil
}

// AnalyzeVulnerability analyzes a vulnerability using AI.
func (c *Client) AnalyzeVulnerability(ctx context.Context, req VulnerabilityAnalysisRequest) (*VulnerabilityAnalysis, error) {
	prompt := BuildVulnerabilityAnalysisPrompt(req)

	resp, err := c.GenerateContentWithSystem(ctx, GetSystemPrompt("security_analyst"), prompt)
	if err != nil {
		return nil, err
	}

	return ParseVulnerabilityAnalysis(resp.Text)
}

// GenerateSecuritySummary generates a security summary for a scan.
func (c *Client) GenerateSecuritySummary(ctx context.Context, req SummaryRequest) (*SecuritySummary, error) {
	prompt := BuildSummaryPrompt(req)

	resp, err := c.GenerateContentWithSystem(ctx, GetSystemPrompt("security_consultant"), prompt)
	if err != nil {
		return nil, err
	}

	return ParseSecuritySummary(resp.Text)
}

// SuggestRemediation suggests remediation for vulnerabilities.
func (c *Client) SuggestRemediation(ctx context.Context, req RemediationRequest) (*RemediationSuggestion, error) {
	prompt := BuildRemediationPrompt(req)

	resp, err := c.GenerateContentWithSystem(ctx, GetSystemPrompt("fix_generator"), prompt)
	if err != nil {
		return nil, err
	}

	return ParseRemediationSuggestion(resp.Text)
}

// ReviewCode performs an AI code review.
func (c *Client) ReviewCode(ctx context.Context, req CodeReviewRequest) (*CodeReview, error) {
	prompt := BuildCodeReviewPrompt(req)

	resp, err := c.GenerateContentWithSystem(ctx, GetSystemPrompt("code_reviewer"), prompt)
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

// ===== ADKClient Enhanced Methods =====

// AnalyzeVulnerabilities sends findings to ADK for intelligent analysis.
// It validates findings, identifies false positives, and provides risk assessment.
func (adk *ADKClient) AnalyzeVulnerabilities(ctx context.Context, input *AnalysisInput) (*AgentResponse, error) {
	adk.logger.WithFields(logrus.Fields{
		"findings_count": len(input.Findings),
		"has_context":    len(input.CodeContext) > 0,
	}).Info("Starting vulnerability analysis with ADK")

	// Build the analysis prompt
	prompt := BuildVulnerabilityValidationPrompt(input)

	// Send analysis request with security expert system prompt
	resp, err := adk.GenerateContentWithSystem(ctx, SecurityExpertSystemPrompt, prompt)
	if err != nil {
		adk.logger.WithError(err).Error("Failed to analyze vulnerabilities")
		return nil, fmt.Errorf("vulnerability analysis failed: %w", err)
	}

	// Parse the response
	agentResponse, err := ParseAgentResponse(resp.Text)
	if err != nil {
		adk.logger.WithError(err).Warn("Failed to parse agent response, attempting fallback")
		// Return partial response with raw text
		return &AgentResponse{
			Recommendations: []string{resp.Text},
			ProcessedAt:     time.Now(),
		}, nil
	}

	agentResponse.ProcessedAt = time.Now()

	adk.logger.WithFields(logrus.Fields{
		"validated_count": len(agentResponse.ValidatedFindings),
		"false_positives": len(agentResponse.FalsePositives),
		"recommendations": len(agentResponse.Recommendations),
	}).Info("Vulnerability analysis completed")

	return agentResponse, nil
}

// GenerateFix requests an AI-generated code fix for a vulnerability.
func (adk *ADKClient) GenerateFix(ctx context.Context, vuln *models.Vulnerability) (*FixSuggestion, error) {
	adk.logger.WithFields(logrus.Fields{
		"rule_id":  vuln.RuleID,
		"severity": vuln.Severity,
		"file":     vuln.FilePath,
	}).Info("Generating fix suggestion")

	// Build fix generation prompt
	prompt := BuildFixGenerationPrompt(vuln)

	// Generate fix
	resp, err := adk.GenerateContentWithSystem(ctx, GetSystemPrompt("fix_generator"), prompt)
	if err != nil {
		adk.logger.WithError(err).Error("Failed to generate fix")
		return nil, fmt.Errorf("fix generation failed: %w", err)
	}

	// Parse the fix suggestion
	fix, err := ParseFixSuggestion(resp.Text)
	if err != nil {
		adk.logger.WithError(err).Warn("Failed to parse fix suggestion")
		return &FixSuggestion{
			OriginalCode:  vuln.CodeSnippet,
			Explanation:   resp.Text,
			BestPractices: []string{},
		}, nil
	}

	fix.OriginalCode = vuln.CodeSnippet

	adk.logger.Info("Fix suggestion generated successfully")
	return fix, nil
}

// PrioritizeFindings ranks findings by actual risk considering context.
func (adk *ADKClient) PrioritizeFindings(ctx context.Context, findings []models.Finding) ([]models.Finding, error) {
	if len(findings) == 0 {
		return findings, nil
	}

	adk.logger.WithField("findings_count", len(findings)).Info("Prioritizing findings")

	// Build prioritization prompt
	prompt := BuildRiskPrioritizationPrompt(findings)

	resp, err := adk.GenerateContentWithSystem(ctx, GetSystemPrompt("vulnerability_validator"), prompt)
	if err != nil {
		adk.logger.WithError(err).Error("Failed to prioritize findings")
		return nil, fmt.Errorf("prioritization failed: %w", err)
	}

	// Parse priority order
	priorityOrder, err := ParsePriorityOrder(resp.Text)
	if err != nil {
		adk.logger.WithError(err).Warn("Failed to parse priority order, returning original order")
		return findings, nil
	}

	// Reorder findings based on priority
	prioritized := reorderFindings(findings, priorityOrder)

	adk.logger.WithField("prioritized_count", len(prioritized)).Info("Findings prioritized successfully")
	return prioritized, nil
}

// GenerateReport creates a comprehensive security report.
func (adk *ADKClient) GenerateReport(ctx context.Context, scan *ScanResult) (*Report, error) {
	adk.logger.WithFields(logrus.Fields{
		"scan_id":    scan.Scan.ID,
		"vuln_count": len(scan.Vulnerabilities),
	}).Info("Generating comprehensive report")

	// Build report generation prompt
	prompt := BuildReportGenerationPrompt(scan)

	// Generate report
	resp, err := adk.GenerateContentWithSystem(ctx, GetSystemPrompt("security_consultant"), prompt)
	if err != nil {
		adk.logger.WithError(err).Error("Failed to generate report")
		return nil, fmt.Errorf("report generation failed: %w", err)
	}

	// Parse report
	report, err := ParseReport(resp.Text)
	if err != nil {
		adk.logger.WithError(err).Warn("Failed to parse report, creating basic report")
		report = &Report{
			Title:            "Security Scan Report",
			ExecutiveSummary: resp.Text,
			GeneratedAt:      time.Now(),
		}
	}

	// Add metrics
	report.Metrics = buildReportMetrics(scan)
	report.GeneratedAt = time.Now()

	adk.logger.Info("Report generated successfully")
	return report, nil
}

// GetTools returns the tool registry for the ADK client.
func (adk *ADKClient) GetTools() *ToolRegistry {
	return adk.tools
}

// ExecuteTool executes a specific tool by name.
func (adk *ADKClient) ExecuteTool(ctx context.Context, toolName string, params map[string]interface{}) (interface{}, error) {
	result, err := adk.tools.Execute(ctx, toolName, params)
	if err != nil {
		adk.logger.WithError(err).WithField("tool", toolName).Error("Tool execution failed")
		return nil, err
	}

	adk.logger.WithField("tool", toolName).Debug("Tool executed successfully")
	return result, nil
}

// ===== Helper Functions =====

// reorderFindings reorders findings based on priority order.
func reorderFindings(findings []models.Finding, priorityOrder []string) []models.Finding {
	if len(priorityOrder) == 0 {
		return findings
	}

	// Create a map for quick lookup
	findingMap := make(map[string]models.Finding)
	for _, f := range findings {
		key := fmt.Sprintf("%s:%s:%d", f.FilePath, f.RuleID, f.Line)
		findingMap[key] = f
	}

	// Reorder based on priority
	result := make([]models.Finding, 0, len(findings))
	seen := make(map[string]bool)

	for _, key := range priorityOrder {
		if f, exists := findingMap[key]; exists && !seen[key] {
			result = append(result, f)
			seen[key] = true
		}
	}

	// Add any remaining findings not in priority order
	for _, f := range findings {
		key := fmt.Sprintf("%s:%s:%d", f.FilePath, f.RuleID, f.Line)
		if !seen[key] {
			result = append(result, f)
		}
	}

	return result
}

// buildReportMetrics creates metrics from scan results.
func buildReportMetrics(scan *ScanResult) *ReportMetrics {
	metrics := &ReportMetrics{
		TotalFindings: len(scan.Vulnerabilities),
		BySeverity:    make(map[string]int),
		ByCategory:    make(map[string]int),
		FilesScanned:  scan.Scan.FilesScanned,
		LinesScanned:  scan.Scan.LinesScanned,
	}

	for _, v := range scan.Vulnerabilities {
		metrics.BySeverity[string(v.Severity)]++
		metrics.ByCategory[string(v.Category)]++
	}

	if scan.Scan.Duration != nil {
		metrics.ScanDuration = time.Duration(*scan.Scan.Duration) * time.Millisecond
	}

	return metrics
}

// ParseAgentResponse parses the AI response into AgentResponse.
func ParseAgentResponse(response string) (*AgentResponse, error) {
	// Try to parse as JSON first
	var agentResp AgentResponse
	if err := json.Unmarshal([]byte(response), &agentResp); err == nil {
		return &agentResp, nil
	}

	// Fall back to text parsing
	agentResp = AgentResponse{
		ValidatedFindings: []ValidatedFinding{},
		FalsePositives:    []string{},
		PriorityOrder:     []string{},
		Recommendations:   parseNumberedList(extractSection(response, "RECOMMENDATIONS:")),
	}

	// Parse risk assessment
	riskSection := extractSection(response, "RISK_ASSESSMENT:")
	if riskSection != "" {
		agentResp.RiskAssessment = &RiskAssessment{
			Summary: riskSection,
		}
	}

	return &agentResp, nil
}

// ParseFixSuggestion parses the AI response into FixSuggestion.
func ParseFixSuggestion(response string) (*FixSuggestion, error) {
	fix := &FixSuggestion{}

	// Try JSON parse first
	if err := json.Unmarshal([]byte(response), fix); err == nil {
		return fix, nil
	}

	// Text parsing fallback
	fix.Explanation = extractSection(response, "EXPLANATION:")
	fix.FixedCode = extractCodeBlock(response, "FIXED_CODE:")
	fix.BestPractices = parseBulletList(extractSection(response, "BEST_PRACTICES:"))

	return fix, nil
}

// ParsePriorityOrder parses priority order from response.
func ParsePriorityOrder(response string) ([]string, error) {
	var order []string

	// Try JSON parse
	if err := json.Unmarshal([]byte(response), &order); err == nil {
		return order, nil
	}

	// Try to find a JSON array in the response
	if start := findJSONArray(response); start != "" {
		if err := json.Unmarshal([]byte(start), &order); err == nil {
			return order, nil
		}
	}

	// Parse numbered list
	order = parseNumberedList(response)
	return order, nil
}

// ParseReport parses the AI response into Report.
func ParseReport(response string) (*Report, error) {
	report := &Report{}

	// Try JSON parse
	if err := json.Unmarshal([]byte(response), report); err == nil {
		return report, nil
	}

	// Text parsing
	report.ExecutiveSummary = extractSection(response, "EXECUTIVE_SUMMARY:")
	report.ComplianceNotes = parseBulletList(extractSection(response, "COMPLIANCE_NOTES:"))

	// Parse recommendations
	recsSection := extractSection(response, "RECOMMENDATIONS:")
	recsList := parseNumberedList(recsSection)
	for i, rec := range recsList {
		report.Recommendations = append(report.Recommendations, ReportRecommendation{
			Priority:    i + 1,
			Description: rec,
		})
	}

	return report, nil
}

// findJSONArray finds and extracts a JSON array from text.
func findJSONArray(text string) string {
	start := -1
	depth := 0

	for i, c := range text {
		if c == '[' {
			if start == -1 {
				start = i
			}
			depth++
		} else if c == ']' {
			depth--
			if depth == 0 && start != -1 {
				return text[start : i+1]
			}
		}
	}

	return ""
}
