// Package agent provides Google ADK integration for intelligent code analysis.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
)

// DependencyAnalysisSystemPrompt is the system prompt for dependency security analysis.
const DependencyAnalysisSystemPrompt = `
You are Bastion's Dependency Security Analyst - an expert in software supply chain security.

Your role is to analyze dependency vulnerability reports and provide:

1. **Risk Prioritization**: Not all vulnerabilities are equally dangerous
   - Consider exploitability
   - Assess actual impact on THIS codebase
   - Account for defense-in-depth mechanisms
   - Identify false positives

2. **Upgrade Strategy**: Smart recommendations
   - Assess breaking change risk
   - Suggest upgrade paths (direct vs transitive)
   - Consider version compatibility
   - Recommend testing approach

3. **Remediation Guidance**: Actionable steps
   - Immediate actions for critical issues
   - Long-term mitigation strategies
   - Alternative packages if needed
   - Temporary workarounds

4. **Business Context**: Practical advice
   - Balance security vs development velocity
   - Consider maintenance burden
   - Account for team capacity
   - Provide realistic timelines

Remember: The goal is ACTIONABLE intelligence, not fear. Help developers
make informed decisions about their dependency security.
`

// Dependency represents a project dependency.
type Dependency struct {
	Name       string            `json:"name"`
	Version    string            `json:"version"`
	Type       string            `json:"type"`   // direct, transitive
	Source     string            `json:"source"` // npm, pypi, maven, etc.
	License    string            `json:"license,omitempty"`
	Homepage   string            `json:"homepage,omitempty"`
	Repository string            `json:"repository,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// VulnerabilityReport represents a vulnerability in a dependency.
type VulnerabilityReport struct {
	CVE             string            `json:"cve"`
	Severity        string            `json:"severity"` // critical, high, medium, low
	Title           string            `json:"title"`
	Description     string            `json:"description"`
	AffectedVersion string            `json:"affected_version"`
	FixedVersion    string            `json:"fixed_version,omitempty"`
	CVSS            float64           `json:"cvss,omitempty"`
	Published       string            `json:"published,omitempty"`
	References      []string          `json:"references,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// ProjectContext provides context about the project being analyzed.
type ProjectContext struct {
	Type                string   `json:"type"` // web_application, library, cli, etc.
	Framework           string   `json:"framework,omitempty"`
	Environment         string   `json:"environment"` // production, staging, development
	HasWAF              bool     `json:"has_waf,omitempty"`
	HasMonitoring       bool     `json:"has_monitoring,omitempty"`
	HasIDS              bool     `json:"has_ids,omitempty"`
	NetworkIsolation    bool     `json:"network_isolation,omitempty"`
	Languages           []string `json:"languages,omitempty"`
	TeamSize            int      `json:"team_size,omitempty"`
	DeploymentFrequency string   `json:"deployment_frequency,omitempty"`
}

// RiskAnalysis contains the prioritized risk assessment.
type RiskAnalysis struct {
	PriorityOrder   []PrioritizedVulnerability `json:"priority_order"`
	FalsePositives  []FalsePositive            `json:"false_positives"`
	LowRiskFindings []LowRiskFinding           `json:"low_risk_findings"`
	Summary         RiskSummary                `json:"summary"`
	Recommendations []string                   `json:"recommendations"`
}

// PrioritizedVulnerability represents a vulnerability with priority assessment.
type PrioritizedVulnerability struct {
	Dependency     Dependency          `json:"dependency"`
	Vulnerability  VulnerabilityReport `json:"vulnerability"`
	ActualRisk     string              `json:"actual_risk"` // CRITICAL, HIGH, MEDIUM, LOW
	Reasoning      string              `json:"reasoning"`
	Priority       int                 `json:"priority"`       // 1 = highest
	Urgency        string              `json:"urgency"`        // immediate, high, medium, low
	Exploitability string              `json:"exploitability"` // easy, moderate, difficult, theoretical
	Impact         string              `json:"impact"`         // severe, moderate, limited, minimal
	Mitigation     string              `json:"mitigation,omitempty"`
}

// FalsePositive represents a vulnerability identified as a false positive.
type FalsePositive struct {
	Vulnerability VulnerabilityReport `json:"vulnerability"`
	Reason        string              `json:"reason"`
	Confidence    float64             `json:"confidence"`
}

// LowRiskFinding represents a vulnerability with low actual risk.
type LowRiskFinding struct {
	Vulnerability VulnerabilityReport `json:"vulnerability"`
	Reason        string              `json:"reason"`
	ActualRisk    string              `json:"actual_risk"`
}

// RiskSummary provides an overall summary of the risk analysis.
type RiskSummary struct {
	TotalVulnerabilities int     `json:"total_vulnerabilities"`
	CriticalCount        int     `json:"critical_count"`
	HighCount            int     `json:"high_count"`
	MediumCount          int     `json:"medium_count"`
	LowCount             int     `json:"low_count"`
	FalsePositiveCount   int     `json:"false_positive_count"`
	OverallRisk          string  `json:"overall_risk"`
	RiskScore            float64 `json:"risk_score"` // 0-100
}

// UpgradeProposal represents a proposed dependency upgrade.
type UpgradeProposal struct {
	Dependency      Dependency `json:"dependency"`
	CurrentVersion  string     `json:"current_version"`
	TargetVersion   string     `json:"target_version"`
	Changelog       string     `json:"changelog,omitempty"`
	BreakingChanges []string   `json:"breaking_changes,omitempty"`
	ProjectUsage    string     `json:"project_usage,omitempty"`
	TestCoverage    float64    `json:"test_coverage,omitempty"`
}

// UpgradeAssessment contains the assessment of an upgrade proposal.
type UpgradeAssessment struct {
	BreakingChangesRisk    string        `json:"breaking_changes_risk"` // low, medium, high
	EffortEstimate         string        `json:"effort_estimate"`
	TestingRecommendations []string      `json:"testing_recommendations"`
	RollbackPlan           string        `json:"rollback_plan"`
	Confidence             float64       `json:"confidence"` // 0-1
	Risks                  []string      `json:"risks,omitempty"`
	Benefits               []string      `json:"benefits,omitempty"`
	Timeline               string        `json:"timeline,omitempty"`
	StepByStep             []UpgradeStep `json:"step_by_step,omitempty"`
}

// UpgradeStep represents a step in the upgrade process.
type UpgradeStep struct {
	Step        int      `json:"step"`
	Description string   `json:"description"`
	Commands    []string `json:"commands,omitempty"`
	Checks      []string `json:"checks,omitempty"`
}

// Alternative represents an alternative package recommendation.
type Alternative struct {
	Package         string   `json:"package"`
	Pros            []string `json:"pros"`
	Cons            []string `json:"cons"`
	MigrationEffort string   `json:"migration_effort"` // low, medium, high
	Confidence      float64  `json:"confidence"`       // 0-1
	Documentation   string   `json:"documentation,omitempty"`
	MigrationGuide  string   `json:"migration_guide,omitempty"`
	Compatibility   string   `json:"compatibility,omitempty"`
}

// SecurityExceptionRequest represents a request for a security exception.
type SecurityExceptionRequest struct {
	Vulnerability         VulnerabilityReport `json:"vulnerability"`
	BusinessJustification string              `json:"business_justification"`
	MitigationMeasures    []string            `json:"mitigation_measures"`
	RequestedBy           string              `json:"requested_by"`
	ExpirationDate        string              `json:"expiration_date,omitempty"`
}

// SecurityExceptionResponse contains the recommendation for a security exception.
type SecurityExceptionResponse struct {
	Recommendation         string   `json:"recommendation"` // approve, reject, conditional
	Conditions             []string `json:"conditions,omitempty"`
	MonitoringRequirements []string `json:"monitoring_requirements,omitempty"`
	ExpirationDate         string   `json:"expiration_date,omitempty"`
	Reasoning              string   `json:"reasoning"`
	RiskLevel              string   `json:"risk_level"`
	AlternativeActions     []string `json:"alternative_actions,omitempty"`
}

// AnalyzeDependencyRisks analyzes dependencies and vulnerabilities to provide prioritized risk assessment.
func AnalyzeDependencyRisks(ctx context.Context, client *ADKClient, deps []Dependency, vulns []VulnerabilityReport, context ProjectContext) (*RiskAnalysis, error) {
	if client == nil {
		return nil, fmt.Errorf("ADK client is not initialized")
	}

	prompt := buildVulnerabilityPrioritizationPrompt(deps, vulns, context)

	response, err := client.GenerateContentWithSystem(ctx, DependencyAnalysisSystemPrompt, prompt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate risk analysis: %w", err)
	}

	var analysis RiskAnalysis
	if err := json.Unmarshal([]byte(response.Text), &analysis); err != nil {
		// If JSON parsing fails, try to extract JSON from markdown
		jsonStr := extractJSONFromMarkdown(response.Text)
		if err := json.Unmarshal([]byte(jsonStr), &analysis); err != nil {
			return nil, fmt.Errorf("failed to parse risk analysis response: %w", err)
		}
	}

	return &analysis, nil
}

// AssessUpgradeImpact assesses the impact of upgrading a dependency.
func AssessUpgradeImpact(ctx context.Context, client *ADKClient, upgrade UpgradeProposal) (*UpgradeAssessment, error) {
	if client == nil {
		return nil, fmt.Errorf("ADK client is not initialized")
	}

	prompt := buildUpgradeImpactPrompt(upgrade)

	response, err := client.GenerateContentWithSystem(ctx, DependencyAnalysisSystemPrompt, prompt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate upgrade assessment: %w", err)
	}

	var assessment UpgradeAssessment
	if err := json.Unmarshal([]byte(response.Text), &assessment); err != nil {
		jsonStr := extractJSONFromMarkdown(response.Text)
		if err := json.Unmarshal([]byte(jsonStr), &assessment); err != nil {
			return nil, fmt.Errorf("failed to parse upgrade assessment: %w", err)
		}
	}

	return &assessment, nil
}

// RecommendAlternatives recommends alternative packages for a problematic dependency.
func RecommendAlternatives(ctx context.Context, client *ADKClient, pkg Dependency, reason string, requirements []string, currentUsage string) ([]Alternative, error) {
	if client == nil {
		return nil, fmt.Errorf("ADK client is not initialized")
	}

	prompt := buildAlternativeRecommendationPrompt(pkg, reason, requirements, currentUsage)

	response, err := client.GenerateContentWithSystem(ctx, DependencyAnalysisSystemPrompt, prompt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate alternatives: %w", err)
	}

	var result struct {
		Recommendations []Alternative `json:"recommendations"`
	}

	if err := json.Unmarshal([]byte(response.Text), &result); err != nil {
		jsonStr := extractJSONFromMarkdown(response.Text)
		if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
			return nil, fmt.Errorf("failed to parse alternatives: %w", err)
		}
	}

	return result.Recommendations, nil
}

// EvaluateSecurityException evaluates a security exception request.
func EvaluateSecurityException(ctx context.Context, client *ADKClient, request SecurityExceptionRequest) (*SecurityExceptionResponse, error) {
	if client == nil {
		return nil, fmt.Errorf("ADK client is not initialized")
	}

	prompt := buildSecurityExceptionPrompt(request)

	response, err := client.GenerateContentWithSystem(ctx, DependencyAnalysisSystemPrompt, prompt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate exception evaluation: %w", err)
	}

	var evaluation SecurityExceptionResponse
	if err := json.Unmarshal([]byte(response.Text), &evaluation); err != nil {
		jsonStr := extractJSONFromMarkdown(response.Text)
		if err := json.Unmarshal([]byte(jsonStr), &evaluation); err != nil {
			return nil, fmt.Errorf("failed to parse exception evaluation: %w", err)
		}
	}

	return &evaluation, nil
}

// buildVulnerabilityPrioritizationPrompt builds the prompt for vulnerability prioritization.
func buildVulnerabilityPrioritizationPrompt(deps []Dependency, vulns []VulnerabilityReport, context ProjectContext) string {
	depsJSON, _ := json.MarshalIndent(deps, "", "  ")
	vulnsJSON, _ := json.MarshalIndent(vulns, "", "  ")
	contextJSON, _ := json.MarshalIndent(context, "", "  ")

	return fmt.Sprintf(`Analyze the following dependencies and vulnerabilities to provide a prioritized risk assessment.

**Dependencies:**
%s

**Vulnerabilities:**
%s

**Project Context:**
%s

Provide your analysis in the following JSON format:
{
  "priority_order": [
    {
      "dependency": {...},
      "vulnerability": {...},
      "actual_risk": "CRITICAL|HIGH|MEDIUM|LOW",
      "reasoning": "Detailed explanation of why this risk level",
      "priority": 1,
      "urgency": "immediate|high|medium|low",
      "exploitability": "easy|moderate|difficult|theoretical",
      "impact": "severe|moderate|limited|minimal",
      "mitigation": "Optional mitigation strategy"
    }
  ],
  "false_positives": [
    {
      "vulnerability": {...},
      "reason": "Why this is a false positive",
      "confidence": 0.95
    }
  ],
  "low_risk_findings": [
    {
      "vulnerability": {...},
      "reason": "Why this has low actual risk",
      "actual_risk": "LOW"
    }
  ],
  "summary": {
    "total_vulnerabilities": 0,
    "critical_count": 0,
    "high_count": 0,
    "medium_count": 0,
    "low_count": 0,
    "false_positive_count": 0,
    "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW",
    "risk_score": 0.0
  },
  "recommendations": ["Actionable recommendation 1", "Actionable recommendation 2"]
}`, string(depsJSON), string(vulnsJSON), string(contextJSON))
}

// buildUpgradeImpactPrompt builds the prompt for upgrade impact assessment.
func buildUpgradeImpactPrompt(upgrade UpgradeProposal) string {
	upgradeJSON, _ := json.MarshalIndent(upgrade, "", "  ")

	return fmt.Sprintf(`Assess the impact of upgrading the following dependency:

%s

Provide your assessment in the following JSON format:
{
  "breaking_changes_risk": "low|medium|high",
  "effort_estimate": "e.g., 30 minutes, 2 hours, 1 day",
  "testing_recommendations": [
    "Test scenario 1",
    "Test scenario 2"
  ],
  "rollback_plan": "Step-by-step rollback procedure",
  "confidence": 0.95,
  "risks": ["Risk 1", "Risk 2"],
  "benefits": ["Benefit 1", "Benefit 2"],
  "timeline": "Recommended timeline for upgrade",
  "step_by_step": [
    {
      "step": 1,
      "description": "Step description",
      "commands": ["command1", "command2"],
      "checks": ["Check 1", "Check 2"]
    }
  ]
}`, string(upgradeJSON))
}

// buildAlternativeRecommendationPrompt builds the prompt for alternative package recommendations.
func buildAlternativeRecommendationPrompt(pkg Dependency, reason string, requirements []string, currentUsage string) string {
	pkgJSON, _ := json.MarshalIndent(pkg, "", "  ")
	reqsJSON, _ := json.MarshalIndent(requirements, "", "  ")

	return fmt.Sprintf(`Recommend alternative packages for the following problematic dependency:

**Problematic Package:**
%s

**Reason for Replacement:**
%s

**Project Requirements:**
%s

**Current Usage:**
%s

Provide your recommendations in the following JSON format:
{
  "recommendations": [
    {
      "package": "package-name",
      "pros": ["Pro 1", "Pro 2"],
      "cons": ["Con 1", "Con 2"],
      "migration_effort": "low|medium|high",
      "confidence": 0.9,
      "documentation": "URL to documentation",
      "migration_guide": "URL to migration guide",
      "compatibility": "Compatibility notes"
    }
  ]
}`, string(pkgJSON), reason, string(reqsJSON), currentUsage)
}

// buildSecurityExceptionPrompt builds the prompt for security exception evaluation.
func buildSecurityExceptionPrompt(request SecurityExceptionRequest) string {
	requestJSON, _ := json.MarshalIndent(request, "", "  ")

	return fmt.Sprintf(`Evaluate the following security exception request:

%s

Provide your evaluation in the following JSON format:
{
  "recommendation": "approve|reject|conditional",
  "conditions": ["Condition 1", "Condition 2"],
  "monitoring_requirements": ["Monitoring requirement 1"],
  "expiration_date": "YYYY-MM-DD",
  "reasoning": "Detailed reasoning for the recommendation",
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "alternative_actions": ["Alternative action 1"]
}`, string(requestJSON))
}

// extractJSONFromMarkdown extracts JSON from markdown code blocks.
func extractJSONFromMarkdown(text string) string {
	// Look for JSON in code blocks
	start := -1
	end := -1

	// Try to find ```json or ``` blocks
	jsonBlockStart := "```json"
	codeBlockStart := "```"
	codeBlockEnd := "```"

	if idx := findString(text, jsonBlockStart); idx != -1 {
		start = idx + len(jsonBlockStart)
		if endIdx := findString(text[start:], codeBlockEnd); endIdx != -1 {
			end = start + endIdx
		}
	} else if idx := findString(text, codeBlockStart); idx != -1 {
		start = idx + len(codeBlockStart)
		if endIdx := findString(text[start:], codeBlockEnd); endIdx != -1 {
			end = start + endIdx
		}
	}

	if start != -1 && end != -1 {
		jsonStr := text[start:end]
		// Clean up whitespace
		jsonStr = trimWhitespace(jsonStr)
		return jsonStr
	}

	// Try to find JSON object directly
	openBrace := findString(text, "{")
	if openBrace != -1 {
		// Find matching closing brace
		depth := 0
		for i := openBrace; i < len(text); i++ {
			if text[i] == '{' {
				depth++
			} else if text[i] == '}' {
				depth--
				if depth == 0 {
					return text[openBrace : i+1]
				}
			}
		}
	}

	return text
}

// Helper functions for string operations
func findString(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func trimWhitespace(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\n' || s[start] == '\r' || s[start] == '\t') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\n' || s[end-1] == '\r' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
