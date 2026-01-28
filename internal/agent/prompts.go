package agent

import (
	"fmt"
	"strings"
)

// VulnerabilityAnalysisRequest holds data for vulnerability analysis.
type VulnerabilityAnalysisRequest struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	FilePath    string   `json:"file_path"`
	CodeSnippet string   `json:"code_snippet"`
	Language    string   `json:"language"`
	Context     string   `json:"context,omitempty"`
}

// BuildVulnerabilityAnalysisPrompt builds the prompt for vulnerability analysis.
func BuildVulnerabilityAnalysisPrompt(req VulnerabilityAnalysisRequest) string {
	return fmt.Sprintf(`You are a senior security engineer analyzing a potential security vulnerability.
Analyze the following vulnerability finding and provide detailed insights.

## Vulnerability Details
- **Title**: %s
- **Category**: %s
- **Severity**: %s
- **File**: %s
- **Language**: %s

## Code Snippet
%s

## Additional Context
%s

## Your Analysis Should Include:

1. **Explanation**: Explain what this vulnerability is and why it's dangerous in 2-3 sentences.

2. **Risk Assessment**: Describe the potential impact if this vulnerability is exploited.
   - What could an attacker do?
   - What data or systems could be compromised?
   - Is this vulnerability easy to exploit?

3. **Exploit Scenario**: Provide a brief scenario of how an attacker might exploit this vulnerability.

4. **Recommendations**: Provide 3-5 specific, actionable recommendations to fix this issue.
   Include code examples where applicable.

5. **Confidence Score**: Rate your confidence that this is a true positive (0.0 to 1.0).
   Explain your reasoning.

Please format your response as follows:
EXPLANATION:
[Your explanation]

RISK_ASSESSMENT:
[Your risk assessment]

EXPLOIT_SCENARIO:
[Your exploit scenario]

RECOMMENDATIONS:
1. [First recommendation]
2. [Second recommendation]
...

CONFIDENCE: [0.0-1.0]
CONFIDENCE_REASONING: [Your reasoning]
`,
		req.Title,
		req.Category,
		req.Severity,
		req.FilePath,
		req.Language,
		formatCodeBlock(req.CodeSnippet, req.Language),
		defaultIfEmpty(req.Context, "No additional context provided."),
	)
}

// SummaryRequest holds data for security summary generation.
type SummaryRequest struct {
	RepositoryName string            `json:"repository_name"`
	Branch         string            `json:"branch"`
	TotalFiles     int               `json:"total_files"`
	LinesScanned   int               `json:"lines_scanned"`
	VulnCounts     map[string]int    `json:"vulnerability_counts"`
	TopVulns       []VulnSummaryItem `json:"top_vulnerabilities"`
	Languages      []string          `json:"languages"`
}

// VulnSummaryItem represents a vulnerability for summary.
type VulnSummaryItem struct {
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	File     string `json:"file"`
}

// BuildSummaryPrompt builds the prompt for security summary.
func BuildSummaryPrompt(req SummaryRequest) string {
	var vulnList strings.Builder
	for _, v := range req.TopVulns {
		vulnList.WriteString(fmt.Sprintf("- [%s] %s in %s (%s)\n", v.Severity, v.Title, v.File, v.Category))
	}

	return fmt.Sprintf(`You are a security consultant preparing an executive summary for a code security audit.

## Scan Results

**Repository**: %s
**Branch**: %s
**Files Scanned**: %d
**Lines of Code**: %d
**Languages**: %s

### Vulnerability Counts
- Critical: %d
- High: %d
- Medium: %d
- Low: %d
- Info: %d

### Top Vulnerabilities Found
%s

## Generate an Executive Summary

Please provide:

1. **EXECUTIVE_SUMMARY**: A 3-4 sentence executive summary suitable for non-technical stakeholders.

2. **KEY_FINDINGS**: List the 3-5 most important security findings.

3. **RISK_ASSESSMENT**: Overall risk level (Critical/High/Medium/Low) with explanation.

4. **RECOMMENDATIONS**: Top 5 prioritized recommendations for improving security.

5. **COMPLIANCE_NOTES**: Any relevant compliance considerations (OWASP, PCI-DSS, GDPR, etc.)

Format your response with clear section headers.
`,
		req.RepositoryName,
		req.Branch,
		req.TotalFiles,
		req.LinesScanned,
		strings.Join(req.Languages, ", "),
		req.VulnCounts["critical"],
		req.VulnCounts["high"],
		req.VulnCounts["medium"],
		req.VulnCounts["low"],
		req.VulnCounts["info"],
		vulnList.String(),
	)
}

// RemediationRequest holds data for remediation suggestion.
type RemediationRequest struct {
	Vulnerabilities []VulnForRemediation `json:"vulnerabilities"`
	Language        string               `json:"language"`
	Framework       string               `json:"framework,omitempty"`
}

// VulnForRemediation represents a vulnerability for remediation.
type VulnForRemediation struct {
	Title       string `json:"title"`
	Category    string `json:"category"`
	CodeSnippet string `json:"code_snippet"`
	FilePath    string `json:"file_path"`
	Line        int    `json:"line"`
}

// BuildRemediationPrompt builds the prompt for remediation suggestions.
func BuildRemediationPrompt(req RemediationRequest) string {
	var vulnDetails strings.Builder
	for i, v := range req.Vulnerabilities {
		vulnDetails.WriteString(fmt.Sprintf(`
### Vulnerability %d: %s
**Category**: %s
**File**: %s (line %d)
**Code**:
%s
`, i+1, v.Title, v.Category, v.FilePath, v.Line, formatCodeBlock(v.CodeSnippet, req.Language)))
	}

	framework := req.Framework
	if framework == "" {
		framework = "standard library"
	}

	return fmt.Sprintf(`You are a senior %s developer with security expertise.
Provide specific code fixes for the following vulnerabilities.

**Language**: %s
**Framework**: %s

%s

## For Each Vulnerability, Provide:

1. **EXPLANATION**: Brief explanation of the vulnerability (1-2 sentences)

2. **FIXED_CODE**: The corrected code that addresses the security issue.
   - Use the same style and conventions as the original code
   - Include all necessary imports
   - Make minimal changes to fix the issue

3. **BEST_PRACTICES**: Additional security best practices related to this type of vulnerability

Format each fix clearly with the vulnerability number.
`,
		req.Language,
		req.Language,
		framework,
		vulnDetails.String(),
	)
}

// CodeReviewRequest holds data for AI code review.
type CodeReviewRequest struct {
	Code     string   `json:"code"`
	Language string   `json:"language"`
	FilePath string   `json:"file_path"`
	Focus    []string `json:"focus,omitempty"` // security, performance, best-practices
}

// BuildCodeReviewPrompt builds the prompt for code review.
func BuildCodeReviewPrompt(req CodeReviewRequest) string {
	focus := "security vulnerabilities, code quality, and best practices"
	if len(req.Focus) > 0 {
		focus = strings.Join(req.Focus, ", ")
	}

	return fmt.Sprintf(`You are performing a code review as a senior %s developer with security expertise.

**File**: %s
**Focus Areas**: %s

## Code to Review
%s

## Provide a Comprehensive Review

### SECURITY_ISSUES
List any security vulnerabilities or concerns found.
For each issue:
- Line number(s)
- Description
- Severity (Critical/High/Medium/Low)
- Recommended fix

### CODE_QUALITY
Comment on:
- Code organization and structure
- Error handling
- Edge cases
- Potential bugs

### BEST_PRACTICES
Suggestions for:
- Improving maintainability
- Following language idioms
- Performance optimizations

### POSITIVE_ASPECTS
Note what the code does well.

### SUMMARY
Overall assessment and top 3 priority improvements.

Be specific and provide line numbers where applicable.
`,
		req.Language,
		req.FilePath,
		focus,
		formatCodeBlock(req.Code, req.Language),
	)
}

// Helper functions

// formatCodeBlock formats code with markdown code block.
func formatCodeBlock(code, language string) string {
	if code == "" {
		return "```\nNo code provided\n```"
	}
	return fmt.Sprintf("```%s\n%s\n```", language, code)
}

// defaultIfEmpty returns the default value if s is empty.
func defaultIfEmpty(s, defaultVal string) string {
	if s == "" {
		return defaultVal
	}
	return s
}

// SystemPrompts contains various system prompts for different tasks.
var SystemPrompts = map[string]string{
	"security_analyst": `You are an expert security analyst specializing in application security.
Your role is to:
- Identify and explain security vulnerabilities
- Assess risk and potential impact
- Provide actionable remediation advice
- Consider both technical and business context

Always be thorough but concise. Prioritize findings by severity.`,

	"code_reviewer": `You are a senior software engineer performing security-focused code reviews.
Your role is to:
- Identify security vulnerabilities and code quality issues
- Explain problems clearly with specific examples
- Suggest concrete fixes with code samples
- Balance security with practical implementation

Focus on high-impact issues first. Be constructive and educational.`,

	"security_consultant": `You are a security consultant preparing reports for stakeholders.
Your role is to:
- Summarize findings in clear, business-friendly language
- Quantify risk and potential impact
- Prioritize recommendations
- Consider compliance requirements

Balance technical accuracy with accessibility. Focus on actionable insights.`,
}

// GetSystemPrompt returns a system prompt by name.
func GetSystemPrompt(name string) string {
	if prompt, ok := SystemPrompts[name]; ok {
		return prompt
	}
	return SystemPrompts["security_analyst"]
}
