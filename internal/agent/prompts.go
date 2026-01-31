package agent

import (
	"encoding/json"
	"fmt"
	"strings"

	"code-security-auditor/internal/models"
)

// SecurityExpertSystemPrompt is the comprehensive system prompt for ADK security analysis.
const SecurityExpertSystemPrompt = `You are an expert security auditor and code reviewer with deep knowledge of:
- OWASP Top 10 vulnerabilities and their mitigations
- Secure coding practices across multiple languages (Go, Python, JavaScript, Java, PHP, Ruby)
- Common attack vectors and exploitation techniques
- CVE database and vulnerability patterns
- Code quality and performance optimization
- Compliance frameworks (PCI-DSS, HIPAA, SOC2, GDPR)

Your role is to analyze code security findings and provide:
1. Validation of detected vulnerabilities (true positive vs false positive)
2. Severity assessment based on actual exploitability
3. Contextual risk analysis considering the technology stack
4. Actionable fix suggestions with explanations
5. Prioritization based on business impact and exploitability

Always consider:
- The specific technology stack and framework in use
- The context in which the code is used (public API, internal tool, etc.)
- Defense in depth mechanisms that may already be in place
- Actual exploitability vs theoretical risk
- Business logic and data sensitivity
- Attack surface and exposure level

Response Guidelines:
- Be precise and technical when describing vulnerabilities
- Provide specific, actionable recommendations
- Include code examples for fixes when applicable
- Rate confidence levels honestly
- Consider false positive likelihood based on context
- Map findings to CWE and OWASP categories when possible`

// VulnerabilityAnalysisRequest holds data for vulnerability analysis.
type VulnerabilityAnalysisRequest struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	FilePath    string `json:"file_path"`
	CodeSnippet string `json:"code_snippet"`
	Language    string `json:"language"`
	Context     string `json:"context,omitempty"`
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

// BuildVulnerabilityValidationPrompt builds a comprehensive prompt for validating multiple findings.
func BuildVulnerabilityValidationPrompt(input *AnalysisInput) string {
	var findingsJSON strings.Builder
	findingsJSON.WriteString("[\n")

	for i, f := range input.Findings {
		if i > 0 {
			findingsJSON.WriteString(",\n")
		}
		findingData, _ := json.MarshalIndent(map[string]interface{}{
			"index":       i + 1,
			"rule_id":     f.RuleID,
			"severity":    f.Severity,
			"category":    f.Category,
			"file":        f.FilePath,
			"line":        f.Line,
			"code":        f.CodeSnippet,
			"description": f.Remediation,
		}, "  ", "  ")
		findingsJSON.Write(findingData)
	}
	findingsJSON.WriteString("\n]")

	var contextInfo strings.Builder
	if input.RepoMetadata != nil {
		contextInfo.WriteString(fmt.Sprintf(`
Repository Context:
- Name: %s
- Language: %s
- Framework: %s
- Has ORM: %v
- Database: %s
`, input.RepoMetadata.Name,
			input.RepoMetadata.Language,
			defaultIfEmpty(input.RepoMetadata.Framework, "Unknown"),
			input.RepoMetadata.HasORM,
			defaultIfEmpty(input.RepoMetadata.Database, "Unknown")))
	}

	// Add code context snippets
	if len(input.CodeContext) > 0 {
		contextInfo.WriteString("\nCode Context (surrounding code for key files):\n")
		count := 0
		for filepath, code := range input.CodeContext {
			if count >= 5 { // Limit to 5 files for prompt size
				break
			}
			contextInfo.WriteString(fmt.Sprintf("\n### %s\n```\n%s\n```\n", filepath, truncateCode(code, 500)))
			count++
		}
	}

	return fmt.Sprintf(`Analyze the following security findings and validate each one.

## Findings to Analyze
%s

%s

## For Each Finding, Provide:

1. **is_valid_vulnerability**: true or false
2. **confidence**: 0.0 to 1.0
3. **actual_severity**: critical, high, medium, low, or info
4. **reasoning**: Why this is or isn't a real vulnerability
5. **exploitability**: How easy it is to exploit (high, medium, low)
6. **attack_vector**: Brief description of potential attack
7. **cwe_mapping**: Relevant CWE ID (e.g., "CWE-89")
8. **cvss_score**: Estimated CVSS score (0.0-10.0)
9. **mitigation_priority**: 1 (highest) to 5 (lowest)

Also provide:
- **false_positives**: List of finding indices that are false positives
- **priority_order**: Ordered list of finding indices by actual risk
- **risk_assessment**: Overall risk assessment summary
- **recommendations**: Top 5 security recommendations

Respond in JSON format:
{
  "validated_findings": [...],
  "false_positives": [...],
  "priority_order": [...],
  "risk_assessment": {
    "overall_risk": "...",
    "exploitability": "...",
    "impact": "...",
    "summary": "..."
  },
  "recommendations": [...]
}
`, findingsJSON.String(), contextInfo.String())
}

// BuildFixGenerationPrompt builds a prompt for generating a code fix.
func BuildFixGenerationPrompt(vuln *models.Vulnerability) string {
	return fmt.Sprintf(`You are a senior security engineer providing a code fix for a vulnerability.

## Vulnerability Details
- **Rule ID**: %s
- **Title**: %s
- **Category**: %s
- **Severity**: %s
- **File**: %s
- **Line**: %d

## Vulnerable Code
%s

## Description
%s

## Current Remediation Advice
%s

## Your Task

Provide a secure fix for this vulnerability. Your response should include:

1. **EXPLANATION**: Brief explanation of the vulnerability and why the fix works (2-3 sentences)

2. **FIXED_CODE**: The corrected code that addresses the security issue
   - Maintain the same coding style as the original
   - Include all necessary imports
   - Make minimal changes to fix the issue
   - Add comments explaining security-relevant changes

3. **BEST_PRACTICES**: Security best practices for preventing similar issues
   - List 3-5 relevant best practices

4. **BREAKING_CHANGE**: Whether this fix could cause breaking changes (true/false)

5. **REFERENCES**: Relevant security resources (OWASP, CWE, etc.)

Format your response:
EXPLANATION:
[Your explanation]

FIXED_CODE:
%s[language]
[Your fixed code]
%s

BEST_PRACTICES:
- [Practice 1]
- [Practice 2]
...

BREAKING_CHANGE: [true/false]

REFERENCES:
- [Reference 1]
- [Reference 2]
`,
		vuln.RuleID,
		vuln.Title,
		vuln.Category,
		vuln.Severity,
		vuln.FilePath,
		vuln.LineStart,
		formatCodeBlock(vuln.CodeSnippet, vuln.Metadata.Language),
		vuln.Description,
		defaultIfEmpty(vuln.Remediation, "No remediation advice provided."),
		"```", "```",
	)
}

// BuildRiskPrioritizationPrompt builds a prompt for prioritizing findings.
func BuildRiskPrioritizationPrompt(findings []models.Finding) string {
	var findingsList strings.Builder

	for i, f := range findings {
		findingsList.WriteString(fmt.Sprintf(`
%d. [%s] %s
   - File: %s (line %d)
   - Category: %s
   - Code: %s
   - Confidence: %.2f
`,
			i+1,
			f.Severity,
			f.Title,
			f.FilePath,
			f.Line,
			f.Category,
			truncateCode(f.CodeSnippet, 100),
			f.Confidence,
		))
	}

	return fmt.Sprintf(`Prioritize the following security findings based on actual risk.

## Findings
%s

## Prioritization Criteria

Consider these factors when prioritizing:
1. **Exploitability**: How easy is it to exploit?
2. **Impact**: What damage could result?
3. **Exposure**: Is this in public-facing code?
4. **Data Sensitivity**: Does it handle sensitive data?
5. **Attack Surface**: How accessible is this code?

## Response Format

Return a JSON array of finding identifiers in priority order (highest risk first).
Each identifier should be: "filepath:rule_id:line"

For example:
[
  "handlers/user.go:G201:45",
  "api/auth.go:G401:23",
  ...
]

Also provide a brief justification for your top 3 priorities.

PRIORITY_ORDER:
[Your JSON array]

JUSTIFICATION:
1. [Why finding X is highest priority]
2. [Why finding Y is second priority]
3. [Why finding Z is third priority]
`, findingsList.String())
}

// BuildReportGenerationPrompt builds a prompt for generating a security report.
func BuildReportGenerationPrompt(scan *ScanResult) string {
	var severityCounts strings.Builder
	bySeverity := make(map[string]int)
	byCategory := make(map[string]int)

	for _, v := range scan.Vulnerabilities {
		bySeverity[string(v.Severity)]++
		byCategory[string(v.Category)]++
	}

	severityCounts.WriteString(fmt.Sprintf(`
- Critical: %d
- High: %d
- Medium: %d
- Low: %d
- Info: %d
`,
		bySeverity["critical"],
		bySeverity["high"],
		bySeverity["medium"],
		bySeverity["low"],
		bySeverity["info"]))

	var topVulns strings.Builder
	limit := 10
	if len(scan.Vulnerabilities) < limit {
		limit = len(scan.Vulnerabilities)
	}
	for i := 0; i < limit; i++ {
		v := scan.Vulnerabilities[i]
		topVulns.WriteString(fmt.Sprintf("- [%s] %s in %s (%s)\n",
			v.Severity, v.Title, v.FilePath, v.Category))
	}

	repoInfo := "Unknown Repository"
	if scan.Repository != nil {
		repoInfo = fmt.Sprintf("%s/%s (%s)", scan.Repository.Owner, scan.Repository.Name, scan.Repository.Branch)
	}

	return fmt.Sprintf(`Generate a comprehensive security report for this scan.

## Scan Overview
- **Repository**: %s
- **Scan ID**: %s
- **Status**: %s
- **Files Scanned**: %d
- **Lines Scanned**: %d
- **Total Findings**: %d

## Findings by Severity
%s

## Top Vulnerabilities
%s

## Report Requirements

Generate a professional security report with:

1. **EXECUTIVE_SUMMARY**: 3-4 sentences for non-technical stakeholders
   - Overall security posture
   - Key risk areas
   - Recommendation summary

2. **RISK_ASSESSMENT**: Overall risk evaluation
   - Risk level (Critical/High/Medium/Low)
   - Key risk factors
   - Business impact potential

3. **KEY_FINDINGS**: Top 5 most important findings
   - What they are
   - Why they matter
   - Potential impact

4. **RECOMMENDATIONS**: Top 5 prioritized actions
   - Specific remediation steps
   - Priority level
   - Estimated effort

5. **COMPLIANCE_NOTES**: Relevant compliance considerations
   - OWASP alignment
   - PCI-DSS implications (if applicable)
   - Other relevant standards

Format with clear section headers.
`,
		repoInfo,
		scan.Scan.ID.String(),
		scan.Scan.Status,
		scan.Scan.FilesScanned,
		scan.Scan.LinesScanned,
		len(scan.Vulnerabilities),
		severityCounts.String(),
		topVulns.String(),
	)
}

// BuildPatternLearningPrompt builds a prompt for learning new vulnerability patterns.
func BuildPatternLearningPrompt(examples []PatternExample) string {
	var examplesList strings.Builder

	for i, ex := range examples {
		examplesList.WriteString(fmt.Sprintf(`
### Example %d
**Language**: %s
**Category**: %s
**Is Vulnerable**: %v

%s

%s
`,
			i+1,
			ex.Language,
			ex.Category,
			ex.IsVulnerable,
			formatCodeBlock(ex.Code, ex.Language),
			defaultIfEmpty(ex.Explanation, ""),
		))
	}

	return fmt.Sprintf(`Learn security patterns from these examples and identify key indicators.

## Examples
%s

## Analysis Required

1. **PATTERNS_IDENTIFIED**: What patterns indicate vulnerability vs safe code?

2. **KEY_INDICATORS**: What specific code elements should trigger alerts?

3. **FALSE_POSITIVE_INDICATORS**: What patterns suggest false positives?

4. **DETECTION_RULES**: Suggest regex or AST patterns for detection

5. **CONTEXT_CLUES**: What context helps determine true vs false positive?

Provide detailed analysis to improve vulnerability detection accuracy.
`, examplesList.String())
}

// PatternExample represents an example for pattern learning.
type PatternExample struct {
	Code         string `json:"code"`
	Language     string `json:"language"`
	Category     string `json:"category"`
	IsVulnerable bool   `json:"is_vulnerable"`
	Explanation  string `json:"explanation,omitempty"`
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

// truncateCode truncates code to a maximum length.
func truncateCode(code string, maxLen int) string {
	if len(code) <= maxLen {
		return code
	}
	return code[:maxLen] + "..."
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

	"vulnerability_validator": `You are an expert vulnerability validator specializing in distinguishing true vulnerabilities from false positives.
Your role is to:
- Analyze code context thoroughly
- Consider the full attack surface
- Evaluate defense mechanisms in place
- Provide confidence scores with reasoning

Be conservative - prefer false negatives over false positives in reporting.`,

	"fix_generator": `You are a senior security engineer specializing in writing secure code fixes.
Your role is to:
- Provide minimal, targeted fixes that address the root cause
- Maintain code style and conventions
- Consider edge cases and potential regressions
- Explain the security implications of changes

Always test your fixes mentally for completeness and correctness.`,
}

// GetSystemPrompt returns a system prompt by name.
func GetSystemPrompt(name string) string {
	if prompt, ok := SystemPrompts[name]; ok {
		return prompt
	}
	return SystemPrompts["security_analyst"]
}
