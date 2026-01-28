package agent

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// VulnerabilityAnalysis holds the parsed AI analysis of a vulnerability.
type VulnerabilityAnalysis struct {
	Explanation          string   `json:"explanation"`
	RiskAssessment       string   `json:"risk_assessment"`
	ExploitScenario      string   `json:"exploit_scenario"`
	Recommendations      []string `json:"recommendations"`
	ConfidenceScore      float64  `json:"confidence_score"`
	ConfidenceReasoning  string   `json:"confidence_reasoning"`
	GeneratedAt          time.Time `json:"generated_at"`
}

// ParseVulnerabilityAnalysis parses AI response into structured analysis.
func ParseVulnerabilityAnalysis(response string) (*VulnerabilityAnalysis, error) {
	analysis := &VulnerabilityAnalysis{
		GeneratedAt: time.Now(),
	}

	// Parse sections
	analysis.Explanation = extractSection(response, "EXPLANATION:")
	analysis.RiskAssessment = extractSection(response, "RISK_ASSESSMENT:")
	analysis.ExploitScenario = extractSection(response, "EXPLOIT_SCENARIO:")
	analysis.ConfidenceReasoning = extractSection(response, "CONFIDENCE_REASONING:")

	// Parse recommendations
	recsSection := extractSection(response, "RECOMMENDATIONS:")
	analysis.Recommendations = parseNumberedList(recsSection)

	// Parse confidence score
	confidenceMatch := regexp.MustCompile(`CONFIDENCE:\s*([\d.]+)`).FindStringSubmatch(response)
	if len(confidenceMatch) > 1 {
		if score, err := strconv.ParseFloat(confidenceMatch[1], 64); err == nil {
			analysis.ConfidenceScore = score
		}
	}

	// Default confidence if not found
	if analysis.ConfidenceScore == 0 {
		analysis.ConfidenceScore = 0.7
	}

	return analysis, nil
}

// SecuritySummary holds the parsed AI security summary.
type SecuritySummary struct {
	ExecutiveSummary string             `json:"executive_summary"`
	KeyFindings      []string           `json:"key_findings"`
	RiskAssessment   RiskLevel          `json:"risk_assessment"`
	Recommendations  []Recommendation   `json:"recommendations"`
	ComplianceNotes  []string           `json:"compliance_notes"`
	GeneratedAt      time.Time          `json:"generated_at"`
}

// RiskLevel represents the overall risk assessment.
type RiskLevel struct {
	Level       string `json:"level"` // Critical, High, Medium, Low
	Explanation string `json:"explanation"`
}

// Recommendation represents a prioritized recommendation.
type Recommendation struct {
	Priority    int    `json:"priority"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

// ParseSecuritySummary parses AI response into security summary.
func ParseSecuritySummary(response string) (*SecuritySummary, error) {
	summary := &SecuritySummary{
		GeneratedAt: time.Now(),
	}

	// Parse sections
	summary.ExecutiveSummary = extractSection(response, "EXECUTIVE_SUMMARY:")

	// Parse key findings
	keyFindings := extractSection(response, "KEY_FINDINGS:")
	summary.KeyFindings = parseNumberedList(keyFindings)

	// Parse risk assessment
	riskSection := extractSection(response, "RISK_ASSESSMENT:")
	summary.RiskAssessment = parseRiskLevel(riskSection)

	// Parse recommendations
	recsSection := extractSection(response, "RECOMMENDATIONS:")
	recsList := parseNumberedList(recsSection)
	for i, rec := range recsList {
		summary.Recommendations = append(summary.Recommendations, Recommendation{
			Priority:    i + 1,
			Description: rec,
		})
	}

	// Parse compliance notes
	complianceSection := extractSection(response, "COMPLIANCE_NOTES:")
	summary.ComplianceNotes = parseBulletList(complianceSection)

	return summary, nil
}

// RemediationSuggestion holds parsed remediation suggestions.
type RemediationSuggestion struct {
	Fixes       []VulnFix `json:"fixes"`
	GeneratedAt time.Time `json:"generated_at"`
}

// VulnFix represents a fix for a single vulnerability.
type VulnFix struct {
	VulnIndex     int      `json:"vulnerability_index"`
	Explanation   string   `json:"explanation"`
	FixedCode     string   `json:"fixed_code"`
	BestPractices []string `json:"best_practices"`
}

// ParseRemediationSuggestion parses AI response into remediation suggestions.
func ParseRemediationSuggestion(response string) (*RemediationSuggestion, error) {
	suggestion := &RemediationSuggestion{
		GeneratedAt: time.Now(),
	}

	// Split by vulnerability markers
	vulnPattern := regexp.MustCompile(`(?i)###?\s*Vulnerability\s*(\d+)`)
	matches := vulnPattern.FindAllStringSubmatchIndex(response, -1)

	for i, match := range matches {
		var section string
		if i < len(matches)-1 {
			section = response[match[0]:matches[i+1][0]]
		} else {
			section = response[match[0]:]
		}

		fix := VulnFix{
			VulnIndex: i + 1,
		}

		// Extract explanation
		fix.Explanation = extractSection(section, "EXPLANATION:")
		if fix.Explanation == "" {
			fix.Explanation = extractSection(section, "**EXPLANATION**:")
		}

		// Extract fixed code
		fix.FixedCode = extractCodeBlock(section, "FIXED_CODE:")
		if fix.FixedCode == "" {
			fix.FixedCode = extractCodeBlock(section, "**FIXED_CODE**:")
		}

		// Extract best practices
		bpSection := extractSection(section, "BEST_PRACTICES:")
		if bpSection == "" {
			bpSection = extractSection(section, "**BEST_PRACTICES**:")
		}
		fix.BestPractices = parseBulletList(bpSection)

		suggestion.Fixes = append(suggestion.Fixes, fix)
	}

	return suggestion, nil
}

// CodeReview holds parsed code review results.
type CodeReview struct {
	SecurityIssues  []SecurityIssue  `json:"security_issues"`
	QualityIssues   []string         `json:"quality_issues"`
	BestPractices   []string         `json:"best_practices"`
	PositiveAspects []string         `json:"positive_aspects"`
	Summary         string           `json:"summary"`
	GeneratedAt     time.Time        `json:"generated_at"`
}

// SecurityIssue represents a security issue found in code review.
type SecurityIssue struct {
	Line        string `json:"line"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Fix         string `json:"recommended_fix"`
}

// ParseCodeReview parses AI response into code review.
func ParseCodeReview(response string) (*CodeReview, error) {
	review := &CodeReview{
		GeneratedAt: time.Now(),
	}

	// Parse security issues
	securitySection := extractSection(response, "SECURITY_ISSUES")
	review.SecurityIssues = parseSecurityIssues(securitySection)

	// Parse code quality
	qualitySection := extractSection(response, "CODE_QUALITY")
	review.QualityIssues = parseBulletList(qualitySection)

	// Parse best practices
	bpSection := extractSection(response, "BEST_PRACTICES")
	review.BestPractices = parseBulletList(bpSection)

	// Parse positive aspects
	positiveSection := extractSection(response, "POSITIVE_ASPECTS")
	review.PositiveAspects = parseBulletList(positiveSection)

	// Parse summary
	review.Summary = extractSection(response, "SUMMARY")

	return review, nil
}

// Helper functions

// extractSection extracts a section from the response.
func extractSection(response, sectionName string) string {
	// Try to find the section header
	patterns := []string{
		sectionName,
		"**" + sectionName + "**",
		"### " + sectionName,
		"## " + sectionName,
	}

	var startIdx int
	found := false

	for _, pattern := range patterns {
		idx := strings.Index(response, pattern)
		if idx != -1 {
			startIdx = idx + len(pattern)
			found = true
			break
		}
	}

	if !found {
		return ""
	}

	// Find the end of the section (next section header or end of response)
	content := response[startIdx:]

	// Look for next section marker
	endPatterns := []string{"\n##", "\n**", "\nEXPLANATION:", "\nRISK_ASSESSMENT:",
		"\nEXPLOIT_SCENARIO:", "\nRECOMMENDATIONS:", "\nCONFIDENCE:",
		"\nKEY_FINDINGS:", "\nCOMPLIANCE_NOTES:", "\nSECURITY_ISSUES",
		"\nCODE_QUALITY", "\nBEST_PRACTICES", "\nPOSITIVE_ASPECTS", "\nSUMMARY"}

	minEnd := len(content)
	for _, pattern := range endPatterns {
		if idx := strings.Index(content, pattern); idx != -1 && idx < minEnd {
			minEnd = idx
		}
	}

	return strings.TrimSpace(content[:minEnd])
}

// extractCodeBlock extracts a code block from the response.
func extractCodeBlock(response, marker string) string {
	section := extractSection(response, marker)
	if section == "" {
		return ""
	}

	// Find code block
	codePattern := regexp.MustCompile("```[a-z]*\n([\\s\\S]*?)```")
	match := codePattern.FindStringSubmatch(section)
	if len(match) > 1 {
		return strings.TrimSpace(match[1])
	}

	// Return section if no code block found
	return section
}

// parseNumberedList parses a numbered list from text.
func parseNumberedList(text string) []string {
	var items []string

	// Match numbered items (1. item, 2. item, etc.)
	pattern := regexp.MustCompile(`(?m)^\s*\d+[.)]\s*(.+)`)
	matches := pattern.FindAllStringSubmatch(text, -1)

	for _, match := range matches {
		if len(match) > 1 {
			item := strings.TrimSpace(match[1])
			if item != "" {
				items = append(items, item)
			}
		}
	}

	// If no numbered items found, try bullet points
	if len(items) == 0 {
		return parseBulletList(text)
	}

	return items
}

// parseBulletList parses a bullet list from text.
func parseBulletList(text string) []string {
	var items []string

	// Match bullet items (- item, * item, • item)
	pattern := regexp.MustCompile(`(?m)^\s*[-*•]\s*(.+)`)
	matches := pattern.FindAllStringSubmatch(text, -1)

	for _, match := range matches {
		if len(match) > 1 {
			item := strings.TrimSpace(match[1])
			if item != "" {
				items = append(items, item)
			}
		}
	}

	return items
}

// parseRiskLevel parses risk level from text.
func parseRiskLevel(text string) RiskLevel {
	level := RiskLevel{
		Level:       "Medium",
		Explanation: text,
	}

	// Try to extract the level
	textLower := strings.ToLower(text)
	if strings.Contains(textLower, "critical") {
		level.Level = "Critical"
	} else if strings.Contains(textLower, "high") {
		level.Level = "High"
	} else if strings.Contains(textLower, "medium") {
		level.Level = "Medium"
	} else if strings.Contains(textLower, "low") {
		level.Level = "Low"
	}

	return level
}

// parseSecurityIssues parses security issues from text.
func parseSecurityIssues(text string) []SecurityIssue {
	var issues []SecurityIssue

	// Split by bullet points or numbered items
	lines := strings.Split(text, "\n")
	var currentIssue *SecurityIssue

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Check if this is a new issue
		if strings.HasPrefix(trimmed, "-") || strings.HasPrefix(trimmed, "*") ||
			regexp.MustCompile(`^\d+[.)]`).MatchString(trimmed) {

			if currentIssue != nil {
				issues = append(issues, *currentIssue)
			}

			currentIssue = &SecurityIssue{
				Description: strings.TrimLeft(trimmed, "-*0123456789.) "),
				Severity:    "Medium", // Default
			}

			// Try to extract severity
			lineLower := strings.ToLower(trimmed)
			if strings.Contains(lineLower, "critical") {
				currentIssue.Severity = "Critical"
			} else if strings.Contains(lineLower, "high") {
				currentIssue.Severity = "High"
			} else if strings.Contains(lineLower, "low") {
				currentIssue.Severity = "Low"
			}

			// Try to extract line number
			linePattern := regexp.MustCompile(`(?i)line\s*(\d+)`)
			if match := linePattern.FindStringSubmatch(trimmed); len(match) > 1 {
				currentIssue.Line = match[1]
			}
		} else if currentIssue != nil {
			// Continuation of current issue
			currentIssue.Description += " " + trimmed
		}
	}

	if currentIssue != nil {
		issues = append(issues, *currentIssue)
	}

	return issues
}
