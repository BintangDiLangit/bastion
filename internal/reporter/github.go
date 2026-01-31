package reporter

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-github/v57/github"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"code-security-auditor/internal/models"
)

// GitHubClient provides comprehensive GitHub integration.
type GitHubClient struct {
	client *github.Client
	logger *logrus.Logger
}

// NewGitHubClient creates a new GitHub client.
func NewGitHubClient(token string, logger *logrus.Logger) *GitHubClient {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	return &GitHubClient{
		client: client,
		logger: logger,
	}
}

// GitHubReporter posts scan results to GitHub PRs (backwards compatible).
type GitHubReporter struct {
	client *github.Client
	logger *logrus.Logger
}

// NewGitHubReporter creates a new GitHub reporter.
func NewGitHubReporter(token string, logger *logrus.Logger) *GitHubReporter {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	return &GitHubReporter{
		client: client,
		logger: logger,
	}
}

// PullRequest represents a pull request for PR operations.
type PullRequest struct {
	Owner      string
	Repo       string
	Number     int
	BaseBranch string
	HeadBranch string
	HeadSHA    string
}

// PostPRComment posts a scan summary as a PR comment.
func (r *GitHubReporter) PostPRComment(ctx context.Context, owner, repo string, prNumber int, data ReportData) error {
	comment := r.buildPRComment(data)

	_, _, err := r.client.Issues.CreateComment(ctx, owner, repo, prNumber, &github.IssueComment{
		Body: github.String(comment),
	})
	if err != nil {
		return fmt.Errorf("failed to post PR comment: %w", err)
	}

	r.logger.WithFields(logrus.Fields{
		"owner":     owner,
		"repo":      repo,
		"pr_number": prNumber,
	}).Info("Posted PR comment")

	return nil
}

// PostPRCommentFromReport posts a formatted comment from ReportData.
func (c *GitHubClient) PostPRComment(ctx context.Context, pr *PullRequest, data ReportData) error {
	comment := c.buildEnhancedPRComment(data)

	_, _, err := c.client.Issues.CreateComment(ctx, pr.Owner, pr.Repo, pr.Number, &github.IssueComment{
		Body: github.String(comment),
	})
	if err != nil {
		return fmt.Errorf("failed to post PR comment: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"owner":     pr.Owner,
		"repo":      pr.Repo,
		"pr_number": pr.Number,
	}).Info("Posted enhanced PR comment")

	return nil
}

// buildEnhancedPRComment builds an enhanced PR comment with more details.
func (c *GitHubClient) buildEnhancedPRComment(data ReportData) string {
	var sb strings.Builder

	// Header
	sb.WriteString("## 🔒 Security Scan Results\n\n")

	critical := data.Summary.VulnsBySeverity[models.SeverityCritical]
	high := data.Summary.VulnsBySeverity[models.SeverityHigh]
	medium := data.Summary.VulnsBySeverity[models.SeverityMedium]
	low := data.Summary.VulnsBySeverity[models.SeverityLow]

	// Overall status
	if critical > 0 {
		sb.WriteString("**Overall Status:** 🔴 **Critical Issues Found**\n\n")
	} else if high > 0 {
		sb.WriteString("**Overall Status:** 🟠 **High Severity Issues Found**\n\n")
	} else if medium > 0 || low > 0 {
		sb.WriteString("**Overall Status:** 🟡 **Issues Found**\n\n")
	} else {
		sb.WriteString("**Overall Status:** ✅ **No Issues Found!**\n\n")
	}

	// Summary table
	sb.WriteString("### Summary\n")
	sb.WriteString("| Severity | Count |\n")
	sb.WriteString("|----------|-------|\n")
	sb.WriteString(fmt.Sprintf("| 🔴 Critical | %d |\n", critical))
	sb.WriteString(fmt.Sprintf("| 🟠 High | %d |\n", high))
	sb.WriteString(fmt.Sprintf("| 🟡 Medium | %d |\n", medium))
	sb.WriteString(fmt.Sprintf("| 🟢 Low | %d |\n", low))
	sb.WriteString(fmt.Sprintf("\n**Total Issues:** %d | **Risk Score:** %.1f/10 | **Grade:** %s\n\n",
		data.Summary.TotalVulnerabilities,
		data.Summary.RiskScore/10,
		data.Summary.Grade))

	// Action required
	if critical > 0 || high > 0 {
		sb.WriteString("> ⚠️ **Action Required:** Critical or high severity vulnerabilities detected. Please address before merging.\n\n")
	}

	// Critical issues detail
	if critical > 0 || high > 0 {
		sb.WriteString("### 🚨 Critical Issues\n\n")
		count := 0
		for _, v := range data.Vulnerabilities {
			if v.Severity != models.SeverityCritical && v.Severity != models.SeverityHigh {
				continue
			}
			count++
			if count > 5 {
				remaining := critical + high - 5
				sb.WriteString(fmt.Sprintf("\n<details>\n<summary>...and %d more critical/high issues</summary>\n\nSee full report for details.\n</details>\n", remaining))
				break
			}

			emoji := getSeverityEmoji(v.Severity)
			sb.WriteString(fmt.Sprintf("#### %d. %s %s\n", count, emoji, v.Title))
			sb.WriteString(fmt.Sprintf("**Severity:** %s  \n", v.Severity))
			sb.WriteString(fmt.Sprintf("**File:** `%s:%d`  \n", v.FilePath, v.LineStart))

			if len(v.References.CWE) > 0 {
				sb.WriteString(fmt.Sprintf("**CWE:** [CWE-%s](https://cwe.mitre.org/data/definitions/%s.html)  \n", v.References.CWE[0], v.References.CWE[0]))
			}

			sb.WriteString(fmt.Sprintf("\n%s\n\n", truncate(v.Description, 300)))

			if v.CodeSnippet != "" {
				sb.WriteString("<details>\n<summary>View Vulnerable Code</summary>\n\n```go\n")
				sb.WriteString(truncate(v.CodeSnippet, 500))
				sb.WriteString("\n```\n</details>\n\n")
			}

			if v.Remediation != "" {
				sb.WriteString("<details>\n<summary>🔧 Recommended Fix</summary>\n\n")
				sb.WriteString(v.Remediation)
				sb.WriteString("\n</details>\n\n")
			}

			sb.WriteString("---\n\n")
		}
	}

	// AI Insights
	if data.AIInsights != nil && data.AIInsights.ExecutiveSummary != "" {
		sb.WriteString("<details>\n<summary>🤖 AI Analysis</summary>\n\n")
		sb.WriteString(data.AIInsights.ExecutiveSummary)
		sb.WriteString("\n</details>\n\n")
	}

	// Footer
	sb.WriteString("---\n")
	sb.WriteString("*Scan performed by [Code Security Auditor](https://code-security-auditor)*")

	return sb.String()
}

// UpdatePRComment updates an existing PR comment.
func (r *GitHubReporter) UpdatePRComment(ctx context.Context, owner, repo string, commentID int64, data ReportData) error {
	comment := r.buildPRComment(data)

	_, _, err := r.client.Issues.EditComment(ctx, owner, repo, commentID, &github.IssueComment{
		Body: github.String(comment),
	})
	if err != nil {
		return fmt.Errorf("failed to update PR comment: %w", err)
	}

	return nil
}

// buildPRComment builds the PR comment body.
func (r *GitHubReporter) buildPRComment(data ReportData) string {
	var sb strings.Builder

	// Header
	sb.WriteString("## 🔒 Security Scan Results\n\n")

	// Summary
	sb.WriteString("### Summary\n\n")
	sb.WriteString("| Severity | Count |\n")
	sb.WriteString("|----------|-------|\n")

	critical := data.Summary.VulnsBySeverity[models.SeverityCritical]
	high := data.Summary.VulnsBySeverity[models.SeverityHigh]
	medium := data.Summary.VulnsBySeverity[models.SeverityMedium]
	low := data.Summary.VulnsBySeverity[models.SeverityLow]

	sb.WriteString(fmt.Sprintf("| 🔴 Critical | %d |\n", critical))
	sb.WriteString(fmt.Sprintf("| 🟠 High | %d |\n", high))
	sb.WriteString(fmt.Sprintf("| 🟡 Medium | %d |\n", medium))
	sb.WriteString(fmt.Sprintf("| 🟢 Low | %d |\n", low))
	sb.WriteString(fmt.Sprintf("\n**Total Issues:** %d | **Risk Score:** %.1f/100 | **Grade:** %s\n\n",
		data.Summary.TotalVulnerabilities,
		data.Summary.RiskScore,
		data.Summary.Grade))

	// Status
	if critical > 0 || high > 0 {
		sb.WriteString("⚠️ **Action Required:** Critical or high severity vulnerabilities detected.\n\n")
	} else if data.Summary.TotalVulnerabilities == 0 {
		sb.WriteString("✅ **No vulnerabilities detected!**\n\n")
	}

	// Top vulnerabilities (limit to 5)
	if len(data.Vulnerabilities) > 0 {
		sb.WriteString("### Top Vulnerabilities\n\n")

		limit := 5
		if len(data.Vulnerabilities) < limit {
			limit = len(data.Vulnerabilities)
		}

		for i := 0; i < limit; i++ {
			v := data.Vulnerabilities[i]
			emoji := getSeverityEmoji(v.Severity)
			sb.WriteString(fmt.Sprintf("**%s %s**\n", emoji, v.Title))
			sb.WriteString(fmt.Sprintf("- File: `%s:%d`\n", v.FilePath, v.LineStart))
			sb.WriteString(fmt.Sprintf("- Category: %s\n\n", v.Category))
		}

		if len(data.Vulnerabilities) > 5 {
			sb.WriteString(fmt.Sprintf("*...and %d more vulnerabilities*\n\n", len(data.Vulnerabilities)-5))
		}
	}

	// Footer
	sb.WriteString("---\n")
	sb.WriteString("*Scan performed by [Code Security Auditor](https://code-security-auditor)*")

	return sb.String()
}

// getSeverityEmoji returns an emoji for severity.
func getSeverityEmoji(severity models.Severity) string {
	switch severity {
	case models.SeverityCritical:
		return "🔴"
	case models.SeverityHigh:
		return "🟠"
	case models.SeverityMedium:
		return "🟡"
	case models.SeverityLow:
		return "🟢"
	default:
		return "🔵"
	}
}

// CreateCheckRun creates a GitHub check run for the scan.
func (r *GitHubReporter) CreateCheckRun(ctx context.Context, owner, repo, sha string, data ReportData) (*github.CheckRun, error) {
	// Determine conclusion based on vulnerabilities
	conclusion := "success"
	critical := data.Summary.VulnsBySeverity[models.SeverityCritical]
	high := data.Summary.VulnsBySeverity[models.SeverityHigh]

	if critical > 0 {
		conclusion = "failure"
	} else if high > 0 {
		conclusion = "neutral"
	}

	// Build annotations for vulnerabilities
	var annotations []*github.CheckRunAnnotation
	for i, v := range data.Vulnerabilities {
		if i >= 50 { // GitHub limits annotations
			break
		}

		level := "warning"
		switch v.Severity {
		case models.SeverityCritical, models.SeverityHigh:
			level = "failure"
		case models.SeverityLow, models.SeverityInfo:
			level = "notice"
		}

		annotations = append(annotations, &github.CheckRunAnnotation{
			Path:            github.String(v.FilePath),
			StartLine:       github.Int(v.LineStart),
			EndLine:         github.Int(v.LineEnd),
			AnnotationLevel: github.String(level),
			Title:           github.String(v.Title),
			Message:         github.String(v.Description),
		})
	}

	// Create check run
	opts := github.CreateCheckRunOptions{
		Name:       "Security Scan",
		HeadSHA:    sha,
		Status:     github.String("completed"),
		Conclusion: github.String(conclusion),
		Output: &github.CheckRunOutput{
			Title:       github.String("Security Scan Results"),
			Summary:     github.String(r.buildCheckRunSummary(data)),
			Annotations: annotations,
		},
	}

	checkRun, _, err := r.client.Checks.CreateCheckRun(ctx, owner, repo, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create check run: %w", err)
	}

	r.logger.WithFields(logrus.Fields{
		"owner":      owner,
		"repo":       repo,
		"sha":        sha,
		"conclusion": conclusion,
	}).Info("Created GitHub check run")

	return checkRun, nil
}

// CreateCheckRunWithActions creates a check run with action buttons.
func (c *GitHubClient) CreateCheckRunWithActions(ctx context.Context, owner, repo, sha string, data ReportData) (*github.CheckRun, error) {
	critical := data.Summary.VulnsBySeverity[models.SeverityCritical]
	high := data.Summary.VulnsBySeverity[models.SeverityHigh]

	conclusion := "success"
	if critical > 0 {
		conclusion = "failure"
	} else if high > 0 {
		conclusion = "neutral"
	}

	// Build annotations
	var annotations []*github.CheckRunAnnotation
	for i, v := range data.Vulnerabilities {
		if i >= 50 {
			break
		}

		level := "warning"
		switch v.Severity {
		case models.SeverityCritical, models.SeverityHigh:
			level = "failure"
		case models.SeverityLow, models.SeverityInfo:
			level = "notice"
		}

		message := v.Description
		if v.Remediation != "" {
			message += "\n\n**Suggested Fix:** " + v.Remediation
		}

		annotations = append(annotations, &github.CheckRunAnnotation{
			Path:            github.String(v.FilePath),
			StartLine:       github.Int(v.LineStart),
			EndLine:         github.Int(v.LineEnd),
			AnnotationLevel: github.String(level),
			Title:           github.String(v.Title),
			Message:         github.String(message),
			RawDetails:      github.String(v.CodeSnippet),
		})
	}

	opts := github.CreateCheckRunOptions{
		Name:       "Code Security Auditor",
		HeadSHA:    sha,
		Status:     github.String("completed"),
		Conclusion: github.String(conclusion),
		Output: &github.CheckRunOutput{
			Title:       github.String("Security Scan Results"),
			Summary:     github.String(c.buildDetailedCheckRunSummary(data)),
			Text:        github.String(c.buildCheckRunDetails(data)),
			Annotations: annotations,
		},
	}

	checkRun, _, err := c.client.Checks.CreateCheckRun(ctx, owner, repo, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create check run: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"owner":       owner,
		"repo":        repo,
		"sha":         sha,
		"conclusion":  conclusion,
		"annotations": len(annotations),
	}).Info("Created GitHub check run with annotations")

	return checkRun, nil
}

// buildDetailedCheckRunSummary builds a detailed check run summary.
func (c *GitHubClient) buildDetailedCheckRunSummary(data ReportData) string {
	var sb strings.Builder

	sb.WriteString("## Security Scan Summary\n\n")

	critical := data.Summary.VulnsBySeverity[models.SeverityCritical]
	high := data.Summary.VulnsBySeverity[models.SeverityHigh]

	if critical > 0 {
		sb.WriteString("🔴 **CRITICAL ISSUES FOUND** - Immediate action required\n\n")
	} else if high > 0 {
		sb.WriteString("🟠 **HIGH SEVERITY ISSUES FOUND** - Action recommended before merge\n\n")
	} else if data.Summary.TotalVulnerabilities > 0 {
		sb.WriteString("🟡 **Minor issues found** - Review recommended\n\n")
	} else {
		sb.WriteString("✅ **No security issues found!**\n\n")
	}

	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Total Vulnerabilities | %d |\n", data.Summary.TotalVulnerabilities))
	sb.WriteString(fmt.Sprintf("| Critical | %d |\n", critical))
	sb.WriteString(fmt.Sprintf("| High | %d |\n", high))
	sb.WriteString(fmt.Sprintf("| Medium | %d |\n", data.Summary.VulnsBySeverity[models.SeverityMedium]))
	sb.WriteString(fmt.Sprintf("| Low | %d |\n", data.Summary.VulnsBySeverity[models.SeverityLow]))
	sb.WriteString(fmt.Sprintf("| Files Scanned | %d |\n", data.Summary.FilesScanned))
	sb.WriteString(fmt.Sprintf("| Risk Score | %.1f/100 |\n", data.Summary.RiskScore))
	sb.WriteString(fmt.Sprintf("| Grade | **%s** |\n", data.Summary.Grade))

	return sb.String()
}

// buildCheckRunDetails builds detailed text for check run.
func (c *GitHubClient) buildCheckRunDetails(data ReportData) string {
	var sb strings.Builder

	if data.AIInsights != nil && data.AIInsights.ExecutiveSummary != "" {
		sb.WriteString("## AI Analysis\n\n")
		sb.WriteString(data.AIInsights.ExecutiveSummary)
		sb.WriteString("\n\n")
	}

	if len(data.Summary.VulnsByCategory) > 0 {
		sb.WriteString("## Vulnerabilities by Category\n\n")
		for cat, count := range data.Summary.VulnsByCategory {
			sb.WriteString(fmt.Sprintf("- **%s**: %d\n", cat, count))
		}
	}

	return sb.String()
}

// buildCheckRunSummary builds the check run summary.
func (r *GitHubReporter) buildCheckRunSummary(data ReportData) string {
	var sb strings.Builder

	sb.WriteString("## Security Scan Summary\n\n")
	sb.WriteString(fmt.Sprintf("- **Total Vulnerabilities:** %d\n", data.Summary.TotalVulnerabilities))
	sb.WriteString(fmt.Sprintf("- **Critical:** %d\n", data.Summary.VulnsBySeverity[models.SeverityCritical]))
	sb.WriteString(fmt.Sprintf("- **High:** %d\n", data.Summary.VulnsBySeverity[models.SeverityHigh]))
	sb.WriteString(fmt.Sprintf("- **Medium:** %d\n", data.Summary.VulnsBySeverity[models.SeverityMedium]))
	sb.WriteString(fmt.Sprintf("- **Low:** %d\n", data.Summary.VulnsBySeverity[models.SeverityLow]))
	sb.WriteString(fmt.Sprintf("- **Files Scanned:** %d\n", data.Summary.FilesScanned))
	sb.WriteString(fmt.Sprintf("- **Risk Score:** %.1f/100\n", data.Summary.RiskScore))
	sb.WriteString(fmt.Sprintf("- **Grade:** %s\n", data.Summary.Grade))

	return sb.String()
}

// SetCommitStatus sets a commit status.
func (r *GitHubReporter) SetCommitStatus(ctx context.Context, owner, repo, sha string, data ReportData) error {
	state := "success"
	description := "No vulnerabilities found"

	critical := data.Summary.VulnsBySeverity[models.SeverityCritical]
	high := data.Summary.VulnsBySeverity[models.SeverityHigh]

	if critical > 0 {
		state = "failure"
		description = fmt.Sprintf("%d critical vulnerabilities found", critical)
	} else if high > 0 {
		state = "failure"
		description = fmt.Sprintf("%d high severity vulnerabilities found", high)
	} else if data.Summary.TotalVulnerabilities > 0 {
		state = "success"
		description = fmt.Sprintf("%d vulnerabilities found (no critical/high)", data.Summary.TotalVulnerabilities)
	}

	_, _, err := r.client.Repositories.CreateStatus(ctx, owner, repo, sha, &github.RepoStatus{
		State:       github.String(state),
		Description: github.String(description),
		Context:     github.String("security/code-auditor"),
	})

	return err
}

// UpdateCommitStatus updates commit status with more detail.
func (c *GitHubClient) UpdateCommitStatus(ctx context.Context, owner, repo, sha string, status ScanStatus) error {
	_, _, err := c.client.Repositories.CreateStatus(ctx, owner, repo, sha, &github.RepoStatus{
		State:       github.String(string(status.State)),
		Description: github.String(truncate(status.Description, 140)),
		Context:     github.String("security/code-auditor"),
		TargetURL:   github.String(status.TargetURL),
	})

	if err != nil {
		return fmt.Errorf("failed to update commit status: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"owner": owner,
		"repo":  repo,
		"sha":   sha,
		"state": status.State,
	}).Info("Updated commit status")

	return nil
}

// ScanStatus represents the status to set on a commit.
type ScanStatus struct {
	State       CommitState
	Description string
	TargetURL   string
}

// CommitState represents possible commit states.
type CommitState string

const (
	CommitStatePending CommitState = "pending"
	CommitStateSuccess CommitState = "success"
	CommitStateFailure CommitState = "failure"
	CommitStateError   CommitState = "error"
)

// AnnotateCode adds inline comments to code.
func (c *GitHubClient) AnnotateCode(ctx context.Context, owner, repo string, prNumber int, findings []models.Vulnerability) error {
	for _, v := range findings {
		if v.Severity != models.SeverityCritical && v.Severity != models.SeverityHigh {
			continue // Only annotate critical/high findings
		}

		body := fmt.Sprintf("## %s %s\n\n", getSeverityEmoji(v.Severity), v.Title)
		body += fmt.Sprintf("**Severity:** %s\n", v.Severity)
		if len(v.References.CWE) > 0 {
			body += fmt.Sprintf("**CWE:** CWE-%s\n", v.References.CWE[0])
		}
		body += fmt.Sprintf("\n%s\n", v.Description)

		if v.Remediation != "" {
			body += fmt.Sprintf("\n**Recommended Fix:**\n%s\n", v.Remediation)
		}

		comment := &github.PullRequestComment{
			Body: github.String(body),
			Path: github.String(v.FilePath),
			Line: github.Int(v.LineStart),
			Side: github.String("RIGHT"),
		}

		_, _, err := c.client.PullRequests.CreateComment(ctx, owner, repo, prNumber, comment)
		if err != nil {
			c.logger.WithError(err).WithFields(logrus.Fields{
				"file": v.FilePath,
				"line": v.LineStart,
			}).Warn("Failed to create inline comment")
			continue
		}
	}

	c.logger.WithFields(logrus.Fields{
		"owner":     owner,
		"repo":      repo,
		"pr_number": prNumber,
	}).Info("Added code annotations")

	return nil
}

// CreateIssue creates a GitHub issue for a vulnerability.
type IssueRequest struct {
	Title     string
	Body      string
	Labels    []string
	Assignees []string
}

// CreateIssues creates GitHub issues for critical vulnerabilities.
func (c *GitHubClient) CreateIssues(ctx context.Context, owner, repo string, findings []models.Vulnerability) ([]*github.Issue, error) {
	var createdIssues []*github.Issue

	for _, v := range findings {
		if v.Severity != models.SeverityCritical {
			continue // Only create issues for critical vulnerabilities
		}

		title := fmt.Sprintf("[SECURITY] %s in %s", v.Title, v.FilePath)

		body := fmt.Sprintf("## 🔴 Critical Security Vulnerability\n\n")
		body += fmt.Sprintf("**Severity:** %s\n", v.Severity)
		body += fmt.Sprintf("**Category:** %s\n", v.Category)
		body += fmt.Sprintf("**File:** `%s:%d`\n", v.FilePath, v.LineStart)

		if len(v.References.CWE) > 0 {
			body += fmt.Sprintf("**CWE:** [CWE-%s](https://cwe.mitre.org/data/definitions/%s.html)\n", v.References.CWE[0], v.References.CWE[0])
		}

		body += fmt.Sprintf("\n### Description\n%s\n", v.Description)

		if v.CodeSnippet != "" {
			body += fmt.Sprintf("\n### Vulnerable Code\n```\n%s\n```\n", v.CodeSnippet)
		}

		if v.Remediation != "" {
			body += fmt.Sprintf("\n### Recommended Fix\n%s\n", v.Remediation)
		}

		body += "\n---\n*Created by Code Security Auditor*"

		labels := []string{"security", "critical", "vulnerability"}

		issue, _, err := c.client.Issues.Create(ctx, owner, repo, &github.IssueRequest{
			Title:  github.String(title),
			Body:   github.String(body),
			Labels: &labels,
		})

		if err != nil {
			c.logger.WithError(err).WithField("title", title).Warn("Failed to create issue")
			continue
		}

		createdIssues = append(createdIssues, issue)
		c.logger.WithFields(logrus.Fields{
			"issue_number": issue.GetNumber(),
			"title":        title,
		}).Info("Created security issue")
	}

	return createdIssues, nil
}

// CreateSecurityIssue creates a single security issue with full details.
func (c *GitHubClient) CreateSecurityIssue(ctx context.Context, owner, repo string, scanID uuid.UUID, data ReportData) (*github.Issue, error) {
	critical := data.Summary.VulnsBySeverity[models.SeverityCritical]
	high := data.Summary.VulnsBySeverity[models.SeverityHigh]

	title := fmt.Sprintf("[SECURITY] %d Critical, %d High vulnerabilities found", critical, high)

	body := fmt.Sprintf("## 🔒 Security Scan Results\n\n")
	body += fmt.Sprintf("**Scan ID:** %s\n", scanID)
	body += fmt.Sprintf("**Repository:** %s\n", data.Repository.FullName)
	body += fmt.Sprintf("**Branch:** %s\n", data.Scan.Branch)
	body += fmt.Sprintf("**Risk Score:** %.1f/100\n\n", data.Summary.RiskScore)

	body += "### Summary\n"
	body += fmt.Sprintf("| Severity | Count |\n")
	body += "|----------|-------|\n"
	body += fmt.Sprintf("| Critical | %d |\n", critical)
	body += fmt.Sprintf("| High | %d |\n", high)
	body += fmt.Sprintf("| Medium | %d |\n", data.Summary.VulnsBySeverity[models.SeverityMedium])
	body += fmt.Sprintf("| Low | %d |\n\n", data.Summary.VulnsBySeverity[models.SeverityLow])

	body += "### Critical Vulnerabilities\n\n"
	count := 0
	for _, v := range data.Vulnerabilities {
		if v.Severity != models.SeverityCritical {
			continue
		}
		count++
		if count > 10 {
			body += fmt.Sprintf("\n*...and %d more critical vulnerabilities*\n", critical-10)
			break
		}
		body += fmt.Sprintf("- [ ] **%s** in `%s:%d`\n", v.Title, v.FilePath, v.LineStart)
	}

	body += "\n---\n*Created by Code Security Auditor*"

	labels := []string{"security", "scan-results"}
	if critical > 0 {
		labels = append(labels, "critical")
	}

	issue, _, err := c.client.Issues.Create(ctx, owner, repo, &github.IssueRequest{
		Title:  github.String(title),
		Body:   github.String(body),
		Labels: &labels,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create security issue: %w", err)
	}

	c.logger.WithField("issue_number", issue.GetNumber()).Info("Created security summary issue")

	return issue, nil
}

// FindExistingComment finds an existing comment by marker.
func (c *GitHubClient) FindExistingComment(ctx context.Context, owner, repo string, prNumber int, marker string) (*github.IssueComment, error) {
	comments, _, err := c.client.Issues.ListComments(ctx, owner, repo, prNumber, nil)
	if err != nil {
		return nil, err
	}

	for _, comment := range comments {
		if strings.Contains(comment.GetBody(), marker) {
			return comment, nil
		}
	}

	return nil, nil
}

// UpdateOrCreatePRComment updates existing comment or creates new one.
func (c *GitHubClient) UpdateOrCreatePRComment(ctx context.Context, pr *PullRequest, data ReportData) error {
	marker := "<!-- code-security-auditor -->"

	existing, err := c.FindExistingComment(ctx, pr.Owner, pr.Repo, pr.Number, marker)
	if err != nil {
		return err
	}

	comment := marker + "\n" + c.buildEnhancedPRComment(data)

	if existing != nil {
		_, _, err = c.client.Issues.EditComment(ctx, pr.Owner, pr.Repo, existing.GetID(), &github.IssueComment{
			Body: github.String(comment),
		})
		if err != nil {
			return fmt.Errorf("failed to update comment: %w", err)
		}
		c.logger.Info("Updated existing PR comment")
	} else {
		_, _, err = c.client.Issues.CreateComment(ctx, pr.Owner, pr.Repo, pr.Number, &github.IssueComment{
			Body: github.String(comment),
		})
		if err != nil {
			return fmt.Errorf("failed to create comment: %w", err)
		}
		c.logger.Info("Created new PR comment")
	}

	return nil
}
