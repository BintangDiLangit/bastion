package reporter

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-github/v57/github"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/code-security-auditor/internal/models"
)

// GitHubReporter posts scan results to GitHub PRs.
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
	sb.WriteString("*Scan performed by [Code Security Auditor](https://github.com/code-security-auditor)*")

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
