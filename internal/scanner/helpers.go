package scanner

import (
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"code-security-auditor/internal/config"
	"code-security-auditor/internal/models"
	"code-security-auditor/internal/scanner/rules"
)

// mustNewGitManager creates a new GitManager or panics on error.
func mustNewGitManager(cfg config.GitConfig, logger *logrus.Logger) *GitManager {
	gm, err := NewGitManager(cfg, logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize GitManager")
		return nil
	}
	return gm
}

// convertFindingsToVulnerabilities converts rule findings to vulnerabilities.
func convertFindingsToVulnerabilities(findings []rules.Finding, scanID uuid.UUID) []models.Vulnerability {
	vulns := make([]models.Vulnerability, len(findings))
	for i, f := range findings {
		vulns[i] = models.Vulnerability{
			ID:          uuid.New(),
			ScanID:      scanID,
			RuleID:      f.RuleID,
			Title:       f.Title,
			Description: f.Description,
			Severity:    models.Severity(f.Severity),
			Category:    models.VulnerabilityCategory(f.Category),
			FilePath:    f.FilePath,
			LineStart:   f.Line,
			LineEnd:     f.LineEnd,
			CodeSnippet: f.CodeSnippet,
			Remediation: f.Remediation,
			Confidence:  f.Confidence,
			CreatedAt:   time.Now(),
		}
	}
	return vulns
}
