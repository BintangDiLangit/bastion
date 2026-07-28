package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
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
	occurrences := make(map[string]int)
	for i, f := range findings {
		fingerprint := findingFingerprint(f)
		occurrence := occurrences[fingerprint]
		occurrences[fingerprint]++
		if occurrence > 0 {
			sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d", fingerprint, occurrence)))
			fingerprint = hex.EncodeToString(sum[:16])
		}
		vulns[i] = models.Vulnerability{
			ID:          uuid.New(),
			Fingerprint: fingerprint,
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

var snippetLine = regexp.MustCompile(`(?m)^>\s*\d+\s*\|\s*(.*)$`)

func findingFingerprint(f rules.Finding) string {
	source := ""
	if match := snippetLine.FindStringSubmatch(f.CodeSnippet); len(match) == 2 {
		source = strings.Join(strings.Fields(match[1]), " ")
	}
	value := strings.ToLower(f.RuleID) + "\x00" + filepath.ToSlash(filepath.Clean(f.FilePath)) + "\x00" + source
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:16])
}
