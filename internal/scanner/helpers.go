package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
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
		cvssScore, cvssVector := rules.CVSSForRule(f.RuleID)
		vulns[i] = models.Vulnerability{
			ID:          uuid.New(),
			Fingerprint: fingerprint,
			ScanID:      scanID,
			RuleID:      f.RuleID,
			Title:       f.Title,
			Description: f.Description,
			Severity:    models.Severity(f.Severity),
			Category:    mapCategory(f.Category),
			FilePath:    f.FilePath,
			LineStart:   f.Line,
			LineEnd:     f.LineEnd,
			CodeSnippet: f.CodeSnippet,
			Remediation: f.Remediation,
			References:  buildReferences(f),
			Confidence:  f.Confidence,
			CVSSScore:   cvssScore,
			CVSSVector:  cvssVector,
			CreatedAt:   time.Now(),
		}
	}
	return vulns
}

var cweRe = regexp.MustCompile(`^CWE-\d+$`)

// buildReferences folds a rule finding's single CWE string and its free-form
// References slice into the typed models.References buckets.
//
// The rules are inconsistent about where they put things: most set f.CWE and
// stash OWASP cheatsheet URLs in f.References, but the secrets rule also puts
// the literal "CWE-798" into f.References. Route by shape, not by position, and
// dedupe CWEs so that overlap collapses to one entry.
func buildReferences(f rules.Finding) models.References {
	var r models.References
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		switch {
		case cweRe.MatchString(s):
			if !slices.Contains(r.CWE, s) {
				r.CWE = append(r.CWE, s)
			}
		case strings.HasPrefix(s, "http") && strings.Contains(s, "owasp.org"):
			if !slices.Contains(r.OWASP, s) {
				r.OWASP = append(r.OWASP, s)
			}
		default:
			if !slices.Contains(r.URLs, s) {
				r.URLs = append(r.URLs, s)
			}
		}
	}
	add(f.CWE)
	for _, ref := range f.References {
		add(ref)
	}
	return r
}

// mapCategory translates a rule-engine category string into the models category
// enum. The two vocabularies differ (e.g. the rules emit "sql_injection" but
// the models enum only has "injection"); an unknown value falls back to
// CategoryOther rather than minting an invalid enum member.
func mapCategory(c string) models.VulnerabilityCategory {
	switch rules.Category(c) {
	case rules.CategorySQLInjection, rules.CategoryCommandInjection,
		rules.CategoryPathTraversal, rules.CategoryInsecureDeserialization:
		return models.CategoryInjection
	case rules.CategoryXSS:
		return models.CategoryXSS
	case rules.CategorySecrets, rules.CategoryHardcodedCredentials:
		return models.CategorySecrets
	case rules.CategoryDependency:
		return models.CategoryDependency
	case rules.CategoryWeakCrypto, rules.CategoryInsecureRandom:
		return models.CategoryCryptography
	case rules.CategoryMisconfiguration:
		return models.CategoryConfiguration
	case rules.CategoryCodeQuality:
		return models.CategoryCodeQuality
	default:
		return models.CategoryOther
	}
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
