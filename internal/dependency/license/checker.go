package license

import (
	"context"
	"fmt"
	"strings"

	"code-security-auditor/internal/dependency"

	"github.com/sirupsen/logrus"
)

type LicenseChecker struct {
	rules  *LicenseRules
	logger *logrus.Logger
}

type LicenseRules struct {
	Allowed        []string            // Permitted licenses
	Denied         []string            // Forbidden licenses
	ReviewRequired []string            // Need manual review
	Compatibility  map[string][]string // License compatibility matrix
}

type LicenseIssue struct {
	Dependency     dependency.Dependency
	License        string
	IssueType      LicenseIssueType
	Severity       string
	Explanation    string
	Recommendation string
}

type LicenseIssueType string

const (
	Forbidden    LicenseIssueType = "forbidden"
	Incompatible LicenseIssueType = "incompatible"
	NeedsReview  LicenseIssueType = "needs_review"
	Missing      LicenseIssueType = "missing"
	Ambiguous    LicenseIssueType = "ambiguous"
)

func NewChecker(logger *logrus.Logger) *LicenseChecker {
	// Default rules - ideally loaded from config
	rules := &LicenseRules{
		Allowed: []string{
			"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense",
		},
		Denied: []string{
			"GPL-3.0", "AGPL-3.0", "WTFPL",
		},
		ReviewRequired: []string{
			"LGPL-2.1", "LGPL-3.0", "MPL-2.0", "CDDL-1.0",
		},
		Compatibility: map[string][]string{
			"MIT":         {"MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Unlicense", "LGPL-2.1", "LGPL-3.0", "GPL-2.0", "GPL-3.0", "AGPL-3.0"},
			"Apache-2.0":  {"MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Unlicense", "LGPL-3.0", "GPL-3.0", "AGPL-3.0"},
			"GPL-3.0":     {"MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Unlicense", "GPL-2.0", "GPL-3.0"}, // Simplified
			"Proprietary": {},
		},
	}
	return &LicenseChecker{
		rules:  rules,
		logger: logger,
	}
}

// CheckDependency verifies compliance for a single dependency
func (c *LicenseChecker) CheckDependency(ctx context.Context, dep dependency.Dependency) (*LicenseIssue, error) {
	license := dep.License
	if license == "" {
		return &LicenseIssue{
			Dependency:     dep,
			License:        "Unknown",
			IssueType:      Missing,
			Severity:       "MEDIUM",
			Explanation:    "License not detected",
			Recommendation: "Manually verify license",
		}, nil
	}

	// 1. Check Denied
	if contains(c.rules.Denied, license) {
		return &LicenseIssue{
			Dependency:     dep,
			License:        license,
			IssueType:      Forbidden,
			Severity:       "HIGH",
			Explanation:    fmt.Sprintf("License %s is explicitly forbidden by policy", license),
			Recommendation: "Replace with compliant alternative",
		}, nil
	}

	// 2. Check Review Required
	if contains(c.rules.ReviewRequired, license) {
		return &LicenseIssue{
			Dependency:     dep,
			License:        license,
			IssueType:      NeedsReview,
			Severity:       "MEDIUM",
			Explanation:    fmt.Sprintf("License %s requires legal review", license),
			Recommendation: "Submit for manual review",
		}, nil
	}

	// 3. Check Allowed (Implicitly allowed if not denied/review? Or strict whitelist?)
	// Strict whitelist approach:
	if !contains(c.rules.Allowed, license) {
		return &LicenseIssue{
			Dependency:     dep,
			License:        license,
			IssueType:      Ambiguous,
			Severity:       "LOW",
			Explanation:    fmt.Sprintf("License %s is not explicitly allowed", license),
			Recommendation: "Review and add to allowed list if appropriate",
		}, nil
	}

	return nil, nil // Compliant
}

// CheckCompatibility checks if dependency license is compatible with project license
func (c *LicenseChecker) CheckCompatibility(projectLicense string, depLicense string) (bool, string) {
	compatibleLicenses, ok := c.rules.Compatibility[projectLicense]
	if !ok {
		// If project license unknown, we can't strict check, but generic denied still applies
		return true, "Project license not in compatibility matrix"
	}

	if contains(compatibleLicenses, depLicense) {
		return true, "Compatible"
	}

	return false, fmt.Sprintf("%s is generally not compatible with project license %s", depLicense, projectLicense)
}

func contains(list []string, item string) bool {
	for _, s := range list {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}
