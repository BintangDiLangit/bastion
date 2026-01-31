package license

import (
	"code-security-auditor/internal/dependency"
	"strings"
)

// Checker verifies license compliance
type Checker struct {
	allowedLicenses []string
	bannedLicenses  []string
}

func NewChecker() *Checker {
	return &Checker{
		allowedLicenses: []string{"MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Unlicense"},
		bannedLicenses:  []string{"GPL-3.0", "AGPL-3.0", "WTFPL"}, // Example strict policy
	}
}

// Check returns true if the license is allowed, false otherwise
// Returns a reason string if rejected
func (c *Checker) Check(license string) (bool, string) {
	if license == "" {
		return true, "unknown" // Policy: allow unknown? or warning?
	}

	license = strings.TrimSpace(license)

	// Check prohibited first
	for _, banned := range c.bannedLicenses {
		if strings.EqualFold(license, banned) {
			return false, "prohibited license"
		}
	}

	// Check allowed
	for _, allowed := range c.allowedLicenses {
		if strings.EqualFold(license, allowed) {
			return true, "allowed"
		}
	}

	// Default to warning/manual review for others
	return true, "needs review"
}

// AssessDependency checks a dependency and adds a compliance note if needed
// This assumes we might extend Dependency model with ComplianceStatus later
func (c *Checker) AssessDependency(dep dependency.Dependency) string {
	allowed, reason := c.Check(dep.License)
	if !allowed {
		return "Non-compliant: " + reason
	}
	return "Compliant"
}
