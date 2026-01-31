package rules

import (
	"bufio"
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"code-security-auditor/internal/models"
	"code-security-auditor/internal/scanner"
)

// DependencyRule detects vulnerable or outdated dependencies.
type DependencyRule struct {
	*BaseRule
	knownVulnerabilities map[string][]VulnerableDependency
}

// VulnerableDependency represents a known vulnerable dependency.
type VulnerableDependency struct {
	Name            string
	VulnerableRange string // Semver range
	FixedVersion    string
	CVE             string
	Severity        models.Severity
	Description     string
}

// NewDependencyRule creates a new dependency vulnerability rule.
func NewDependencyRule() *DependencyRule {
	base := NewBaseRule(
		"dependency",
		"Vulnerable Dependency",
		"Potentially vulnerable dependency detected",
		models.SeverityHigh,
		models.CategoryDependency,
	)

	base.SetLanguages([]string{}) // Check dependency files for all languages

	base.SetRemediation(`Update vulnerable dependencies to their fixed versions:

For Go:
  go get -u package@latest
  go mod tidy

For JavaScript/Node.js:
  npm update package-name
  npm audit fix

For Python:
  pip install --upgrade package-name
  pip-audit

For Ruby:
  bundle update gem-name
  bundle audit

Best Practices:
1. Regularly update dependencies
2. Use automated dependency scanning (Dependabot, Snyk, etc.)
3. Pin dependency versions in production
4. Review changelogs before major updates
5. Run tests after updating dependencies
`)

	base.SetReferences(models.References{
		CWE:   []string{"CWE-1104"},
		OWASP: []string{"A06:2021"},
		URLs: []string{
			"https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
		},
	})

	rule := &DependencyRule{
		BaseRule:             base,
		knownVulnerabilities: make(map[string][]VulnerableDependency),
	}

	rule.initKnownVulnerabilities()

	return rule
}

// initKnownVulnerabilities initializes the database of known vulnerabilities.
func (r *DependencyRule) initKnownVulnerabilities() {
	// Note: In production, this would be loaded from an external database
	// like the GitHub Advisory Database, NVD, or a commercial vulnerability database

	// Example known vulnerabilities (simplified for demonstration)
	r.knownVulnerabilities = map[string][]VulnerableDependency{
		// JavaScript/Node.js
		"lodash": {
			{
				Name:            "lodash",
				VulnerableRange: "<4.17.21",
				FixedVersion:    "4.17.21",
				CVE:             "CVE-2021-23337",
				Severity:        models.SeverityHigh,
				Description:     "Command Injection vulnerability",
			},
		},
		"minimist": {
			{
				Name:            "minimist",
				VulnerableRange: "<1.2.6",
				FixedVersion:    "1.2.6",
				CVE:             "CVE-2021-44906",
				Severity:        models.SeverityCritical,
				Description:     "Prototype Pollution",
			},
		},
		"axios": {
			{
				Name:            "axios",
				VulnerableRange: "<0.21.2",
				FixedVersion:    "0.21.2",
				CVE:             "CVE-2021-3749",
				Severity:        models.SeverityHigh,
				Description:     "Server-Side Request Forgery",
			},
		},
		"express": {
			{
				Name:            "express",
				VulnerableRange: "<4.19.0",
				FixedVersion:    "4.19.0",
				CVE:             "CVE-2024-29041",
				Severity:        models.SeverityMedium,
				Description:     "Open Redirect vulnerability",
			},
		},
		// Python
		"django": {
			{
				Name:            "django",
				VulnerableRange: "<4.2.11",
				FixedVersion:    "4.2.11",
				CVE:             "CVE-2024-27351",
				Severity:        models.SeverityHigh,
				Description:     "Potential denial-of-service in intcomma filter",
			},
		},
		"requests": {
			{
				Name:            "requests",
				VulnerableRange: "<2.31.0",
				FixedVersion:    "2.31.0",
				CVE:             "CVE-2023-32681",
				Severity:        models.SeverityMedium,
				Description:     "Information disclosure vulnerability",
			},
		},
		"flask": {
			{
				Name:            "flask",
				VulnerableRange: "<2.3.2",
				FixedVersion:    "2.3.2",
				CVE:             "CVE-2023-30861",
				Severity:        models.SeverityHigh,
				Description:     "Possible disclosure of permanent session cookie",
			},
		},
		// Go
		"golang.org/x/crypto": {
			{
				Name:            "golang.org/x/crypto",
				VulnerableRange: "<0.17.0",
				FixedVersion:    "0.17.0",
				CVE:             "CVE-2023-48795",
				Severity:        models.SeverityMedium,
				Description:     "SSH handshake prefix truncation attack",
			},
		},
		// Ruby
		"rails": {
			{
				Name:            "rails",
				VulnerableRange: "<7.0.8",
				FixedVersion:    "7.0.8",
				CVE:             "CVE-2023-38037",
				Severity:        models.SeverityMedium,
				Description:     "Possible ReDoS in block_format",
			},
		},
	}
}

// Check implements the Rule interface.
func (r *DependencyRule) Check(ctx context.Context, file *scanner.ParsedFile) ([]models.Vulnerability, error) {
	var vulns []models.Vulnerability

	// Check if this is a dependency file
	depType := r.detectDependencyFile(file.Path)
	if depType == "" {
		return vulns, nil
	}

	// Parse dependencies based on file type
	deps := r.parseDependencies(file, depType)

	// Check each dependency against known vulnerabilities
	for _, dep := range deps {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if knownVulns, exists := r.knownVulnerabilities[dep.Name]; exists {
			for _, kv := range knownVulns {
				if r.isVersionVulnerable(dep.Version, kv.VulnerableRange) {
					vuln := models.Vulnerability{
						ID:          uuid.New(),
						RuleID:      r.ID(),
						Title:       fmt.Sprintf("Vulnerable dependency: %s", dep.Name),
						Description: fmt.Sprintf("%s version %s is vulnerable to %s: %s", dep.Name, dep.Version, kv.CVE, kv.Description),
						Severity:    kv.Severity,
						Category:    r.Category(),
						FilePath:    file.Path,
						LineStart:   dep.Line,
						LineEnd:     dep.Line,
						CodeSnippet: getCodeSnippet(file.Lines, dep.Line, 2),
						Remediation: fmt.Sprintf("Update %s to version %s or later.\n\n%s", dep.Name, kv.FixedVersion, r.remediation),
						References: models.References{
							CVE:   []string{kv.CVE},
							CWE:   r.references.CWE,
							OWASP: r.references.OWASP,
							URLs:  r.references.URLs,
						},
						Confidence: 0.9,
						Metadata: models.VulnMetadata{
							Language: depType,
							Tags:     []string{kv.CVE},
							CustomFields: map[string]string{
								"current_version": dep.Version,
								"fixed_version":   kv.FixedVersion,
							},
						},
					}
					vulns = append(vulns, vuln)
				}
			}
		}
	}

	return vulns, nil
}

// detectDependencyFile identifies the type of dependency file.
func (r *DependencyRule) detectDependencyFile(path string) string {
	pathLower := strings.ToLower(path)

	switch {
	case strings.HasSuffix(pathLower, "package.json"):
		return "javascript"
	case strings.HasSuffix(pathLower, "package-lock.json"):
		return "javascript"
	case strings.HasSuffix(pathLower, "yarn.lock"):
		return "javascript"
	case strings.HasSuffix(pathLower, "go.mod"):
		return "go"
	case strings.HasSuffix(pathLower, "go.sum"):
		return "go"
	case strings.HasSuffix(pathLower, "requirements.txt"):
		return "python"
	case strings.HasSuffix(pathLower, "pipfile"):
		return "python"
	case strings.HasSuffix(pathLower, "pipfile.lock"):
		return "python"
	case strings.HasSuffix(pathLower, "setup.py"):
		return "python"
	case strings.HasSuffix(pathLower, "pyproject.toml"):
		return "python"
	case strings.HasSuffix(pathLower, "gemfile"):
		return "ruby"
	case strings.HasSuffix(pathLower, "gemfile.lock"):
		return "ruby"
	case strings.HasSuffix(pathLower, "composer.json"):
		return "php"
	case strings.HasSuffix(pathLower, "composer.lock"):
		return "php"
	case strings.HasSuffix(pathLower, "cargo.toml"):
		return "rust"
	case strings.HasSuffix(pathLower, "cargo.lock"):
		return "rust"
	case strings.HasSuffix(pathLower, "pom.xml"):
		return "java"
	case strings.HasSuffix(pathLower, "build.gradle"):
		return "java"
	}

	return ""
}

// Dependency represents a parsed dependency.
type Dependency struct {
	Name    string
	Version string
	Line    int
}

// parseDependencies parses dependencies from a file.
func (r *DependencyRule) parseDependencies(file *scanner.ParsedFile, depType string) []Dependency {
	switch depType {
	case "javascript":
		return r.parseJavaScriptDeps(file)
	case "go":
		return r.parseGoDeps(file)
	case "python":
		return r.parsePythonDeps(file)
	case "ruby":
		return r.parseRubyDeps(file)
	default:
		return nil
	}
}

// parseJavaScriptDeps parses package.json dependencies.
func (r *DependencyRule) parseJavaScriptDeps(file *scanner.ParsedFile) []Dependency {
	var deps []Dependency

	// Simple regex-based parsing
	depPattern := regexp.MustCompile(`"([^"]+)"\s*:\s*"([^"]+)"`)

	inDeps := false
	for i, line := range file.Lines {
		trimmed := strings.TrimSpace(line)

		// Track if we're in dependencies section
		if strings.Contains(trimmed, `"dependencies"`) || strings.Contains(trimmed, `"devDependencies"`) {
			inDeps = true
			continue
		}

		if inDeps {
			if trimmed == "}" {
				inDeps = false
				continue
			}

			matches := depPattern.FindStringSubmatch(line)
			if len(matches) == 3 {
				name := matches[1]
				version := strings.TrimPrefix(matches[2], "^")
				version = strings.TrimPrefix(version, "~")

				deps = append(deps, Dependency{
					Name:    name,
					Version: version,
					Line:    i + 1,
				})
			}
		}
	}

	return deps
}

// parseGoDeps parses go.mod dependencies.
func (r *DependencyRule) parseGoDeps(file *scanner.ParsedFile) []Dependency {
	var deps []Dependency

	// Parse require statements
	requirePattern := regexp.MustCompile(`^\s*([^\s]+)\s+v?([0-9][^\s]*)`)
	inRequire := false

	for i, line := range file.Lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "require (") {
			inRequire = true
			continue
		}

		if inRequire {
			if trimmed == ")" {
				inRequire = false
				continue
			}

			matches := requirePattern.FindStringSubmatch(trimmed)
			if len(matches) == 3 {
				deps = append(deps, Dependency{
					Name:    matches[1],
					Version: matches[2],
					Line:    i + 1,
				})
			}
		}

		// Single line require
		if strings.HasPrefix(trimmed, "require ") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 3 {
				version := strings.TrimPrefix(parts[2], "v")
				deps = append(deps, Dependency{
					Name:    parts[1],
					Version: version,
					Line:    i + 1,
				})
			}
		}
	}

	return deps
}

// parsePythonDeps parses requirements.txt dependencies.
func (r *DependencyRule) parsePythonDeps(file *scanner.ParsedFile) []Dependency {
	var deps []Dependency

	reqPattern := regexp.MustCompile(`^([a-zA-Z0-9_-]+)\s*(?:==|>=|<=|~=|>|<)\s*([0-9][^\s;#]*)`)

	sc := bufio.NewScanner(strings.NewReader(string(file.Content)))
	lineNum := 0

	for sc.Scan() {
		lineNum++
		line := sc.Text()
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		matches := reqPattern.FindStringSubmatch(trimmed)
		if len(matches) == 3 {
			deps = append(deps, Dependency{
				Name:    strings.ToLower(matches[1]),
				Version: matches[2],
				Line:    lineNum,
			})
		}
	}

	return deps
}

// parseRubyDeps parses Gemfile dependencies.
func (r *DependencyRule) parseRubyDeps(file *scanner.ParsedFile) []Dependency {
	var deps []Dependency

	gemPattern := regexp.MustCompile(`gem\s+['"]([^'"]+)['"](?:,\s*['"]([^'"]+)['"])?`)

	for i, line := range file.Lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		matches := gemPattern.FindStringSubmatch(line)
		if len(matches) >= 2 {
			dep := Dependency{
				Name: matches[1],
				Line: i + 1,
			}
			if len(matches) >= 3 && matches[2] != "" {
				dep.Version = strings.TrimPrefix(matches[2], "~>")
				dep.Version = strings.TrimPrefix(dep.Version, ">=")
				dep.Version = strings.TrimSpace(dep.Version)
			}
			deps = append(deps, dep)
		}
	}

	return deps
}

// isVersionVulnerable checks if a version is in the vulnerable range.
func (r *DependencyRule) isVersionVulnerable(version, vulnerableRange string) bool {
	// Simplified version comparison
	// In production, use a proper semver library

	if vulnerableRange == "" || version == "" {
		return false
	}

	// Extract the comparison operator and version
	var operator string
	var rangeVersion string

	if strings.HasPrefix(vulnerableRange, "<=") {
		operator = "<="
		rangeVersion = strings.TrimPrefix(vulnerableRange, "<=")
	} else if strings.HasPrefix(vulnerableRange, "<") {
		operator = "<"
		rangeVersion = strings.TrimPrefix(vulnerableRange, "<")
	} else if strings.HasPrefix(vulnerableRange, ">=") {
		operator = ">="
		rangeVersion = strings.TrimPrefix(vulnerableRange, ">=")
	} else if strings.HasPrefix(vulnerableRange, ">") {
		operator = ">"
		rangeVersion = strings.TrimPrefix(vulnerableRange, ">")
	} else {
		// Exact match
		return version == vulnerableRange
	}

	// Simple string comparison (works for simple semver)
	cmp := compareVersions(version, rangeVersion)

	switch operator {
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	}

	return false
}

// compareVersions compares two version strings.
func compareVersions(v1, v2 string) int {
	// Simple version comparison
	// In production, use a proper semver library
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var p1, p2 int
		if i < len(parts1) {
			fmt.Sscanf(parts1[i], "%d", &p1)
		}
		if i < len(parts2) {
			fmt.Sscanf(parts2[i], "%d", &p2)
		}

		if p1 < p2 {
			return -1
		}
		if p1 > p2 {
			return 1
		}
	}

	return 0
}
