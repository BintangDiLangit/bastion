package rules

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"code-security-auditor/internal/models"
	"code-security-auditor/internal/scanner"
)

// SQLInjectionRule detects potential SQL injection vulnerabilities.
type SQLInjectionRule struct {
	*BaseRule
}

// NewSQLInjectionRule creates a new SQL injection detection rule.
func NewSQLInjectionRule() *SQLInjectionRule {
	base := NewBaseRule(
		"sql_injection",
		"SQL Injection",
		"Potential SQL injection vulnerability detected",
		models.SeverityCritical,
		models.CategoryInjection,
	)

	base.SetLanguages([]string{"go", "python", "javascript", "typescript", "java", "php", "ruby", "csharp"})

	base.SetRemediation(`Use parameterized queries or prepared statements instead of string concatenation.

For Go:
  db.Query("SELECT * FROM users WHERE id = $1", userID)

For Python:
  cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

For JavaScript/Node.js:
  db.query("SELECT * FROM users WHERE id = ?", [userId])

For Java:
  PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
  stmt.setInt(1, userId);
`)

	base.SetReferences(models.References{
		CWE:   []string{"CWE-89"},
		OWASP: []string{"A03:2021"},
		URLs: []string{
			"https://owasp.org/www-community/attacks/SQL_Injection",
			"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
		},
	})

	return &SQLInjectionRule{BaseRule: base}
}

// Check implements the Rule interface.
func (r *SQLInjectionRule) Check(ctx context.Context, file *scanner.ParsedFile) ([]models.Vulnerability, error) {
	var vulns []models.Vulnerability

	patterns := r.getPatterns(file.Language)

	for i, line := range file.Lines {
		lineNum := i + 1

		for _, pattern := range patterns {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}

			if pattern.regex.MatchString(line) {
				// Additional context check to reduce false positives
				if r.isLikelyVulnerable(line, file.Language) {
					vuln := models.Vulnerability{
						ID:          uuid.New(),
						RuleID:      r.ID(),
						Title:       r.Name(),
						Description: fmt.Sprintf("%s: %s", r.Description(), pattern.description),
						Severity:    r.Severity(),
						Category:    r.Category(),
						FilePath:    file.Path,
						LineStart:   lineNum,
						LineEnd:     lineNum,
						CodeSnippet: getCodeSnippet(file.Lines, lineNum, 3),
						Remediation: r.remediation,
						References:  r.references,
						Confidence:  pattern.confidence,
						Metadata: models.VulnMetadata{
							Language: file.Language,
						},
					}
					vulns = append(vulns, vuln)
				}
			}
		}
	}

	return vulns, nil
}

type sqlPattern struct {
	regex       *regexp.Regexp
	description string
	confidence  float64
}

// getPatterns returns SQL injection patterns for a language.
func (r *SQLInjectionRule) getPatterns(language string) []sqlPattern {
	var patterns []sqlPattern

	// Common SQL concatenation patterns
	commonPatterns := []struct {
		pattern     string
		description string
		confidence  float64
	}{
		{
			pattern:     `(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION).*\+\s*["']?\w+["']?\s*\+`,
			description: "String concatenation in SQL query",
			confidence:  0.8,
		},
		{
			pattern:     `(?i)(SELECT|INSERT|UPDATE|DELETE).*%[sv]`,
			description: "String formatting in SQL query",
			confidence:  0.75,
		},
		{
			pattern:     `(?i)(SELECT|INSERT|UPDATE|DELETE).*\$\{.*\}`,
			description: "Template literal in SQL query",
			confidence:  0.85,
		},
		{
			pattern:     `(?i)(SELECT|INSERT|UPDATE|DELETE).*\bfmt\.Sprintf\b`,
			description: "fmt.Sprintf used in SQL query",
			confidence:  0.9,
		},
	}

	// Language-specific patterns
	langPatterns := map[string][]struct {
		pattern     string
		description string
		confidence  float64
	}{
		"go": {
			{
				pattern:     `(?i)db\.(Query|Exec|QueryRow)\s*\(\s*["'].*\+`,
				description: "Concatenation in database query",
				confidence:  0.85,
			},
			{
				pattern:     `(?i)db\.(Query|Exec|QueryRow)\s*\(.*fmt\.Sprintf`,
				description: "fmt.Sprintf in database query",
				confidence:  0.9,
			},
		},
		"python": {
			{
				pattern:     `(?i)cursor\.(execute|executemany)\s*\([^,]*%`,
				description: "% formatting in cursor.execute",
				confidence:  0.85,
			},
			{
				pattern:     `(?i)cursor\.(execute|executemany)\s*\([^,]*\.format\(`,
				description: ".format() in cursor.execute",
				confidence:  0.85,
			},
			{
				pattern:     `(?i)cursor\.(execute|executemany)\s*\(.*f["']`,
				description: "f-string in cursor.execute",
				confidence:  0.9,
			},
		},
		"javascript": {
			{
				pattern:     "(?i)(query|execute)\\s*\\(\\s*`.*\\$\\{",
				description: "Template literal in query",
				confidence:  0.85,
			},
			{
				pattern:     `(?i)(query|execute)\s*\(\s*["'].*\+`,
				description: "String concatenation in query",
				confidence:  0.8,
			},
		},
		"typescript": {
			{
				pattern:     "(?i)(query|execute)\\s*\\(\\s*`.*\\$\\{",
				description: "Template literal in query",
				confidence:  0.85,
			},
			{
				pattern:     `(?i)(query|execute)\s*\(\s*["'].*\+`,
				description: "String concatenation in query",
				confidence:  0.8,
			},
		},
		"java": {
			{
				pattern:     `(?i)(executeQuery|executeUpdate|execute)\s*\([^)]*\+`,
				description: "String concatenation in execute",
				confidence:  0.85,
			},
			{
				pattern:     `(?i)Statement\s+\w+\s*=.*createStatement`,
				description: "Using Statement instead of PreparedStatement",
				confidence:  0.7,
			},
		},
		"php": {
			{
				pattern:     `(?i)(mysql_query|mysqli_query|pg_query)\s*\([^)]*\.\s*\$`,
				description: "Variable concatenation in query",
				confidence:  0.9,
			},
			{
				pattern:     `(?i)\$\w+\s*=\s*["'].*SELECT.*["']\s*\.\s*\$`,
				description: "SQL string with variable concatenation",
				confidence:  0.85,
			},
		},
		"ruby": {
			{
				pattern:     `(?i)(where|find_by_sql|execute)\s*\([^)]*#\{`,
				description: "String interpolation in query",
				confidence:  0.85,
			},
			{
				pattern:     `(?i)(where|find_by_sql|execute)\s*\([^)]*\+`,
				description: "String concatenation in query",
				confidence:  0.8,
			},
		},
		"csharp": {
			{
				pattern:     `(?i)(ExecuteReader|ExecuteNonQuery|ExecuteScalar)\s*\([^)]*\+`,
				description: "String concatenation in Execute",
				confidence:  0.85,
			},
			{
				pattern:     `(?i)SqlCommand\s*\([^)]*\+`,
				description: "String concatenation in SqlCommand",
				confidence:  0.85,
			},
		},
	}

	// Add common patterns
	for _, p := range commonPatterns {
		regex, err := regexp.Compile(p.pattern)
		if err == nil {
			patterns = append(patterns, sqlPattern{
				regex:       regex,
				description: p.description,
				confidence:  p.confidence,
			})
		}
	}

	// Add language-specific patterns
	if langPats, ok := langPatterns[language]; ok {
		for _, p := range langPats {
			regex, err := regexp.Compile(p.pattern)
			if err == nil {
				patterns = append(patterns, sqlPattern{
					regex:       regex,
					description: p.description,
					confidence:  p.confidence,
				})
			}
		}
	}

	return patterns
}

// isLikelyVulnerable performs additional checks to reduce false positives.
func (r *SQLInjectionRule) isLikelyVulnerable(line, language string) bool {
	// Check for safe patterns that indicate parameterized queries
	safePatterns := []string{
		// Go
		"$1", "$2", "$3", // PostgreSQL placeholders
		"?",              // MySQL placeholders
		// Python
		"%s,",   // Proper parameterized query
		"%(", // Named parameters
		// General
		":param", ":id", ":name", // Named parameters
	}

	for _, safe := range safePatterns {
		if strings.Contains(line, safe) {
			// Has placeholder, might be safe
			// Additional check: is there also concatenation?
			if !strings.Contains(line, "+") && !strings.Contains(line, "fmt.Sprintf") {
				return false
			}
		}
	}

	// Check if it's a comment
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
		return false
	}

	return true
}
