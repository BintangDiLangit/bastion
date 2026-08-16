package rules

import (
	"fmt"
	"regexp"
	"strings"
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
		"Potential SQL injection vulnerability",
		SeverityCritical,
		CategorySQLInjection,
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

	base.SetReferences([]string{
		"https://owasp.org/Top10/A03_2021-Injection/",
		"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
	},
	)

	rule := &SQLInjectionRule{BaseRule: base}
	return rule
}

// Check implements the Rule interface.
func (r *SQLInjectionRule) Check(file ParsedFile) []Finding {
	var vulns []Finding

	for i, line := range file.GetLines() {
		lineNum := i + 1

		patterns := r.getPatterns(file.GetLanguage())
		for _, pattern := range patterns {
			loc := pattern.regex.FindStringIndex(line)
			if loc == nil {
				continue
			}
			vuln := Finding{
				RuleID:      r.ID(),
				Title:       r.Name(),
				Description: fmt.Sprintf("Potential SQL injection detected: %s", strings.TrimSpace(line)),
				Severity:    string(r.GetSeverity()),
				Category:    string(r.GetCategory()),
				FilePath:    file.GetPath(),
				Line:        lineNum,
				Column:      loc[0] + 1,
				CodeSnippet: getCodeSnippet(file.GetLines(), lineNum, 2),
				Remediation: r.remediation,
				CWE:         "CWE-89",
				Confidence:  0.8,
				References:  r.GetReferences(),
				MatchText:   line[loc[0]:loc[1]],
				MatchStart:  loc[0],
				MatchEnd:    loc[1],
			}
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

type sqlPattern struct {
	regex       *regexp.Regexp
	description string
	confidence  float64
}

// getPatterns returns SQL injection patterns for a language.
func (r *SQLInjectionRule) getPatterns(language string) []sqlPattern {
	var patterns []sqlPattern

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
		"?", // MySQL placeholders
		// Python
		"%s,", // Proper parameterized query
		"%(",  // Named parameters
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
