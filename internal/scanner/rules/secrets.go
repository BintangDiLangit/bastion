package rules

// bastion:ignore-file secrets detector signatures are data, not credentials

import (
	"fmt"
	"regexp"
	"strings"
)

// SecretsRule detects hardcoded secrets and credentials.
type SecretsRule struct {
	*BaseRule
	secretPatterns []secretPattern
}

type secretPattern struct {
	name        string
	regex       *regexp.Regexp
	description string
	severity    Severity
	confidence  float64
}

// NewSecretsRule creates a new secrets detection rule.
func NewSecretsRule() *SecretsRule {
	base := NewBaseRule(
		"secrets",
		"Hardcoded Secrets",
		"Hardcoded secret or credential detected",
		SeverityCritical,
		CategorySecrets,
	)

	// Secrets apply to all languages
	base.SetLanguages([]string{})

	base.SetRemediation(`Remove hardcoded secrets and use secure alternatives:

1. Environment Variables:
   export API_KEY="your-api-key"
   # In code: os.Getenv("API_KEY")

2. Secret Management Services:
   - AWS Secrets Manager
   - HashiCorp Vault
   - Azure Key Vault
   - Google Secret Manager

3. Configuration Files (outside repo):
   # config.local.yaml (gitignored)
   api_key: "your-api-key"

4. .env files (gitignored):
   API_KEY=your-api-key
   # Use dotenv library to load

5. For CI/CD:
   - GitHub Secrets
   - GitLab CI Variables
   - Environment variables in CI platform

IMPORTANT: If a secret was committed, assume it is compromised and rotate it immediately.
`)

	base.SetReferences([]string{
		"https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
		"https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
	},
	)

	rule := &SecretsRule{BaseRule: base}
	rule.initPatterns()

	return rule
}

// initPatterns initializes the secret detection patterns.
func (r *SecretsRule) initPatterns() {
	patterns := []struct {
		name        string
		pattern     string
		description string
		severity    Severity
		confidence  float64
	}{
		// API Keys
		{
			name:        "aws_access_key",
			pattern:     `(?i)(AKIA[0-9A-Z]{16})`,
			description: "AWS Access Key ID",
			severity:    SeverityCritical,
			confidence:  0.95,
		},
		{
			name:        "aws_secret_key",
			pattern:     `(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?`,
			description: "AWS Secret Access Key",
			severity:    SeverityCritical,
			confidence:  0.9,
		},
		{
			name:        "google_api_key",
			pattern:     `AIza[0-9A-Za-z\-_]{35}`,
			description: "Google API Key",
			severity:    SeverityCritical,
			confidence:  0.95,
		},
		{
			name:        "google_oauth",
			pattern:     `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`,
			description: "Google OAuth Client ID",
			severity:    SeverityHigh,
			confidence:  0.9,
		},
		{
			name:        "github_token",
			pattern:     `(?i)(gh[pousr]_[A-Za-z0-9_]{36,})`,
			description: "GitHub Token",
			severity:    SeverityCritical,
			confidence:  0.95,
		},
		{
			name:        "github_oauth",
			pattern:     `(?i)github[_\-]?oauth[_\-]?token\s*[:=]\s*["']?([A-Za-z0-9_]{40})["']?`,
			description: "GitHub OAuth Token",
			severity:    SeverityCritical,
			confidence:  0.9,
		},
		{
			name:        "slack_token",
			pattern:     `xox[baprs]-([0-9a-zA-Z]{10,48})`,
			description: "Slack Token",
			severity:    SeverityCritical,
			confidence:  0.95,
		},
		{
			name:        "slack_webhook",
			pattern:     `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`,
			description: "Slack Webhook URL",
			severity:    SeverityHigh,
			confidence:  0.95,
		},
		{
			name:        "stripe_key",
			pattern:     `(?i)(sk_live_[0-9a-zA-Z]{24,})`,
			description: "Stripe Live Secret Key",
			severity:    SeverityCritical,
			confidence:  0.95,
		},
		{
			name:        "stripe_restricted",
			pattern:     `(?i)(rk_live_[0-9a-zA-Z]{24,})`,
			description: "Stripe Restricted Key",
			severity:    SeverityCritical,
			confidence:  0.95,
		},
		{
			name:        "twilio_sid",
			pattern:     `AC[a-z0-9]{32}`,
			description: "Twilio Account SID",
			severity:    SeverityHigh,
			confidence:  0.9,
		},
		{
			name:        "twilio_token",
			pattern:     `(?i)twilio[_\-]?auth[_\-]?token\s*[:=]\s*["']?([a-z0-9]{32})["']?`,
			description: "Twilio Auth Token",
			severity:    SeverityCritical,
			confidence:  0.85,
		},
		{
			name:        "sendgrid_key",
			pattern:     `SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`,
			description: "SendGrid API Key",
			severity:    SeverityCritical,
			confidence:  0.95,
		},
		{
			name:        "mailchimp_key",
			pattern:     `[a-f0-9]{32}-us[0-9]{1,2}`,
			description: "Mailchimp API Key",
			severity:    SeverityHigh,
			confidence:  0.85,
		},
		// Private Keys
		{
			name:        "private_key",
			pattern:     `-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`,
			description: "Private Key",
			severity:    SeverityCritical,
			confidence:  0.95,
		},
		{
			name:        "pgp_private",
			pattern:     `-----BEGIN PGP PRIVATE KEY BLOCK-----`,
			description: "PGP Private Key",
			severity:    SeverityCritical,
			confidence:  0.95,
		},
		// Database Credentials
		{
			name:        "postgres_url",
			pattern:     `(?i)postgres(ql)?://[^:]+:[^@]+@[^/]+/[^\s"']+`,
			description: "PostgreSQL Connection String with Password",
			severity:    SeverityCritical,
			confidence:  0.9,
		},
		{
			name:        "mysql_url",
			pattern:     `(?i)mysql://[^:]+:[^@]+@[^/]+/[^\s"']+`,
			description: "MySQL Connection String with Password",
			severity:    SeverityCritical,
			confidence:  0.9,
		},
		{
			name:        "mongodb_url",
			pattern:     `(?i)mongodb(\+srv)?://[^:]+:[^@]+@[^/]+`,
			description: "MongoDB Connection String with Password",
			severity:    SeverityCritical,
			confidence:  0.9,
		},
		{
			name:        "redis_url",
			pattern:     `(?i)redis://[^:]*:[^@]+@[^/]+`,
			description: "Redis Connection String with Password",
			severity:    SeverityCritical,
			confidence:  0.9,
		},
		// Generic Secrets
		{
			name:        "generic_api_key",
			pattern:     `(?i)(api[_\-]?key|apikey)\s*[:=]\s*["']?([A-Za-z0-9_\-]{20,})["']?`,
			description: "Generic API Key",
			severity:    SeverityHigh,
			confidence:  0.7,
		},
		{
			name:        "generic_secret",
			pattern:     `(?i)(secret|token|password|passwd|pwd|auth)[_\-]?(key|token)?\s*[:=]\s*["']([^"'\s]{8,})["']`,
			description: "Generic Secret/Password",
			severity:    SeverityHigh,
			confidence:  0.75,
		},
		{
			name:        "bearer_token",
			pattern:     `(?i)(bearer\s+)[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+`,
			description: "Bearer Token (JWT)",
			severity:    SeverityHigh,
			confidence:  0.85,
		},
		{
			name:        "basic_auth",
			pattern:     `(?i)\bbasic\s+[A-Za-z0-9+/]{12,}={0,2}\b`,
			description: "Basic Auth Credentials",
			severity:    SeverityHigh,
			confidence:  0.8,
		},
		// Cloud Provider Secrets
		{
			name:        "azure_storage_key",
			pattern:     `(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+`,
			description: "Azure Storage Account Key",
			severity:    SeverityCritical,
			confidence:  0.95,
		},
		{
			name:        "gcp_service_account",
			pattern:     `"type"\s*:\s*"service_account"`,
			description: "GCP Service Account Key File",
			severity:    SeverityCritical,
			confidence:  0.9,
		},
		// NPM Token
		{
			name:        "npm_token",
			pattern:     `//registry\.npmjs\.org/:_authToken=([A-Za-z0-9\-_]+)`,
			description: "NPM Auth Token",
			severity:    SeverityCritical,
			confidence:  0.95,
		},
		// Heroku
		{
			name:        "heroku_api_key",
			pattern:     `(?i)heroku[_\-]?api[_\-]?key\s*[:=]\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']?`,
			description: "Heroku API Key",
			severity:    SeverityCritical,
			confidence:  0.9,
		},
	}

	for _, p := range patterns {
		regex, err := regexp.Compile(p.pattern)
		if err != nil {
			continue
		}
		r.secretPatterns = append(r.secretPatterns, secretPattern{
			name:        p.name,
			regex:       regex,
			description: p.description,
			severity:    p.severity,
			confidence:  p.confidence,
		})
	}
}

// Check implements the Rule interface.
func (r *SecretsRule) Check(file ParsedFile) []Finding {
	var vulns []Finding

	// Skip certain files
	if r.shouldSkipFile(file.GetPath()) {
		return vulns
	}

	for i, line := range file.GetLines() {
		lineNum := i + 1

		// Skip comments
		if r.isCommentLine(line, file.GetLanguage()) {
			continue
		}

		for _, pattern := range r.secretPatterns {
			loc := pattern.regex.FindStringIndex(line)
			if loc == nil {
				continue
			}
			// Additional validation
			if r.isLikelySecret(line, pattern) {
				vuln := Finding{
					RuleID:      r.ID(),
					Title:       fmt.Sprintf("%s: %s", r.Name(), pattern.description),
					Description: fmt.Sprintf("Detected potential %s in source code", pattern.description),
					Severity:    string(pattern.severity),
					Category:    string(r.GetCategory()),
					FilePath:    file.GetPath(),
					Line:        lineNum,
					Column:      loc[0] + 1,
					CodeSnippet: r.maskSecret(getCodeSnippet(file.GetLines(), lineNum, 2)),
					Remediation: r.remediation,
					CWE:         "CWE-798",
					Confidence:  pattern.confidence,
					References:  []string{"CWE-798"},
					// Masked so the raw secret never leaves the scanner.
					MatchText:  r.maskSecret(line[loc[0]:loc[1]]),
					MatchStart: loc[0],
					MatchEnd:   loc[1],
				}
				vulns = append(vulns, vuln)
			}
		}
	}

	return vulns
}

// shouldSkipFile checks if a file should be skipped.
func (r *SecretsRule) shouldSkipFile(path string) bool {
	// Skip test files with mock data
	skipPatterns := []string{
		"test", "_test", ".test.", "spec", "_spec",
		"mock", "fixture", "example", "sample",
		".md", ".txt", ".rst", "README",
		"CHANGELOG", "LICENSE",
	}

	pathLower := strings.ToLower(path)
	for _, pattern := range skipPatterns {
		if strings.Contains(pathLower, pattern) {
			// Don't skip if it's actually a secrets file
			if !strings.Contains(pathLower, "secret") {
				return true
			}
		}
	}

	return false
}

// isCommentLine checks if a line is a comment.
func (r *SecretsRule) isCommentLine(line, language string) bool {
	trimmed := strings.TrimSpace(line)

	// Single-line comments
	singleLineComments := map[string][]string{
		"go":         {"//"},
		"javascript": {"//"},
		"typescript": {"//"},
		"python":     {"#"},
		"ruby":       {"#"},
		"shell":      {"#"},
		"yaml":       {"#"},
		"java":       {"//"},
		"c":          {"//"},
		"cpp":        {"//"},
		"csharp":     {"//"},
		"php":        {"//", "#"},
	}

	if comments, ok := singleLineComments[language]; ok {
		for _, comment := range comments {
			if strings.HasPrefix(trimmed, comment) {
				return true
			}
		}
	}

	// Generic comment detection
	if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
		return true
	}

	return false
}

// isLikelySecret performs additional validation.
func (r *SecretsRule) isLikelySecret(line string, pattern secretPattern) bool {
	lineLower := strings.ToLower(line)

	// Check for placeholder/example indicators
	placeholders := []string{
		"example", "sample", "test", "demo", "dummy", "fake",
		"placeholder", "your-", "xxx", "changeme", "replace",
		"todo", "fixme", "<", ">", "${", "{{",
		"password123", "secret123", "admin123",
	}

	for _, placeholder := range placeholders {
		if strings.Contains(lineLower, placeholder) {
			return false
		}
	}

	// Check for environment variable references
	envPatterns := []string{
		"os.getenv", "os.environ", "process.env",
		"env(", "getenv(", "environ[",
	}

	for _, env := range envPatterns {
		if strings.Contains(lineLower, env) {
			return false
		}
	}

	return true
}

// maskSecret masks the secret in the code snippet.
func (r *SecretsRule) maskSecret(snippet string) string {
	// Mask potential secrets in the snippet
	for _, pattern := range r.secretPatterns {
		snippet = pattern.regex.ReplaceAllStringFunc(snippet, func(match string) string {
			if len(match) <= 8 {
				return "***REDACTED***"
			}
			return match[:4] + "***REDACTED***" + match[len(match)-4:]
		})
	}
	return snippet
}
