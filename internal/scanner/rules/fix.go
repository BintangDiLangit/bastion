package rules

import (
	"regexp"

	"github.com/BintangDiLangit/bastion/internal/models"
)

// Suggested fixes, hand-authored per rule, mirroring cvss.go.
//
// A fix is a machine-readable companion to the human-prose Remediation. For
// most rules it is guidance: Before is the real matched code, After is a secure
// exemplar an agent or human adapts. A rule whose secure form is a deterministic,
// value-restoring token flip carries an `apply` func; those, and only those,
// become models.FixSafeReplace and are applied by `bastion fix --write`.
//
// Keyed by rule ID across BOTH namespaces, exactly like cvssByRule. A test
// asserts every cvssByRule ID has an entry here, so a new rule cannot ship
// without a considered fix.
type fixTemplate struct {
	summary  string
	exemplar string // secure form, shown as After for guidance fixes
	// apply returns the deterministic replacement for the matched text and true
	// when the match is one of the safe, mechanically-fixable forms. nil ⇒ the
	// rule is guidance-only.
	apply func(match string) (string, bool)
}

// tlsReenable flips the value-restoring TLS-verification toggles. Each entry is
// anchored to its own flag so a match like `InsecureSkipVerify: true` becomes
// `InsecureSkipVerify: false` without disturbing anything else on the line.
var tlsReenable = []struct {
	re   *regexp.Regexp
	repl string
}{
	{regexp.MustCompile(`(?i)(InsecureSkipVerify\s*:\s*)true`), "${1}false"},
	{regexp.MustCompile(`(?i)(rejectUnauthorized\s*:\s*)false`), "${1}true"},
	{regexp.MustCompile(`(verify\s*=\s*)False`), "${1}True"},
	{regexp.MustCompile(`(?i)(CURLOPT_SSL_VERIFYPEER\s*,\s*)(?:0|false)`), "${1}1"},
}

func applyTLS(match string) (string, bool) {
	for _, t := range tlsReenable {
		if t.re.MatchString(match) {
			return t.re.ReplaceAllString(match, t.repl), true
		}
	}
	// e.g. ssl._create_unverified_context — real, but no safe drop-in.
	return "", false
}

var fixByRule = map[string]fixTemplate{
	// Interface rules
	"sql_injection": {
		summary:  "Pass user input as a query parameter instead of concatenating it.",
		exemplar: `db.Query("SELECT * FROM users WHERE id = $1", userID)`,
	},
	"xss": {
		summary:  "Escape or sanitize the value before it reaches the page.",
		exemplar: `template.HTMLEscapeString(userInput) // or a context-aware sanitizer`,
	},
	"secrets": {
		summary:  "Remove the hardcoded secret; read it from the environment or a secret manager.",
		exemplar: `apiKey := os.Getenv("API_KEY")`,
	},
	"dependency": {
		summary:  "Upgrade the dependency to a patched version.",
		exemplar: `// bump to the fixed version in your manifest, then re-lock`,
	},

	// Pattern rules
	"RULE-SQL-001": {
		summary:  "Use a parameterized query instead of string concatenation.",
		exemplar: `db.Query("SELECT * FROM users WHERE id = $1", userID)`,
	},
	"RULE-XSS-001": {
		summary:  "Escape the value for its output context before rendering.",
		exemplar: `element.textContent = userInput // not innerHTML`,
	},
	"RULE-SEC-001": {
		summary:  "Move the password out of source into an environment variable or secret store.",
		exemplar: `password := os.Getenv("DB_PASSWORD")`,
	},
	"RULE-SEC-002": {
		summary:  "Move the API key out of source into an environment variable or secret store.",
		exemplar: `apiKey := os.Getenv("API_KEY")`,
	},
	"RULE-SEC-003": {
		summary:  "Never commit a private key; load it from a mounted secret or KMS.",
		exemplar: `key := os.Getenv("PRIVATE_KEY") // supplied at deploy time`,
	},
	"RULE-CMD-001": {
		summary:  "Avoid the shell; pass arguments as a list to exec, never an interpolated string.",
		exemplar: `exec.Command("ping", "-c", "1", host) // args are not shell-parsed`,
	},
	"RULE-CRYPTO-001": {
		summary:  "MD5 is broken; use SHA-256, or bcrypt/scrypt/Argon2 for passwords.",
		exemplar: `sha256.Sum256(data) // changes the digest — migrate stored values`,
	},
	"RULE-DESER-001": {
		summary:  "Do not deserialize untrusted data; use a safe format and validate it.",
		exemplar: `json.Unmarshal(trustedBytes, &v) // avoid native object deserialization`,
	},
	"RULE-SSRF-001": {
		summary:  "Validate the URL against an allowlist of hosts before fetching it.",
		exemplar: `if !allowedHost(u.Host) { return errForbidden }`,
	},
	"RULE-PATH-001": {
		summary:  "Clean the path and confirm it stays within the intended base directory.",
		exemplar: `p := filepath.Join(base, name); if !strings.HasPrefix(p, base) { reject }`,
	},
	"RULE-RAND-001": {
		summary:  "Use a cryptographically secure generator for security values.",
		exemplar: `crypto/rand (Go), secrets (Python), crypto.randomBytes (Node.js)`,
	},
	"RULE-CRYPTO-002": {
		summary:  "SHA-1 is weak; use SHA-256 or stronger.",
		exemplar: `sha256.Sum256(data) // changes the digest — migrate stored values`,
	},
	"RULE-CRYPTO-003": {
		summary:  "Replace the weak cipher/mode with AES-GCM or ChaCha20-Poly1305.",
		exemplar: `cipher.NewGCM(block) // authenticated encryption with a random nonce`,
	},
	"RULE-TLS-001": {
		summary:  "Re-enable TLS certificate verification.",
		exemplar: `InsecureSkipVerify: false // trust a proper CA bundle`,
		apply:    applyTLS,
	},
}

// FixForRule builds a per-finding fix from the exact matched code. It returns
// nil for a rule with no fix entry (callers render that as "no suggested fix").
func FixForRule(ruleID, matchText string) *models.Fix {
	t, ok := fixByRule[ruleID]
	if !ok {
		return nil
	}
	fix := &models.Fix{
		Summary: t.summary,
		Kind:    models.FixGuidance,
		Before:  matchText,
		After:   t.exemplar,
	}
	if t.apply != nil {
		if repl, done := t.apply(matchText); done {
			fix.Kind = models.FixSafeReplace
			fix.After = repl
			fix.Replacement = repl
		}
	}
	return fix
}
