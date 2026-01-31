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

// XSSRule detects potential Cross-Site Scripting vulnerabilities.
type XSSRule struct {
	*BaseRule
}

// NewXSSRule creates a new XSS detection rule.
func NewXSSRule() *XSSRule {
	base := NewBaseRule(
		"xss",
		"Cross-Site Scripting (XSS)",
		"Potential cross-site scripting vulnerability detected",
		models.SeverityHigh,
		models.CategoryXSS,
	)

	base.SetLanguages([]string{"javascript", "typescript", "html", "php", "python", "go", "java", "ruby"})

	base.SetRemediation(`Prevent XSS by:
1. Encoding output data before rendering in HTML
2. Using Content Security Policy (CSP) headers
3. Using frameworks that auto-escape output (React, Angular, Vue.js)
4. Validating and sanitizing user input
5. Using HTTPOnly and Secure flags on cookies

For JavaScript:
  // Instead of innerHTML, use textContent
  element.textContent = userInput;
  
  // Or use DOMPurify for sanitization
  element.innerHTML = DOMPurify.sanitize(userInput);

For Go (html/template):
  // html/template auto-escapes by default
  tmpl.Execute(w, data)

For Python (Django):
  <!-- Django auto-escapes by default -->
  {{ user_input }}
  
  <!-- For raw HTML (dangerous), explicitly mark as safe only if sanitized -->
  {{ sanitized_content|safe }}
`)

	base.SetReferences(models.References{
		CWE:   []string{"CWE-79"},
		OWASP: []string{"A03:2021"},
		URLs: []string{
			"https://owasp.org/www-community/attacks/xss/",
			"https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
		},
	})

	return &XSSRule{BaseRule: base}
}

// Check implements the Rule interface.
func (r *XSSRule) Check(ctx context.Context, file *scanner.ParsedFile) ([]models.Vulnerability, error) {
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
				// Additional context check
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

type xssPattern struct {
	regex       *regexp.Regexp
	description string
	confidence  float64
}

// getPatterns returns XSS patterns for a language.
func (r *XSSRule) getPatterns(language string) []xssPattern {
	var patterns []xssPattern

	// Common dangerous patterns
	commonPatterns := []struct {
		pattern     string
		description string
		confidence  float64
	}{
		{
			pattern:     `(?i)\.innerHTML\s*=`,
			description: "Direct innerHTML assignment",
			confidence:  0.85,
		},
		{
			pattern:     `(?i)\.outerHTML\s*=`,
			description: "Direct outerHTML assignment",
			confidence:  0.85,
		},
		{
			pattern:     `(?i)document\.write\s*\(`,
			description: "document.write usage",
			confidence:  0.9,
		},
		{
			pattern:     `(?i)document\.writeln\s*\(`,
			description: "document.writeln usage",
			confidence:  0.9,
		},
		{
			pattern:     `(?i)eval\s*\(`,
			description: "eval() function usage",
			confidence:  0.95,
		},
		{
			pattern:     `(?i)setTimeout\s*\(\s*["']`,
			description: "setTimeout with string argument",
			confidence:  0.7,
		},
		{
			pattern:     `(?i)setInterval\s*\(\s*["']`,
			description: "setInterval with string argument",
			confidence:  0.7,
		},
	}

	// Language-specific patterns
	langPatterns := map[string][]struct {
		pattern     string
		description string
		confidence  float64
	}{
		"javascript": {
			{
				pattern:     `(?i)\$\s*\(\s*["'].*["']\s*\)\s*\.\s*html\s*\(`,
				description: "jQuery .html() method",
				confidence:  0.8,
			},
			{
				pattern:     `(?i)\$\s*\(\s*["'].*["']\s*\)\s*\.\s*append\s*\(`,
				description: "jQuery .append() with potential user input",
				confidence:  0.7,
			},
			{
				pattern:     `(?i)dangerouslySetInnerHTML`,
				description: "React dangerouslySetInnerHTML",
				confidence:  0.85,
			},
			{
				pattern:     `(?i)v-html\s*=`,
				description: "Vue.js v-html directive",
				confidence:  0.85,
			},
			{
				pattern:     `(?i)\[innerHTML\]`,
				description: "Angular innerHTML binding",
				confidence:  0.85,
			},
		},
		"typescript": {
			{
				pattern:     `(?i)dangerouslySetInnerHTML`,
				description: "React dangerouslySetInnerHTML",
				confidence:  0.85,
			},
			{
				pattern:     `(?i)\[innerHTML\]`,
				description: "Angular innerHTML binding",
				confidence:  0.85,
			},
			{
				pattern:     `(?i)bypassSecurityTrust`,
				description: "Angular security bypass",
				confidence:  0.9,
			},
		},
		"html": {
			{
				pattern:     `(?i)on\w+\s*=\s*["'][^"']*\+`,
				description: "Event handler with concatenation",
				confidence:  0.85,
			},
			{
				pattern:     `(?i)<script[^>]*>[^<]*\$\{`,
				description: "Template literal in script tag",
				confidence:  0.9,
			},
			{
				pattern:     `(?i)href\s*=\s*["']javascript:`,
				description: "javascript: protocol in href",
				confidence:  0.95,
			},
		},
		"php": {
			{
				pattern:     `(?i)echo\s+\$_(GET|POST|REQUEST|COOKIE)`,
				description: "Echoing unsanitized user input",
				confidence:  0.95,
			},
			{
				pattern:     `(?i)print\s+\$_(GET|POST|REQUEST|COOKIE)`,
				description: "Printing unsanitized user input",
				confidence:  0.95,
			},
			{
				pattern:     `(?i)<\?=\s*\$_(GET|POST|REQUEST|COOKIE)`,
				description: "Short echo of user input",
				confidence:  0.95,
			},
		},
		"python": {
			{
				pattern:     `(?i)render_template_string\s*\(`,
				description: "render_template_string usage",
				confidence:  0.85,
			},
			{
				pattern:     `(?i)\|\s*safe\b`,
				description: "Django/Jinja2 safe filter",
				confidence:  0.8,
			},
			{
				pattern:     `(?i)mark_safe\s*\(`,
				description: "Django mark_safe usage",
				confidence:  0.85,
			},
			{
				pattern:     `(?i)Markup\s*\(`,
				description: "Flask Markup usage",
				confidence:  0.8,
			},
		},
		"go": {
			{
				pattern:     `(?i)template\.HTML\s*\(`,
				description: "template.HTML bypasses escaping",
				confidence:  0.85,
			},
			{
				pattern:     `(?i)template\.JS\s*\(`,
				description: "template.JS bypasses escaping",
				confidence:  0.85,
			},
			{
				pattern:     `(?i)template\.URL\s*\(`,
				description: "template.URL bypasses escaping",
				confidence:  0.8,
			},
			{
				pattern:     `(?i)w\.Write\s*\(\[\]byte\s*\(`,
				description: "Direct byte write to response",
				confidence:  0.7,
			},
		},
		"java": {
			{
				pattern:     `(?i)out\.print(ln)?\s*\(\s*request\.getParameter`,
				description: "Printing request parameter directly",
				confidence:  0.9,
			},
			{
				pattern:     `(?i)response\.getWriter\(\)\.print`,
				description: "Direct response write",
				confidence:  0.75,
			},
		},
		"ruby": {
			{
				pattern:     `(?i)\.html_safe`,
				description: "html_safe method bypasses escaping",
				confidence:  0.85,
			},
			{
				pattern:     `(?i)raw\s*\(`,
				description: "raw helper bypasses escaping",
				confidence:  0.85,
			},
			{
				pattern:     `(?i)<%==`,
				description: "ERB raw output",
				confidence:  0.9,
			},
		},
	}

	// Add common patterns
	for _, p := range commonPatterns {
		regex, err := regexp.Compile(p.pattern)
		if err == nil {
			patterns = append(patterns, xssPattern{
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
				patterns = append(patterns, xssPattern{
					regex:       regex,
					description: p.description,
					confidence:  p.confidence,
				})
			}
		}
	}

	return patterns
}

// isLikelyVulnerable performs additional checks.
func (r *XSSRule) isLikelyVulnerable(line, language string) bool {
	// Check if it's a comment
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") ||
		strings.HasPrefix(trimmed, "<!--") {
		return false
	}

	// Check for sanitization functions
	sanitizers := []string{
		"DOMPurify", "sanitize", "escape", "encode",
		"htmlspecialchars", "htmlentities",
		"html.EscapeString", "template.HTMLEscapeString",
		"encodeURIComponent", "encodeURI",
	}

	lineLower := strings.ToLower(line)
	for _, sanitizer := range sanitizers {
		if strings.Contains(lineLower, strings.ToLower(sanitizer)) {
			return false
		}
	}

	return true
}
