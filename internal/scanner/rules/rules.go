// Package rules provides the rule engine for vulnerability detection.
package rules

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"code-security-auditor/internal/config"
)

// Severity represents the severity level of a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Category represents the category of a security finding.
type Category string

const (
	CategorySQLInjection         Category = "sql_injection"
	CategoryXSS                  Category = "xss"
	CategorySecrets              Category = "secrets"
	CategoryDependency           Category = "dependency"
	CategoryPathTraversal        Category = "path_traversal"
	CategoryCommandInjection     Category = "command_injection"
	CategorySSRF                 Category = "ssrf"
	CategoryInsecureDeserialization Category = "insecure_deserialization"
	CategoryWeakCrypto           Category = "weak_crypto"
	CategoryInsecureRandom       Category = "insecure_random"
	CategoryHardcodedCredentials Category = "hardcoded_credentials"
	CategoryMisconfiguration     Category = "misconfiguration"
	CategoryCodeQuality          Category = "code_quality"
)

// Finding represents a security or code quality finding from rules.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	FilePath    string   `json:"file_path"`
	Line        int      `json:"line"`
	LineEnd     int      `json:"line_end,omitempty"`
	Column      int      `json:"column,omitempty"`
	CodeSnippet string   `json:"code_snippet"`
	Remediation string   `json:"remediation,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	Confidence  float64  `json:"confidence"`
	References  []string `json:"references,omitempty"`
}

// ParsedFile interface to avoid import cycle
type ParsedFile interface {
	GetPath() string
	GetLanguage() string
	GetLines() []string
	GetContent() []byte
}

// ParsedFileAdapter adapts scanner.ParsedFile to the ParsedFile interface
type ParsedFileAdapter struct {
	Path     string
	Language string
	Lines    []string
	Content  []byte
}

func (p *ParsedFileAdapter) GetPath() string     { return p.Path }
func (p *ParsedFileAdapter) GetLanguage() string { return p.Language }
func (p *ParsedFileAdapter) GetLines() []string  { return p.Lines }
func (p *ParsedFileAdapter) GetContent() []byte  { return p.Content }

// Rule represents a security detection rule.
type Rule interface {
	ID() string
	Name() string
	Description() string
	GetSeverity() Severity
	GetCategory() Category
	Languages() []string
	Check(file ParsedFile) []Finding
}

// RuleEngine manages and executes security rules.
type RuleEngine struct {
	rules        map[string]Rule
	patterns     []*PatternRule
	enabledRules map[string]bool
	logger       *logrus.Logger
	mu           sync.RWMutex
}

// PatternRule represents a pattern-based detection rule.
type PatternRule struct {
	ID          string
	Title       string
	Pattern     *regexp.Regexp
	Severity    Severity
	Category    Category
	Description string
	Remediation string
	CWE         string
	Languages   []string
	Confidence  float64
	Exclude     *regexp.Regexp
}

// NewRuleEngine creates a new RuleEngine.
func NewRuleEngine(cfg config.ScannerConfig, logger *logrus.Logger) *RuleEngine {
	engine := &RuleEngine{
		rules:        make(map[string]Rule),
		patterns:     make([]*PatternRule, 0),
		enabledRules: make(map[string]bool),
		logger:       logger,
	}

	// Set enabled rules from config
	for _, ruleID := range cfg.EnabledRules {
		engine.enabledRules[ruleID] = true
	}

	// Register built-in rules
	engine.registerBuiltinRules()

	return engine
}

// Register registers a rule with the engine.
func (e *RuleEngine) Register(rule Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.rules[rule.ID()] = rule
	e.logger.WithFields(logrus.Fields{
		"rule_id":  rule.ID(),
		"name":     rule.Name(),
		"severity": rule.GetSeverity(),
	}).Debug("Registered security rule")
}

// RegisterPattern registers a pattern-based rule.
func (e *RuleEngine) RegisterPattern(rule *PatternRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.patterns = append(e.patterns, rule)
}

// Unregister removes a rule from the engine.
func (e *RuleEngine) Unregister(ruleID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.rules, ruleID)
}

// GetRule returns a rule by ID.
func (e *RuleEngine) GetRule(ruleID string) (Rule, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	rule, ok := e.rules[ruleID]
	return rule, ok
}

// ListRules returns all registered rules.
func (e *RuleEngine) ListRules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rules := make([]Rule, 0, len(e.rules))
	for _, rule := range e.rules {
		rules = append(rules, rule)
	}
	return rules
}

// IsEnabled checks if a rule is enabled.
func (e *RuleEngine) IsEnabled(ruleID string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if len(e.enabledRules) == 0 {
		return true // All rules enabled if no specific list
	}
	return e.enabledRules[ruleID]
}

// Analyze runs all applicable rules on a file.
func (e *RuleEngine) Analyze(file interface{}) []Finding {
	// Convert to ParsedFile interface
	var pf ParsedFile
	switch f := file.(type) {
	case ParsedFile:
		pf = f
	case *ParsedFileAdapter:
		pf = f
	default:
		// Try to use reflection or type assertion for the actual scanner.ParsedFile
		// For now, create an adapter
		return nil
	}

	var findings []Finding

	e.mu.RLock()
	defer e.mu.RUnlock()

	// Run registered rules
	for id, rule := range e.rules {
		if !e.IsEnabled(id) {
			continue
		}

		if !ruleAppliesToLanguage(rule.Languages(), pf.GetLanguage()) {
			continue
		}

		ruleFindings := rule.Check(pf)
		findings = append(findings, ruleFindings...)
	}

	// Run pattern rules
	findings = append(findings, e.runPatternRules(pf)...)

	return findings
}

// AnalyzeWithAdapter runs analysis on a file using the adapter pattern.
func (e *RuleEngine) AnalyzeWithAdapter(path, language string, lines []string, content []byte) []Finding {
	adapter := &ParsedFileAdapter{
		Path:     path,
		Language: language,
		Lines:    lines,
		Content:  content,
	}
	return e.Analyze(adapter)
}

// runPatternRules runs all pattern-based rules.
func (e *RuleEngine) runPatternRules(file ParsedFile) []Finding {
	var findings []Finding
	lines := file.GetLines()

	for _, pattern := range e.patterns {
		// Check language applicability
		if len(pattern.Languages) > 0 {
			applicable := false
			for _, lang := range pattern.Languages {
				if lang == file.GetLanguage() {
					applicable = true
					break
				}
			}
			if !applicable {
				continue
			}
		}

		// Check each line
		for i, line := range lines {
			if !pattern.Pattern.MatchString(line) {
				continue
			}

			// Check exclusion pattern
			if pattern.Exclude != nil && pattern.Exclude.MatchString(line) {
				continue
			}

			loc := pattern.Pattern.FindStringIndex(line)
			column := 1
			if loc != nil {
				column = loc[0] + 1
			}

			findings = append(findings, Finding{
				RuleID:      pattern.ID,
				Title:       pattern.Title,
				Description: pattern.Description,
				Severity:    string(pattern.Severity),
				Category:    string(pattern.Category),
				FilePath:    file.GetPath(),
				Line:        i + 1,
				Column:      column,
				CodeSnippet: getCodeSnippet(lines, i+1, 2),
				Remediation: pattern.Remediation,
				CWE:         pattern.CWE,
				Confidence:  pattern.Confidence,
			})
		}
	}

	return findings
}

// ruleAppliesToLanguage checks if a rule applies to a language.
func ruleAppliesToLanguage(languages []string, language string) bool {
	if len(languages) == 0 {
		return true
	}

	for _, lang := range languages {
		if lang == language {
			return true
		}
	}
	return false
}

// registerBuiltinRules registers built-in security patterns.
func (e *RuleEngine) registerBuiltinRules() {
	// SQL Injection patterns
	e.RegisterPattern(&PatternRule{
		ID:          "RULE-SQL-001",
		Title:       "Potential SQL Injection",
		Pattern:     regexp.MustCompile(`(?i)(execute|query|exec)\s*\(\s*['"]?\s*[\w.]*\s*\+`),
		Severity:    SeverityCritical,
		Category:    CategorySQLInjection,
		Description: "String concatenation in SQL query may lead to SQL injection",
		Remediation: "Use parameterized queries or prepared statements",
		CWE:         "CWE-89",
		Confidence:  0.8,
	})

	// XSS patterns
	e.RegisterPattern(&PatternRule{
		ID:          "RULE-XSS-001",
		Title:       "Potential Cross-Site Scripting",
		Pattern:     regexp.MustCompile(`(?i)(innerHTML|outerHTML|document\.write)\s*=`),
		Severity:    SeverityHigh,
		Category:    CategoryXSS,
		Description: "Direct HTML manipulation may lead to XSS vulnerabilities",
		Remediation: "Use textContent or proper HTML sanitization",
		CWE:         "CWE-79",
		Languages:   []string{"javascript", "typescript"},
		Confidence:  0.75,
	})

	// Secrets patterns
	e.RegisterPattern(&PatternRule{
		ID:          "RULE-SEC-001",
		Title:       "Hardcoded Password",
		Pattern:     regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]`),
		Severity:    SeverityCritical,
		Category:    CategorySecrets,
		Description: "Hardcoded password detected in source code",
		Remediation: "Use environment variables or a secrets manager",
		CWE:         "CWE-798",
		Confidence:  0.85,
		Exclude:     regexp.MustCompile(`(?i)(example|test|sample|placeholder|your[_-]?password)`),
	})

	e.RegisterPattern(&PatternRule{
		ID:          "RULE-SEC-002",
		Title:       "Hardcoded API Key",
		Pattern:     regexp.MustCompile(`(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"][a-zA-Z0-9]{16,}['"]`),
		Severity:    SeverityCritical,
		Category:    CategorySecrets,
		Description: "Hardcoded API key detected in source code",
		Remediation: "Store API keys in environment variables or a secrets manager",
		CWE:         "CWE-798",
		Confidence:  0.9,
	})

	e.RegisterPattern(&PatternRule{
		ID:          "RULE-SEC-003",
		Title:       "Hardcoded Private Key",
		Pattern:     regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		Severity:    SeverityCritical,
		Category:    CategorySecrets,
		Description: "Private key embedded in source code",
		Remediation: "Store private keys securely outside of source code",
		CWE:         "CWE-321",
		Confidence:  0.99,
	})

	// Command Injection patterns
	e.RegisterPattern(&PatternRule{
		ID:          "RULE-CMD-001",
		Title:       "Potential Command Injection",
		Pattern:     regexp.MustCompile(`(?i)(exec|system|popen|subprocess\.call|os\.system)\s*\(\s*[^)]*\+`),
		Severity:    SeverityCritical,
		Category:    CategoryCommandInjection,
		Description: "Command construction using string concatenation may lead to injection",
		Remediation: "Use subprocess with list arguments, avoid shell=True",
		CWE:         "CWE-78",
		Confidence:  0.8,
	})

	// Weak Crypto patterns
	e.RegisterPattern(&PatternRule{
		ID:          "RULE-CRYPTO-001",
		Title:       "Weak Cryptographic Hash (MD5)",
		Pattern:     regexp.MustCompile(`(?i)\bmd5\s*\(`),
		Severity:    SeverityMedium,
		Category:    CategoryWeakCrypto,
		Description: "MD5 is cryptographically broken and should not be used for security",
		Remediation: "Use SHA-256 or stronger for cryptographic purposes",
		CWE:         "CWE-328",
		Confidence:  0.9,
	})

	// Insecure Deserialization
	e.RegisterPattern(&PatternRule{
		ID:          "RULE-DESER-001",
		Title:       "Insecure Deserialization",
		Pattern:     regexp.MustCompile(`(?i)(pickle\.load|yaml\.load|unserialize|ObjectInputStream)`),
		Severity:    SeverityCritical,
		Category:    CategoryInsecureDeserialization,
		Description: "Deserializing untrusted data may lead to remote code execution",
		Remediation: "Use safe deserialization methods (yaml.safe_load, JSON)",
		CWE:         "CWE-502",
		Confidence:  0.85,
	})
}

// getCodeSnippet returns a code snippet around a line.
func getCodeSnippet(lines []string, line, context int) string {
	start := line - context - 1
	if start < 0 {
		start = 0
	}
	end := line + context
	if end > len(lines) {
		end = len(lines)
	}

	var snippet strings.Builder
	for i := start; i < end; i++ {
		prefix := "  "
		if i == line-1 {
			prefix = "> "
		}
		snippet.WriteString(fmt.Sprintf("%s%4d | %s\n", prefix, i+1, lines[i]))
	}

	return snippet.String()
}

// BaseRule provides common functionality for custom rules.
type BaseRule struct {
	id          string
	name        string
	description string
	severity    Severity
	category    Category
	languages   []string
	remediation string
}

// NewBaseRule creates a new BaseRule.
func NewBaseRule(id, name, description string, severity Severity, category Category) *BaseRule {
	return &BaseRule{
		id:          id,
		name:        name,
		description: description,
		severity:    severity,
		category:    category,
	}
}

// ID returns the rule ID.
func (r *BaseRule) ID() string { return r.id }

// Name returns the rule name.
func (r *BaseRule) Name() string { return r.name }

// Description returns the rule description.
func (r *BaseRule) Description() string { return r.description }

// GetSeverity returns the severity.
func (r *BaseRule) GetSeverity() Severity { return r.severity }

// GetCategory returns the category.
func (r *BaseRule) GetCategory() Category { return r.category }

// Languages returns supported languages.
func (r *BaseRule) Languages() []string { return r.languages }

// SetLanguages sets the supported languages.
func (r *BaseRule) SetLanguages(langs []string) *BaseRule {
	r.languages = langs
	return r
}

// SetRemediation sets the remediation text.
func (r *BaseRule) SetRemediation(text string) *BaseRule {
	r.remediation = text
	return r
}

// RuleInfo holds information about a rule for reporting.
type RuleInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Category    Category `json:"category"`
	Languages   []string `json:"languages"`
	Enabled     bool     `json:"enabled"`
}

// GetRuleInfo returns information about a rule.
func GetRuleInfo(rule Rule) RuleInfo {
	return RuleInfo{
		ID:          rule.ID(),
		Name:        rule.Name(),
		Description: rule.Description(),
		Severity:    rule.GetSeverity(),
		Category:    rule.GetCategory(),
		Languages:   rule.Languages(),
		Enabled:     true,
	}
}
