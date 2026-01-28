// Package rules provides the rule engine for vulnerability detection.
package rules

import (
	"context"
	"fmt"
	"regexp"
	"sync"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/code-security-auditor/internal/models"
	"github.com/code-security-auditor/internal/scanner"
)

// Rule represents a security rule.
type Rule interface {
	// ID returns the unique identifier for the rule.
	ID() string
	// Name returns the human-readable name.
	Name() string
	// Description returns the rule description.
	Description() string
	// Severity returns the severity level.
	Severity() models.Severity
	// Category returns the vulnerability category.
	Category() models.VulnerabilityCategory
	// Languages returns supported languages (empty means all).
	Languages() []string
	// Check checks a file for vulnerabilities.
	Check(ctx context.Context, file *scanner.ParsedFile) ([]models.Vulnerability, error)
}

// Engine manages and executes security rules.
type Engine struct {
	rules  map[string]Rule
	logger *logrus.Logger
	mu     sync.RWMutex
}

// NewEngine creates a new rule Engine.
func NewEngine(logger *logrus.Logger) *Engine {
	return &Engine{
		rules:  make(map[string]Rule),
		logger: logger,
	}
}

// Register registers a rule with the engine.
func (e *Engine) Register(rule Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.rules[rule.ID()] = rule
	e.logger.WithFields(logrus.Fields{
		"rule_id":  rule.ID(),
		"name":     rule.Name(),
		"severity": rule.Severity(),
	}).Debug("Registered security rule")
}

// Unregister removes a rule from the engine.
func (e *Engine) Unregister(ruleID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.rules, ruleID)
}

// GetRule returns a rule by ID.
func (e *Engine) GetRule(ruleID string) (Rule, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	rule, ok := e.rules[ruleID]
	return rule, ok
}

// ListRules returns all registered rules.
func (e *Engine) ListRules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rules := make([]Rule, 0, len(e.rules))
	for _, rule := range e.rules {
		rules = append(rules, rule)
	}
	return rules
}

// Analyze runs all applicable rules on a file.
func (e *Engine) Analyze(ctx context.Context, file *scanner.ParsedFile, enabledRules []string) ([]models.Vulnerability, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var vulns []models.Vulnerability

	// Build enabled rules map
	enabledMap := make(map[string]bool)
	if len(enabledRules) > 0 {
		for _, id := range enabledRules {
			enabledMap[id] = true
		}
	}

	for id, rule := range e.rules {
		// Check if rule is enabled
		if len(enabledRules) > 0 && !enabledMap[id] {
			continue
		}

		// Check if rule applies to this language
		if !ruleAppliesToLanguage(rule, file.Language) {
			continue
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Run the rule
		ruleVulns, err := rule.Check(ctx, file)
		if err != nil {
			e.logger.WithError(err).WithFields(logrus.Fields{
				"rule_id": id,
				"file":    file.Path,
			}).Warn("Rule check failed")
			continue
		}

		vulns = append(vulns, ruleVulns...)
	}

	return vulns, nil
}

// ruleAppliesToLanguage checks if a rule applies to a language.
func ruleAppliesToLanguage(rule Rule, language string) bool {
	languages := rule.Languages()
	if len(languages) == 0 {
		return true // Applies to all languages
	}

	for _, lang := range languages {
		if lang == language {
			return true
		}
	}
	return false
}

// BaseRule provides common functionality for rules.
type BaseRule struct {
	id          string
	name        string
	description string
	severity    models.Severity
	category    models.VulnerabilityCategory
	languages   []string
	patterns    []*Pattern
	remediation string
	references  models.References
}

// Pattern represents a detection pattern.
type Pattern struct {
	Regex       *regexp.Regexp
	Description string
	Confidence  float64
}

// NewBaseRule creates a new BaseRule.
func NewBaseRule(id, name, description string, severity models.Severity, category models.VulnerabilityCategory) *BaseRule {
	return &BaseRule{
		id:          id,
		name:        name,
		description: description,
		severity:    severity,
		category:    category,
		patterns:    make([]*Pattern, 0),
		references:  models.References{},
	}
}

// ID returns the rule ID.
func (r *BaseRule) ID() string { return r.id }

// Name returns the rule name.
func (r *BaseRule) Name() string { return r.name }

// Description returns the rule description.
func (r *BaseRule) Description() string { return r.description }

// Severity returns the severity.
func (r *BaseRule) Severity() models.Severity { return r.severity }

// Category returns the category.
func (r *BaseRule) Category() models.VulnerabilityCategory { return r.category }

// Languages returns supported languages.
func (r *BaseRule) Languages() []string { return r.languages }

// SetLanguages sets the supported languages.
func (r *BaseRule) SetLanguages(langs []string) {
	r.languages = langs
}

// AddPattern adds a detection pattern.
func (r *BaseRule) AddPattern(pattern string, description string, confidence float64) error {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid pattern: %w", err)
	}

	r.patterns = append(r.patterns, &Pattern{
		Regex:       regex,
		Description: description,
		Confidence:  confidence,
	})

	return nil
}

// SetRemediation sets the remediation text.
func (r *BaseRule) SetRemediation(text string) {
	r.remediation = text
}

// SetReferences sets the references.
func (r *BaseRule) SetReferences(refs models.References) {
	r.references = refs
}

// CheckPatterns checks all patterns against a file.
func (r *BaseRule) CheckPatterns(ctx context.Context, file *scanner.ParsedFile) ([]models.Vulnerability, error) {
	var vulns []models.Vulnerability

	for i, line := range file.Lines {
		lineNum := i + 1

		for _, pattern := range r.patterns {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}

			matches := pattern.Regex.FindAllStringIndex(line, -1)
			for _, match := range matches {
				vuln := models.Vulnerability{
					ID:          uuid.New(),
					RuleID:      r.id,
					Title:       r.name,
					Description: fmt.Sprintf("%s: %s", r.description, pattern.Description),
					Severity:    r.severity,
					Category:    r.category,
					FilePath:    file.Path,
					LineStart:   lineNum,
					LineEnd:     lineNum,
					CodeSnippet: getCodeSnippet(file.Lines, lineNum, 3),
					Remediation: r.remediation,
					References:  r.references,
					Confidence:  pattern.Confidence,
					Metadata: models.VulnMetadata{
						Language: file.Language,
					},
				}

				colStart := match[0] + 1
				colEnd := match[1]
				vuln.ColumnStart = &colStart
				vuln.ColumnEnd = &colEnd

				vulns = append(vulns, vuln)
			}
		}
	}

	return vulns, nil
}

// getCodeSnippet extracts a code snippet around a line.
func getCodeSnippet(lines []string, lineNum, context int) string {
	start := lineNum - context - 1
	if start < 0 {
		start = 0
	}

	end := lineNum + context
	if end > len(lines) {
		end = len(lines)
	}

	snippet := ""
	for i := start; i < end; i++ {
		prefix := "  "
		if i == lineNum-1 {
			prefix = "> "
		}
		snippet += fmt.Sprintf("%s%d: %s\n", prefix, i+1, lines[i])
	}

	return snippet
}

// RuleInfo holds information about a rule for reporting.
type RuleInfo struct {
	ID          string                    `json:"id"`
	Name        string                    `json:"name"`
	Description string                    `json:"description"`
	Severity    models.Severity           `json:"severity"`
	Category    models.VulnerabilityCategory `json:"category"`
	Languages   []string                  `json:"languages"`
	Enabled     bool                      `json:"enabled"`
}

// GetRuleInfo returns information about a rule.
func GetRuleInfo(rule Rule) RuleInfo {
	return RuleInfo{
		ID:          rule.ID(),
		Name:        rule.Name(),
		Description: rule.Description(),
		Severity:    rule.Severity(),
		Category:    rule.Category(),
		Languages:   rule.Languages(),
		Enabled:     true,
	}
}
