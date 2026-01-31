// Package scanner provides code scanning and analysis functionality.
package scanner

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"code-security-auditor/internal/config"
	"code-security-auditor/internal/scanner/rules"
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
	CategorySQLInjection            Category = "sql_injection"
	CategoryXSS                     Category = "xss"
	CategorySecrets                 Category = "secrets"
	CategoryDependency              Category = "dependency"
	CategoryPathTraversal           Category = "path_traversal"
	CategoryCommandInjection        Category = "command_injection"
	CategorySSRF                    Category = "ssrf"
	CategoryInsecureDeserialization Category = "insecure_deserialization"
	CategoryWeakCrypto              Category = "weak_crypto"
	CategoryInsecureRandom          Category = "insecure_random"
	CategoryHardcodedCredentials    Category = "hardcoded_credentials"
	CategorySensitiveDataExposure   Category = "sensitive_data_exposure"
	CategoryMissingAuth             Category = "missing_auth"
	CategoryCodeQuality             Category = "code_quality"
	CategoryMisconfiguration        Category = "misconfiguration"
)

// Finding represents a security or code quality finding.
type Finding struct {
	RuleID      string            `json:"rule_id"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Severity    Severity          `json:"severity"`
	Category    Category          `json:"category"`
	FilePath    string            `json:"file_path"`
	Line        int               `json:"line"`
	LineEnd     int               `json:"line_end,omitempty"`
	Column      int               `json:"column,omitempty"`
	ColumnEnd   int               `json:"column_end,omitempty"`
	CodeSnippet string            `json:"code_snippet"`
	Remediation string            `json:"remediation,omitempty"`
	CWE         string            `json:"cwe,omitempty"`
	CVSS        float64           `json:"cvss,omitempty"`
	Confidence  float64           `json:"confidence"`
	References  []string          `json:"references,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// AnalysisResult contains the results of analyzing a repository.
type AnalysisResult struct {
	TotalFiles    int             `json:"total_files"`
	TotalLines    int             `json:"total_lines"`
	Findings      []Finding       `json:"findings"`
	Metrics       *CodeMetrics    `json:"metrics"`
	Summary       AnalysisSummary `json:"summary"`
	LanguageStats map[string]int  `json:"language_stats"`
	QualityIssues []QualityIssue  `json:"quality_issues"`
}

// AnalysisSummary provides a summary of the analysis.
type AnalysisSummary struct {
	CriticalCount int     `json:"critical_count"`
	HighCount     int     `json:"high_count"`
	MediumCount   int     `json:"medium_count"`
	LowCount      int     `json:"low_count"`
	InfoCount     int     `json:"info_count"`
	TotalCount    int     `json:"total_count"`
	SecurityScore float64 `json:"security_score"`
	QualityScore  float64 `json:"quality_score"`
}

// Analyzer performs static code analysis.
type Analyzer struct {
	config     config.ScannerConfig
	logger     *logrus.Logger
	ruleEngine *rules.RuleEngine
	patterns   map[string][]*PatternRule
	mu         sync.RWMutex
}

// NewAnalyzer creates a new Analyzer.
func NewAnalyzer(cfg config.ScannerConfig, logger *logrus.Logger) *Analyzer {
	a := &Analyzer{
		config:   cfg,
		logger:   logger,
		patterns: make(map[string][]*PatternRule),
	}

	// Initialize rule engine
	a.ruleEngine = rules.NewEngine(cfg, logger)

	// Register built-in patterns
	a.registerBuiltinPatterns()

	return a
}

// AnalyzeRepository performs comprehensive analysis on a repository.
func (a *Analyzer) AnalyzeRepository(ctx context.Context, files []*ParsedFile) (*AnalysisResult, error) {
	result := &AnalysisResult{
		Findings:      make([]Finding, 0),
		LanguageStats: make(map[string]int),
		QualityIssues: make([]QualityIssue, 0),
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, a.config.MaxConcurrent)

	for _, file := range files {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		wg.Add(1)
		go func(f *ParsedFile) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			// Analyze file
			findings := a.AnalyzeFile(ctx, f)
			qualityIssues := a.AnalyzeCodeQuality(f)

			mu.Lock()
			result.TotalFiles++
			result.TotalLines += f.LineCount
			result.Findings = append(result.Findings, findings...)
			result.QualityIssues = append(result.QualityIssues, qualityIssues...)
			result.LanguageStats[f.Language]++
			mu.Unlock()
		}(file)
	}

	wg.Wait()

	// Calculate metrics
	result.Metrics = a.CalculateMetrics(files)

	// Calculate summary
	result.Summary = a.calculateSummary(result.Findings)
	result.Summary.QualityScore = result.Metrics.ComplexityScore

	// Sort findings by severity
	a.sortFindings(result.Findings)

	return result, nil
}

// AnalyzeFile analyzes a single file for security vulnerabilities.
func (a *Analyzer) AnalyzeFile(ctx context.Context, file *ParsedFile) []Finding {
	var findings []Finding

	// Run pattern-based analysis
	patternFindings := a.runPatternAnalysis(file)
	findings = append(findings, patternFindings...)

	// Run rule engine
	ruleFindings := a.ruleEngine.Analyze(file)
	for _, rf := range ruleFindings {
		findings = append(findings, Finding{
			RuleID:      rf.RuleID,
			Title:       rf.Title,
			Description: rf.Description,
			Severity:    Severity(rf.Severity),
			Category:    Category(rf.Category),
			FilePath:    file.Path,
			Line:        rf.Line,
			LineEnd:     rf.LineEnd,
			Column:      rf.Column,
			CodeSnippet: rf.CodeSnippet,
			Remediation: rf.Remediation,
			CWE:         rf.CWE,
			Confidence:  rf.Confidence,
		})
	}

	// Language-specific analysis
	switch file.Language {
	case "go":
		findings = append(findings, a.analyzeGo(file)...)
	case "python":
		findings = append(findings, a.analyzePython(file)...)
	case "javascript", "typescript":
		findings = append(findings, a.analyzeJS(file)...)
	case "java":
		findings = append(findings, a.analyzeJava(file)...)
	case "php":
		findings = append(findings, a.analyzePHP(file)...)
	}

	return findings
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

// registerBuiltinPatterns registers built-in security patterns.
func (a *Analyzer) registerBuiltinPatterns() {
	// SQL Injection patterns
	a.addPattern(&PatternRule{
		ID:          "SQL001",
		Title:       "Potential SQL Injection",
		Pattern:     regexp.MustCompile(`(?i)(execute|query|exec)\s*\(\s*['"]?\s*[\w.]*\s*\+`),
		Severity:    SeverityCritical,
		Category:    CategorySQLInjection,
		Description: "String concatenation in SQL query may lead to SQL injection",
		Remediation: "Use parameterized queries or prepared statements",
		CWE:         "CWE-89",
		Confidence:  0.8,
	})

	a.addPattern(&PatternRule{
		ID:          "SQL002",
		Title:       "SQL Query with String Formatting",
		Pattern:     regexp.MustCompile(`(?i)(execute|query)\s*\(\s*f['"]|\.format\s*\(`),
		Severity:    SeverityCritical,
		Category:    CategorySQLInjection,
		Description: "SQL query using string formatting may be vulnerable to injection",
		Remediation: "Use parameterized queries instead of string formatting",
		CWE:         "CWE-89",
		Confidence:  0.85,
	})

	// XSS patterns
	a.addPattern(&PatternRule{
		ID:          "XSS001",
		Title:       "Potential Cross-Site Scripting (XSS)",
		Pattern:     regexp.MustCompile(`(?i)(innerHTML|outerHTML|document\.write)\s*=`),
		Severity:    SeverityHigh,
		Category:    CategoryXSS,
		Description: "Direct HTML manipulation may lead to XSS vulnerabilities",
		Remediation: "Use textContent or proper HTML sanitization",
		CWE:         "CWE-79",
		Languages:   []string{"javascript", "typescript"},
		Confidence:  0.75,
	})

	a.addPattern(&PatternRule{
		ID:          "XSS002",
		Title:       "Unsafe eval() Usage",
		Pattern:     regexp.MustCompile(`\beval\s*\(`),
		Severity:    SeverityHigh,
		Category:    CategoryXSS,
		Description: "eval() can execute arbitrary code and may lead to XSS",
		Remediation: "Avoid eval(); use JSON.parse() for JSON data or safer alternatives",
		CWE:         "CWE-95",
		Confidence:  0.9,
	})

	// Secrets patterns
	a.addPattern(&PatternRule{
		ID:          "SEC001",
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

	a.addPattern(&PatternRule{
		ID:          "SEC002",
		Title:       "Hardcoded API Key",
		Pattern:     regexp.MustCompile(`(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"][a-zA-Z0-9]{16,}['"]`),
		Severity:    SeverityCritical,
		Category:    CategorySecrets,
		Description: "Hardcoded API key detected in source code",
		Remediation: "Store API keys in environment variables or a secrets manager",
		CWE:         "CWE-798",
		Confidence:  0.9,
	})

	a.addPattern(&PatternRule{
		ID:          "SEC003",
		Title:       "Hardcoded AWS Credentials",
		Pattern:     regexp.MustCompile(`(?i)(AKIA[A-Z0-9]{16}|aws[_-]?(secret[_-]?access[_-]?key|access[_-]?key[_-]?id)\s*[:=])`),
		Severity:    SeverityCritical,
		Category:    CategorySecrets,
		Description: "AWS credentials detected in source code",
		Remediation: "Use IAM roles or AWS Secrets Manager",
		CWE:         "CWE-798",
		Confidence:  0.95,
	})

	a.addPattern(&PatternRule{
		ID:          "SEC004",
		Title:       "Hardcoded Private Key",
		Pattern:     regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		Severity:    SeverityCritical,
		Category:    CategorySecrets,
		Description: "Private key embedded in source code",
		Remediation: "Store private keys securely outside of source code",
		CWE:         "CWE-321",
		Confidence:  0.99,
	})

	a.addPattern(&PatternRule{
		ID:          "SEC005",
		Title:       "Hardcoded JWT Secret",
		Pattern:     regexp.MustCompile(`(?i)(jwt[_-]?secret|token[_-]?secret)\s*[:=]\s*['"][^'"]{16,}['"]`),
		Severity:    SeverityCritical,
		Category:    CategorySecrets,
		Description: "JWT secret key embedded in source code",
		Remediation: "Store JWT secrets in environment variables",
		CWE:         "CWE-798",
		Confidence:  0.9,
	})

	// Command Injection patterns
	a.addPattern(&PatternRule{
		ID:          "CMD001",
		Title:       "Potential Command Injection",
		Pattern:     regexp.MustCompile(`(?i)(exec|system|popen|subprocess\.call|os\.system)\s*\(\s*[^)]*\+`),
		Severity:    SeverityCritical,
		Category:    CategoryCommandInjection,
		Description: "Command construction using string concatenation may lead to injection",
		Remediation: "Use subprocess with list arguments, avoid shell=True",
		CWE:         "CWE-78",
		Confidence:  0.8,
	})

	a.addPattern(&PatternRule{
		ID:          "CMD002",
		Title:       "Unsafe Shell Execution",
		Pattern:     regexp.MustCompile(`(?i)subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True`),
		Severity:    SeverityHigh,
		Category:    CategoryCommandInjection,
		Description: "shell=True in subprocess may allow command injection",
		Remediation: "Use subprocess with list arguments without shell=True",
		CWE:         "CWE-78",
		Languages:   []string{"python"},
		Confidence:  0.85,
	})

	// Path Traversal patterns
	a.addPattern(&PatternRule{
		ID:          "PATH001",
		Title:       "Potential Path Traversal",
		Pattern:     regexp.MustCompile(`(?i)(open|read|write|file)\s*\(\s*[^)]*\+`),
		Severity:    SeverityHigh,
		Category:    CategoryPathTraversal,
		Description: "File path construction using concatenation may allow path traversal",
		Remediation: "Use path.Clean() or equivalent, validate user input",
		CWE:         "CWE-22",
		Confidence:  0.7,
	})

	// Weak Crypto patterns
	a.addPattern(&PatternRule{
		ID:          "CRYPTO001",
		Title:       "Weak Cryptographic Hash (MD5)",
		Pattern:     regexp.MustCompile(`(?i)\bmd5\s*\(`),
		Severity:    SeverityMedium,
		Category:    CategoryWeakCrypto,
		Description: "MD5 is cryptographically broken and should not be used for security",
		Remediation: "Use SHA-256 or stronger for cryptographic purposes",
		CWE:         "CWE-328",
		Confidence:  0.9,
	})

	a.addPattern(&PatternRule{
		ID:          "CRYPTO002",
		Title:       "Weak Cryptographic Hash (SHA1)",
		Pattern:     regexp.MustCompile(`(?i)\bsha1\s*\(`),
		Severity:    SeverityMedium,
		Category:    CategoryWeakCrypto,
		Description: "SHA1 is deprecated for security purposes",
		Remediation: "Use SHA-256 or stronger",
		CWE:         "CWE-328",
		Confidence:  0.85,
	})

	// Insecure Random patterns
	a.addPattern(&PatternRule{
		ID:          "RAND001",
		Title:       "Insecure Random Number Generator",
		Pattern:     regexp.MustCompile(`(?i)\bmath\.random\s*\(|random\.random\s*\(|rand\s*\(`),
		Severity:    SeverityMedium,
		Category:    CategoryInsecureRandom,
		Description: "Weak random number generator used for security-sensitive operation",
		Remediation: "Use crypto/rand or secrets module for security-sensitive random numbers",
		CWE:         "CWE-330",
		Confidence:  0.7,
	})

	// SSRF patterns
	a.addPattern(&PatternRule{
		ID:          "SSRF001",
		Title:       "Potential Server-Side Request Forgery",
		Pattern:     regexp.MustCompile(`(?i)(http\.get|requests\.get|fetch|axios|curl)\s*\(\s*[^)]*\+`),
		Severity:    SeverityHigh,
		Category:    CategorySSRF,
		Description: "URL construction using user input may lead to SSRF",
		Remediation: "Validate and sanitize URLs, use allowlists for external requests",
		CWE:         "CWE-918",
		Confidence:  0.75,
	})

	// Insecure Deserialization patterns
	a.addPattern(&PatternRule{
		ID:          "DESER001",
		Title:       "Insecure Deserialization",
		Pattern:     regexp.MustCompile(`(?i)(pickle\.load|yaml\.load|unserialize|ObjectInputStream)`),
		Severity:    SeverityCritical,
		Category:    CategoryInsecureDeserialization,
		Description: "Deserializing untrusted data may lead to remote code execution",
		Remediation: "Use safe deserialization methods (yaml.safe_load, JSON)",
		CWE:         "CWE-502",
		Confidence:  0.85,
	})

	// Debug/Development patterns
	a.addPattern(&PatternRule{
		ID:          "DEBUG001",
		Title:       "Debug Mode Enabled",
		Pattern:     regexp.MustCompile(`(?i)(debug\s*[:=]\s*true|DEBUG\s*=\s*1|app\.debug\s*=\s*True)`),
		Severity:    SeverityMedium,
		Category:    CategoryMisconfiguration,
		Description: "Debug mode should be disabled in production",
		Remediation: "Disable debug mode in production environments",
		CWE:         "CWE-489",
		Confidence:  0.8,
	})

	// TODO/FIXME patterns
	a.addPattern(&PatternRule{
		ID:          "QUAL001",
		Title:       "Security-Related TODO/FIXME",
		Pattern:     regexp.MustCompile(`(?i)(TODO|FIXME|XXX|HACK)[:\s]*(security|auth|password|cred|secret|vuln|injection)`),
		Severity:    SeverityLow,
		Category:    CategoryCodeQuality,
		Description: "Security-related TODO comment found",
		Remediation: "Address the security concern indicated in the comment",
		Confidence:  0.9,
	})
}

// addPattern adds a pattern rule to the analyzer.
func (a *Analyzer) addPattern(rule *PatternRule) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(rule.Languages) == 0 {
		a.patterns["all"] = append(a.patterns["all"], rule)
	} else {
		for _, lang := range rule.Languages {
			a.patterns[lang] = append(a.patterns[lang], rule)
		}
	}
}

// runPatternAnalysis runs pattern-based analysis on a file.
func (a *Analyzer) runPatternAnalysis(file *ParsedFile) []Finding {
	var findings []Finding

	a.mu.RLock()
	patterns := make([]*PatternRule, 0)
	patterns = append(patterns, a.patterns["all"]...)
	patterns = append(patterns, a.patterns[file.Language]...)
	a.mu.RUnlock()

	for i, line := range file.Lines {
		lineNum := i + 1

		for _, pattern := range patterns {
			// Check if pattern matches
			if !pattern.Pattern.MatchString(line) {
				continue
			}

			// Check exclusion pattern
			if pattern.Exclude != nil && pattern.Exclude.MatchString(line) {
				continue
			}

			// Find match location
			loc := pattern.Pattern.FindStringIndex(line)
			column := 1
			if loc != nil {
				column = loc[0] + 1
			}

			findings = append(findings, Finding{
				RuleID:      pattern.ID,
				Title:       pattern.Title,
				Description: pattern.Description,
				Severity:    pattern.Severity,
				Category:    pattern.Category,
				FilePath:    file.Path,
				Line:        lineNum,
				Column:      column,
				CodeSnippet: getCodeSnippet(file.Lines, lineNum, 2),
				Remediation: pattern.Remediation,
				CWE:         pattern.CWE,
				Confidence:  pattern.Confidence,
			})
		}
	}

	return findings
}

// Language-specific analyzers

// analyzeGo performs Go-specific security analysis.
func (a *Analyzer) analyzeGo(file *ParsedFile) []Finding {
	var findings []Finding

	// Check for unsafe package usage
	for _, imp := range file.Imports {
		if imp.Path == "unsafe" {
			findings = append(findings, Finding{
				RuleID:      "GO001",
				Title:       "Unsafe Package Usage",
				Description: "The unsafe package bypasses Go's type safety",
				Severity:    SeverityMedium,
				Category:    CategoryCodeQuality,
				FilePath:    file.Path,
				Line:        imp.Line,
				Remediation: "Avoid using unsafe package unless absolutely necessary",
				Confidence:  0.95,
			})
		}
	}

	// Check for SQL query patterns
	sqlPatterns := []struct {
		pattern *regexp.Regexp
		desc    string
	}{
		{regexp.MustCompile(`db\.Query\s*\([^)]*\+`), "String concatenation in SQL query"},
		{regexp.MustCompile(`db\.Exec\s*\([^)]*\+`), "String concatenation in SQL exec"},
		{regexp.MustCompile(`fmt\.Sprintf\s*\([^)]*SELECT|INSERT|UPDATE|DELETE`), "SQL query in Sprintf"},
	}

	for i, line := range file.Lines {
		for _, sp := range sqlPatterns {
			if sp.pattern.MatchString(line) {
				findings = append(findings, Finding{
					RuleID:      "GO-SQL001",
					Title:       "Potential SQL Injection",
					Description: sp.desc,
					Severity:    SeverityCritical,
					Category:    CategorySQLInjection,
					FilePath:    file.Path,
					Line:        i + 1,
					CodeSnippet: getCodeSnippet(file.Lines, i+1, 2),
					Remediation: "Use parameterized queries with ? placeholders",
					CWE:         "CWE-89",
					Confidence:  0.85,
				})
			}
		}
	}

	return findings
}

// analyzePython performs Python-specific security analysis.
func (a *Analyzer) analyzePython(file *ParsedFile) []Finding {
	var findings []Finding

	// Check for dangerous function usage
	dangerousFuncs := map[*regexp.Regexp]struct {
		ruleID string
		title  string
		desc   string
		sev    Severity
		cat    Category
	}{
		regexp.MustCompile(`\beval\s*\(`): {
			"PY001", "Dangerous eval() Usage",
			"eval() can execute arbitrary code", SeverityCritical, CategoryCommandInjection,
		},
		regexp.MustCompile(`\bexec\s*\(`): {
			"PY002", "Dangerous exec() Usage",
			"exec() can execute arbitrary code", SeverityCritical, CategoryCommandInjection,
		},
		regexp.MustCompile(`\b__import__\s*\(`): {
			"PY003", "Dynamic Import",
			"Dynamic imports can load arbitrary modules", SeverityMedium, CategoryCommandInjection,
		},
		regexp.MustCompile(`pickle\.loads?\s*\(`): {
			"PY004", "Insecure Pickle Deserialization",
			"Pickle can execute arbitrary code during deserialization", SeverityCritical, CategoryInsecureDeserialization,
		},
		regexp.MustCompile(`yaml\.load\s*\([^)]*\)`): {
			"PY005", "Insecure YAML Loading",
			"yaml.load without Loader can execute arbitrary code", SeverityCritical, CategoryInsecureDeserialization,
		},
	}

	for i, line := range file.Lines {
		for pattern, info := range dangerousFuncs {
			if pattern.MatchString(line) {
				// Special check for yaml.load with Loader
				if info.ruleID == "PY005" && strings.Contains(line, "Loader=") {
					continue
				}

				findings = append(findings, Finding{
					RuleID:      info.ruleID,
					Title:       info.title,
					Description: info.desc,
					Severity:    info.sev,
					Category:    info.cat,
					FilePath:    file.Path,
					Line:        i + 1,
					CodeSnippet: getCodeSnippet(file.Lines, i+1, 2),
					Confidence:  0.9,
				})
			}
		}
	}

	return findings
}

// analyzeJS performs JavaScript/TypeScript-specific security analysis.
func (a *Analyzer) analyzeJS(file *ParsedFile) []Finding {
	var findings []Finding

	// Check for dangerous patterns
	jsPatterns := map[*regexp.Regexp]struct {
		ruleID string
		title  string
		desc   string
		sev    Severity
		cat    Category
		remed  string
	}{
		regexp.MustCompile(`\.innerHTML\s*=\s*[^'"]`): {
			"JS001", "Potential XSS via innerHTML",
			"Setting innerHTML with dynamic content may cause XSS",
			SeverityHigh, CategoryXSS,
			"Use textContent or sanitize HTML before insertion",
		},
		regexp.MustCompile(`document\.write\s*\(`): {
			"JS002", "document.write Usage",
			"document.write can cause XSS and performance issues",
			SeverityMedium, CategoryXSS,
			"Use DOM manipulation methods instead",
		},
		regexp.MustCompile(`new Function\s*\(`): {
			"JS003", "Dynamic Function Creation",
			"new Function() is similar to eval() and can execute arbitrary code",
			SeverityHigh, CategoryCommandInjection,
			"Avoid creating functions dynamically from strings",
		},
		regexp.MustCompile(`setTimeout\s*\(\s*['"]`): {
			"JS004", "String in setTimeout",
			"Passing strings to setTimeout is similar to eval()",
			SeverityMedium, CategoryCommandInjection,
			"Pass function references instead of strings",
		},
		regexp.MustCompile(`\$\s*\(\s*[^'")\s]`): {
			"JS005", "jQuery Selector with Variable",
			"Using untrusted data in jQuery selectors can lead to XSS",
			SeverityMedium, CategoryXSS,
			"Validate and sanitize input before using in selectors",
		},
	}

	for i, line := range file.Lines {
		for pattern, info := range jsPatterns {
			if pattern.MatchString(line) {
				findings = append(findings, Finding{
					RuleID:      info.ruleID,
					Title:       info.title,
					Description: info.desc,
					Severity:    info.sev,
					Category:    info.cat,
					FilePath:    file.Path,
					Line:        i + 1,
					CodeSnippet: getCodeSnippet(file.Lines, i+1, 2),
					Remediation: info.remed,
					Confidence:  0.8,
				})
			}
		}
	}

	return findings
}

// analyzeJava performs Java-specific security analysis.
func (a *Analyzer) analyzeJava(file *ParsedFile) []Finding {
	var findings []Finding

	// Java security patterns
	javaPatterns := map[*regexp.Regexp]struct {
		ruleID string
		title  string
		desc   string
		sev    Severity
		cat    Category
	}{
		regexp.MustCompile(`Runtime\.getRuntime\(\)\.exec\s*\(`): {
			"JAVA001", "Command Execution",
			"Runtime.exec() may be vulnerable to command injection",
			SeverityCritical, CategoryCommandInjection,
		},
		regexp.MustCompile(`new\s+ObjectInputStream\s*\(`): {
			"JAVA002", "Insecure Deserialization",
			"ObjectInputStream can execute arbitrary code during deserialization",
			SeverityCritical, CategoryInsecureDeserialization,
		},
		regexp.MustCompile(`\.createQuery\s*\(\s*['"].*\+`): {
			"JAVA003", "HQL/JPQL Injection",
			"String concatenation in query may lead to injection",
			SeverityCritical, CategorySQLInjection,
		},
		regexp.MustCompile(`XXE|DocumentBuilder|SAXParser`): {
			"JAVA004", "Potential XXE Vulnerability",
			"XML parsers may be vulnerable to XXE attacks if not configured securely",
			SeverityHigh, CategoryMisconfiguration,
		},
	}

	for i, line := range file.Lines {
		for pattern, info := range javaPatterns {
			if pattern.MatchString(line) {
				findings = append(findings, Finding{
					RuleID:      info.ruleID,
					Title:       info.title,
					Description: info.desc,
					Severity:    info.sev,
					Category:    info.cat,
					FilePath:    file.Path,
					Line:        i + 1,
					CodeSnippet: getCodeSnippet(file.Lines, i+1, 2),
					Confidence:  0.8,
				})
			}
		}
	}

	return findings
}

// analyzePHP performs PHP-specific security analysis.
func (a *Analyzer) analyzePHP(file *ParsedFile) []Finding {
	var findings []Finding

	// PHP security patterns
	phpPatterns := map[*regexp.Regexp]struct {
		ruleID string
		title  string
		desc   string
		sev    Severity
		cat    Category
	}{
		regexp.MustCompile(`\$_(GET|POST|REQUEST|COOKIE)\s*\[`): {
			"PHP001", "Unsanitized User Input",
			"Direct use of superglobals without sanitization",
			SeverityMedium, CategoryXSS,
		},
		regexp.MustCompile(`mysql_query\s*\(\s*\$`): {
			"PHP002", "SQL Injection (mysql_query)",
			"Deprecated mysql_query with variable may cause SQL injection",
			SeverityCritical, CategorySQLInjection,
		},
		regexp.MustCompile(`\beval\s*\(\s*\$`): {
			"PHP003", "Code Injection via eval",
			"eval with user input enables remote code execution",
			SeverityCritical, CategoryCommandInjection,
		},
		regexp.MustCompile(`shell_exec|exec|system|passthru|popen`): {
			"PHP004", "Command Execution Function",
			"Command execution function may be vulnerable to injection",
			SeverityHigh, CategoryCommandInjection,
		},
		regexp.MustCompile(`unserialize\s*\(\s*\$`): {
			"PHP005", "Insecure Deserialization",
			"unserialize with user input may lead to object injection",
			SeverityCritical, CategoryInsecureDeserialization,
		},
	}

	for i, line := range file.Lines {
		for pattern, info := range phpPatterns {
			if pattern.MatchString(line) {
				findings = append(findings, Finding{
					RuleID:      info.ruleID,
					Title:       info.title,
					Description: info.desc,
					Severity:    info.sev,
					Category:    info.cat,
					FilePath:    file.Path,
					Line:        i + 1,
					CodeSnippet: getCodeSnippet(file.Lines, i+1, 2),
					Confidence:  0.85,
				})
			}
		}
	}

	return findings
}

// CodeMetrics holds code quality metrics.
type CodeMetrics struct {
	TotalFiles        int             `json:"total_files"`
	TotalLines        int             `json:"total_lines"`
	CodeLines         int             `json:"code_lines"`
	CommentLines      int             `json:"comment_lines"`
	BlankLines        int             `json:"blank_lines"`
	LanguageBreakdown map[string]int  `json:"language_breakdown"`
	FileTypeBreakdown map[string]int  `json:"file_type_breakdown"`
	AverageFileSize   float64         `json:"average_file_size"`
	LargestFiles      []FileSizeInfo  `json:"largest_files"`
	ComplexityScore   float64         `json:"complexity_score"`
	DuplicationScore  float64         `json:"duplication_score"`
	FunctionMetrics   FunctionMetrics `json:"function_metrics"`
}

// FileSizeInfo holds size information for a file.
type FileSizeInfo struct {
	Path  string `json:"path"`
	Lines int    `json:"lines"`
	Size  int64  `json:"size"`
}

// FunctionMetrics holds function-related metrics.
type FunctionMetrics struct {
	TotalFunctions      int     `json:"total_functions"`
	AverageFunctionSize float64 `json:"average_function_size"`
	LargestFunction     int     `json:"largest_function"`
	ExportedFunctions   int     `json:"exported_functions"`
	AverageComplexity   float64 `json:"average_complexity"`
}

// CalculateMetrics calculates code metrics for parsed files.
func (a *Analyzer) CalculateMetrics(files []*ParsedFile) *CodeMetrics {
	metrics := &CodeMetrics{
		TotalFiles:        len(files),
		LanguageBreakdown: make(map[string]int),
		FileTypeBreakdown: make(map[string]int),
		LargestFiles:      make([]FileSizeInfo, 0),
	}

	var totalSize int64
	var totalFunctions int
	var totalFunctionLines int
	var largestFunction int
	var exportedFunctions int
	var totalComplexity int

	for _, file := range files {
		metrics.TotalLines += file.LineCount
		totalSize += file.Size

		// Count line types
		codeLines, commentLines, blankLines := countLineTypes(file)
		metrics.CodeLines += codeLines
		metrics.CommentLines += commentLines
		metrics.BlankLines += blankLines

		// Language breakdown
		metrics.LanguageBreakdown[file.Language]++

		// Track largest files
		metrics.LargestFiles = insertSorted(metrics.LargestFiles, FileSizeInfo{
			Path:  file.Path,
			Lines: file.LineCount,
			Size:  file.Size,
		}, 10)

		// Function metrics
		for _, fn := range file.Functions {
			totalFunctions++
			fnLines := fn.EndLine - fn.StartLine + 1
			if fnLines < 1 {
				fnLines = 1
			}
			totalFunctionLines += fnLines
			if fnLines > largestFunction {
				largestFunction = fnLines
			}
			if fn.IsExported {
				exportedFunctions++
			}
			totalComplexity += fn.Complexity
		}
	}

	// Calculate averages
	if metrics.TotalFiles > 0 {
		metrics.AverageFileSize = float64(totalSize) / float64(metrics.TotalFiles)
	}

	// Function metrics
	metrics.FunctionMetrics = FunctionMetrics{
		TotalFunctions:    totalFunctions,
		LargestFunction:   largestFunction,
		ExportedFunctions: exportedFunctions,
	}
	if totalFunctions > 0 {
		metrics.FunctionMetrics.AverageFunctionSize = float64(totalFunctionLines) / float64(totalFunctions)
		metrics.FunctionMetrics.AverageComplexity = float64(totalComplexity) / float64(totalFunctions)
	}

	// Calculate scores
	metrics.ComplexityScore = a.calculateComplexityScore(files)
	metrics.DuplicationScore = a.CalculateDuplication(files)

	return metrics
}

// countLineTypes counts code, comment, and blank lines.
func countLineTypes(file *ParsedFile) (code, comments, blank int) {
	inBlockComment := false

	for _, line := range file.Lines {
		trimmed := strings.TrimSpace(line)

		if trimmed == "" {
			blank++
			continue
		}

		// Check for comments based on language
		switch file.Language {
		case "go", "java", "javascript", "typescript", "c", "cpp", "csharp", "rust", "kotlin", "swift":
			if inBlockComment {
				comments++
				if strings.Contains(trimmed, "*/") {
					inBlockComment = false
				}
				continue
			}
			if strings.HasPrefix(trimmed, "//") {
				comments++
				continue
			}
			if strings.HasPrefix(trimmed, "/*") {
				comments++
				if !strings.Contains(trimmed, "*/") {
					inBlockComment = true
				}
				continue
			}
		case "python", "ruby":
			if strings.HasPrefix(trimmed, "#") {
				comments++
				continue
			}
		case "shell":
			if strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "#!") {
				comments++
				continue
			}
		case "html", "xml":
			if strings.HasPrefix(trimmed, "<!--") {
				comments++
				if !strings.Contains(trimmed, "-->") {
					inBlockComment = true
				}
				continue
			}
			if inBlockComment {
				comments++
				if strings.Contains(trimmed, "-->") {
					inBlockComment = false
				}
				continue
			}
		}

		code++
	}

	return code, comments, blank
}

// insertSorted inserts a file info into a sorted slice, keeping only top N.
func insertSorted(slice []FileSizeInfo, item FileSizeInfo, maxLen int) []FileSizeInfo {
	i := 0
	for i < len(slice) && slice[i].Lines > item.Lines {
		i++
	}

	slice = append(slice, FileSizeInfo{})
	copy(slice[i+1:], slice[i:])
	slice[i] = item

	if len(slice) > maxLen {
		slice = slice[:maxLen]
	}

	return slice
}

// calculateComplexityScore calculates a complexity score.
func (a *Analyzer) calculateComplexityScore(files []*ParsedFile) float64 {
	if len(files) == 0 {
		return 100
	}

	var totalComplexity float64
	var fileCount int

	for _, file := range files {
		complexity := a.calculateFileComplexity(file)
		totalComplexity += complexity
		fileCount++
	}

	avgComplexity := totalComplexity / float64(fileCount)
	score := 100 - (avgComplexity * 5)
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}

// calculateFileComplexity calculates complexity for a single file.
func (a *Analyzer) calculateFileComplexity(file *ParsedFile) float64 {
	var complexity float64

	for _, line := range file.Lines {
		trimmed := strings.TrimSpace(line)

		// Count control flow complexity
		keywords := []string{"if ", "else ", "for ", "while ", "switch ", "case ", "try ", "catch ", "except ", "finally "}
		for _, kw := range keywords {
			if strings.Contains(trimmed, kw) || strings.HasPrefix(trimmed, kw) {
				complexity++
			}
		}

		// Deep nesting indicator
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if indent > 16 {
			complexity += 0.5
		}
	}

	// Normalize by file size
	if file.LineCount > 0 {
		complexity = complexity / float64(file.LineCount) * 100
	}

	return complexity
}

// QualityIssue represents a code quality issue.
type QualityIssue struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Line    int    `json:"line"`
	Column  int    `json:"column,omitempty"`
	Context string `json:"context,omitempty"`
	File    string `json:"file"`
}

// AnalyzeCodeQuality analyzes code quality issues.
func (a *Analyzer) AnalyzeCodeQuality(file *ParsedFile) []QualityIssue {
	var issues []QualityIssue

	// Check for long lines
	for i, line := range file.Lines {
		if len(line) > 120 {
			issues = append(issues, QualityIssue{
				Type:    "long_line",
				Message: fmt.Sprintf("Line exceeds 120 characters (%d)", len(line)),
				Line:    i + 1,
				Column:  121,
				File:    file.Path,
			})
		}
	}

	// Check for large functions
	for _, fn := range file.Functions {
		fnSize := fn.EndLine - fn.StartLine
		if fnSize > 100 {
			issues = append(issues, QualityIssue{
				Type:    "large_function",
				Message: fmt.Sprintf("Function %s is too large (%d lines)", fn.Name, fnSize),
				Line:    fn.StartLine,
				Context: fn.Name,
				File:    file.Path,
			})
		}
		if fn.Complexity > 15 {
			issues = append(issues, QualityIssue{
				Type:    "high_complexity",
				Message: fmt.Sprintf("Function %s has high complexity (%d)", fn.Name, fn.Complexity),
				Line:    fn.StartLine,
				Context: fn.Name,
				File:    file.Path,
			})
		}
	}

	// Check for TODO/FIXME comments
	for i, line := range file.Lines {
		upper := strings.ToUpper(line)
		if strings.Contains(upper, "TODO") ||
			strings.Contains(upper, "FIXME") ||
			strings.Contains(upper, "HACK") ||
			strings.Contains(upper, "XXX") {
			issues = append(issues, QualityIssue{
				Type:    "todo_comment",
				Message: "Found TODO/FIXME comment",
				Line:    i + 1,
				File:    file.Path,
			})
		}
	}

	return issues
}

// CalculateDuplication detects code duplication.
func (a *Analyzer) CalculateDuplication(files []*ParsedFile) float64 {
	lineHashes := make(map[string]int)
	duplicateLines := 0
	totalLines := 0

	for _, file := range files {
		for _, line := range file.Lines {
			trimmed := strings.TrimSpace(line)
			if len(trimmed) < 10 {
				continue
			}

			totalLines++
			lineHashes[trimmed]++
		}
	}

	for _, count := range lineHashes {
		if count > 1 {
			duplicateLines += count - 1
		}
	}

	if totalLines == 0 {
		return 100
	}

	duplicationRatio := float64(duplicateLines) / float64(totalLines)
	score := (1 - duplicationRatio) * 100

	return score
}

// calculateSummary calculates the analysis summary.
func (a *Analyzer) calculateSummary(findings []Finding) AnalysisSummary {
	summary := AnalysisSummary{}

	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			summary.CriticalCount++
		case SeverityHigh:
			summary.HighCount++
		case SeverityMedium:
			summary.MediumCount++
		case SeverityLow:
			summary.LowCount++
		case SeverityInfo:
			summary.InfoCount++
		}
	}

	summary.TotalCount = len(findings)

	// Calculate security score (100 = perfect, 0 = worst)
	// Weight: Critical=25, High=10, Medium=5, Low=2, Info=1
	totalWeight := float64(summary.CriticalCount*25 + summary.HighCount*10 + summary.MediumCount*5 + summary.LowCount*2 + summary.InfoCount)
	if summary.TotalCount > 0 {
		summary.SecurityScore = 100 - (totalWeight / float64(summary.TotalCount+10) * 10)
		if summary.SecurityScore < 0 {
			summary.SecurityScore = 0
		}
	} else {
		summary.SecurityScore = 100
	}

	return summary
}

// sortFindings sorts findings by severity (critical first).
func (a *Analyzer) sortFindings(findings []Finding) {
	severityOrder := map[Severity]int{
		SeverityCritical: 0,
		SeverityHigh:     1,
		SeverityMedium:   2,
		SeverityLow:      3,
		SeverityInfo:     4,
	}

	sort.Slice(findings, func(i, j int) bool {
		if severityOrder[findings[i].Severity] != severityOrder[findings[j].Severity] {
			return severityOrder[findings[i].Severity] < severityOrder[findings[j].Severity]
		}
		if findings[i].FilePath != findings[j].FilePath {
			return findings[i].FilePath < findings[j].FilePath
		}
		return findings[i].Line < findings[j].Line
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
