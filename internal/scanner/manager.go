// Package scanner provides code scanning and vulnerability detection.
package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"code-security-auditor/internal/config"
	"code-security-auditor/internal/models"
	"code-security-auditor/internal/scanner/rules"
)

// Manager orchestrates the scanning process (basic manager).
type Manager struct {
	config     config.ScannerConfig
	gitOps     *GitManager
	parser     *Parser
	analyzer   *Analyzer
	ruleEngine *rules.RuleEngine
	logger     *logrus.Logger
}

// NewManager creates a new scan Manager.
func NewManager(
	scannerCfg config.ScannerConfig,
	gitCfg config.GitConfig,
	logger *logrus.Logger,
) *Manager {
	ruleEngine := rules.NewEngine(scannerCfg, logger)

	// Register default rules
	ruleEngine.Register(rules.NewSQLInjectionRule())
	ruleEngine.Register(rules.NewXSSRule())
	ruleEngine.Register(rules.NewSecretsRule())
	ruleEngine.Register(rules.NewDependencyRule())

	return &Manager{
		config:     scannerCfg,
		gitOps:     mustNewGitManager(gitCfg, logger),
		parser:     NewParser(scannerCfg, logger),
		analyzer:   NewAnalyzer(scannerCfg, logger),
		ruleEngine: ruleEngine,
		logger:     logger,
	}
}

// ScanOptions holds options for a scan.
type ScanOptions struct {
	EnabledRules  []string `json:"enabled_rules,omitempty"`
	MaxFiles      int      `json:"max_files,omitempty"`
	ExcludedPaths []string `json:"excluded_paths,omitempty"`
	Timeout       time.Duration
	Branch        string `json:"branch,omitempty"`
	CommitSHA     string `json:"commit_sha,omitempty"`

	// PathPrefix is prepended to every reported file path. Scanning a
	// subdirectory would otherwise report paths relative to that subdirectory,
	// and since the path feeds the fingerprint, a subdirectory scan could never
	// be compared against a baseline taken from the whole tree.
	PathPrefix string `json:"path_prefix,omitempty"`
}

// ScanResult holds the result of a scan.
type ScanResult struct {
	Vulnerabilities []models.Vulnerability
	Metrics         CodeMetrics
	FilesScanned    int
	LinesScanned    int
	Duration        time.Duration
	Errors          []ScanError
}

// ScanError represents an error during scanning.
type ScanError struct {
	File    string `json:"file"`
	Message string `json:"message"`
	Phase   string `json:"phase"`
}

// Scan performs a full security scan on a repository (original method).
func (m *Manager) Scan(ctx context.Context, repo *models.Repository, scan *models.Scan, opts ScanOptions) (*ScanResult, error) {
	startTime := time.Now()
	m.logger.WithFields(logrus.Fields{
		"repository": repo.FullName,
		"scan_id":    scan.ID,
		"branch":     opts.Branch,
	}).Info("Starting security scan")

	result := &ScanResult{
		Vulnerabilities: make([]models.Vulnerability, 0),
		Errors:          make([]ScanError, 0),
	}

	// Apply timeout
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = m.config.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Clone repository
	cloneResult, err := m.gitOps.Clone(ctx, CloneOptions{
		URL:       repo.CloneURL,
		Branch:    opts.Branch,
		CommitSHA: opts.CommitSHA,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to clone repository: %w", err)
	}
	clonePath := cloneResult.Path
	defer m.cleanup(clonePath)

	// Parse files
	files, skipped, err := m.parser.ParseRepository(ctx, clonePath, m.getExcludedPaths(opts), opts.MaxFiles, opts.PathPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to parse repository: %w", err)
	}
	result.Errors = append(result.Errors, skipped...)

	result.FilesScanned = len(files)

	// Calculate total lines
	for _, f := range files {
		result.LinesScanned += f.LineCount
	}

	// Get enabled rules
	enabledRules := m.getEnabledRules(opts)

	// Analyze files
	vulns, errors := m.analyzeFiles(ctx, scan.ID, files, enabledRules)
	result.Vulnerabilities = vulns
	result.Errors = append(result.Errors, errors...)

	// Calculate metrics
	metrics := m.analyzer.CalculateMetrics(files)
	result.Metrics = *metrics

	result.Duration = time.Since(startTime)

	m.logger.WithFields(logrus.Fields{
		"repository":      repo.FullName,
		"scan_id":         scan.ID,
		"files_scanned":   result.FilesScanned,
		"lines_scanned":   result.LinesScanned,
		"vulnerabilities": len(result.Vulnerabilities),
		"duration":        result.Duration,
	}).Info("Scan completed")

	return result, nil
}

// ScanPath performs a scan on a local path.
func (m *Manager) ScanPath(ctx context.Context, scanID uuid.UUID, path string, opts ScanOptions) (*ScanResult, error) {
	startTime := time.Now()
	m.logger.WithFields(logrus.Fields{
		"path":    path,
		"scan_id": scanID,
	}).Info("Starting local path scan")

	result := &ScanResult{
		Vulnerabilities: make([]models.Vulnerability, 0),
		Errors:          make([]ScanError, 0),
	}

	// Parse files
	files, skipped, err := m.parser.ParseRepository(ctx, path, m.getExcludedPaths(opts), opts.MaxFiles, opts.PathPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to parse path: %w", err)
	}
	result.Errors = append(result.Errors, skipped...)

	result.FilesScanned = len(files)
	for _, f := range files {
		result.LinesScanned += f.LineCount
	}

	// Get enabled rules
	enabledRules := m.getEnabledRules(opts)

	// Analyze files
	vulns, errors := m.analyzeFiles(ctx, scanID, files, enabledRules)
	result.Vulnerabilities = vulns
	result.Errors = append(result.Errors, errors...)

	// Calculate metrics
	metrics := m.analyzer.CalculateMetrics(files)
	result.Metrics = *metrics

	result.Duration = time.Since(startTime)

	return result, nil
}

// analyzeFiles analyzes files for vulnerabilities.
func (m *Manager) analyzeFiles(ctx context.Context, scanID uuid.UUID, files []*ParsedFile, enabledRules []string) ([]models.Vulnerability, []ScanError) {
	var (
		vulns  []models.Vulnerability
		errors []ScanError
		mu     sync.Mutex
		wg     sync.WaitGroup
	)

	// Create worker pool
	workers := m.config.MaxConcurrent
	if workers == 0 {
		workers = 4
	}

	fileChan := make(chan *ParsedFile, len(files))
	for _, f := range files {
		fileChan <- f
	}
	close(fileChan)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range fileChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				// Run rules on file
				fileFindings := filterByRules(m.ruleEngine.Analyze(file), enabledRules)
				fileVulns := convertFindingsToVulnerabilities(fileFindings, scanID)

				mu.Lock()
				vulns = append(vulns, fileVulns...)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// Workers append as they finish, so order depends on scheduling. Sort so
	// two runs over the same tree produce byte-identical output.
	sort.Slice(vulns, func(i, j int) bool {
		if vulns[i].FilePath != vulns[j].FilePath {
			return vulns[i].FilePath < vulns[j].FilePath
		}
		if vulns[i].LineStart != vulns[j].LineStart {
			return vulns[i].LineStart < vulns[j].LineStart
		}
		return vulns[i].RuleID < vulns[j].RuleID
	})

	return vulns, errors
}

// filterByRules keeps only findings selected by --rules / enabled_rules.
// An empty selection keeps everything.
//
// A selector matches either a rule ID ("RULE-SQL-001") or a category
// ("sql_injection"). The engine has two ID namespaces — interface rules are
// named by category, pattern rules by RULE-XXX-NNN — and matching on both is
// what makes `--rules sql_injection` select all the SQL rules rather than one.
func filterByRules(findings []rules.Finding, enabled []string) []rules.Finding {
	if len(enabled) == 0 {
		return findings
	}

	want := make(map[string]bool, len(enabled))
	for _, r := range enabled {
		want[strings.ToLower(strings.TrimSpace(r))] = true
	}

	kept := make([]rules.Finding, 0, len(findings))
	for _, f := range findings {
		if want[strings.ToLower(f.RuleID)] || want[strings.ToLower(f.Category)] {
			kept = append(kept, f)
		}
	}
	return kept
}

// getExcludedPaths returns the list of excluded paths.
func (m *Manager) getExcludedPaths(opts ScanOptions) []string {
	excluded := make([]string, 0, len(m.config.ExcludedPaths)+len(opts.ExcludedPaths))
	excluded = append(excluded, m.config.ExcludedPaths...)
	excluded = append(excluded, opts.ExcludedPaths...)
	return excluded
}

// getEnabledRules returns the list of enabled rules.
func (m *Manager) getEnabledRules(opts ScanOptions) []string {
	if len(opts.EnabledRules) > 0 {
		return opts.EnabledRules
	}
	return m.config.EnabledRules
}

// cleanup removes temporary files.
func (m *Manager) cleanup(path string) {
	if path == "" {
		return
	}
	if err := os.RemoveAll(path); err != nil {
		m.logger.WithError(err).Warnf("Failed to cleanup path: %s", path)
	}
}

// ValidatePath validates that a path is safe to scan.
func (m *Manager) ValidatePath(path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("path does not exist: %w", err)
	}

	if !info.IsDir() {
		return fmt.Errorf("path is not a directory")
	}

	return nil
}
