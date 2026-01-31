// Package scanner provides code scanning and vulnerability detection.
package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"code-security-auditor/internal/config"
	"code-security-auditor/internal/models"
	"code-security-auditor/internal/scanner/rules"
)

// Manager orchestrates the scanning process.
type Manager struct {
	config     config.ScannerConfig
	gitOps     *GitOperations
	parser     *Parser
	analyzer   *Analyzer
	ruleEngine *rules.Engine
	logger     *logrus.Logger
}

// NewManager creates a new scan Manager.
func NewManager(
	scannerCfg config.ScannerConfig,
	gitCfg config.GitConfig,
	logger *logrus.Logger,
) *Manager {
	ruleEngine := rules.NewEngine(logger)
	
	// Register default rules
	ruleEngine.Register(rules.NewSQLInjectionRule())
	ruleEngine.Register(rules.NewXSSRule())
	ruleEngine.Register(rules.NewSecretsRule())
	ruleEngine.Register(rules.NewDependencyRule())

	return &Manager{
		config:     scannerCfg,
		gitOps:     NewGitOperations(gitCfg, logger),
		parser:     NewParser(scannerCfg, logger),
		analyzer:   NewAnalyzer(scannerCfg, logger),
		ruleEngine: ruleEngine,
		logger:     logger,
	}
}

// ScanOptions holds options for a scan.
type ScanOptions struct {
	Branch        string
	CommitSHA     string
	EnabledRules  []string
	ExcludedPaths []string
	MaxFiles      int
	Timeout       time.Duration
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

// Scan performs a full security scan on a repository.
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
		timeout = m.config.ScanTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Clone repository
	clonePath, err := m.gitOps.Clone(ctx, repo.CloneURL, opts.Branch, opts.CommitSHA)
	if err != nil {
		return nil, fmt.Errorf("failed to clone repository: %w", err)
	}
	defer m.cleanup(clonePath)

	// Parse files
	files, err := m.parser.ParseRepository(ctx, clonePath, m.getExcludedPaths(opts))
	if err != nil {
		return nil, fmt.Errorf("failed to parse repository: %w", err)
	}

	// Limit files if specified
	maxFiles := opts.MaxFiles
	if maxFiles == 0 {
		maxFiles = m.config.MaxFilesPerScan
	}
	if len(files) > maxFiles {
		files = files[:maxFiles]
	}

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
	result.Errors = errors

	// Calculate metrics
	result.Metrics = m.analyzer.CalculateMetrics(files)

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
	files, err := m.parser.ParseRepository(ctx, path, m.getExcludedPaths(opts))
	if err != nil {
		return nil, fmt.Errorf("failed to parse path: %w", err)
	}

	result.FilesScanned = len(files)
	for _, f := range files {
		result.LinesScanned += f.LineCount
	}

	// Get enabled rules
	enabledRules := m.getEnabledRules(opts)

	// Analyze files
	vulns, errors := m.analyzeFiles(ctx, scanID, files, enabledRules)
	result.Vulnerabilities = vulns
	result.Errors = errors

	// Calculate metrics
	result.Metrics = m.analyzer.CalculateMetrics(files)

	result.Duration = time.Since(startTime)

	return result, nil
}

// analyzeFiles analyzes files for vulnerabilities.
func (m *Manager) analyzeFiles(ctx context.Context, scanID uuid.UUID, files []*ParsedFile, enabledRules []string) ([]models.Vulnerability, []ScanError) {
	var (
		vulns   []models.Vulnerability
		errors  []ScanError
		mu      sync.Mutex
		wg      sync.WaitGroup
	)

	// Create worker pool
	workers := m.config.ConcurrentWorkers
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
				fileVulns, err := m.ruleEngine.Analyze(ctx, file, enabledRules)
				if err != nil {
					mu.Lock()
					errors = append(errors, ScanError{
						File:    file.Path,
						Message: err.Error(),
						Phase:   "analysis",
					})
					mu.Unlock()
					continue
				}

				// Add scan ID to vulnerabilities
				for i := range fileVulns {
					fileVulns[i].ScanID = scanID
				}

				mu.Lock()
				vulns = append(vulns, fileVulns...)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return vulns, errors
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

// Progress represents scan progress.
type Progress struct {
	Phase          string  `json:"phase"`
	Progress       float64 `json:"progress"`
	FilesProcessed int     `json:"files_processed"`
	TotalFiles     int     `json:"total_files"`
	CurrentFile    string  `json:"current_file,omitempty"`
	Message        string  `json:"message,omitempty"`
}

// ProgressCallback is called with progress updates.
type ProgressCallback func(Progress)

// ScanWithProgress performs a scan with progress updates.
func (m *Manager) ScanWithProgress(ctx context.Context, repo *models.Repository, scan *models.Scan, opts ScanOptions, callback ProgressCallback) (*ScanResult, error) {
	callback(Progress{Phase: "cloning", Progress: 0, Message: "Cloning repository..."})

	// Clone repository
	clonePath, err := m.gitOps.Clone(ctx, repo.CloneURL, opts.Branch, opts.CommitSHA)
	if err != nil {
		return nil, fmt.Errorf("failed to clone repository: %w", err)
	}
	defer m.cleanup(clonePath)

	callback(Progress{Phase: "parsing", Progress: 10, Message: "Parsing files..."})

	// Parse files
	files, err := m.parser.ParseRepository(ctx, clonePath, m.getExcludedPaths(opts))
	if err != nil {
		return nil, fmt.Errorf("failed to parse repository: %w", err)
	}

	callback(Progress{Phase: "analyzing", Progress: 30, TotalFiles: len(files), Message: "Analyzing files..."})

	result := &ScanResult{
		Vulnerabilities: make([]models.Vulnerability, 0),
		Errors:          make([]ScanError, 0),
		FilesScanned:    len(files),
	}

	for _, f := range files {
		result.LinesScanned += f.LineCount
	}

	// Analyze with progress
	enabledRules := m.getEnabledRules(opts)
	for i, file := range files {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		fileVulns, err := m.ruleEngine.Analyze(ctx, file, enabledRules)
		if err != nil {
			result.Errors = append(result.Errors, ScanError{
				File:    file.Path,
				Message: err.Error(),
				Phase:   "analysis",
			})
			continue
		}

		for j := range fileVulns {
			fileVulns[j].ScanID = scan.ID
		}
		result.Vulnerabilities = append(result.Vulnerabilities, fileVulns...)

		progress := 30 + (float64(i+1) / float64(len(files)) * 60)
		callback(Progress{
			Phase:          "analyzing",
			Progress:       progress,
			FilesProcessed: i + 1,
			TotalFiles:     len(files),
			CurrentFile:    file.Path,
		})
	}

	callback(Progress{Phase: "complete", Progress: 100, Message: "Scan complete"})

	result.Metrics = m.analyzer.CalculateMetrics(files)
	return result, nil
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
