// Package scanner provides code scanning and vulnerability detection.
package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"code-security-auditor/internal/agent"
	"code-security-auditor/internal/config"
	"code-security-auditor/internal/database"
	"code-security-auditor/internal/models"
	"code-security-auditor/internal/queue"
	"code-security-auditor/internal/scanner/rules"
)

// ScanPhase represents the current phase of a scan.
type ScanPhase string

const (
	ScanPhaseInitializing ScanPhase = "initializing"
	ScanPhaseCloning      ScanPhase = "cloning"
	ScanPhaseParsing      ScanPhase = "parsing"
	ScanPhaseAnalyzing    ScanPhase = "analyzing"
	ScanPhaseAIAnalysis   ScanPhase = "ai_analysis"
	ScanPhaseReporting    ScanPhase = "reporting"
	ScanPhaseComplete     ScanPhase = "complete"
	ScanPhaseFailed       ScanPhase = "failed"
	ScanPhaseCancelled    ScanPhase = "cancelled"
)

// TriggerType represents what triggered the scan.
type TriggerType string

const (
	TriggerTypeManual    TriggerType = "manual"
	TriggerTypeWebhook   TriggerType = "webhook"
	TriggerTypeScheduled TriggerType = "scheduled"
	TriggerTypePR        TriggerType = "pull_request"
)

// Manager orchestrates the scanning process (basic manager).
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

// ScanManager is the enhanced orchestrator with full integration.
type ScanManager struct {
	manager   *Manager
	db        *database.PostgresDB
	adkClient *agent.ADKClient
	queue     *queue.Client
	notifier  Notifier
	config    config.ScannerConfig
	logger    *logrus.Logger
}

// Notifier interface for sending notifications.
type Notifier interface {
	NotifyScanComplete(ctx context.Context, scan *models.Scan, result *EnhancedScanResult) error
	NotifyScanFailed(ctx context.Context, scan *models.Scan, err error) error
}

// NoopNotifier is a no-op notifier for when notifications are disabled.
type NoopNotifier struct{}

func (n *NoopNotifier) NotifyScanComplete(ctx context.Context, scan *models.Scan, result *EnhancedScanResult) error {
	return nil
}
func (n *NoopNotifier) NotifyScanFailed(ctx context.Context, scan *models.Scan, err error) error {
	return nil
}

// ScanManagerConfig holds configuration for ScanManager.
type ScanManagerConfig struct {
	ScannerConfig config.ScannerConfig
	GitConfig     config.GitConfig
	Database      *database.PostgresDB
	ADKClient     *agent.ADKClient
	Queue         *queue.Client
	Notifier      Notifier
	Logger        *logrus.Logger
}

// NewScanManager creates a new enhanced ScanManager.
func NewScanManager(cfg ScanManagerConfig) *ScanManager {
	notifier := cfg.Notifier
	if notifier == nil {
		notifier = &NoopNotifier{}
	}

	return &ScanManager{
		manager:   NewManager(cfg.ScannerConfig, cfg.GitConfig, cfg.Logger),
		db:        cfg.Database,
		adkClient: cfg.ADKClient,
		queue:     cfg.Queue,
		notifier:  notifier,
		config:    cfg.ScannerConfig,
		logger:    cfg.Logger,
	}
}

// ScanRequest represents a request to scan a repository.
type ScanRequest struct {
	RepositoryURL string      `json:"repository_url"`
	Branch        string      `json:"branch"`
	CommitSHA     string      `json:"commit_sha,omitempty"`
	TriggerType   TriggerType `json:"trigger_type"`
	Options       ScanOptions `json:"options"`
	Repository    *models.Repository
	Scan          *models.Scan
}

// ScanOptions holds options for a scan.
type ScanOptions struct {
	FullScan       bool     `json:"full_scan"`
	Languages      []string `json:"languages,omitempty"`
	EnabledRules   []string `json:"enabled_rules,omitempty"`
	DisabledRules  []string `json:"disabled_rules,omitempty"`
	MaxFileSizeMB  int      `json:"max_file_size_mb,omitempty"`
	SkipPatterns   []string `json:"skip_patterns,omitempty"`
	UseADKAnalysis bool     `json:"use_adk_analysis"`
	GenerateReport bool     `json:"generate_report"`
	PostToGitHub   bool     `json:"post_to_github"`
	ExcludedPaths  []string `json:"excluded_paths,omitempty"`
	MaxFiles       int      `json:"max_files,omitempty"`
	Timeout        time.Duration
}

// EnhancedScanResult holds the comprehensive result of a scan.
type EnhancedScanResult struct {
	ScanID          uuid.UUID              `json:"scan_id"`
	Status          models.ScanStatus      `json:"status"`
	StartTime       time.Time              `json:"start_time"`
	EndTime         time.Time              `json:"end_time"`
	FilesScanned    int                    `json:"files_scanned"`
	LinesScanned    int                    `json:"lines_scanned"`
	TotalFindings   int                    `json:"total_findings"`
	Vulnerabilities []models.Vulnerability `json:"vulnerabilities"`
	AIAnalysis      *agent.AgentResponse   `json:"ai_analysis,omitempty"`
	Metrics         *CodeMetrics           `json:"metrics"`
	Report          *agent.Report          `json:"report,omitempty"`
	Duration        time.Duration          `json:"duration"`
	Errors          []ScanError            `json:"errors,omitempty"`
	Error           error                  `json:"-"`
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

// ScanProgress tracks the progress of a scan.
type ScanProgress struct {
	ScanID         uuid.UUID `json:"scan_id"`
	Phase          ScanPhase `json:"phase"`
	Progress       float64   `json:"progress"`
	FilesProcessed int       `json:"files_processed"`
	TotalFiles     int       `json:"total_files"`
	CurrentFile    string    `json:"current_file,omitempty"`
	Message        string    `json:"message,omitempty"`
	StartedAt      time.Time `json:"started_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// ProgressTracker tracks and reports scan progress.
type ProgressTracker struct {
	scanID         uuid.UUID
	progress       *ScanProgress
	callbacks      []func(ScanProgress)
	mu             sync.RWMutex
	filesProcessed int32
}

// NewProgressTracker creates a new progress tracker.
func NewProgressTracker(scanID uuid.UUID) *ProgressTracker {
	return &ProgressTracker{
		scanID: scanID,
		progress: &ScanProgress{
			ScanID:    scanID,
			Phase:     ScanPhaseInitializing,
			StartedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		callbacks: make([]func(ScanProgress), 0),
	}
}

// OnProgress registers a callback for progress updates.
func (pt *ProgressTracker) OnProgress(callback func(ScanProgress)) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.callbacks = append(pt.callbacks, callback)
}

// Update updates the progress and notifies callbacks.
func (pt *ProgressTracker) Update(phase ScanPhase, progress float64, message string) {
	pt.mu.Lock()
	pt.progress.Phase = phase
	pt.progress.Progress = progress
	pt.progress.Message = message
	pt.progress.UpdatedAt = time.Now()
	progressCopy := *pt.progress
	callbacks := pt.callbacks
	pt.mu.Unlock()

	for _, cb := range callbacks {
		cb(progressCopy)
	}
}

// UpdateFile updates the current file being processed.
func (pt *ProgressTracker) UpdateFile(file string, processed, total int) {
	pt.mu.Lock()
	pt.progress.CurrentFile = file
	pt.progress.FilesProcessed = processed
	pt.progress.TotalFiles = total
	pt.progress.Progress = float64(processed) / float64(total) * 100
	pt.progress.UpdatedAt = time.Now()
	progressCopy := *pt.progress
	callbacks := pt.callbacks
	pt.mu.Unlock()

	for _, cb := range callbacks {
		cb(progressCopy)
	}
}

// IncrementFiles atomically increments the files processed count.
func (pt *ProgressTracker) IncrementFiles() int {
	return int(atomic.AddInt32(&pt.filesProcessed, 1))
}

// GetProgress returns the current progress.
func (pt *ProgressTracker) GetProgress() ScanProgress {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	return *pt.progress
}

// ExecuteScan performs a full security scan with comprehensive workflow.
func (sm *ScanManager) ExecuteScan(ctx context.Context, req *ScanRequest) (*EnhancedScanResult, error) {
	startTime := time.Now()
	scanID := uuid.New()

	tracker := NewProgressTracker(scanID)

	result := &EnhancedScanResult{
		ScanID:    scanID,
		Status:    models.ScanStatusRunning,
		StartTime: startTime,
		Errors:    make([]ScanError, 0),
	}

	sm.logger.WithFields(logrus.Fields{
		"scan_id":        scanID,
		"repository_url": req.RepositoryURL,
		"branch":         req.Branch,
		"trigger":        req.TriggerType,
	}).Info("Starting enhanced security scan")

	// Use defer for cleanup and final status update
	var clonePath string
	defer func() {
		sm.cleanup(clonePath)
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(startTime)

		if result.Error != nil {
			result.Status = models.ScanStatusFailed
			tracker.Update(ScanPhaseFailed, 0, result.Error.Error())
			sm.notifier.NotifyScanFailed(ctx, req.Scan, result.Error)
		} else {
			result.Status = models.ScanStatusCompleted
			tracker.Update(ScanPhaseComplete, 100, "Scan complete")
			sm.notifier.NotifyScanComplete(ctx, req.Scan, result)
		}

		sm.logger.WithFields(logrus.Fields{
			"scan_id":         scanID,
			"status":          result.Status,
			"duration":        result.Duration,
			"vulnerabilities": result.TotalFindings,
		}).Info("Scan completed")
	}()

	// Step 1: Validate request
	tracker.Update(ScanPhaseInitializing, 5, "Validating request")
	if err := sm.validateRequest(req); err != nil {
		result.Error = fmt.Errorf("validation failed: %w", err)
		return result, result.Error
	}

	// Step 2: Create scan record if not provided
	if req.Scan == nil {
		req.Scan = &models.Scan{
			ID:          scanID,
			Status:      models.ScanStatusRunning,
			Type:        models.ScanTypeFull,
			TriggerType: models.ScanTriggerManual,
			Branch:      req.Branch,
			CommitSHA:   req.CommitSHA,
		}
	}

	// Step 3: Clone repository
	tracker.Update(ScanPhaseCloning, 10, "Cloning repository")
	var err error
	clonePath, err = sm.cloneRepository(ctx, req)
	if err != nil {
		result.Error = fmt.Errorf("clone failed: %w", err)
		return result, result.Error
	}

	// Step 4: Identify files to scan
	tracker.Update(ScanPhaseParsing, 20, "Parsing files")
	files, err := sm.parseFiles(ctx, clonePath, req.Options)
	if err != nil {
		result.Error = fmt.Errorf("parsing failed: %w", err)
		return result, result.Error
	}

	result.FilesScanned = len(files)
	for _, f := range files {
		result.LinesScanned += f.LineCount
	}

	// Step 5-6: Run static analysis (concurrent)
	tracker.Update(ScanPhaseAnalyzing, 30, "Analyzing files")
	vulns, scanErrors := sm.analyzeFilesConcurrent(ctx, scanID, files, req.Options, tracker)
	result.Vulnerabilities = vulns
	result.Errors = append(result.Errors, scanErrors...)
	result.TotalFindings = len(vulns)

	// Step 7: Calculate metrics
	tracker.Update(ScanPhaseAnalyzing, 60, "Calculating metrics")
	metrics := sm.manager.analyzer.CalculateMetrics(files)
	result.Metrics = &metrics

	// Step 8: Send to ADK for intelligent analysis (if enabled)
	if req.Options.UseADKAnalysis && sm.adkClient != nil && len(vulns) > 0 {
		tracker.Update(ScanPhaseAIAnalysis, 70, "Running AI analysis")
		aiResponse, err := sm.runADKAnalysis(ctx, vulns, clonePath)
		if err != nil {
			sm.logger.WithError(err).Warn("AI analysis failed, continuing without AI insights")
			result.Errors = append(result.Errors, ScanError{
				Phase:   "ai_analysis",
				Message: err.Error(),
			})
		} else {
			result.AIAnalysis = aiResponse
		}
	}

	// Step 9: Generate report (if enabled)
	if req.Options.GenerateReport && sm.adkClient != nil {
		tracker.Update(ScanPhaseReporting, 85, "Generating report")
		report, err := sm.generateReport(ctx, req.Scan, result)
		if err != nil {
			sm.logger.WithError(err).Warn("Report generation failed")
			result.Errors = append(result.Errors, ScanError{
				Phase:   "report_generation",
				Message: err.Error(),
			})
		} else {
			result.Report = report
		}
	}

	// Step 10: Update scan record in database
	if sm.db != nil && req.Scan != nil {
		tracker.Update(ScanPhaseComplete, 95, "Updating database")
		if err := sm.updateScanRecord(ctx, req.Scan, result); err != nil {
			sm.logger.WithError(err).Error("Failed to update scan record")
		}
	}

	return result, nil
}

// validateRequest validates the scan request.
func (sm *ScanManager) validateRequest(req *ScanRequest) error {
	if req.RepositoryURL == "" && req.Repository == nil {
		return fmt.Errorf("repository URL or repository object required")
	}

	if req.Branch == "" {
		req.Branch = "main" // Default branch
	}

	if req.TriggerType == "" {
		req.TriggerType = TriggerTypeManual
	}

	return nil
}

// cloneRepository clones the repository.
func (sm *ScanManager) cloneRepository(ctx context.Context, req *ScanRequest) (string, error) {
	repoURL := req.RepositoryURL
	if req.Repository != nil {
		repoURL = req.Repository.CloneURL
	}

	return sm.manager.gitOps.Clone(ctx, repoURL, req.Branch, req.CommitSHA)
}

// parseFiles parses files in the repository.
func (sm *ScanManager) parseFiles(ctx context.Context, clonePath string, opts ScanOptions) ([]*ParsedFile, error) {
	excludedPaths := append(sm.config.ExcludedPaths, opts.ExcludedPaths...)
	files, err := sm.manager.parser.ParseRepository(ctx, clonePath, excludedPaths)
	if err != nil {
		return nil, err
	}

	// Apply max files limit
	maxFiles := opts.MaxFiles
	if maxFiles == 0 {
		maxFiles = sm.config.MaxFilesPerScan
	}
	if maxFiles > 0 && len(files) > maxFiles {
		files = files[:maxFiles]
	}

	return files, nil
}

// analyzeFilesConcurrent analyzes files concurrently.
func (sm *ScanManager) analyzeFilesConcurrent(
	ctx context.Context,
	scanID uuid.UUID,
	files []*ParsedFile,
	opts ScanOptions,
	tracker *ProgressTracker,
) ([]models.Vulnerability, []ScanError) {
	var (
		vulns  []models.Vulnerability
		errors []ScanError
		mu     sync.Mutex
		wg     sync.WaitGroup
	)

	// Create worker pool
	workers := sm.config.ConcurrentWorkers
	if workers == 0 {
		workers = 4
	}

	// Create file channel
	fileChan := make(chan *ParsedFile, len(files))
	for _, f := range files {
		fileChan <- f
	}
	close(fileChan)

	// Get enabled rules
	enabledRules := opts.EnabledRules
	if len(enabledRules) == 0 {
		enabledRules = sm.config.EnabledRules
	}

	// Process files with workers
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

				// Update progress
				processed := tracker.IncrementFiles()
				tracker.UpdateFile(file.Path, processed, len(files))

				// Run rules on file
				fileVulns, err := sm.manager.ruleEngine.Analyze(ctx, file, enabledRules)
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

// runADKAnalysis runs AI analysis on vulnerabilities.
func (sm *ScanManager) runADKAnalysis(ctx context.Context, vulns []models.Vulnerability, clonePath string) (*agent.AgentResponse, error) {
	if sm.adkClient == nil {
		return nil, fmt.Errorf("ADK client not configured")
	}

	// Convert vulnerabilities to findings
	findings := make([]models.Finding, len(vulns))
	for i, v := range vulns {
		findings[i] = v.ToFinding()
	}

	// Build code context map
	codeContext := make(map[string]string)
	for _, v := range vulns {
		if _, exists := codeContext[v.FilePath]; !exists {
			// Read file content for context
			content, err := os.ReadFile(filepath.Join(clonePath, v.FilePath))
			if err == nil {
				codeContext[v.FilePath] = string(content)
			}
		}
	}

	input := &agent.AnalysisInput{
		Findings:    findings,
		CodeContext: codeContext,
	}

	return sm.adkClient.AnalyzeVulnerabilities(ctx, input)
}

// generateReport generates a security report.
func (sm *ScanManager) generateReport(ctx context.Context, scan *models.Scan, result *EnhancedScanResult) (*agent.Report, error) {
	if sm.adkClient == nil {
		return nil, fmt.Errorf("ADK client not configured")
	}

	scanResult := &agent.ScanResult{
		Scan:            scan,
		Vulnerabilities: result.Vulnerabilities,
	}

	return sm.adkClient.GenerateReport(ctx, scanResult)
}

// updateScanRecord updates the scan record in the database.
func (sm *ScanManager) updateScanRecord(ctx context.Context, scan *models.Scan, result *EnhancedScanResult) error {
	scan.Status = result.Status
	scan.FilesScanned = result.FilesScanned
	scan.LinesScanned = result.LinesScanned
	duration := int64(result.Duration.Milliseconds())
	scan.Duration = &duration

	// Use database if available
	if sm.db != nil {
		_, err := sm.db.ExecContext(ctx, `
			UPDATE scans 
			SET status = $1, files_scanned = $2, lines_scanned = $3, 
			    duration = $4, completed_at = $5, updated_at = NOW()
			WHERE id = $6
		`, scan.Status, scan.FilesScanned, scan.LinesScanned,
			scan.Duration, result.EndTime, scan.ID)
		return err
	}

	return nil
}

// cleanup removes temporary files.
func (sm *ScanManager) cleanup(path string) {
	if path == "" {
		return
	}
	if err := os.RemoveAll(path); err != nil {
		sm.logger.WithError(err).Warnf("Failed to cleanup path: %s", path)
	}
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
		vulns  []models.Vulnerability
		errors []ScanError
		mu     sync.Mutex
		wg     sync.WaitGroup
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

// CancelScan cancels a running scan.
func (sm *ScanManager) CancelScan(ctx context.Context, scanID uuid.UUID) error {
	sm.logger.WithField("scan_id", scanID).Info("Cancelling scan")

	if sm.db != nil {
		_, err := sm.db.ExecContext(ctx, `
			UPDATE scans 
			SET status = $1, updated_at = NOW()
			WHERE id = $2 AND status = $3
		`, models.ScanStatusCancelled, scanID, models.ScanStatusRunning)
		return err
	}

	return nil
}

// GetManager returns the underlying basic Manager.
func (sm *ScanManager) GetManager() *Manager {
	return sm.manager
}
