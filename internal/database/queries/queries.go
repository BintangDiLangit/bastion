// Package queries provides SQL query constants and repository implementations.
package queries

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"code-security-auditor/internal/models"
)

// ============================================================================
// Repository Queries
// ============================================================================

const (
	InsertRepository = `
		INSERT INTO repositories (
			id, name, full_name, url, clone_url, provider, default_branch, 
			private, description, language, webhook_id, webhook_secret, 
			settings, owner, is_active, created_at, updated_at
		) VALUES (
			:id, :name, :full_name, :url, :clone_url, :provider, :default_branch,
			:private, :description, :language, :webhook_id, :webhook_secret,
			:settings, :owner, :is_active, :created_at, :updated_at
		)
	`

	SelectRepositoryByID = `
		SELECT * FROM repositories WHERE id = $1
	`

	SelectRepositoryByFullName = `
		SELECT * FROM repositories WHERE full_name = $1
	`

	SelectRepositoryByURL = `
		SELECT * FROM repositories WHERE url = $1
	`

	SelectRepositories = `
		SELECT * FROM repositories
		WHERE is_active = true
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	SelectRepositoriesAll = `
		SELECT * FROM repositories
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	SelectRepositoriesByProvider = `
		SELECT * FROM repositories
		WHERE provider = $1 AND is_active = true
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	CountRepositories = `
		SELECT COUNT(*) FROM repositories WHERE is_active = true
	`

	UpdateRepository = `
		UPDATE repositories
		SET name = :name, full_name = :full_name, url = :url, clone_url = :clone_url,
		    provider = :provider, default_branch = :default_branch, private = :private,
		    description = :description, language = :language, webhook_id = :webhook_id,
		    webhook_secret = :webhook_secret, settings = :settings, last_scan_id = :last_scan_id,
		    last_scanned_at = :last_scanned_at, total_scans = :total_scans, 
		    is_active = :is_active, updated_at = :updated_at
		WHERE id = :id
	`

	UpdateRepositoryLastScan = `
		UPDATE repositories
		SET last_scan_id = $2, last_scanned_at = $3, total_scans = total_scans + 1, updated_at = NOW()
		WHERE id = $1
	`

	DeleteRepository = `
		DELETE FROM repositories WHERE id = $1
	`

	SoftDeleteRepository = `
		UPDATE repositories SET is_active = false, updated_at = NOW() WHERE id = $1
	`
)

// ============================================================================
// Scan Queries
// ============================================================================

const (
	InsertScan = `
		INSERT INTO scans (
			id, repository_id, status, type, triggered_by, branch, commit_sha, 
			pr_number, started_at, completed_at, duration_ms, total_files_scanned, 
			lines_scanned, total_vulnerabilities, critical_count, high_count,
			medium_count, low_count, error_message, metadata, created_at, updated_at
		) VALUES (
			:id, :repository_id, :status, :type, :triggered_by, :branch, :commit_sha,
			:pr_number, :started_at, :completed_at, :duration_ms, :total_files_scanned,
			:lines_scanned, :total_vulnerabilities, :critical_count, :high_count,
			:medium_count, :low_count, :error_message, :metadata, :created_at, :updated_at
		)
	`

	SelectScanByID = `
		SELECT * FROM scans WHERE id = $1
	`

	SelectScansByRepository = `
		SELECT * FROM scans
		WHERE repository_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	SelectScansByRepositoryAndStatus = `
		SELECT * FROM scans
		WHERE repository_id = $1 AND status = $2
		ORDER BY created_at DESC
		LIMIT $3 OFFSET $4
	`

	SelectLatestScanByRepository = `
		SELECT * FROM scans
		WHERE repository_id = $1
		ORDER BY created_at DESC
		LIMIT 1
	`

	SelectLatestCompletedScanByRepository = `
		SELECT * FROM scans
		WHERE repository_id = $1 AND status = 'completed'
		ORDER BY created_at DESC
		LIMIT 1
	`

	SelectPendingScans = `
		SELECT * FROM scans
		WHERE status = 'pending'
		ORDER BY created_at ASC
		LIMIT $1
	`

	SelectRunningScans = `
		SELECT * FROM scans
		WHERE status = 'running'
		ORDER BY started_at ASC
	`

	UpdateScan = `
		UPDATE scans
		SET status = :status, started_at = :started_at, completed_at = :completed_at,
		    duration_ms = :duration_ms, total_files_scanned = :total_files_scanned, 
		    lines_scanned = :lines_scanned, total_vulnerabilities = :total_vulnerabilities,
		    critical_count = :critical_count, high_count = :high_count,
		    medium_count = :medium_count, low_count = :low_count,
		    error_message = :error_message, metadata = :metadata, 
		    security_score = :security_score, code_quality_score = :code_quality_score,
		    agent_summary = :agent_summary, agent_analysis = :agent_analysis,
		    updated_at = :updated_at
		WHERE id = :id
	`

	UpdateScanStatus = `
		UPDATE scans
		SET status = $2, updated_at = NOW()
		WHERE id = $1
	`

	UpdateScanStarted = `
		UPDATE scans
		SET status = 'running', started_at = NOW(), updated_at = NOW()
		WHERE id = $1
	`

	UpdateScanCompleted = `
		UPDATE scans
		SET status = 'completed', completed_at = NOW(), 
		    duration_ms = EXTRACT(EPOCH FROM (NOW() - started_at)) * 1000,
		    updated_at = NOW()
		WHERE id = $1
	`

	UpdateScanFailed = `
		UPDATE scans
		SET status = 'failed', completed_at = NOW(), error_message = $2, updated_at = NOW()
		WHERE id = $1
	`

	DeleteScan = `
		DELETE FROM scans WHERE id = $1
	`

	CountScansByStatus = `
		SELECT status, COUNT(*) as count FROM scans GROUP BY status
	`

	CountScansByRepositoryAndPeriod = `
		SELECT COUNT(*) FROM scans
		WHERE repository_id = $1 AND created_at >= $2 AND created_at <= $3
	`
)

// ============================================================================
// Vulnerability Queries
// ============================================================================

const (
	InsertVulnerability = `
		INSERT INTO vulnerabilities (
			id, scan_id, rule_id, title, description, severity, category, 
			file_path, line_start, line_end, column_start, column_end, 
			code_snippet, remediation, references, metadata, confidence, 
			cwe_id, cvss_score, false_positive, suppressed, created_at
		) VALUES (
			:id, :scan_id, :rule_id, :title, :description, :severity, :category,
			:file_path, :line_start, :line_end, :column_start, :column_end,
			:code_snippet, :remediation, :references, :metadata, :confidence,
			:cwe_id, :cvss_score, :false_positive, :suppressed, :created_at
		)
	`

	InsertVulnerabilityBulk = `
		INSERT INTO vulnerabilities (
			id, scan_id, rule_id, title, description, severity, category,
			file_path, line_start, line_end, column_start, column_end,
			code_snippet, remediation, references, metadata, confidence,
			cwe_id, cvss_score, false_positive, suppressed, created_at
		) VALUES (
			:id, :scan_id, :rule_id, :title, :description, :severity, :category,
			:file_path, :line_start, :line_end, :column_start, :column_end,
			:code_snippet, :remediation, :references, :metadata, :confidence,
			:cwe_id, :cvss_score, :false_positive, :suppressed, :created_at
		)
	`

	SelectVulnerabilityByID = `
		SELECT * FROM vulnerabilities WHERE id = $1
	`

	SelectVulnerabilitiesByScan = `
		SELECT * FROM vulnerabilities
		WHERE scan_id = $1
		ORDER BY 
			CASE severity 
				WHEN 'critical' THEN 1 
				WHEN 'high' THEN 2 
				WHEN 'medium' THEN 3 
				WHEN 'low' THEN 4 
				ELSE 5 
			END,
			file_path, line_start
	`

	SelectVulnerabilitiesByScanPaginated = `
		SELECT * FROM vulnerabilities
		WHERE scan_id = $1
		ORDER BY 
			CASE severity 
				WHEN 'critical' THEN 1 
				WHEN 'high' THEN 2 
				WHEN 'medium' THEN 3 
				WHEN 'low' THEN 4 
				ELSE 5 
			END,
			file_path, line_start
		LIMIT $2 OFFSET $3
	`

	SelectVulnerabilitiesBySeverity = `
		SELECT * FROM vulnerabilities
		WHERE scan_id = $1 AND severity = $2
		ORDER BY file_path, line_start
	`

	SelectVulnerabilitiesByCategory = `
		SELECT * FROM vulnerabilities
		WHERE scan_id = $1 AND category = $2
		ORDER BY severity, file_path, line_start
	`

	SelectVulnerabilitiesByFile = `
		SELECT * FROM vulnerabilities
		WHERE scan_id = $1 AND file_path = $2
		ORDER BY line_start
	`

	SelectActiveVulnerabilitiesByScan = `
		SELECT * FROM vulnerabilities
		WHERE scan_id = $1 AND false_positive = false AND suppressed = false
		ORDER BY 
			CASE severity 
				WHEN 'critical' THEN 1 
				WHEN 'high' THEN 2 
				WHEN 'medium' THEN 3 
				WHEN 'low' THEN 4 
				ELSE 5 
			END
	`

	CountVulnerabilitiesByScan = `
		SELECT severity, COUNT(*) as count
		FROM vulnerabilities
		WHERE scan_id = $1
		GROUP BY severity
	`

	CountVulnerabilitiesByScanAndCategory = `
		SELECT category, COUNT(*) as count
		FROM vulnerabilities
		WHERE scan_id = $1
		GROUP BY category
	`

	UpdateVulnerability = `
		UPDATE vulnerabilities
		SET false_positive = :false_positive, suppressed = :suppressed,
		    suppressed_by = :suppressed_by, suppressed_at = :suppressed_at,
		    suppression_reason = :suppression_reason, fixed_at = :fixed_at
		WHERE id = :id
	`

	MarkVulnerabilityFalsePositive = `
		UPDATE vulnerabilities
		SET false_positive = true
		WHERE id = $1
	`

	MarkVulnerabilitySuppressed = `
		UPDATE vulnerabilities
		SET suppressed = true, suppressed_by = $2, suppressed_at = NOW(), suppression_reason = $3
		WHERE id = $1
	`

	DeleteVulnerabilitiesByScan = `
		DELETE FROM vulnerabilities WHERE scan_id = $1
	`
)

// ============================================================================
// Report Queries
// ============================================================================

const (
	InsertReport = `
		INSERT INTO scan_reports (
			id, scan_id, repository_id, report_type, status, file_path, 
			file_size, summary, generated_at, expires_at, created_at
		) VALUES (
			:id, :scan_id, :repository_id, :report_type, :status, :file_path,
			:file_size, :summary, :generated_at, :expires_at, :created_at
		)
	`

	SelectReportByID = `
		SELECT * FROM scan_reports WHERE id = $1
	`

	SelectReportsByScan = `
		SELECT * FROM scan_reports
		WHERE scan_id = $1
		ORDER BY created_at DESC
	`

	SelectReportsByRepository = `
		SELECT * FROM scan_reports
		WHERE repository_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	SelectReportByType = `
		SELECT * FROM scan_reports
		WHERE scan_id = $1 AND report_type = $2
		LIMIT 1
	`

	UpdateReport = `
		UPDATE scan_reports
		SET status = :status, file_path = :file_path, file_size = :file_size,
		    summary = :summary, generated_at = :generated_at
		WHERE id = :id
	`

	UpdateReportDownloadCount = `
		UPDATE scan_reports
		SET download_count = download_count + 1, last_downloaded_at = NOW()
		WHERE id = $1
	`

	DeleteReport = `
		DELETE FROM scan_reports WHERE id = $1
	`

	DeleteExpiredReports = `
		DELETE FROM scan_reports WHERE expires_at < NOW()
	`
)

// ============================================================================
// Webhook Event Queries
// ============================================================================

const (
	InsertWebhookEvent = `
		INSERT INTO webhook_events (
			id, source, event_type, repository_url, repository_id, 
			payload, processed, created_at
		) VALUES (
			:id, :source, :event_type, :repository_url, :repository_id,
			:payload, :processed, :created_at
		)
	`

	SelectWebhookEventByID = `
		SELECT * FROM webhook_events WHERE id = $1
	`

	SelectUnprocessedWebhookEvents = `
		SELECT * FROM webhook_events
		WHERE processed = false AND (next_retry_at IS NULL OR next_retry_at <= NOW())
		ORDER BY created_at ASC
		LIMIT $1
	`

	UpdateWebhookEventProcessed = `
		UPDATE webhook_events
		SET processed = true, processed_at = NOW()
		WHERE id = $1
	`

	UpdateWebhookEventFailed = `
		UPDATE webhook_events
		SET error_message = $2, retry_count = retry_count + 1, 
		    next_retry_at = NOW() + INTERVAL '1 minute' * POWER(2, retry_count)
		WHERE id = $1
	`

	DeleteOldWebhookEvents = `
		DELETE FROM webhook_events WHERE created_at < NOW() - INTERVAL '30 days'
	`
)

// ============================================================================
// API Key Queries
// ============================================================================

const (
	InsertAPIKey = `
		INSERT INTO api_keys (
			id, name, key_hash, prefix, scopes, rate_limit, 
			expires_at, owner_id, owner_type, description, metadata, created_at
		) VALUES (
			:id, :name, :key_hash, :prefix, :scopes, :rate_limit,
			:expires_at, :owner_id, :owner_type, :description, :metadata, :created_at
		)
	`

	SelectAPIKeyByHash = `
		SELECT * FROM api_keys 
		WHERE key_hash = $1 AND revoked_at IS NULL 
		  AND (expires_at IS NULL OR expires_at > NOW())
	`

	SelectAPIKeyByPrefix = `
		SELECT * FROM api_keys WHERE prefix = $1
	`

	SelectAPIKeysByOwner = `
		SELECT * FROM api_keys 
		WHERE owner_id = $1 AND revoked_at IS NULL
		ORDER BY created_at DESC
	`

	UpdateAPIKeyLastUsed = `
		UPDATE api_keys SET last_used_at = NOW() WHERE id = $1
	`

	RevokeAPIKey = `
		UPDATE api_keys SET revoked_at = NOW() WHERE id = $1
	`
)

// ============================================================================
// Suppression Rule Queries
// ============================================================================

const (
	InsertSuppressionRule = `
		INSERT INTO suppression_rules (
			id, repository_id, rule_id, file_pattern, reason, 
			expires_at, created_by, severity, category, is_global, created_at
		) VALUES (
			:id, :repository_id, :rule_id, :file_pattern, :reason,
			:expires_at, :created_by, :severity, :category, :is_global, :created_at
		)
	`

	SelectSuppressionRulesByRepository = `
		SELECT * FROM suppression_rules
		WHERE (repository_id = $1 OR is_global = true)
		  AND (expires_at IS NULL OR expires_at > NOW())
		ORDER BY created_at DESC
	`

	DeleteSuppressionRule = `
		DELETE FROM suppression_rules WHERE id = $1
	`
)

// ============================================================================
// Repository Implementations
// ============================================================================

// RepositoryRepository handles repository database operations.
type RepositoryRepository struct {
	db *sqlx.DB
}

// NewRepositoryRepository creates a new RepositoryRepository.
func NewRepositoryRepository(db *sqlx.DB) *RepositoryRepository {
	return &RepositoryRepository{db: db}
}

// Create creates a new repository.
func (r *RepositoryRepository) Create(ctx context.Context, repo *models.Repository) error {
	_, err := r.db.NamedExecContext(ctx, InsertRepository, repo)
	return err
}

// GetByID retrieves a repository by ID.
func (r *RepositoryRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Repository, error) {
	var repo models.Repository
	err := r.db.GetContext(ctx, &repo, SelectRepositoryByID, id)
	if err != nil {
		return nil, err
	}
	return &repo, nil
}

// GetByFullName retrieves a repository by full name.
func (r *RepositoryRepository) GetByFullName(ctx context.Context, fullName string) (*models.Repository, error) {
	var repo models.Repository
	err := r.db.GetContext(ctx, &repo, SelectRepositoryByFullName, fullName)
	if err != nil {
		return nil, err
	}
	return &repo, nil
}

// GetByURL retrieves a repository by URL.
func (r *RepositoryRepository) GetByURL(ctx context.Context, url string) (*models.Repository, error) {
	var repo models.Repository
	err := r.db.GetContext(ctx, &repo, SelectRepositoryByURL, url)
	if err != nil {
		return nil, err
	}
	return &repo, nil
}

// List lists repositories with pagination.
func (r *RepositoryRepository) List(ctx context.Context, limit, offset int) ([]models.Repository, error) {
	var repos []models.Repository
	err := r.db.SelectContext(ctx, &repos, SelectRepositories, limit, offset)
	return repos, err
}

// ListByProvider lists repositories by provider with pagination.
func (r *RepositoryRepository) ListByProvider(ctx context.Context, provider string, limit, offset int) ([]models.Repository, error) {
	var repos []models.Repository
	err := r.db.SelectContext(ctx, &repos, SelectRepositoriesByProvider, provider, limit, offset)
	return repos, err
}

// Count returns the total count of active repositories.
func (r *RepositoryRepository) Count(ctx context.Context) (int, error) {
	var count int
	err := r.db.GetContext(ctx, &count, CountRepositories)
	return count, err
}

// Update updates a repository.
func (r *RepositoryRepository) Update(ctx context.Context, repo *models.Repository) error {
	_, err := r.db.NamedExecContext(ctx, UpdateRepository, repo)
	return err
}

// UpdateLastScan updates the last scan information.
func (r *RepositoryRepository) UpdateLastScan(ctx context.Context, repoID, scanID uuid.UUID, scannedAt time.Time) error {
	_, err := r.db.ExecContext(ctx, UpdateRepositoryLastScan, repoID, scanID, scannedAt)
	return err
}

// Delete deletes a repository.
func (r *RepositoryRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, DeleteRepository, id)
	return err
}

// SoftDelete soft-deletes a repository.
func (r *RepositoryRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, SoftDeleteRepository, id)
	return err
}

// ============================================================================
// Scan Repository
// ============================================================================

// ScanRepository handles scan database operations.
type ScanRepository struct {
	db *sqlx.DB
}

// NewScanRepository creates a new ScanRepository.
func NewScanRepository(db *sqlx.DB) *ScanRepository {
	return &ScanRepository{db: db}
}

// Create creates a new scan.
func (r *ScanRepository) Create(ctx context.Context, scan *models.Scan) error {
	_, err := r.db.NamedExecContext(ctx, InsertScan, scan)
	return err
}

// GetByID retrieves a scan by ID.
func (r *ScanRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Scan, error) {
	var scan models.Scan
	err := r.db.GetContext(ctx, &scan, SelectScanByID, id)
	if err != nil {
		return nil, err
	}
	return &scan, nil
}

// GetByRepository retrieves scans by repository ID.
func (r *ScanRepository) GetByRepository(ctx context.Context, repoID uuid.UUID, limit, offset int) ([]models.Scan, error) {
	var scans []models.Scan
	err := r.db.SelectContext(ctx, &scans, SelectScansByRepository, repoID, limit, offset)
	return scans, err
}

// GetByRepositoryAndStatus retrieves scans by repository ID and status.
func (r *ScanRepository) GetByRepositoryAndStatus(ctx context.Context, repoID uuid.UUID, status string, limit, offset int) ([]models.Scan, error) {
	var scans []models.Scan
	err := r.db.SelectContext(ctx, &scans, SelectScansByRepositoryAndStatus, repoID, status, limit, offset)
	return scans, err
}

// GetLatestByRepository retrieves the latest scan for a repository.
func (r *ScanRepository) GetLatestByRepository(ctx context.Context, repoID uuid.UUID) (*models.Scan, error) {
	var scan models.Scan
	err := r.db.GetContext(ctx, &scan, SelectLatestScanByRepository, repoID)
	if err != nil {
		return nil, err
	}
	return &scan, nil
}

// GetLatestCompletedByRepository retrieves the latest completed scan for a repository.
func (r *ScanRepository) GetLatestCompletedByRepository(ctx context.Context, repoID uuid.UUID) (*models.Scan, error) {
	var scan models.Scan
	err := r.db.GetContext(ctx, &scan, SelectLatestCompletedScanByRepository, repoID)
	if err != nil {
		return nil, err
	}
	return &scan, nil
}

// GetPending retrieves pending scans.
func (r *ScanRepository) GetPending(ctx context.Context, limit int) ([]models.Scan, error) {
	var scans []models.Scan
	err := r.db.SelectContext(ctx, &scans, SelectPendingScans, limit)
	return scans, err
}

// GetRunning retrieves running scans.
func (r *ScanRepository) GetRunning(ctx context.Context) ([]models.Scan, error) {
	var scans []models.Scan
	err := r.db.SelectContext(ctx, &scans, SelectRunningScans)
	return scans, err
}

// Update updates a scan.
func (r *ScanRepository) Update(ctx context.Context, scan *models.Scan) error {
	_, err := r.db.NamedExecContext(ctx, UpdateScan, scan)
	return err
}

// UpdateStatus updates only the scan status.
func (r *ScanRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status string) error {
	_, err := r.db.ExecContext(ctx, UpdateScanStatus, id, status)
	return err
}

// MarkStarted marks a scan as started.
func (r *ScanRepository) MarkStarted(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, UpdateScanStarted, id)
	return err
}

// MarkCompleted marks a scan as completed.
func (r *ScanRepository) MarkCompleted(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, UpdateScanCompleted, id)
	return err
}

// MarkFailed marks a scan as failed.
func (r *ScanRepository) MarkFailed(ctx context.Context, id uuid.UUID, errorMsg string) error {
	_, err := r.db.ExecContext(ctx, UpdateScanFailed, id, errorMsg)
	return err
}

// Delete deletes a scan.
func (r *ScanRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, DeleteScan, id)
	return err
}

// ============================================================================
// Vulnerability Repository
// ============================================================================

// VulnerabilityRepository handles vulnerability database operations.
type VulnerabilityRepository struct {
	db *sqlx.DB
}

// NewVulnerabilityRepository creates a new VulnerabilityRepository.
func NewVulnerabilityRepository(db *sqlx.DB) *VulnerabilityRepository {
	return &VulnerabilityRepository{db: db}
}

// Create creates a new vulnerability.
func (r *VulnerabilityRepository) Create(ctx context.Context, vuln *models.Vulnerability) error {
	_, err := r.db.NamedExecContext(ctx, InsertVulnerability, vuln)
	return err
}

// CreateBulk creates multiple vulnerabilities in a single transaction.
func (r *VulnerabilityRepository) CreateBulk(ctx context.Context, vulns []models.Vulnerability) error {
	if len(vulns) == 0 {
		return nil
	}

	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	for _, vuln := range vulns {
		if _, err := tx.NamedExecContext(ctx, InsertVulnerability, vuln); err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to insert vulnerability: %w", err)
		}
	}

	return tx.Commit()
}

// GetByID retrieves a vulnerability by ID.
func (r *VulnerabilityRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Vulnerability, error) {
	var vuln models.Vulnerability
	err := r.db.GetContext(ctx, &vuln, SelectVulnerabilityByID, id)
	if err != nil {
		return nil, err
	}
	return &vuln, nil
}

// GetByScan retrieves vulnerabilities by scan ID.
func (r *VulnerabilityRepository) GetByScan(ctx context.Context, scanID uuid.UUID) ([]models.Vulnerability, error) {
	var vulns []models.Vulnerability
	err := r.db.SelectContext(ctx, &vulns, SelectVulnerabilitiesByScan, scanID)
	return vulns, err
}

// GetByScanPaginated retrieves vulnerabilities by scan ID with pagination.
func (r *VulnerabilityRepository) GetByScanPaginated(ctx context.Context, scanID uuid.UUID, limit, offset int) ([]models.Vulnerability, error) {
	var vulns []models.Vulnerability
	err := r.db.SelectContext(ctx, &vulns, SelectVulnerabilitiesByScanPaginated, scanID, limit, offset)
	return vulns, err
}

// GetBySeverity retrieves vulnerabilities by scan ID and severity.
func (r *VulnerabilityRepository) GetBySeverity(ctx context.Context, scanID uuid.UUID, severity string) ([]models.Vulnerability, error) {
	var vulns []models.Vulnerability
	err := r.db.SelectContext(ctx, &vulns, SelectVulnerabilitiesBySeverity, scanID, severity)
	return vulns, err
}

// GetByCategory retrieves vulnerabilities by scan ID and category.
func (r *VulnerabilityRepository) GetByCategory(ctx context.Context, scanID uuid.UUID, category string) ([]models.Vulnerability, error) {
	var vulns []models.Vulnerability
	err := r.db.SelectContext(ctx, &vulns, SelectVulnerabilitiesByCategory, scanID, category)
	return vulns, err
}

// GetByFile retrieves vulnerabilities by scan ID and file path.
func (r *VulnerabilityRepository) GetByFile(ctx context.Context, scanID uuid.UUID, filePath string) ([]models.Vulnerability, error) {
	var vulns []models.Vulnerability
	err := r.db.SelectContext(ctx, &vulns, SelectVulnerabilitiesByFile, scanID, filePath)
	return vulns, err
}

// GetActive retrieves active (non-suppressed, non-false-positive) vulnerabilities.
func (r *VulnerabilityRepository) GetActive(ctx context.Context, scanID uuid.UUID) ([]models.Vulnerability, error) {
	var vulns []models.Vulnerability
	err := r.db.SelectContext(ctx, &vulns, SelectActiveVulnerabilitiesByScan, scanID)
	return vulns, err
}

// CountByScan returns vulnerability counts by severity for a scan.
func (r *VulnerabilityRepository) CountByScan(ctx context.Context, scanID uuid.UUID) (map[models.Severity]int, error) {
	rows, err := r.db.QueryxContext(ctx, CountVulnerabilitiesByScan, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[models.Severity]int)
	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, err
		}
		counts[models.Severity(severity)] = count
	}

	return counts, nil
}

// CountByScanAndCategory returns vulnerability counts by category for a scan.
func (r *VulnerabilityRepository) CountByScanAndCategory(ctx context.Context, scanID uuid.UUID) (map[string]int, error) {
	rows, err := r.db.QueryxContext(ctx, CountVulnerabilitiesByScanAndCategory, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var category string
		var count int
		if err := rows.Scan(&category, &count); err != nil {
			return nil, err
		}
		counts[category] = count
	}

	return counts, nil
}

// Update updates a vulnerability.
func (r *VulnerabilityRepository) Update(ctx context.Context, vuln *models.Vulnerability) error {
	_, err := r.db.NamedExecContext(ctx, UpdateVulnerability, vuln)
	return err
}

// MarkFalsePositive marks a vulnerability as false positive.
func (r *VulnerabilityRepository) MarkFalsePositive(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, MarkVulnerabilityFalsePositive, id)
	return err
}

// MarkSuppressed marks a vulnerability as suppressed.
func (r *VulnerabilityRepository) MarkSuppressed(ctx context.Context, id uuid.UUID, suppressedBy, reason string) error {
	_, err := r.db.ExecContext(ctx, MarkVulnerabilitySuppressed, id, suppressedBy, reason)
	return err
}

// DeleteByScan deletes all vulnerabilities for a scan.
func (r *VulnerabilityRepository) DeleteByScan(ctx context.Context, scanID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, DeleteVulnerabilitiesByScan, scanID)
	return err
}

// ============================================================================
// Report Repository
// ============================================================================

// ReportRepository handles report database operations.
type ReportRepository struct {
	db *sqlx.DB
}

// NewReportRepository creates a new ReportRepository.
func NewReportRepository(db *sqlx.DB) *ReportRepository {
	return &ReportRepository{db: db}
}

// Create creates a new report.
func (r *ReportRepository) Create(ctx context.Context, report *models.Report) error {
	_, err := r.db.NamedExecContext(ctx, InsertReport, report)
	return err
}

// GetByID retrieves a report by ID.
func (r *ReportRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Report, error) {
	var report models.Report
	err := r.db.GetContext(ctx, &report, SelectReportByID, id)
	if err != nil {
		return nil, err
	}
	return &report, nil
}

// GetByScan retrieves reports by scan ID.
func (r *ReportRepository) GetByScan(ctx context.Context, scanID uuid.UUID) ([]models.Report, error) {
	var reports []models.Report
	err := r.db.SelectContext(ctx, &reports, SelectReportsByScan, scanID)
	return reports, err
}

// GetByRepository retrieves reports by repository ID.
func (r *ReportRepository) GetByRepository(ctx context.Context, repoID uuid.UUID, limit, offset int) ([]models.Report, error) {
	var reports []models.Report
	err := r.db.SelectContext(ctx, &reports, SelectReportsByRepository, repoID, limit, offset)
	return reports, err
}

// GetByType retrieves a report by scan ID and type.
func (r *ReportRepository) GetByType(ctx context.Context, scanID uuid.UUID, reportType string) (*models.Report, error) {
	var report models.Report
	err := r.db.GetContext(ctx, &report, SelectReportByType, scanID, reportType)
	if err != nil {
		return nil, err
	}
	return &report, nil
}

// Update updates a report.
func (r *ReportRepository) Update(ctx context.Context, report *models.Report) error {
	_, err := r.db.NamedExecContext(ctx, UpdateReport, report)
	return err
}

// IncrementDownloadCount increments the download count for a report.
func (r *ReportRepository) IncrementDownloadCount(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, UpdateReportDownloadCount, id)
	return err
}

// Delete deletes a report.
func (r *ReportRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, DeleteReport, id)
	return err
}

// DeleteExpired deletes expired reports.
func (r *ReportRepository) DeleteExpired(ctx context.Context) (int64, error) {
	result, err := r.db.ExecContext(ctx, DeleteExpiredReports)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ============================================================================
// Webhook Event Repository
// ============================================================================

// WebhookEventRepository handles webhook event database operations.
type WebhookEventRepository struct {
	db *sqlx.DB
}

// NewWebhookEventRepository creates a new WebhookEventRepository.
func NewWebhookEventRepository(db *sqlx.DB) *WebhookEventRepository {
	return &WebhookEventRepository{db: db}
}

// Create creates a new webhook event.
func (r *WebhookEventRepository) Create(ctx context.Context, event *models.WebhookEvent) error {
	_, err := r.db.NamedExecContext(ctx, InsertWebhookEvent, event)
	return err
}

// GetByID retrieves a webhook event by ID.
func (r *WebhookEventRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.WebhookEvent, error) {
	var event models.WebhookEvent
	err := r.db.GetContext(ctx, &event, SelectWebhookEventByID, id)
	if err != nil {
		return nil, err
	}
	return &event, nil
}

// GetUnprocessed retrieves unprocessed webhook events.
func (r *WebhookEventRepository) GetUnprocessed(ctx context.Context, limit int) ([]models.WebhookEvent, error) {
	var events []models.WebhookEvent
	err := r.db.SelectContext(ctx, &events, SelectUnprocessedWebhookEvents, limit)
	return events, err
}

// MarkProcessed marks a webhook event as processed.
func (r *WebhookEventRepository) MarkProcessed(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, UpdateWebhookEventProcessed, id)
	return err
}

// MarkFailed marks a webhook event as failed.
func (r *WebhookEventRepository) MarkFailed(ctx context.Context, id uuid.UUID, errorMsg string) error {
	_, err := r.db.ExecContext(ctx, UpdateWebhookEventFailed, id, errorMsg)
	return err
}

// DeleteOld deletes old webhook events.
func (r *WebhookEventRepository) DeleteOld(ctx context.Context) (int64, error) {
	result, err := r.db.ExecContext(ctx, DeleteOldWebhookEvents)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ============================================================================
// Utility Functions
// ============================================================================

// NullableTime converts a pointer to sql.NullTime.
func NullableTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

// NullableString converts a string to sql.NullString.
func NullableString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// NullableInt64 converts a pointer to sql.NullInt64.
func NullableInt64(i *int64) sql.NullInt64 {
	if i == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *i, Valid: true}
}
