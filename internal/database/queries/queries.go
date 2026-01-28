// Package queries provides SQL query constants and repository implementations.
package queries

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/code-security-auditor/internal/models"
)

// Repository queries
const (
	InsertRepository = `
		INSERT INTO repositories (id, name, full_name, url, clone_url, provider, default_branch, private, description, language, webhook_id, webhook_secret, settings, created_at, updated_at)
		VALUES (:id, :name, :full_name, :url, :clone_url, :provider, :default_branch, :private, :description, :language, :webhook_id, :webhook_secret, :settings, :created_at, :updated_at)
	`

	SelectRepositoryByID = `
		SELECT * FROM repositories WHERE id = $1
	`

	SelectRepositoryByFullName = `
		SELECT * FROM repositories WHERE full_name = $1
	`

	SelectRepositories = `
		SELECT * FROM repositories
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	UpdateRepository = `
		UPDATE repositories
		SET name = :name, full_name = :full_name, url = :url, clone_url = :clone_url,
		    provider = :provider, default_branch = :default_branch, private = :private,
		    description = :description, language = :language, webhook_id = :webhook_id,
		    webhook_secret = :webhook_secret, settings = :settings, last_scan_id = :last_scan_id,
		    last_scan_at = :last_scan_at, total_scans = :total_scans, updated_at = :updated_at
		WHERE id = :id
	`

	DeleteRepository = `
		DELETE FROM repositories WHERE id = $1
	`
)

// Scan queries
const (
	InsertScan = `
		INSERT INTO scans (id, repository_id, status, type, trigger, branch, commit_sha, pr_number, started_at, completed_at, duration_ms, files_scanned, lines_scanned, error_message, metadata, created_at, updated_at)
		VALUES (:id, :repository_id, :status, :type, :trigger, :branch, :commit_sha, :pr_number, :started_at, :completed_at, :duration_ms, :files_scanned, :lines_scanned, :error_message, :metadata, :created_at, :updated_at)
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

	SelectLatestScanByRepository = `
		SELECT * FROM scans
		WHERE repository_id = $1
		ORDER BY created_at DESC
		LIMIT 1
	`

	UpdateScan = `
		UPDATE scans
		SET status = :status, started_at = :started_at, completed_at = :completed_at,
		    duration_ms = :duration_ms, files_scanned = :files_scanned, lines_scanned = :lines_scanned,
		    error_message = :error_message, metadata = :metadata, updated_at = :updated_at
		WHERE id = :id
	`

	DeleteScan = `
		DELETE FROM scans WHERE id = $1
	`

	CountScansByStatus = `
		SELECT status, COUNT(*) as count FROM scans GROUP BY status
	`
)

// Vulnerability queries
const (
	InsertVulnerability = `
		INSERT INTO vulnerabilities (id, scan_id, rule_id, title, description, severity, category, file_path, line_start, line_end, column_start, column_end, code_snippet, remediation, references, metadata, confidence, false_positive, suppressed, created_at)
		VALUES (:id, :scan_id, :rule_id, :title, :description, :severity, :category, :file_path, :line_start, :line_end, :column_start, :column_end, :code_snippet, :remediation, :references, :metadata, :confidence, :false_positive, :suppressed, :created_at)
	`

	InsertVulnerabilityBulk = `
		INSERT INTO vulnerabilities (id, scan_id, rule_id, title, description, severity, category, file_path, line_start, line_end, column_start, column_end, code_snippet, remediation, references, metadata, confidence, false_positive, suppressed, created_at)
		VALUES (:id, :scan_id, :rule_id, :title, :description, :severity, :category, :file_path, :line_start, :line_end, :column_start, :column_end, :code_snippet, :remediation, :references, :metadata, :confidence, :false_positive, :suppressed, :created_at)
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

	CountVulnerabilitiesByScan = `
		SELECT severity, COUNT(*) as count
		FROM vulnerabilities
		WHERE scan_id = $1
		GROUP BY severity
	`

	UpdateVulnerability = `
		UPDATE vulnerabilities
		SET false_positive = :false_positive, suppressed = :suppressed
		WHERE id = :id
	`

	DeleteVulnerabilitiesByScan = `
		DELETE FROM vulnerabilities WHERE scan_id = $1
	`
)

// Report queries
const (
	InsertReport = `
		INSERT INTO reports (id, scan_id, repository_id, format, status, file_path, file_size, summary, generated_at, expires_at, created_at)
		VALUES (:id, :scan_id, :repository_id, :format, :status, :file_path, :file_size, :summary, :generated_at, :expires_at, :created_at)
	`

	SelectReportByID = `
		SELECT * FROM reports WHERE id = $1
	`

	SelectReportsByScan = `
		SELECT * FROM reports
		WHERE scan_id = $1
		ORDER BY created_at DESC
	`

	SelectReportsByRepository = `
		SELECT * FROM reports
		WHERE repository_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	UpdateReport = `
		UPDATE reports
		SET status = :status, file_path = :file_path, file_size = :file_size,
		    summary = :summary, generated_at = :generated_at
		WHERE id = :id
	`

	DeleteReport = `
		DELETE FROM reports WHERE id = $1
	`
)

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

// List lists repositories with pagination.
func (r *RepositoryRepository) List(ctx context.Context, limit, offset int) ([]models.Repository, error) {
	var repos []models.Repository
	err := r.db.SelectContext(ctx, &repos, SelectRepositories, limit, offset)
	return repos, err
}

// Update updates a repository.
func (r *RepositoryRepository) Update(ctx context.Context, repo *models.Repository) error {
	_, err := r.db.NamedExecContext(ctx, UpdateRepository, repo)
	return err
}

// Delete deletes a repository.
func (r *RepositoryRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, DeleteRepository, id)
	return err
}

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

// GetLatestByRepository retrieves the latest scan for a repository.
func (r *ScanRepository) GetLatestByRepository(ctx context.Context, repoID uuid.UUID) (*models.Scan, error) {
	var scan models.Scan
	err := r.db.GetContext(ctx, &scan, SelectLatestScanByRepository, repoID)
	if err != nil {
		return nil, err
	}
	return &scan, nil
}

// Update updates a scan.
func (r *ScanRepository) Update(ctx context.Context, scan *models.Scan) error {
	_, err := r.db.NamedExecContext(ctx, UpdateScan, scan)
	return err
}

// Delete deletes a scan.
func (r *ScanRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, DeleteScan, id)
	return err
}

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

// Update updates a vulnerability.
func (r *VulnerabilityRepository) Update(ctx context.Context, vuln *models.Vulnerability) error {
	_, err := r.db.NamedExecContext(ctx, UpdateVulnerability, vuln)
	return err
}

// DeleteByScan deletes all vulnerabilities for a scan.
func (r *VulnerabilityRepository) DeleteByScan(ctx context.Context, scanID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, DeleteVulnerabilitiesByScan, scanID)
	return err
}
