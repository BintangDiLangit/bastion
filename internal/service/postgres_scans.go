package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/BintangDiLangit/bastion/internal/models"
	"github.com/BintangDiLangit/bastion/internal/scanner"
)

type PostgresScanStore struct {
	db *sqlx.DB
}

func NewPostgresScanStore(db *sqlx.DB) *PostgresScanStore {
	return &PostgresScanStore{db: db}
}

func (s *PostgresScanStore) EnsureRepository(ctx context.Context, rawURL, branch string) (*models.Repository, error) {
	var repository models.Repository
	err := s.db.GetContext(ctx, &repository, repositorySelect+` WHERE url = $1`, rawURL)
	if err == nil {
		return &repository, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	created, err := models.NewRepository(rawURL)
	if err != nil {
		return nil, err
	}
	if branch != "" {
		created.DefaultBranch = branch
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO repositories
			(id, name, full_name, url, clone_url, provider, default_branch, private, settings, is_active, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,true,$10,$10)
		ON CONFLICT (url) DO NOTHING`,
		created.ID, created.Name, created.FullName, created.URL, created.CloneURL, created.Provider,
		created.DefaultBranch, created.Private, created.Settings, created.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if err := s.db.GetContext(ctx, &repository, repositorySelect+` WHERE url = $1`, rawURL); err != nil {
		return nil, err
	}
	return &repository, nil
}

const repositorySelect = `
	SELECT id,name,full_name,url,clone_url,provider,default_branch,private,
		COALESCE(description,'') AS description,COALESCE(language,'') AS language,
		webhook_id,webhook_secret,settings,
		last_scan_id,last_scanned_at AS last_scan_at,total_scans,created_at,updated_at
	FROM repositories`

const scanSelect = `
	SELECT id,repository_id,status,type,triggered_by AS trigger,COALESCE(branch,'') AS branch,
		COALESCE(commit_sha,'') AS commit_sha,pr_number,started_at,completed_at,duration_ms,
		total_files_scanned AS files_scanned,lines_scanned,error_message,metadata,created_at,updated_at
	FROM scans`

func (s *PostgresScanStore) CreateScan(ctx context.Context, scan *models.Scan) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO scans
			(id,repository_id,status,type,triggered_by,branch,commit_sha,metadata,created_at,updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)`,
		scan.ID, scan.RepositoryID, scan.Status, scan.Type, scan.Trigger, scan.Branch,
		scan.CommitSHA, scan.Metadata, scan.CreatedAt,
	)
	return err
}

func (s *PostgresScanStore) GetScan(ctx context.Context, id uuid.UUID) (*models.Scan, error) {
	var scan models.Scan
	if err := s.db.GetContext(ctx, &scan, scanSelect+` WHERE id = $1`, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &scan, nil
}

func (s *PostgresScanStore) MarkRunning(ctx context.Context, id uuid.UUID) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE scans SET status='running',started_at=NOW(),updated_at=NOW()
		WHERE id=$1 AND status='pending'`, id)
	return changed(result, err)
}

func (s *PostgresScanStore) Complete(ctx context.Context, scan *models.Scan, result *scanner.ScanResult) error {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	counts := map[models.Severity]int{}
	for _, vulnerability := range result.Vulnerabilities {
		counts[vulnerability.Severity]++
	}
	update, err := tx.ExecContext(ctx, `
		UPDATE scans SET status='completed',completed_at=NOW(),duration_ms=$2,
			total_files_scanned=$3,lines_scanned=$4,total_vulnerabilities=$5,
			critical_count=$6,high_count=$7,medium_count=$8,low_count=$9,updated_at=NOW()
		WHERE id=$1 AND status='running'`,
		scan.ID, result.Duration.Milliseconds(), result.FilesScanned, result.LinesScanned,
		len(result.Vulnerabilities), counts[models.SeverityCritical], counts[models.SeverityHigh],
		counts[models.SeverityMedium], counts[models.SeverityLow],
	)
	if err := changed(update, err); err != nil {
		return err
	}
	for _, vulnerability := range result.Vulnerabilities {
		_, err = tx.ExecContext(ctx, `
			INSERT INTO vulnerabilities
				(id,fingerprint,scan_id,rule_id,title,description,severity,category,file_path,line_start,line_end,
				 column_start,column_end,code_snippet,remediation,reference_data,metadata,confidence,
				 is_false_positive,suppressed,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`,
			vulnerability.ID, vulnerability.Fingerprint, scan.ID, vulnerability.RuleID, vulnerability.Title, vulnerability.Description,
			vulnerability.Severity, vulnerability.Category, vulnerability.FilePath, vulnerability.LineStart,
			vulnerability.LineEnd, vulnerability.ColumnStart, vulnerability.ColumnEnd, vulnerability.CodeSnippet,
			vulnerability.Remediation, vulnerability.References, vulnerability.Metadata, vulnerability.Confidence,
			vulnerability.FalsePositive, vulnerability.Suppressed, vulnerability.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("insert vulnerability: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE repositories SET last_scan_id=$2,last_scanned_at=NOW(),total_scans=total_scans+1,updated_at=NOW()
		WHERE id=$1`, scan.RepositoryID, scan.ID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresScanStore) Fail(ctx context.Context, id uuid.UUID, message string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE scans SET status='failed',completed_at=NOW(),error_message=$2,updated_at=NOW()
		WHERE id=$1 AND status='running'`, id, message)
	return err
}

func (s *PostgresScanStore) Cancel(ctx context.Context, id uuid.UUID) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE scans SET status='cancelled',completed_at=NOW(),updated_at=NOW()
		WHERE id=$1 AND status IN ('pending','running')`, id)
	return changed(result, err)
}

func (s *PostgresScanStore) ListVulnerabilities(ctx context.Context, scanID uuid.UUID, limit, offset int) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability
	err := s.db.SelectContext(ctx, &vulnerabilities, `
		SELECT id,fingerprint,scan_id,rule_id,title,description,severity,category,file_path,line_start,line_end,
			column_start,column_end,code_snippet,remediation,reference_data,metadata,confidence,
			is_false_positive AS false_positive,suppressed,created_at
		FROM vulnerabilities WHERE scan_id=$1 ORDER BY severity,line_start LIMIT $2 OFFSET $3`,
		scanID, limit, offset,
	)
	return vulnerabilities, err
}

func (s *PostgresScanStore) Compare(ctx context.Context, scanID uuid.UUID, baselineID *uuid.UUID) (*models.ScanDelta, error) {
	current, err := s.GetScan(ctx, scanID)
	if err != nil {
		return nil, err
	}
	if current.Status != models.ScanStatusCompleted {
		return nil, fmt.Errorf("scan must be completed")
	}

	if baselineID == nil {
		var id uuid.UUID
		err := s.db.GetContext(ctx, &id, `
			SELECT id FROM scans
			WHERE repository_id=$1 AND status='completed' AND id<>$2 AND created_at<$3
			ORDER BY completed_at DESC LIMIT 1`,
			current.RepositoryID, current.ID, current.CreatedAt,
		)
		if err == nil {
			baselineID = &id
		} else if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	}

	currentFindings, err := s.allVulnerabilities(ctx, scanID)
	if err != nil {
		return nil, err
	}
	delta := &models.ScanDelta{
		ScanID:         scanID,
		BaselineScanID: baselineID,
		New:            make([]models.Vulnerability, 0),
		Resolved:       make([]models.Vulnerability, 0),
	}
	if baselineID == nil {
		delta.New = currentFindings
		return delta, nil
	}

	baseline, err := s.GetScan(ctx, *baselineID)
	if err != nil {
		return nil, err
	}
	if baseline.Status != models.ScanStatusCompleted || baseline.RepositoryID != current.RepositoryID {
		return nil, fmt.Errorf("baseline must be a completed scan of the same repository")
	}
	baselineFindings, err := s.allVulnerabilities(ctx, *baselineID)
	if err != nil {
		return nil, err
	}

	return compareFindings(scanID, baselineID, currentFindings, baselineFindings), nil
}

func compareFindings(scanID uuid.UUID, baselineID *uuid.UUID, currentFindings, baselineFindings []models.Vulnerability) *models.ScanDelta {
	delta := &models.ScanDelta{
		ScanID:         scanID,
		BaselineScanID: baselineID,
		New:            make([]models.Vulnerability, 0),
		Resolved:       make([]models.Vulnerability, 0),
	}
	currentByFingerprint := make(map[string]models.Vulnerability, len(currentFindings))
	for _, finding := range currentFindings {
		currentByFingerprint[finding.Fingerprint] = finding
	}
	baselineByFingerprint := make(map[string]models.Vulnerability, len(baselineFindings))
	for _, finding := range baselineFindings {
		baselineByFingerprint[finding.Fingerprint] = finding
	}
	for fingerprint, finding := range currentByFingerprint {
		if _, exists := baselineByFingerprint[fingerprint]; exists {
			delta.Unchanged++
		} else {
			delta.New = append(delta.New, finding)
		}
	}
	for fingerprint, finding := range baselineByFingerprint {
		if _, exists := currentByFingerprint[fingerprint]; !exists {
			delta.Resolved = append(delta.Resolved, finding)
		}
	}
	sort.Slice(delta.New, func(i, j int) bool {
		return delta.New[i].Fingerprint < delta.New[j].Fingerprint
	})
	sort.Slice(delta.Resolved, func(i, j int) bool {
		return delta.Resolved[i].Fingerprint < delta.Resolved[j].Fingerprint
	})
	return delta
}

func (s *PostgresScanStore) allVulnerabilities(ctx context.Context, scanID uuid.UUID) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability
	err := s.db.SelectContext(ctx, &vulnerabilities, `
		SELECT id,fingerprint,scan_id,rule_id,title,description,severity,category,file_path,line_start,line_end,
			column_start,column_end,code_snippet,remediation,reference_data,metadata,confidence,
			is_false_positive AS false_positive,suppressed,created_at
		FROM vulnerabilities WHERE scan_id=$1 AND NOT is_false_positive AND NOT suppressed`,
		scanID,
	)
	return vulnerabilities, err
}

func changed(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}
