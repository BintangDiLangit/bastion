package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// RepositoryProvider represents the Git provider.
type RepositoryProvider string

const (
	ProviderGitHub    RepositoryProvider = "github"
	ProviderGitLab    RepositoryProvider = "gitlab"
	ProviderBitbucket RepositoryProvider = "bitbucket"
	ProviderGeneric   RepositoryProvider = "generic"
)

// Repository represents a code repository.
type Repository struct {
	ID             uuid.UUID          `db:"id" json:"id"`
	Name           string             `db:"name" json:"name"`
	FullName       string             `db:"full_name" json:"full_name"` // owner/repo
	URL            string             `db:"url" json:"url"`
	CloneURL       string             `db:"clone_url" json:"clone_url"`
	Provider       RepositoryProvider `db:"provider" json:"provider"`
	DefaultBranch  string             `db:"default_branch" json:"default_branch"`
	Private        bool               `db:"private" json:"private"`
	Description    string             `db:"description" json:"description"`
	Language       string             `db:"language" json:"language"`
	WebhookID      *string            `db:"webhook_id" json:"webhook_id,omitempty"`
	WebhookSecret  *string            `db:"webhook_secret" json:"-"`
	Settings       RepoSettings       `db:"settings" json:"settings"`
	LastScanID     *uuid.UUID         `db:"last_scan_id" json:"last_scan_id,omitempty"`
	LastScanAt     *time.Time         `db:"last_scan_at" json:"last_scan_at,omitempty"`
	TotalScans     int                `db:"total_scans" json:"total_scans"`
	CreatedAt      time.Time          `db:"created_at" json:"created_at"`
	UpdatedAt      time.Time          `db:"updated_at" json:"updated_at"`
}

// RepoSettings holds repository-specific settings.
type RepoSettings struct {
	AutoScanEnabled    bool     `json:"auto_scan_enabled"`
	ScanOnPush         bool     `json:"scan_on_push"`
	ScanOnPR           bool     `json:"scan_on_pr"`
	ProtectedBranches  []string `json:"protected_branches"`
	ExcludedPaths      []string `json:"excluded_paths"`
	EnabledRules       []string `json:"enabled_rules"`
	DisabledRules      []string `json:"disabled_rules"`
	NotifyOnCritical   bool     `json:"notify_on_critical"`
	NotifyOnHigh       bool     `json:"notify_on_high"`
	FailPROnCritical   bool     `json:"fail_pr_on_critical"`
	FailPROnHigh       bool     `json:"fail_pr_on_high"`
}

// Value implements the driver.Valuer interface.
func (s RepoSettings) Value() (driver.Value, error) {
	return json.Marshal(s)
}

// Scan implements the sql.Scanner interface.
func (s *RepoSettings) Scan(value interface{}) error {
	if value == nil {
		*s = RepoSettings{}
		return nil
	}
	
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}
	
	return json.Unmarshal(bytes, s)
}

// NewRepository creates a new Repository with defaults.
func NewRepository(repoURL string) (*Repository, error) {
	parsed, err := url.Parse(repoURL)
	if err != nil {
		return nil, err
	}

	provider := detectProvider(parsed.Host)
	fullName := strings.TrimPrefix(parsed.Path, "/")
	fullName = strings.TrimSuffix(fullName, ".git")
	
	parts := strings.Split(fullName, "/")
	name := fullName
	if len(parts) > 1 {
		name = parts[len(parts)-1]
	}

	now := time.Now()
	return &Repository{
		ID:            uuid.New(),
		Name:          name,
		FullName:      fullName,
		URL:           repoURL,
		CloneURL:      repoURL,
		Provider:      provider,
		DefaultBranch: "main",
		Settings: RepoSettings{
			AutoScanEnabled:  true,
			ScanOnPush:       true,
			ScanOnPR:         true,
			NotifyOnCritical: true,
			NotifyOnHigh:     true,
			FailPROnCritical: true,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

// detectProvider detects the repository provider from the host.
func detectProvider(host string) RepositoryProvider {
	host = strings.ToLower(host)
	switch {
	case strings.Contains(host, "github"):
		return ProviderGitHub
	case strings.Contains(host, "gitlab"):
		return ProviderGitLab
	case strings.Contains(host, "bitbucket"):
		return ProviderBitbucket
	default:
		return ProviderGeneric
	}
}

// Owner returns the repository owner from the full name.
func (r *Repository) Owner() string {
	parts := strings.Split(r.FullName, "/")
	if len(parts) > 1 {
		return parts[0]
	}
	return ""
}

// RepoName returns just the repository name.
func (r *Repository) RepoName() string {
	parts := strings.Split(r.FullName, "/")
	if len(parts) > 1 {
		return parts[1]
	}
	return r.Name
}

// UpdateLastScan updates the last scan information.
func (r *Repository) UpdateLastScan(scanID uuid.UUID) {
	now := time.Now()
	r.LastScanID = &scanID
	r.LastScanAt = &now
	r.TotalScans++
	r.UpdatedAt = now
}

// RepositoryFilter represents filters for querying repositories.
type RepositoryFilter struct {
	Provider RepositoryProvider `form:"provider"`
	Name     string             `form:"name"`
	Private  *bool              `form:"private"`
	Limit    int                `form:"limit"`
	Offset   int                `form:"offset"`
}

// RepositoryStats holds statistics about a repository.
type RepositoryStats struct {
	RepositoryID    uuid.UUID `json:"repository_id"`
	TotalScans      int       `json:"total_scans"`
	LastScanAt      *time.Time `json:"last_scan_at"`
	TotalVulns      int       `json:"total_vulnerabilities"`
	CriticalCount   int       `json:"critical_count"`
	HighCount       int       `json:"high_count"`
	MediumCount     int       `json:"medium_count"`
	LowCount        int       `json:"low_count"`
	ResolvedCount   int       `json:"resolved_count"`
	TrendDirection  string    `json:"trend_direction"` // improving, worsening, stable
}

// RepositoryCreateRequest represents a request to add a repository.
type RepositoryCreateRequest struct {
	URL           string `json:"url" binding:"required"`
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
	AccessToken   string `json:"access_token,omitempty"`
}

// RepositoryUpdateRequest represents a request to update repository settings.
type RepositoryUpdateRequest struct {
	DefaultBranch *string       `json:"default_branch,omitempty"`
	Description   *string       `json:"description,omitempty"`
	Settings      *RepoSettings `json:"settings,omitempty"`
}

// WebhookConfig represents webhook configuration for a repository.
type WebhookConfig struct {
	RepositoryID uuid.UUID `json:"repository_id"`
	WebhookURL   string    `json:"webhook_url"`
	Secret       string    `json:"secret"`
	Events       []string  `json:"events"`
	Active       bool      `json:"active"`
}
