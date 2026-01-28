package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// ReportFormat represents the format of a report.
type ReportFormat string

const (
	ReportFormatJSON     ReportFormat = "json"
	ReportFormatPDF      ReportFormat = "pdf"
	ReportFormatHTML     ReportFormat = "html"
	ReportFormatMarkdown ReportFormat = "markdown"
	ReportFormatSARIF    ReportFormat = "sarif" // Static Analysis Results Interchange Format
)

// ReportStatus represents the status of a report.
type ReportStatus string

const (
	ReportStatusPending   ReportStatus = "pending"
	ReportStatusGenerating ReportStatus = "generating"
	ReportStatusCompleted  ReportStatus = "completed"
	ReportStatusFailed     ReportStatus = "failed"
)

// Report represents a generated security report.
type Report struct {
	ID           uuid.UUID      `db:"id" json:"id"`
	ScanID       uuid.UUID      `db:"scan_id" json:"scan_id"`
	RepositoryID uuid.UUID      `db:"repository_id" json:"repository_id"`
	Format       ReportFormat   `db:"format" json:"format"`
	Status       ReportStatus   `db:"status" json:"status"`
	FilePath     string         `db:"file_path" json:"file_path,omitempty"`
	FileSize     int64          `db:"file_size" json:"file_size"`
	Summary      ReportSummary  `db:"summary" json:"summary"`
	GeneratedAt  *time.Time     `db:"generated_at" json:"generated_at,omitempty"`
	ExpiresAt    *time.Time     `db:"expires_at" json:"expires_at,omitempty"`
	DownloadURL  string         `db:"-" json:"download_url,omitempty"`
	CreatedAt    time.Time      `db:"created_at" json:"created_at"`
}

// ReportSummary holds the summary of a report.
type ReportSummary struct {
	RepositoryName      string                    `json:"repository_name"`
	Branch              string                    `json:"branch"`
	CommitSHA           string                    `json:"commit_sha"`
	ScanDuration        int64                     `json:"scan_duration_ms"`
	FilesScanned        int                       `json:"files_scanned"`
	LinesScanned        int                       `json:"lines_scanned"`
	TotalVulnerabilities int                      `json:"total_vulnerabilities"`
	VulnsBySeverity     map[Severity]int          `json:"vulnerabilities_by_severity"`
	VulnsByCategory     map[VulnerabilityCategory]int `json:"vulnerabilities_by_category"`
	TopVulnerableFiles  []FileVulnCount           `json:"top_vulnerable_files"`
	RiskScore           float64                   `json:"risk_score"` // 0-100
	Grade               string                    `json:"grade"`      // A, B, C, D, F
	Recommendations     []string                  `json:"recommendations"`
}

// FileVulnCount represents vulnerability count per file.
type FileVulnCount struct {
	FilePath string `json:"file_path"`
	Count    int    `json:"count"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
}

// Value implements the driver.Valuer interface.
func (s ReportSummary) Value() (driver.Value, error) {
	return json.Marshal(s)
}

// Scan implements the sql.Scanner interface.
func (s *ReportSummary) Scan(value interface{}) error {
	if value == nil {
		*s = ReportSummary{}
		return nil
	}
	
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}
	
	return json.Unmarshal(bytes, s)
}

// NewReport creates a new Report with defaults.
func NewReport(scanID, repoID uuid.UUID, format ReportFormat) *Report {
	return &Report{
		ID:           uuid.New(),
		ScanID:       scanID,
		RepositoryID: repoID,
		Format:       format,
		Status:       ReportStatusPending,
		CreatedAt:    time.Now(),
	}
}

// CalculateGrade calculates the security grade based on risk score.
func CalculateGrade(riskScore float64) string {
	switch {
	case riskScore >= 90:
		return "A"
	case riskScore >= 80:
		return "B"
	case riskScore >= 70:
		return "C"
	case riskScore >= 60:
		return "D"
	default:
		return "F"
	}
}

// CalculateRiskScore calculates the risk score from vulnerabilities.
func CalculateRiskScore(vulnsBySeverity map[Severity]int) float64 {
	// Base score starts at 100
	score := 100.0

	// Deduct points based on severity
	criticalPenalty := 20.0
	highPenalty := 10.0
	mediumPenalty := 5.0
	lowPenalty := 2.0
	infoPenalty := 0.5

	score -= float64(vulnsBySeverity[SeverityCritical]) * criticalPenalty
	score -= float64(vulnsBySeverity[SeverityHigh]) * highPenalty
	score -= float64(vulnsBySeverity[SeverityMedium]) * mediumPenalty
	score -= float64(vulnsBySeverity[SeverityLow]) * lowPenalty
	score -= float64(vulnsBySeverity[SeverityInfo]) * infoPenalty

	// Ensure score is between 0 and 100
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}

// ReportFilter represents filters for querying reports.
type ReportFilter struct {
	ScanID       *uuid.UUID    `form:"scan_id"`
	RepositoryID *uuid.UUID    `form:"repository_id"`
	Format       *ReportFormat `form:"format"`
	Status       *ReportStatus `form:"status"`
	FromDate     *time.Time    `form:"from_date"`
	ToDate       *time.Time    `form:"to_date"`
	Limit        int           `form:"limit"`
	Offset       int           `form:"offset"`
}

// ReportRequest represents a request to generate a report.
type ReportRequest struct {
	ScanID       uuid.UUID    `json:"scan_id" binding:"required"`
	Format       ReportFormat `json:"format" binding:"required"`
	IncludeAI    bool         `json:"include_ai_analysis"`
	SendToGitHub bool         `json:"send_to_github"`
	Email        string       `json:"email,omitempty"`
}

// DetailedReport represents a full report with all findings.
type DetailedReport struct {
	Report
	Repository      *Repository      `json:"repository"`
	Scan            *Scan            `json:"scan"`
	Vulnerabilities []Vulnerability  `json:"vulnerabilities"`
	AIInsights      *AIReportInsights `json:"ai_insights,omitempty"`
}

// AIReportInsights holds AI-generated insights for a report.
type AIReportInsights struct {
	ExecutiveSummary    string            `json:"executive_summary"`
	KeyFindings         []string          `json:"key_findings"`
	RiskAssessment      string            `json:"risk_assessment"`
	Recommendations     []Recommendation  `json:"recommendations"`
	TrendAnalysis       string            `json:"trend_analysis,omitempty"`
	ComplianceNotes     []string          `json:"compliance_notes,omitempty"`
	GeneratedAt         time.Time         `json:"generated_at"`
}

// Recommendation represents a security recommendation.
type Recommendation struct {
	Priority    int      `json:"priority"` // 1-5, 1 being highest
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Impact      string   `json:"impact"`
	Effort      string   `json:"effort"` // low, medium, high
	RelatedVulns []string `json:"related_vulnerabilities"`
}

// SARIFReport represents a SARIF format report.
type SARIFReport struct {
	Schema  string      `json:"$schema"`
	Version string      `json:"version"`
	Runs    []SARIFRun  `json:"runs"`
}

// SARIFRun represents a run in SARIF format.
type SARIFRun struct {
	Tool    SARIFTool    `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool represents a tool in SARIF format.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver represents a driver in SARIF format.
type SARIFDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	InformationURI  string      `json:"informationUri"`
	Rules           []SARIFRule `json:"rules"`
}

// SARIFRule represents a rule in SARIF format.
type SARIFRule struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
	FullDescription struct {
		Text string `json:"text"`
	} `json:"fullDescription"`
	HelpURI string `json:"helpUri,omitempty"`
}

// SARIFResult represents a result in SARIF format.
type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"` // error, warning, note
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations"`
}

// SARIFMessage represents a message in SARIF format.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation represents a location in SARIF format.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation represents a physical location in SARIF format.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

// SARIFArtifactLocation represents an artifact location in SARIF format.
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFRegion represents a region in SARIF format.
type SARIFRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}
