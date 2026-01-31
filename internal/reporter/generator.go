// Package reporter provides report generation functionality.
package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"code-security-auditor/internal/models"
)

// ReportType represents the type of report.
type ReportType string

const (
	ReportTypeExecutive ReportType = "executive"
	ReportTypeDetailed  ReportType = "detailed"
	ReportTypeDiff      ReportType = "diff"
)

// Generator generates security reports.
type Generator struct {
	outputDir   string
	templateDir string
	logger      *logrus.Logger
	templates   map[string]*template.Template
	funcMap     template.FuncMap
}

// NewGenerator creates a new report Generator.
func NewGenerator(outputDir, templateDir string, logger *logrus.Logger) (*Generator, error) {
	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	g := &Generator{
		outputDir:   outputDir,
		templateDir: templateDir,
		logger:      logger,
		templates:   make(map[string]*template.Template),
		funcMap: template.FuncMap{
			"lower":         lowerFunc,
			"upper":         upperFunc,
			"mul":           mulFunc,
			"severityEmoji": severityEmojiFunc,
			"truncate":      truncateFunc,
			"percentage":    percentageFunc,
		},
	}

	// Load templates
	if err := g.loadTemplates(); err != nil {
		logger.WithError(err).Warn("Failed to load custom templates, using defaults")
	}

	return g, nil
}

// Template helper functions
func lowerFunc(s string) string                  { return s }
func upperFunc(s string) string                  { return s }
func mulFunc(a, b float64) float64               { return a * b }
func severityEmojiFunc(s models.Severity) string { return getSeverityEmoji(s) }
func truncateFunc(s string, n int) string        { return truncate(s, n) }
func percentageFunc(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b) * 100
}

// loadTemplates loads HTML/Markdown templates.
func (g *Generator) loadTemplates() error {
	if g.templateDir == "" {
		return nil
	}

	// Load HTML template
	htmlPath := filepath.Join(g.templateDir, "report.html")
	if _, err := os.Stat(htmlPath); err == nil {
		tmpl, err := template.New("html").Funcs(g.funcMap).ParseFiles(htmlPath)
		if err != nil {
			return fmt.Errorf("failed to parse HTML template: %w", err)
		}
		g.templates["html"] = tmpl
	}

	// Load Markdown template
	mdPath := filepath.Join(g.templateDir, "report.md")
	if _, err := os.Stat(mdPath); err == nil {
		tmpl, err := template.New("markdown").Funcs(g.funcMap).ParseFiles(mdPath)
		if err != nil {
			return fmt.Errorf("failed to parse Markdown template: %w", err)
		}
		g.templates["markdown"] = tmpl
	}

	// Load Executive Summary template
	execPath := filepath.Join(g.templateDir, "executive.html")
	if _, err := os.Stat(execPath); err == nil {
		tmpl, err := template.New("executive").Funcs(g.funcMap).ParseFiles(execPath)
		if err != nil {
			return fmt.Errorf("failed to parse Executive template: %w", err)
		}
		g.templates["executive"] = tmpl
	}

	return nil
}

// ReportData holds data for report generation.
type ReportData struct {
	Report           *models.Report
	Repository       *models.Repository
	Scan             *models.Scan
	Vulnerabilities  []models.Vulnerability
	Summary          models.ReportSummary
	AIInsights       *models.AIReportInsights
	GeneratedAt      time.Time
	TrendAnalysis    *TrendAnalysis
	ComplianceStatus *ComplianceStatus
	Recommendations  []Recommendation
}

// TrendAnalysis holds trend analysis data.
type TrendAnalysis struct {
	PreviousScanID       uuid.UUID                `json:"previous_scan_id,omitempty"`
	VulnerabilityTrend   string                   `json:"vulnerability_trend"` // increasing, decreasing, stable
	NewVulnerabilities   int                      `json:"new_vulnerabilities"`
	FixedVulnerabilities int                      `json:"fixed_vulnerabilities"`
	RiskScoreChange      float64                  `json:"risk_score_change"`
	TrendData            []TrendDataPoint         `json:"trend_data,omitempty"`
	CategoryTrends       map[string]CategoryTrend `json:"category_trends,omitempty"`
}

// TrendDataPoint represents a point in trend history.
type TrendDataPoint struct {
	ScanDate      time.Time `json:"scan_date"`
	RiskScore     float64   `json:"risk_score"`
	TotalVulns    int       `json:"total_vulns"`
	CriticalVulns int       `json:"critical_vulns"`
}

// CategoryTrend tracks trend for a vulnerability category.
type CategoryTrend struct {
	Current  int    `json:"current"`
	Previous int    `json:"previous"`
	Change   int    `json:"change"`
	Trend    string `json:"trend"` // up, down, stable
}

// ComplianceStatus holds compliance mapping information.
type ComplianceStatus struct {
	OverallCompliant bool                       `json:"overall_compliant"`
	Frameworks       map[string]FrameworkStatus `json:"frameworks"`
}

// FrameworkStatus holds compliance status for a specific framework.
type FrameworkStatus struct {
	Name          string                `json:"name"`
	Compliant     bool                  `json:"compliant"`
	Score         float64               `json:"score"`
	Violations    []ComplianceViolation `json:"violations,omitempty"`
	Passed        int                   `json:"passed"`
	Failed        int                   `json:"failed"`
	NotApplicable int                   `json:"not_applicable"`
}

// ComplianceViolation represents a compliance violation.
type ComplianceViolation struct {
	RuleID      string `json:"rule_id"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Finding     string `json:"finding"`
}

// Recommendation represents a prioritized recommendation.
type Recommendation struct {
	Priority    int    `json:"priority"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
	Effort      string `json:"effort"` // low, medium, high
	Category    string `json:"category"`
}

// DiffReportData holds data for diff reports (PRs).
type DiffReportData struct {
	ReportData
	BaseScan         *models.Scan           `json:"base_scan"`
	NewIssues        []models.Vulnerability `json:"new_issues"`
	FixedIssues      []models.Vulnerability `json:"fixed_issues"`
	UnchangedIssues  []models.Vulnerability `json:"unchanged_issues"`
	RiskScoreChange  float64                `json:"risk_score_change"`
	BaseRiskScore    float64                `json:"base_risk_score"`
	CurrentRiskScore float64                `json:"current_risk_score"`
	ImpactAssessment string                 `json:"impact_assessment"`
}

// Generate generates a report in the specified format.
func (g *Generator) Generate(ctx context.Context, data ReportData, format models.ReportFormat) (*GeneratedReport, error) {
	g.logger.WithFields(logrus.Fields{
		"report_id": data.Report.ID,
		"format":    format,
	}).Info("Generating report")

	var result *GeneratedReport
	var err error

	switch format {
	case models.ReportFormatJSON:
		result, err = g.generateJSON(data)
	case models.ReportFormatHTML:
		result, err = g.generateHTML(data)
	case models.ReportFormatMarkdown:
		result, err = g.generateMarkdown(data)
	case models.ReportFormatPDF:
		result, err = g.generatePDF(data)
	case models.ReportFormatSARIF:
		result, err = g.generateSARIF(data)
	default:
		err = fmt.Errorf("unsupported format: %s", format)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to generate %s report: %w", format, err)
	}

	return result, nil
}

// GenerateExecutiveSummary generates an executive summary report.
func (g *Generator) GenerateExecutiveSummary(ctx context.Context, data ReportData) (*GeneratedReport, error) {
	g.logger.WithField("report_id", data.Report.ID).Info("Generating executive summary")

	// Create executive summary structure
	summary := ExecutiveSummaryReport{
		Metadata: ReportMetadata{
			ReportID:     data.Report.ID.String(),
			ScanID:       data.Scan.ID.String(),
			RepositoryID: data.Repository.ID.String(),
			Repository:   data.Repository.FullName,
			Branch:       data.Scan.Branch,
			CommitSHA:    data.Scan.CommitSHA,
			GeneratedAt:  time.Now().UTC(),
			Version:      "1.0",
		},
		Overview: ExecutiveOverview{
			TotalVulnerabilities: data.Summary.TotalVulnerabilities,
			CriticalCount:        data.Summary.VulnsBySeverity[models.SeverityCritical],
			HighCount:            data.Summary.VulnsBySeverity[models.SeverityHigh],
			RiskScore:            data.Summary.RiskScore,
			Grade:                data.Summary.Grade,
			Status:               g.determineOverallStatus(data.Summary),
		},
		KeyFindings:     g.extractKeyFindings(data),
		Recommendations: g.generateRecommendations(data),
		TrendAnalysis:   data.TrendAnalysis,
	}

	// Add AI insights if available
	if data.AIInsights != nil {
		summary.AIExecutiveSummary = data.AIInsights.ExecutiveSummary
	}

	content, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return nil, err
	}

	filename := fmt.Sprintf("executive-summary-%s.json", data.Report.ID)
	filePath := filepath.Join(g.outputDir, filename)

	if err := os.WriteFile(filePath, content, 0644); err != nil {
		return nil, err
	}

	return &GeneratedReport{
		FilePath: filePath,
		FileSize: int64(len(content)),
		Format:   models.ReportFormatJSON,
		Content:  content,
	}, nil
}

// GenerateDiffReport generates a diff report for PRs.
func (g *Generator) GenerateDiffReport(ctx context.Context, data DiffReportData) (*GeneratedReport, error) {
	g.logger.WithFields(logrus.Fields{
		"report_id":    data.Report.ID,
		"base_scan":    data.BaseScan.ID,
		"new_issues":   len(data.NewIssues),
		"fixed_issues": len(data.FixedIssues),
	}).Info("Generating diff report")

	diffReport := DiffReport{
		Metadata: ReportMetadata{
			ReportID:     data.Report.ID.String(),
			ScanID:       data.Scan.ID.String(),
			RepositoryID: data.Repository.ID.String(),
			Repository:   data.Repository.FullName,
			Branch:       data.Scan.Branch,
			CommitSHA:    data.Scan.CommitSHA,
			GeneratedAt:  time.Now().UTC(),
			Version:      "1.0",
		},
		BaseScan: DiffScanInfo{
			ScanID:    data.BaseScan.ID.String(),
			Branch:    data.BaseScan.Branch,
			CommitSHA: data.BaseScan.CommitSHA,
			RiskScore: data.BaseRiskScore,
		},
		CurrentScan: DiffScanInfo{
			ScanID:    data.Scan.ID.String(),
			Branch:    data.Scan.Branch,
			CommitSHA: data.Scan.CommitSHA,
			RiskScore: data.CurrentRiskScore,
		},
		Summary: DiffSummary{
			NewIssuesCount:   len(data.NewIssues),
			FixedIssuesCount: len(data.FixedIssues),
			UnchangedCount:   len(data.UnchangedIssues),
			RiskScoreChange:  data.RiskScoreChange,
			ImpactAssessment: data.ImpactAssessment,
			NetChange:        len(data.NewIssues) - len(data.FixedIssues),
		},
		NewIssues:   g.convertToVulnEntries(data.NewIssues),
		FixedIssues: g.convertToVulnEntries(data.FixedIssues),
	}

	content, err := json.MarshalIndent(diffReport, "", "  ")
	if err != nil {
		return nil, err
	}

	filename := fmt.Sprintf("diff-report-%s.json", data.Report.ID)
	filePath := filepath.Join(g.outputDir, filename)

	if err := os.WriteFile(filePath, content, 0644); err != nil {
		return nil, err
	}

	return &GeneratedReport{
		FilePath: filePath,
		FileSize: int64(len(content)),
		Format:   models.ReportFormatJSON,
		Content:  content,
	}, nil
}

// ExecutiveSummaryReport is the structure for executive summary.
type ExecutiveSummaryReport struct {
	Metadata           ReportMetadata    `json:"metadata"`
	Overview           ExecutiveOverview `json:"overview"`
	KeyFindings        []KeyFinding      `json:"key_findings"`
	Recommendations    []Recommendation  `json:"recommendations"`
	TrendAnalysis      *TrendAnalysis    `json:"trend_analysis,omitempty"`
	AIExecutiveSummary string            `json:"ai_executive_summary,omitempty"`
}

// ExecutiveOverview holds executive-level metrics.
type ExecutiveOverview struct {
	TotalVulnerabilities int     `json:"total_vulnerabilities"`
	CriticalCount        int     `json:"critical_count"`
	HighCount            int     `json:"high_count"`
	RiskScore            float64 `json:"risk_score"`
	Grade                string  `json:"grade"`
	Status               string  `json:"status"` // critical, warning, good, excellent
}

// KeyFinding represents a key finding for executives.
type KeyFinding struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Impact      string `json:"impact"`
	Location    string `json:"location"`
}

// DiffReport is the structure for diff reports.
type DiffReport struct {
	Metadata    ReportMetadata       `json:"metadata"`
	BaseScan    DiffScanInfo         `json:"base_scan"`
	CurrentScan DiffScanInfo         `json:"current_scan"`
	Summary     DiffSummary          `json:"summary"`
	NewIssues   []VulnerabilityEntry `json:"new_issues"`
	FixedIssues []VulnerabilityEntry `json:"fixed_issues"`
}

// DiffScanInfo holds scan info for diff comparison.
type DiffScanInfo struct {
	ScanID    string  `json:"scan_id"`
	Branch    string  `json:"branch"`
	CommitSHA string  `json:"commit_sha"`
	RiskScore float64 `json:"risk_score"`
}

// DiffSummary holds the summary of changes.
type DiffSummary struct {
	NewIssuesCount   int     `json:"new_issues_count"`
	FixedIssuesCount int     `json:"fixed_issues_count"`
	UnchangedCount   int     `json:"unchanged_count"`
	RiskScoreChange  float64 `json:"risk_score_change"`
	ImpactAssessment string  `json:"impact_assessment"`
	NetChange        int     `json:"net_change"`
}

// Helper methods

func (g *Generator) determineOverallStatus(summary models.ReportSummary) string {
	critical := summary.VulnsBySeverity[models.SeverityCritical]
	high := summary.VulnsBySeverity[models.SeverityHigh]

	if critical > 0 {
		return "critical"
	} else if high > 0 {
		return "warning"
	} else if summary.TotalVulnerabilities > 0 {
		return "good"
	}
	return "excellent"
}

func (g *Generator) extractKeyFindings(data ReportData) []KeyFinding {
	findings := make([]KeyFinding, 0)

	// Sort by severity
	vulns := make([]models.Vulnerability, len(data.Vulnerabilities))
	copy(vulns, data.Vulnerabilities)
	sort.Slice(vulns, func(i, j int) bool {
		return severityRank(vulns[i].Severity) < severityRank(vulns[j].Severity)
	})

	// Take top 5 critical/high findings
	for i, v := range vulns {
		if i >= 5 {
			break
		}
		if v.Severity != models.SeverityCritical && v.Severity != models.SeverityHigh {
			break
		}
		findings = append(findings, KeyFinding{
			Title:       v.Title,
			Description: truncate(v.Description, 200),
			Severity:    string(v.Severity),
			Impact:      v.Remediation,
			Location:    fmt.Sprintf("%s:%d", v.FilePath, v.LineStart),
		})
	}

	return findings
}

func (g *Generator) generateRecommendations(data ReportData) []Recommendation {
	recommendations := make([]Recommendation, 0)
	priority := 1

	critical := data.Summary.VulnsBySeverity[models.SeverityCritical]
	high := data.Summary.VulnsBySeverity[models.SeverityHigh]

	if critical > 0 {
		recommendations = append(recommendations, Recommendation{
			Priority:    priority,
			Title:       "Address Critical Vulnerabilities Immediately",
			Description: fmt.Sprintf("There are %d critical vulnerabilities that require immediate attention.", critical),
			Impact:      "Critical vulnerabilities can lead to complete system compromise.",
			Effort:      "high",
			Category:    "security",
		})
		priority++
	}

	if high > 0 {
		recommendations = append(recommendations, Recommendation{
			Priority:    priority,
			Title:       "Remediate High Severity Issues",
			Description: fmt.Sprintf("Plan to address %d high severity vulnerabilities in the next sprint.", high),
			Impact:      "High severity issues can lead to significant security breaches.",
			Effort:      "medium",
			Category:    "security",
		})
		priority++
	}

	// Add AI-generated recommendations
	if data.AIInsights != nil && len(data.AIInsights.Recommendations) > 0 {
		for _, rec := range data.AIInsights.Recommendations {
			recommendations = append(recommendations, Recommendation{
				Priority:    priority,
				Title:       rec.Title,
				Description: rec.Description,
				Impact:      rec.Impact,
				Effort:      rec.Effort,
				Category:    "security", // Default category for AI recommendations
			})
			priority++
		}
	}

	return recommendations
}

func (g *Generator) convertToVulnEntries(vulns []models.Vulnerability) []VulnerabilityEntry {
	entries := make([]VulnerabilityEntry, 0, len(vulns))
	for _, v := range vulns {
		entries = append(entries, VulnerabilityEntry{
			ID:          v.ID.String(),
			RuleID:      v.RuleID,
			Title:       v.Title,
			Description: v.Description,
			Severity:    string(v.Severity),
			Category:    string(v.Category),
			FilePath:    v.FilePath,
			LineStart:   v.LineStart,
			LineEnd:     v.LineEnd,
			CodeSnippet: v.CodeSnippet,
			Remediation: v.Remediation,
			References:  v.References,
			Confidence:  v.Confidence,
		})
	}
	return entries
}

func severityRank(s models.Severity) int {
	switch s {
	case models.SeverityCritical:
		return 0
	case models.SeverityHigh:
		return 1
	case models.SeverityMedium:
		return 2
	case models.SeverityLow:
		return 3
	default:
		return 4
	}
}

// GeneratedReport holds the result of report generation.
type GeneratedReport struct {
	FilePath string
	FileSize int64
	Format   models.ReportFormat
	Content  []byte
}

// generateJSON generates a JSON report.
func (g *Generator) generateJSON(data ReportData) (*GeneratedReport, error) {
	report := JSONReport{
		Metadata: ReportMetadata{
			ReportID:     data.Report.ID.String(),
			ScanID:       data.Scan.ID.String(),
			RepositoryID: data.Repository.ID.String(),
			Repository:   data.Repository.FullName,
			Branch:       data.Scan.Branch,
			CommitSHA:    data.Scan.CommitSHA,
			GeneratedAt:  time.Now().UTC(),
			Version:      "1.0",
		},
		Summary:         data.Summary,
		Vulnerabilities: make([]VulnerabilityEntry, 0, len(data.Vulnerabilities)),
		TrendAnalysis:   data.TrendAnalysis,
		Compliance:      data.ComplianceStatus,
		Recommendations: data.Recommendations,
	}

	// Add vulnerabilities
	for _, v := range data.Vulnerabilities {
		report.Vulnerabilities = append(report.Vulnerabilities, VulnerabilityEntry{
			ID:          v.ID.String(),
			RuleID:      v.RuleID,
			Title:       v.Title,
			Description: v.Description,
			Severity:    string(v.Severity),
			Category:    string(v.Category),
			FilePath:    v.FilePath,
			LineStart:   v.LineStart,
			LineEnd:     v.LineEnd,
			CodeSnippet: v.CodeSnippet,
			Remediation: v.Remediation,
			References:  v.References,
			Confidence:  v.Confidence,
		})
	}

	// Add AI insights if available
	if data.AIInsights != nil {
		report.AIInsights = data.AIInsights
	}

	// Marshal to JSON
	content, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, err
	}

	// Write to file
	filename := fmt.Sprintf("report-%s.json", data.Report.ID)
	filePath := filepath.Join(g.outputDir, filename)

	if err := os.WriteFile(filePath, content, 0644); err != nil {
		return nil, err
	}

	return &GeneratedReport{
		FilePath: filePath,
		FileSize: int64(len(content)),
		Format:   models.ReportFormatJSON,
		Content:  content,
	}, nil
}

// generateHTML generates an HTML report.
func (g *Generator) generateHTML(data ReportData) (*GeneratedReport, error) {
	var buf bytes.Buffer

	// Use custom template or default
	tmpl := g.templates["html"]
	if tmpl == nil {
		tmpl = template.Must(template.New("html").Funcs(g.funcMap).Parse(defaultHTMLTemplate))
	}

	// Prepare template data
	templateData := map[string]interface{}{
		"Report":          data.Report,
		"Repository":      data.Repository,
		"Scan":            data.Scan,
		"Summary":         data.Summary,
		"Vulnerabilities": data.Vulnerabilities,
		"AIInsights":      data.AIInsights,
		"TrendAnalysis":   data.TrendAnalysis,
		"GeneratedAt":     time.Now().UTC().Format(time.RFC3339),
	}

	if err := tmpl.Execute(&buf, templateData); err != nil {
		return nil, err
	}

	// Write to file
	content := buf.Bytes()
	filename := fmt.Sprintf("report-%s.html", data.Report.ID)
	filePath := filepath.Join(g.outputDir, filename)

	if err := os.WriteFile(filePath, content, 0644); err != nil {
		return nil, err
	}

	return &GeneratedReport{
		FilePath: filePath,
		FileSize: int64(len(content)),
		Format:   models.ReportFormatHTML,
		Content:  content,
	}, nil
}

// generateMarkdown generates a Markdown report.
func (g *Generator) generateMarkdown(data ReportData) (*GeneratedReport, error) {
	var buf bytes.Buffer

	// Use custom template or default
	tmpl := g.templates["markdown"]
	if tmpl == nil {
		tmpl = template.Must(template.New("markdown").Funcs(g.funcMap).Parse(defaultMarkdownTemplate))
	}

	templateData := map[string]interface{}{
		"Report":          data.Report,
		"Repository":      data.Repository,
		"Scan":            data.Scan,
		"Summary":         data.Summary,
		"Vulnerabilities": data.Vulnerabilities,
		"AIInsights":      data.AIInsights,
		"GeneratedAt":     time.Now().UTC().Format(time.RFC3339),
	}

	if err := tmpl.Execute(&buf, templateData); err != nil {
		return nil, err
	}

	content := buf.Bytes()
	filename := fmt.Sprintf("report-%s.md", data.Report.ID)
	filePath := filepath.Join(g.outputDir, filename)

	if err := os.WriteFile(filePath, content, 0644); err != nil {
		return nil, err
	}

	return &GeneratedReport{
		FilePath: filePath,
		FileSize: int64(len(content)),
		Format:   models.ReportFormatMarkdown,
		Content:  content,
	}, nil
}

// generateSARIF generates a SARIF format report.
func (g *Generator) generateSARIF(data ReportData) (*GeneratedReport, error) {
	sarif := models.SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []models.SARIFRun{
			{
				Tool: models.SARIFTool{
					Driver: models.SARIFDriver{
						Name:           "Code Security Auditor",
						Version:        "1.0.0",
						InformationURI: "https://code-security-auditor",
						Rules:          make([]models.SARIFRule, 0),
					},
				},
				Results: make([]models.SARIFResult, 0),
			},
		},
	}

	// Track unique rules
	seenRules := make(map[string]bool)

	for _, v := range data.Vulnerabilities {
		// Add rule if not seen
		if !seenRules[v.RuleID] {
			sarif.Runs[0].Tool.Driver.Rules = append(sarif.Runs[0].Tool.Driver.Rules, models.SARIFRule{
				ID:   v.RuleID,
				Name: v.Title,
				ShortDescription: struct {
					Text string `json:"text"`
				}{Text: v.Title},
				FullDescription: struct {
					Text string `json:"text"`
				}{Text: v.Description},
			})
			seenRules[v.RuleID] = true
		}

		// Add result
		level := "warning"
		switch v.Severity {
		case models.SeverityCritical, models.SeverityHigh:
			level = "error"
		case models.SeverityLow, models.SeverityInfo:
			level = "note"
		}

		sarif.Runs[0].Results = append(sarif.Runs[0].Results, models.SARIFResult{
			RuleID: v.RuleID,
			Level:  level,
			Message: models.SARIFMessage{
				Text: v.Description,
			},
			Locations: []models.SARIFLocation{
				{
					PhysicalLocation: models.SARIFPhysicalLocation{
						ArtifactLocation: models.SARIFArtifactLocation{
							URI: v.FilePath,
						},
						Region: models.SARIFRegion{
							StartLine: v.LineStart,
							EndLine:   v.LineEnd,
						},
					},
				},
			},
		})
	}

	content, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return nil, err
	}

	filename := fmt.Sprintf("report-%s.sarif.json", data.Report.ID)
	filePath := filepath.Join(g.outputDir, filename)

	if err := os.WriteFile(filePath, content, 0644); err != nil {
		return nil, err
	}

	return &GeneratedReport{
		FilePath: filePath,
		FileSize: int64(len(content)),
		Format:   models.ReportFormatSARIF,
		Content:  content,
	}, nil
}

// generatePDF generates a PDF report.
func (g *Generator) generatePDF(data ReportData) (*GeneratedReport, error) {
	// Generate PDF using gofpdf
	pdf := NewPDFGenerator()

	if err := pdf.Generate(data); err != nil {
		return nil, err
	}

	filename := fmt.Sprintf("report-%s.pdf", data.Report.ID)
	filePath := filepath.Join(g.outputDir, filename)

	if err := pdf.Save(filePath); err != nil {
		return nil, err
	}

	info, _ := os.Stat(filePath)
	var fileSize int64
	if info != nil {
		fileSize = info.Size()
	}

	return &GeneratedReport{
		FilePath: filePath,
		FileSize: fileSize,
		Format:   models.ReportFormatPDF,
	}, nil
}

// Data structures for JSON reports

// JSONReport is the JSON report structure.
type JSONReport struct {
	Metadata        ReportMetadata           `json:"metadata"`
	Summary         models.ReportSummary     `json:"summary"`
	Vulnerabilities []VulnerabilityEntry     `json:"vulnerabilities"`
	AIInsights      *models.AIReportInsights `json:"ai_insights,omitempty"`
	TrendAnalysis   *TrendAnalysis           `json:"trend_analysis,omitempty"`
	Compliance      *ComplianceStatus        `json:"compliance,omitempty"`
	Recommendations []Recommendation         `json:"recommendations,omitempty"`
}

// ReportMetadata holds report metadata.
type ReportMetadata struct {
	ReportID     string    `json:"report_id"`
	ScanID       string    `json:"scan_id"`
	RepositoryID string    `json:"repository_id"`
	Repository   string    `json:"repository"`
	Branch       string    `json:"branch"`
	CommitSHA    string    `json:"commit_sha"`
	GeneratedAt  time.Time `json:"generated_at"`
	Version      string    `json:"version"`
}

// VulnerabilityEntry is a vulnerability in the JSON report.
type VulnerabilityEntry struct {
	ID          string            `json:"id"`
	RuleID      string            `json:"rule_id"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Severity    string            `json:"severity"`
	Category    string            `json:"category"`
	FilePath    string            `json:"file_path"`
	LineStart   int               `json:"line_start"`
	LineEnd     int               `json:"line_end"`
	CodeSnippet string            `json:"code_snippet"`
	Remediation string            `json:"remediation"`
	References  models.References `json:"references"`
	Confidence  float64           `json:"confidence"`
}

// DeleteReport deletes a report file.
func (g *Generator) DeleteReport(filePath string) error {
	return os.Remove(filePath)
}

// GetReportPath returns the full path for a report file.
func (g *Generator) GetReportPath(reportID uuid.UUID, format models.ReportFormat) string {
	var ext string
	switch format {
	case models.ReportFormatJSON:
		ext = ".json"
	case models.ReportFormatHTML:
		ext = ".html"
	case models.ReportFormatMarkdown:
		ext = ".md"
	case models.ReportFormatPDF:
		ext = ".pdf"
	case models.ReportFormatSARIF:
		ext = ".sarif.json"
	}
	return filepath.Join(g.outputDir, fmt.Sprintf("report-%s%s", reportID, ext))
}

// GenerateGitHubMarkdown generates a compact markdown for GitHub PRs.
func (g *Generator) GenerateGitHubMarkdown(data ReportData) string {
	var sb bytes.Buffer

	sb.WriteString("## 🔒 Security Scan Results\n\n")

	// Status line
	critical := data.Summary.VulnsBySeverity[models.SeverityCritical]
	high := data.Summary.VulnsBySeverity[models.SeverityHigh]

	if critical > 0 || high > 0 {
		sb.WriteString("**Overall Status:** ⚠️ **Issues Found**\n\n")
	} else if data.Summary.TotalVulnerabilities == 0 {
		sb.WriteString("**Overall Status:** ✅ **No Issues Found**\n\n")
	} else {
		sb.WriteString("**Overall Status:** ℹ️ **Minor Issues Found**\n\n")
	}

	// Summary table
	sb.WriteString("### Summary\n")
	sb.WriteString("| Severity | Count |\n")
	sb.WriteString("|----------|-------|\n")
	sb.WriteString(fmt.Sprintf("| 🔴 Critical | %d |\n", critical))
	sb.WriteString(fmt.Sprintf("| 🟠 High | %d |\n", high))
	sb.WriteString(fmt.Sprintf("| 🟡 Medium | %d |\n", data.Summary.VulnsBySeverity[models.SeverityMedium]))
	sb.WriteString(fmt.Sprintf("| 🔵 Low | %d |\n", data.Summary.VulnsBySeverity[models.SeverityLow]))
	sb.WriteString(fmt.Sprintf("\n**Risk Score:** %.1f/10\n\n", data.Summary.RiskScore/10))

	// Critical issues
	if critical > 0 || high > 0 {
		sb.WriteString("### Critical Issues\n\n")
		count := 0
		for _, v := range data.Vulnerabilities {
			if v.Severity != models.SeverityCritical && v.Severity != models.SeverityHigh {
				continue
			}
			count++
			if count > 5 {
				sb.WriteString(fmt.Sprintf("\n*...and %d more critical/high issues*\n", critical+high-5))
				break
			}

			emoji := getSeverityEmoji(v.Severity)
			sb.WriteString(fmt.Sprintf("#### %d. %s %s in `%s:%d`\n", count, emoji, v.Title, v.FilePath, v.LineStart))
			sb.WriteString(fmt.Sprintf("**Severity:** %s  \n", v.Severity))
			if len(v.References.CWE) > 0 {
				sb.WriteString(fmt.Sprintf("**CWE:** CWE-%s  \n", v.References.CWE[0]))
			}
			sb.WriteString(fmt.Sprintf("**Description:** %s\n\n", truncate(v.Description, 200)))

			if v.CodeSnippet != "" {
				sb.WriteString("**Vulnerable Code:**\n```\n")
				sb.WriteString(truncate(v.CodeSnippet, 200))
				sb.WriteString("\n```\n\n")
			}

			if v.Remediation != "" {
				sb.WriteString(fmt.Sprintf("**Recommended Fix:** %s\n\n", truncate(v.Remediation, 200)))
			}
		}
	}

	sb.WriteString("---\n*Powered by Code Security Auditor*")

	return sb.String()
}
