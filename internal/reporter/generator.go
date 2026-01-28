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
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/code-security-auditor/internal/models"
)

// Generator generates security reports.
type Generator struct {
	outputDir   string
	templateDir string
	logger      *logrus.Logger
	templates   map[string]*template.Template
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
	}

	// Load templates
	if err := g.loadTemplates(); err != nil {
		logger.WithError(err).Warn("Failed to load custom templates, using defaults")
	}

	return g, nil
}

// loadTemplates loads HTML/Markdown templates.
func (g *Generator) loadTemplates() error {
	if g.templateDir == "" {
		return nil
	}

	// Load HTML template
	htmlPath := filepath.Join(g.templateDir, "report.html")
	if _, err := os.Stat(htmlPath); err == nil {
		tmpl, err := template.ParseFiles(htmlPath)
		if err != nil {
			return fmt.Errorf("failed to parse HTML template: %w", err)
		}
		g.templates["html"] = tmpl
	}

	// Load Markdown template
	mdPath := filepath.Join(g.templateDir, "report.md")
	if _, err := os.Stat(mdPath); err == nil {
		tmpl, err := template.ParseFiles(mdPath)
		if err != nil {
			return fmt.Errorf("failed to parse Markdown template: %w", err)
		}
		g.templates["markdown"] = tmpl
	}

	return nil
}

// ReportData holds data for report generation.
type ReportData struct {
	Report          *models.Report
	Repository      *models.Repository
	Scan            *models.Scan
	Vulnerabilities []models.Vulnerability
	Summary         models.ReportSummary
	AIInsights      *models.AIReportInsights
	GeneratedAt     time.Time
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
		tmpl = template.Must(template.New("html").Parse(defaultHTMLTemplate))
	}

	// Prepare template data
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
		tmpl = template.Must(template.New("markdown").Parse(defaultMarkdownTemplate))
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
						InformationURI: "https://github.com/code-security-auditor",
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
