// Package reporter provides dependency security report generation.
package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"code-security-auditor/internal/agent"
	"code-security-auditor/internal/dependency"
	"code-security-auditor/internal/dependency/license"
)

// DependencyReportGenerator generates beautiful dependency security reports.
type DependencyReportGenerator struct {
	templates *template.Template
	logger    *logrus.Logger
	outputDir string
}

// NewDependencyReportGenerator creates a new DependencyReportGenerator.
func NewDependencyReportGenerator(outputDir string, logger *logrus.Logger) (*DependencyReportGenerator, error) {
	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	// Load templates
	tmpl, err := loadDependencyTemplates()
	if err != nil {
		return nil, fmt.Errorf("failed to load templates: %w", err)
	}

	return &DependencyReportGenerator{
		templates: tmpl,
		logger:    logger,
		outputDir: outputDir,
	}, nil
}

// DependencyReportData holds all data for report generation.
type DependencyReportData struct {
	ScanID                string
	Timestamp             time.Time
	ScanDuration          time.Duration
	TotalDependencies     int
	DirectDependencies    int
	TransitiveDependencies int
	VulnerablePackages    int
	TotalVulnerabilities  int
	CriticalVulns         int
	HighVulns              int
	MediumVulns            int
	LowVulns               int
	LicenseIssuesCount    int
	RiskScore              float64
	RiskLevel              string
	Dependencies           []dependency.Dependency
	VulnerabilityReports   []dependency.VulnerabilityReport
	LicenseIssues          []license.LicenseIssue
	Recommendations        []dependency.Recommendation
	RiskAnalysis           *agent.RiskAnalysis
	SBOM                   []byte
	SBOMFormat             string
	Repository             RepositoryInfo
	Trends                 *TrendData
}

// RepositoryInfo holds repository metadata.
type RepositoryInfo struct {
	Name      string
	URL       string
	Branch    string
	CommitSHA string
}

// TrendData holds trend information.
type TrendData struct {
	VulnerabilityChange    string // "+15%" or "-10%"
	CriticalIssuesResolved int
	NewVulnerabilities     int
	LastScanDate           time.Time
}

// GenerateMarkdown generates a Markdown report for GitHub PR comments.
func (g *DependencyReportGenerator) GenerateMarkdown(ctx context.Context, data *DependencyReportData) (string, error) {
	var buf bytes.Buffer

	// Build markdown report
	markdown := g.buildMarkdownReport(data)

	if _, err := buf.WriteString(markdown); err != nil {
		return "", fmt.Errorf("failed to write markdown: %w", err)
	}

	return buf.String(), nil
}

// GenerateHTML generates an HTML report.
func (g *DependencyReportGenerator) GenerateHTML(ctx context.Context, data *DependencyReportData) ([]byte, error) {
	var buf bytes.Buffer

	// Use template if available, otherwise generate programmatically
	if g.templates != nil {
		tmpl := g.templates.Lookup("dependency_report.html")
		if tmpl != nil {
			if err := tmpl.Execute(&buf, data); err != nil {
				return nil, fmt.Errorf("failed to execute template: %w", err)
			}
			return buf.Bytes(), nil
		}
	}

	// Fallback: generate HTML programmatically
	html := g.buildHTMLReport(data)
	return []byte(html), nil
}

// GenerateJSON generates a JSON export of the report.
func (g *DependencyReportGenerator) GenerateJSON(ctx context.Context, data *DependencyReportData) ([]byte, error) {
	jsonData := map[string]interface{}{
		"scan_id":                 data.ScanID,
		"timestamp":                data.Timestamp,
		"scan_duration_seconds":    data.ScanDuration.Seconds(),
		"summary": map[string]interface{}{
			"total_dependencies":      data.TotalDependencies,
			"direct_dependencies":     data.DirectDependencies,
			"transitive_dependencies": data.TransitiveDependencies,
			"vulnerable_packages":      data.VulnerablePackages,
			"total_vulnerabilities":   data.TotalVulnerabilities,
			"critical_vulns":          data.CriticalVulns,
			"high_vulns":              data.HighVulns,
			"medium_vulns":            data.MediumVulns,
			"low_vulns":               data.LowVulns,
			"license_issues":           data.LicenseIssuesCount,
			"risk_score":              data.RiskScore,
			"risk_level":              data.RiskLevel,
		},
		"dependencies":           data.Dependencies,
		"vulnerabilities":       data.VulnerabilityReports,
		"license_issues":         data.LicenseIssues,
		"recommendations":        data.Recommendations,
		"risk_analysis":          data.RiskAnalysis,
		"repository":             data.Repository,
		"trends":                 data.Trends,
		"sbom_available":        len(data.SBOM) > 0,
		"sbom_format":           data.SBOMFormat,
	}

	jsonBytes, err := json.MarshalIndent(jsonData, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return jsonBytes, nil
}

// GeneratePDF generates a PDF report.
func (g *DependencyReportGenerator) GeneratePDF(ctx context.Context, data *DependencyReportData) ([]byte, error) {
	// For now, generate a simple PDF using the existing PDF generator
	// In production, you might want to use a library like wkhtmltopdf or chrome headless
	// to convert HTML to PDF, or use a dedicated PDF library
	
	// Generate HTML first as a fallback
	html, err := g.GenerateHTML(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("failed to generate HTML: %w", err)
	}

	// For now, return HTML as placeholder
	// TODO: Implement proper PDF generation using a PDF library
	// This could use gofpdf, chromedp, or an external service
	g.logger.Warn("PDF generation not fully implemented, returning HTML as placeholder")
	return html, nil
}

// SaveReport saves a report to disk.
func (g *DependencyReportGenerator) SaveReport(ctx context.Context, format string, data *DependencyReportData) (string, error) {
	var content []byte
	var ext string
	var err error

	switch format {
	case "markdown", "md":
		contentStr, err := g.GenerateMarkdown(ctx, data)
		if err != nil {
			return "", err
		}
		content = []byte(contentStr)
		ext = "md"
	case "html":
		content, err = g.GenerateHTML(ctx, data)
		if err != nil {
			return "", err
		}
		ext = "html"
	case "json":
		content, err = g.GenerateJSON(ctx, data)
		if err != nil {
			return "", err
		}
		ext = "json"
	case "pdf":
		content, err = g.GeneratePDF(ctx, data)
		if err != nil {
			return "", err
		}
		ext = "pdf"
	default:
		return "", fmt.Errorf("unsupported format: %s", format)
	}

	// Generate filename
	filename := fmt.Sprintf("bastion-dependency-report-%s.%s", data.ScanID[:8], ext)
	filepath := filepath.Join(g.outputDir, filename)

	// Write file
	if err := os.WriteFile(filepath, content, 0644); err != nil {
		return "", fmt.Errorf("failed to write report: %w", err)
	}

	g.logger.WithFields(logrus.Fields{
		"filepath": filepath,
		"format":   format,
		"size":     len(content),
	}).Info("Report saved successfully")

	return filepath, nil
}

// buildMarkdownReport builds a Markdown report for GitHub PR comments.
func (g *DependencyReportGenerator) buildMarkdownReport(data *DependencyReportData) string {
	var buf strings.Builder

	// Header
	buf.WriteString("# 🏰 Bastion Dependency Security Report\n\n")
	buf.WriteString("## 📊 Summary\n\n")
	buf.WriteString("| Metric | Value |\n")
	buf.WriteString("|--------|-------|\n")
	buf.WriteString(fmt.Sprintf("| Total Dependencies | %d |\n", data.TotalDependencies))
	buf.WriteString(fmt.Sprintf("| Vulnerable Packages | %d |\n", data.VulnerablePackages))
	buf.WriteString(fmt.Sprintf("| Critical Vulnerabilities | 🔴 %d |\n", data.CriticalVulns))
	buf.WriteString(fmt.Sprintf("| High Vulnerabilities | 🟠 %d |\n", data.HighVulns))
	buf.WriteString(fmt.Sprintf("| Medium Vulnerabilities | 🟡 %d |\n", data.MediumVulns))
	buf.WriteString(fmt.Sprintf("| Low Vulnerabilities | 🔵 %d |\n", data.LowVulns))
	buf.WriteString(fmt.Sprintf("| License Issues | ⚠️ %d |\n", data.LicenseIssuesCount))
	buf.WriteString(fmt.Sprintf("\n**Overall Risk Score:** %.1f/10 (%s)\n\n", data.RiskScore, strings.ToUpper(data.RiskLevel)))
	buf.WriteString("---\n\n")

	// Critical Vulnerabilities
	if data.CriticalVulns > 0 {
		buf.WriteString("## 🚨 Critical Vulnerabilities (Immediate Action Required)\n\n")
		criticalVulns := g.filterVulnerabilitiesBySeverity(data.VulnerabilityReports, "critical")
		for i, vulnReport := range criticalVulns[:min(5, len(criticalVulns))] {
			if len(vulnReport.Vulnerabilities) == 0 {
				continue
			}
			vuln := vulnReport.Vulnerabilities[0]
			buf.WriteString(fmt.Sprintf("### %d. %s in `%s@%s`\n", i+1, vuln.Title, vulnReport.Dependency.Name, vulnReport.Dependency.Version))
			if vuln.ID != "" {
				buf.WriteString(fmt.Sprintf("**CVE:** %s  \n", vuln.ID))
			}
			buf.WriteString(fmt.Sprintf("**CVSS Score:** %.1f (%s)  \n", vuln.CVSS, strings.ToUpper(vuln.Severity)))
			buf.WriteString(fmt.Sprintf("**Affected:** `%s@%s`  \n", vulnReport.Dependency.Name, vulnReport.Dependency.Version))
			if vuln.FixedIn != "" {
				buf.WriteString(fmt.Sprintf("**Fixed In:** `%s@%s`  \n", vulnReport.Dependency.Name, vuln.FixedIn))
			}
			buf.WriteString(fmt.Sprintf("\n**Description:** %s\n\n", vuln.Description))
			buf.WriteString("**Remediation:**\n")
			buf.WriteString("```bash\n")
			buf.WriteString(g.generateRemediationCommand(vulnReport.Dependency, vuln.FixedIn))
			buf.WriteString("\n```\n\n")
			buf.WriteString("---\n\n")
		}
	}

	// Dependency Updates Available
	if len(data.Recommendations) > 0 {
		buf.WriteString("## 📦 Dependency Updates Available\n\n")
		buf.WriteString("| Package | Current | Latest | Update Type | Vulnerabilities Fixed |\n")
		buf.WriteString("|---------|---------|--------|-------------|----------------------|\n")
		for _, rec := range data.Recommendations[:min(10, len(data.Recommendations))] {
			vulnsFixed := g.countVulnsFixed(rec.Dependency, data.VulnerabilityReports)
			buf.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %d |\n",
				rec.Dependency.Name,
				rec.Dependency.Version,
				rec.TargetVersion,
				rec.Effort,
				vulnsFixed,
			))
		}
		buf.WriteString("\n---\n\n")
	}

	// License Issues
	if len(data.LicenseIssues) > 0 {
		buf.WriteString("## ⚖️ License Issues\n\n")
		for _, issue := range data.LicenseIssues[:min(5, len(data.LicenseIssues))] {
			buf.WriteString(fmt.Sprintf("### ⚠️ %s License Detected\n", issue.License))
			buf.WriteString(fmt.Sprintf("**Package:** `%s@%s`  \n", issue.Dependency.Name, issue.Dependency.Version))
			buf.WriteString(fmt.Sprintf("**Issue:** %s  \n", issue.Explanation))
			buf.WriteString(fmt.Sprintf("**Recommendation:** %s\n\n", issue.Recommendation))
		}
		buf.WriteString("---\n\n")
	}

	// Trends
	if data.Trends != nil {
		buf.WriteString("## 📈 Trends\n\n")
		if data.Trends.VulnerabilityChange != "" {
			buf.WriteString(fmt.Sprintf("- %s Vulnerabilities %s since last scan\n", getTrendIcon(data.Trends.VulnerabilityChange), data.Trends.VulnerabilityChange))
		}
		if data.Trends.CriticalIssuesResolved > 0 {
			buf.WriteString(fmt.Sprintf("- ✅ %d critical issues from previous scan resolved\n", data.Trends.CriticalIssuesResolved))
		}
		if data.Trends.NewVulnerabilities > 0 {
			buf.WriteString(fmt.Sprintf("- 🆕 %d new medium-severity vulnerabilities introduced\n", data.Trends.NewVulnerabilities))
		}
		buf.WriteString("\n---\n\n")
	}

	// Recommended Actions
	buf.WriteString("## 🛠️ Recommended Actions\n\n")
	immediate := g.filterRecommendationsByPriority(data.Recommendations, 1, 3)
	shortTerm := g.filterRecommendationsByPriority(data.Recommendations, 4, 10)
	longTerm := g.filterRecommendationsByPriority(data.Recommendations, 11, 999)

	if len(immediate) > 0 {
		buf.WriteString("1. **Immediate** (This Week)\n")
		for _, rec := range immediate {
			buf.WriteString(fmt.Sprintf("   - %s\n", g.formatRecommendation(rec)))
		}
		buf.WriteString("\n")
	}

	if len(shortTerm) > 0 {
		buf.WriteString("2. **Short Term** (This Month)\n")
		for _, rec := range shortTerm[:min(5, len(shortTerm))] {
			buf.WriteString(fmt.Sprintf("   - %s\n", g.formatRecommendation(rec)))
		}
		buf.WriteString("\n")
	}

	if len(longTerm) > 0 {
		buf.WriteString("3. **Long Term**\n")
		buf.WriteString("   - Implement automated dependency updates\n")
		buf.WriteString("   - Set up dependency monitoring\n")
		buf.WriteString("   - Establish security review process\n\n")
	}

	// SBOM
	if len(data.SBOM) > 0 {
		buf.WriteString("## 📄 SBOM\n\n")
		buf.WriteString(fmt.Sprintf("Software Bill of Materials (%s format): [Download SBOM](#)\n\n", strings.ToUpper(data.SBOMFormat)))
	}

	// Footer
	buf.WriteString("---\n\n")
	buf.WriteString(fmt.Sprintf("*Report generated by **Bastion** - Your Code's Last Line of Defense*  \n"))
	buf.WriteString(fmt.Sprintf("*Scan ID: `%s` | Duration: %s | [View Full Report](#)*\n", data.ScanID[:8], formatDuration(data.ScanDuration)))

	return buf.String()
}

// buildHTMLReport builds an HTML report.
func (g *DependencyReportGenerator) buildHTMLReport(data *DependencyReportData) string {
	var buf strings.Builder

	buf.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bastion Dependency Security Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #1E40AF; border-bottom: 3px solid #1E40AF; padding-bottom: 10px; }
        h2 { color: #374151; margin-top: 30px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }
        th { background: #f9fafb; font-weight: 600; }
        .critical { color: #DC2626; font-weight: bold; }
        .high { color: #F59E0B; font-weight: bold; }
        .medium { color: #EAB308; }
        .low { color: #3B82F6; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
        .badge-critical { background: #DC2626; color: white; }
        .badge-high { background: #F59E0B; color: white; }
        .badge-medium { background: #EAB308; color: white; }
        .badge-low { background: #3B82F6; color: white; }
        code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-family: 'Monaco', 'Courier New', monospace; }
        pre { background: #1f2937; color: #f9fafb; padding: 16px; border-radius: 6px; overflow-x: auto; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #e5e7eb; color: #6b7280; font-size: 14px; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
`)

	buf.WriteString(fmt.Sprintf(`<h1>🏰 Bastion Dependency Security Report</h1>
        <p><strong>Scan ID:</strong> %s | <strong>Date:</strong> %s | <strong>Duration:</strong> %s</p>
        <h2>📊 Summary</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Total Dependencies</td><td>%d</td></tr>
            <tr><td>Vulnerable Packages</td><td>%d</td></tr>
            <tr><td>Critical Vulnerabilities</td><td class="critical">🔴 %d</td></tr>
            <tr><td>High Vulnerabilities</td><td class="high">🟠 %d</td></tr>
            <tr><td>Medium Vulnerabilities</td><td class="medium">🟡 %d</td></tr>
            <tr><td>Low Vulnerabilities</td><td class="low">🔵 %d</td></tr>
            <tr><td>License Issues</td><td>⚠️ %d</td></tr>
            <tr><td><strong>Risk Score</strong></td><td><strong>%.1f/10 (%s)</strong></td></tr>
        </table>`,
		data.ScanID[:8],
		data.Timestamp.Format("2006-01-02 15:04:05"),
		formatDuration(data.ScanDuration),
		data.TotalDependencies,
		data.VulnerablePackages,
		data.CriticalVulns,
		data.HighVulns,
		data.MediumVulns,
		data.LowVulns,
		data.LicenseIssuesCount,
		data.RiskScore,
		strings.ToUpper(data.RiskLevel),
	))

	// Add vulnerabilities section
	if len(data.VulnerabilityReports) > 0 {
		buf.WriteString(`<h2>🚨 Vulnerabilities</h2><table><tr><th>Package</th><th>Severity</th><th>CVE</th><th>Fixed In</th></tr>`)
		for _, vulnReport := range data.VulnerabilityReports[:min(20, len(data.VulnerabilityReports))] {
			if len(vulnReport.Vulnerabilities) == 0 {
				continue
			}
			vuln := vulnReport.Vulnerabilities[0]
			severityClass := strings.ToLower(vuln.Severity)
			buf.WriteString(fmt.Sprintf(`<tr>
                <td><code>%s@%s</code></td>
                <td><span class="badge badge-%s">%s</span></td>
                <td>%s</td>
                <td>%s</td>
            </tr>`,
				vulnReport.Dependency.Name,
				vulnReport.Dependency.Version,
				severityClass,
				strings.ToUpper(vuln.Severity),
				vuln.ID,
				vuln.FixedIn,
			))
		}
		buf.WriteString(`</table>`)
	}

	buf.WriteString(`<div class="footer">
            <p>Report generated by <strong>Bastion</strong> - Your Code's Last Line of Defense</p>
        </div>
    </div>
</body>
</html>`)

	return buf.String()
}

// Helper functions

func (g *DependencyReportGenerator) filterVulnerabilitiesBySeverity(reports []dependency.VulnerabilityReport, severity string) []dependency.VulnerabilityReport {
	var filtered []dependency.VulnerabilityReport
	for _, report := range reports {
		for _, vuln := range report.Vulnerabilities {
			if strings.EqualFold(vuln.Severity, severity) {
				filtered = append(filtered, report)
				break
			}
		}
	}
	return filtered
}

func (g *DependencyReportGenerator) filterRecommendationsByPriority(recs []dependency.Recommendation, minPriority, maxPriority int) []dependency.Recommendation {
	var filtered []dependency.Recommendation
	for _, rec := range recs {
		if rec.Priority >= minPriority && rec.Priority <= maxPriority {
			filtered = append(filtered, rec)
		}
	}
	return filtered
}

func (g *DependencyReportGenerator) countVulnsFixed(dep dependency.Dependency, reports []dependency.VulnerabilityReport) int {
	count := 0
	for _, report := range reports {
		if report.Dependency.Name == dep.Name {
			count += report.TotalCount
		}
	}
	return count
}

func (g *DependencyReportGenerator) formatRecommendation(rec dependency.Recommendation) string {
	return fmt.Sprintf("%s `%s` to `%s` (%s - %s effort)", strings.ToUpper(rec.Action), rec.Dependency.Name, rec.TargetVersion, rec.Impact, rec.Effort)
}

func (g *DependencyReportGenerator) generateRemediationCommand(dep dependency.Dependency, fixedVersion string) string {
	// Determine package manager from dependency metadata or name
	if strings.Contains(dep.Name, "@") || strings.HasPrefix(dep.Name, "npm:") {
		return fmt.Sprintf("npm update %s@%s", strings.TrimPrefix(dep.Name, "npm:"), fixedVersion)
	}
	// Default to npm for now
	return fmt.Sprintf("npm update %s@%s", dep.Name, fixedVersion)
}

func getTrendIcon(change string) string {
	if strings.HasPrefix(change, "-") {
		return "🔻"
	}
	return "🔺"
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.0fm", d.Minutes())
	}
	return fmt.Sprintf("%.0fh %.0fm", d.Hours(), d.Minutes()-(d.Hours()*60))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// loadDependencyTemplates loads HTML templates for dependency reports.
func loadDependencyTemplates() (*template.Template, error) {
	// For now, return nil - templates can be loaded from files later
	// This allows the programmatic generation to work as fallback
	return nil, nil
}
