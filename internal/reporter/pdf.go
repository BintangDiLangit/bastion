package reporter

import (
	"fmt"
	"strings"

	"github.com/jung-kurt/gofpdf"

	"github.com/code-security-auditor/internal/models"
)

// PDFGenerator generates PDF reports.
type PDFGenerator struct {
	pdf    *gofpdf.Fpdf
	margin float64
}

// NewPDFGenerator creates a new PDF generator.
func NewPDFGenerator() *PDFGenerator {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(15, 15, 15)
	pdf.SetAutoPageBreak(true, 15)

	return &PDFGenerator{
		pdf:    pdf,
		margin: 15,
	}
}

// Generate generates a PDF report from the data.
func (g *PDFGenerator) Generate(data ReportData) error {
	// Add first page
	g.pdf.AddPage()

	// Title
	g.setFont("B", 24)
	g.pdf.SetTextColor(0, 0, 0)
	g.pdf.CellFormat(0, 15, "Security Report", "", 1, "C", false, 0, "")
	g.pdf.Ln(5)

	// Repository info
	g.setFont("", 12)
	g.pdf.SetTextColor(100, 100, 100)
	g.pdf.CellFormat(0, 8, fmt.Sprintf("Repository: %s", data.Repository.FullName), "", 1, "C", false, 0, "")
	g.pdf.CellFormat(0, 8, fmt.Sprintf("Branch: %s | Commit: %s", data.Scan.Branch, truncate(data.Scan.CommitSHA, 8)), "", 1, "C", false, 0, "")
	g.pdf.CellFormat(0, 8, fmt.Sprintf("Generated: %s", data.GeneratedAt.Format("2006-01-02 15:04:05 UTC")), "", 1, "C", false, 0, "")
	g.pdf.Ln(10)

	// Summary section
	g.drawSummary(data.Summary)
	g.pdf.Ln(10)

	// Vulnerability breakdown
	g.drawVulnerabilityBreakdown(data.Summary)
	g.pdf.Ln(10)

	// AI Insights (if available)
	if data.AIInsights != nil {
		g.pdf.AddPage()
		g.drawAIInsights(data.AIInsights)
	}

	// Vulnerabilities
	g.pdf.AddPage()
	g.drawVulnerabilities(data.Vulnerabilities)

	return nil
}

// setFont sets the font with error handling.
func (g *PDFGenerator) setFont(style string, size float64) {
	g.pdf.SetFont("Helvetica", style, size)
}

// drawSummary draws the summary section.
func (g *PDFGenerator) drawSummary(summary models.ReportSummary) {
	// Section header
	g.setFont("B", 16)
	g.pdf.SetTextColor(0, 0, 0)
	g.pdf.CellFormat(0, 10, "Summary", "", 1, "L", false, 0, "")
	g.pdf.Ln(2)

	// Draw summary boxes
	boxWidth := 42.0
	boxHeight := 25.0
	startX := g.margin
	y := g.pdf.GetY()

	// Total vulnerabilities
	g.drawStatBox(startX, y, boxWidth, boxHeight, "Total Issues", fmt.Sprintf("%d", summary.TotalVulnerabilities), 0, 0, 0)

	// Critical
	critical := summary.VulnsBySeverity[models.SeverityCritical]
	g.drawStatBox(startX+boxWidth+5, y, boxWidth, boxHeight, "Critical", fmt.Sprintf("%d", critical), 220, 38, 38)

	// High
	high := summary.VulnsBySeverity[models.SeverityHigh]
	g.drawStatBox(startX+(boxWidth+5)*2, y, boxWidth, boxHeight, "High", fmt.Sprintf("%d", high), 219, 109, 40)

	// Medium
	medium := summary.VulnsBySeverity[models.SeverityMedium]
	g.drawStatBox(startX+(boxWidth+5)*3, y, boxWidth, boxHeight, "Medium", fmt.Sprintf("%d", medium), 210, 153, 34)

	g.pdf.SetY(y + boxHeight + 5)

	// Second row
	y = g.pdf.GetY()

	// Low
	low := summary.VulnsBySeverity[models.SeverityLow]
	g.drawStatBox(startX, y, boxWidth, boxHeight, "Low", fmt.Sprintf("%d", low), 63, 185, 80)

	// Files scanned
	g.drawStatBox(startX+boxWidth+5, y, boxWidth, boxHeight, "Files Scanned", fmt.Sprintf("%d", summary.FilesScanned), 100, 100, 100)

	// Risk score
	g.drawStatBox(startX+(boxWidth+5)*2, y, boxWidth, boxHeight, "Risk Score", fmt.Sprintf("%.1f/100", summary.RiskScore), 88, 166, 255)

	// Grade
	g.drawGradeBox(startX+(boxWidth+5)*3, y, boxWidth, boxHeight, summary.Grade)

	g.pdf.SetY(y + boxHeight + 5)
}

// drawStatBox draws a statistics box.
func (g *PDFGenerator) drawStatBox(x, y, w, h float64, label, value string, r, gr, b int) {
	// Box background
	g.pdf.SetFillColor(245, 245, 245)
	g.pdf.RoundedRect(x, y, w, h, 3, "1234", "F")

	// Value
	g.setFont("B", 18)
	g.pdf.SetTextColor(r, gr, b)
	g.pdf.SetXY(x, y+3)
	g.pdf.CellFormat(w, 12, value, "", 0, "C", false, 0, "")

	// Label
	g.setFont("", 9)
	g.pdf.SetTextColor(100, 100, 100)
	g.pdf.SetXY(x, y+15)
	g.pdf.CellFormat(w, 8, label, "", 0, "C", false, 0, "")
}

// drawGradeBox draws the grade box.
func (g *PDFGenerator) drawGradeBox(x, y, w, h float64, grade string) {
	// Determine color based on grade
	var r, gr, b int
	switch grade {
	case "A":
		r, gr, b = 63, 185, 80
	case "B":
		r, gr, b = 63, 185, 80
	case "C":
		r, gr, b = 210, 153, 34
	case "D":
		r, gr, b = 219, 109, 40
	default:
		r, gr, b = 220, 38, 38
	}

	// Box background with grade color
	g.pdf.SetFillColor(r, gr, b)
	g.pdf.RoundedRect(x, y, w, h, 3, "1234", "F")

	// Grade letter
	g.setFont("B", 24)
	g.pdf.SetTextColor(255, 255, 255)
	g.pdf.SetXY(x, y+2)
	g.pdf.CellFormat(w, 18, grade, "", 0, "C", false, 0, "")

	// Label
	g.setFont("", 8)
	g.pdf.SetXY(x, y+17)
	g.pdf.CellFormat(w, 6, "GRADE", "", 0, "C", false, 0, "")
}

// drawVulnerabilityBreakdown draws the vulnerability breakdown.
func (g *PDFGenerator) drawVulnerabilityBreakdown(summary models.ReportSummary) {
	g.setFont("B", 14)
	g.pdf.SetTextColor(0, 0, 0)
	g.pdf.CellFormat(0, 10, "Vulnerability Breakdown by Category", "", 1, "L", false, 0, "")
	g.pdf.Ln(2)

	// Table header
	g.setFont("B", 10)
	g.pdf.SetFillColor(240, 240, 240)
	g.pdf.CellFormat(100, 8, "Category", "1", 0, "L", true, 0, "")
	g.pdf.CellFormat(40, 8, "Count", "1", 1, "C", true, 0, "")

	// Table rows
	g.setFont("", 10)
	for category, count := range summary.VulnsByCategory {
		g.pdf.CellFormat(100, 7, string(category), "1", 0, "L", false, 0, "")
		g.pdf.CellFormat(40, 7, fmt.Sprintf("%d", count), "1", 1, "C", false, 0, "")
	}
}

// drawAIInsights draws the AI insights section.
func (g *PDFGenerator) drawAIInsights(insights *models.AIReportInsights) {
	g.setFont("B", 16)
	g.pdf.SetTextColor(0, 0, 0)
	g.pdf.CellFormat(0, 10, "AI Analysis", "", 1, "L", false, 0, "")
	g.pdf.Ln(2)

	// Executive summary
	g.setFont("B", 12)
	g.pdf.CellFormat(0, 8, "Executive Summary", "", 1, "L", false, 0, "")

	g.setFont("", 10)
	g.pdf.SetTextColor(50, 50, 50)
	g.pdf.MultiCell(0, 6, insights.ExecutiveSummary, "", "L", false)
	g.pdf.Ln(5)

	// Key findings
	if len(insights.KeyFindings) > 0 {
		g.setFont("B", 12)
		g.pdf.SetTextColor(0, 0, 0)
		g.pdf.CellFormat(0, 8, "Key Findings", "", 1, "L", false, 0, "")

		g.setFont("", 10)
		g.pdf.SetTextColor(50, 50, 50)
		for i, finding := range insights.KeyFindings {
			g.pdf.MultiCell(0, 6, fmt.Sprintf("%d. %s", i+1, finding), "", "L", false)
		}
		g.pdf.Ln(5)
	}

	// Recommendations
	if len(insights.Recommendations) > 0 {
		g.setFont("B", 12)
		g.pdf.SetTextColor(0, 0, 0)
		g.pdf.CellFormat(0, 8, "Recommendations", "", 1, "L", false, 0, "")

		g.setFont("", 10)
		for _, rec := range insights.Recommendations {
			g.pdf.SetTextColor(50, 50, 50)
			g.pdf.MultiCell(0, 6, fmt.Sprintf("%d. %s: %s", rec.Priority, rec.Title, rec.Description), "", "L", false)
		}
	}
}

// drawVulnerabilities draws the vulnerabilities section.
func (g *PDFGenerator) drawVulnerabilities(vulns []models.Vulnerability) {
	g.setFont("B", 16)
	g.pdf.SetTextColor(0, 0, 0)
	g.pdf.CellFormat(0, 10, fmt.Sprintf("Vulnerabilities (%d)", len(vulns)), "", 1, "L", false, 0, "")
	g.pdf.Ln(5)

	for i, vuln := range vulns {
		// Check if we need a new page
		if g.pdf.GetY() > 250 {
			g.pdf.AddPage()
		}

		// Vulnerability header
		g.setFont("B", 11)
		g.pdf.SetTextColor(0, 0, 0)

		// Severity color
		r, gr, b := getSeverityColor(vuln.Severity)
		g.pdf.SetTextColor(r, gr, b)
		g.pdf.CellFormat(0, 7, fmt.Sprintf("[%s] %s", strings.ToUpper(string(vuln.Severity)), vuln.Title), "", 1, "L", false, 0, "")

		// File location
		g.setFont("", 9)
		g.pdf.SetTextColor(100, 100, 100)
		g.pdf.CellFormat(0, 5, fmt.Sprintf("File: %s:%d", vuln.FilePath, vuln.LineStart), "", 1, "L", false, 0, "")

		// Description
		g.setFont("", 10)
		g.pdf.SetTextColor(50, 50, 50)
		g.pdf.MultiCell(0, 5, truncate(vuln.Description, 300), "", "L", false)

		// Remediation (abbreviated)
		if vuln.Remediation != "" {
			g.pdf.Ln(2)
			g.setFont("I", 9)
			g.pdf.SetTextColor(35, 134, 54)
			g.pdf.MultiCell(0, 5, "Remediation: "+truncate(vuln.Remediation, 200), "", "L", false)
		}

		g.pdf.Ln(5)

		// Limit to first 20 vulnerabilities in PDF
		if i >= 19 {
			g.setFont("I", 10)
			g.pdf.SetTextColor(100, 100, 100)
			g.pdf.CellFormat(0, 8, fmt.Sprintf("... and %d more vulnerabilities. See full report for details.", len(vulns)-20), "", 1, "L", false, 0, "")
			break
		}
	}
}

// getSeverityColor returns RGB color for severity.
func getSeverityColor(severity models.Severity) (int, int, int) {
	switch severity {
	case models.SeverityCritical:
		return 220, 38, 38
	case models.SeverityHigh:
		return 219, 109, 40
	case models.SeverityMedium:
		return 210, 153, 34
	case models.SeverityLow:
		return 63, 185, 80
	default:
		return 88, 166, 255
	}
}

// truncate truncates a string to max length.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// Save saves the PDF to a file.
func (g *PDFGenerator) Save(path string) error {
	return g.pdf.OutputFileAndClose(path)
}
