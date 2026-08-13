// Package report turns a completed scan plus engagement metadata into a
// professional pentest report in HTML, Markdown, or PDF. Renderers are pure
// func(ReportModel) ([]byte, error); the CLI owns file writing and exit codes.
package report

import (
	"sort"
	"strings"
	"time"

	"code-security-auditor/internal/engagement"
	"code-security-auditor/internal/models"
	"code-security-auditor/internal/scanner"
)

// Input is the public handoff the CLI fills in. FromInput turns it into the
// ReportModel every renderer consumes.
type Input struct {
	Assessor    engagement.Assessor
	Project     engagement.Project
	Result      *scanner.ScanResult
	Scope       string // what was assessed, e.g. "local: /src/avora" or "git: url@main"
	ToolName    string
	ToolVersion string
	GeneratedAt time.Time
}

// ReportModel is the assembled, render-ready view.
type ReportModel struct {
	Client          string
	Project         string
	Assessor        engagement.Assessor
	ReportDate      string
	Generated       string
	ToolName        string
	ToolVersion     string
	Scope           string
	Confidentiality string

	Summary  SeverityCounts
	Stats    Stats
	Metrics  scanner.CodeMetrics
	ScanMeta ScanMeta
	Findings []ReportFinding
	Roadmap  []RoadmapItem
}

// SeverityCounts is the severity histogram.
type SeverityCounts struct {
	Total, Critical, High, Medium, Low, Info int
}

// Stats holds cross-finding rollups.
type Stats struct {
	ByCategory    map[string]int
	ByRule        map[string]int
	AvgConfidence float64
}

// ScanMeta describes the scan run for the methodology/appendix sections.
type ScanMeta struct {
	FilesScanned int
	LinesScanned int
	Duration     string
	Errors       []scanner.ScanError
}

// ReportFinding is one finding, flattened for rendering.
type ReportFinding struct {
	Index       int
	Anchor      string
	Fingerprint string
	RuleID      string
	Title       string
	Severity    string
	Category    string
	CWE         []string
	OWASP       []string
	CVSSScore   float64
	CVSSVector  string
	Confidence  float64
	FilePath    string
	LineStart   int
	LineEnd     int
	Description string
	CodeSnippet string
	Remediation string
	URLs        []string
}

// RoadmapItem is a prioritized remediation bucket (one per non-empty severity).
type RoadmapItem struct {
	Priority int
	Severity string
	Count    int
	SLA      string
}

// severitySLA is the canned remediation target per severity.
var severitySLA = map[models.Severity]string{
	models.SeverityCritical: "Immediate — within 24–48 hours",
	models.SeverityHigh:     "Within 7 days",
	models.SeverityMedium:   "Within 30 days",
	models.SeverityLow:      "Within 90 days / backlog",
	models.SeverityInfo:     "Best effort",
}

// severityOrder is high-to-low, for stable roadmap and finding ordering.
var severityOrder = []models.Severity{
	models.SeverityCritical, models.SeverityHigh, models.SeverityMedium,
	models.SeverityLow, models.SeverityInfo,
}

// FromInput assembles the render model from a scan result + engagement metadata.
func FromInput(in Input) ReportModel {
	res := in.Result

	// Sort findings by severity (desc), then file:line, for a stable report.
	vulns := make([]models.Vulnerability, len(res.Vulnerabilities))
	copy(vulns, res.Vulnerabilities)
	sort.SliceStable(vulns, func(i, j int) bool {
		wi, wj := vulns[i].Severity.Weight(), vulns[j].Severity.Weight()
		if wi != wj {
			return wi > wj
		}
		if vulns[i].FilePath != vulns[j].FilePath {
			return vulns[i].FilePath < vulns[j].FilePath
		}
		return vulns[i].LineStart < vulns[j].LineStart
	})

	var counts SeverityCounts
	byCategory := map[string]int{}
	byRule := map[string]int{}
	var confSum float64
	findings := make([]ReportFinding, 0, len(vulns))

	for i, v := range vulns {
		counts.Total++
		switch v.Severity {
		case models.SeverityCritical:
			counts.Critical++
		case models.SeverityHigh:
			counts.High++
		case models.SeverityMedium:
			counts.Medium++
		case models.SeverityLow:
			counts.Low++
		case models.SeverityInfo:
			counts.Info++
		}
		byCategory[string(v.Category)]++
		byRule[v.RuleID]++
		confSum += v.Confidence

		findings = append(findings, ReportFinding{
			Index:       i + 1,
			Anchor:      "f-" + shortFingerprint(v.Fingerprint, i),
			Fingerprint: v.Fingerprint,
			RuleID:      v.RuleID,
			Title:       v.Title,
			Severity:    string(v.Severity),
			Category:    string(v.Category),
			CWE:         v.References.CWE,
			OWASP:       v.References.OWASP,
			CVSSScore:   v.CVSSScore,
			CVSSVector:  v.CVSSVector,
			Confidence:  v.Confidence,
			FilePath:    v.FilePath,
			LineStart:   v.LineStart,
			LineEnd:     v.LineEnd,
			Description: v.Description,
			CodeSnippet: v.CodeSnippet,
			Remediation: v.Remediation,
			URLs:        v.References.URLs,
		})
	}

	avgConf := 0.0
	if counts.Total > 0 {
		avgConf = confSum / float64(counts.Total)
	}

	// Roadmap: one bucket per severity that actually has findings, high-to-low.
	var roadmap []RoadmapItem
	sevCount := map[models.Severity]int{
		models.SeverityCritical: counts.Critical, models.SeverityHigh: counts.High,
		models.SeverityMedium: counts.Medium, models.SeverityLow: counts.Low,
		models.SeverityInfo: counts.Info,
	}
	prio := 1
	for _, s := range severityOrder {
		if sevCount[s] == 0 {
			continue
		}
		roadmap = append(roadmap, RoadmapItem{
			Priority: prio,
			Severity: string(s),
			Count:    sevCount[s],
			SLA:      severitySLA[s],
		})
		prio++
	}

	date := in.GeneratedAt
	if date.IsZero() {
		date = time.Now()
	}

	return ReportModel{
		Client:          orDefault(in.Project.Client, in.Project.Name),
		Project:         in.Project.Name,
		Assessor:        in.Assessor,
		ReportDate:      date.Format("2006-01-02"),
		Generated:       date.UTC().Format(time.RFC3339),
		ToolName:        orDefault(in.ToolName, "Bastion"),
		ToolVersion:     in.ToolVersion,
		Scope:           in.Scope,
		Confidentiality: "CONFIDENTIAL",
		Summary:         counts,
		Stats:           Stats{ByCategory: byCategory, ByRule: byRule, AvgConfidence: avgConf},
		Metrics:         res.Metrics,
		ScanMeta: ScanMeta{
			FilesScanned: res.FilesScanned,
			LinesScanned: res.LinesScanned,
			Duration:     res.Duration.String(),
			Errors:       res.Errors,
		},
		Findings: findings,
		Roadmap:  roadmap,
	}
}

func orDefault(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

// shortFingerprint yields a stable anchor fragment. Falls back to the index
// when a finding has no fingerprint (shouldn't happen, but never emit "f-").
func shortFingerprint(fp string, index int) string {
	if len(fp) >= 12 {
		return fp[:12]
	}
	if fp != "" {
		return fp
	}
	return "n" + itoa(index)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
