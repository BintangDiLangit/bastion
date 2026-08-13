package report

import (
	"strings"
	"testing"
	"time"

	"code-security-auditor/internal/engagement"
	"code-security-auditor/internal/models"
	"code-security-auditor/internal/scanner"
)

func sampleInput() Input {
	res := &scanner.ScanResult{
		Vulnerabilities: []models.Vulnerability{
			{
				RuleID:      "sql_injection",
				Fingerprint: "abcdef0123456789",
				Title:       "SQL Injection in query builder",
				Severity:    models.SeverityCritical,
				Category:    models.CategoryInjection,
				FilePath:    "internal/db/query.go",
				LineStart:   42,
				CodeSnippet: ">   42 | q := \"SELECT * FROM users WHERE id=\" + id",
				Remediation: "Use parameterized queries.",
				References:  models.References{CWE: []string{"CWE-89"}, OWASP: []string{"https://owasp.org/Top10/A03_2021-Injection/"}},
				CVSSScore:   9.8,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Confidence:  0.85,
			},
			{
				RuleID:      "RULE-CRYPTO-001",
				Fingerprint: "fedcba9876543210",
				Title:       "Weak Hash (MD5)",
				Severity:    models.SeverityLow,
				Category:    models.CategoryCryptography,
				FilePath:    "internal/auth/hash.go",
				LineStart:   7,
				CodeSnippet: ">    7 | h := md5.New()",
				Remediation: "Use SHA-256.",
				CVSSScore:   5.3,
				Confidence:  0.9,
			},
		},
		Metrics:      scanner.CodeMetrics{TotalFiles: 3, TotalLines: 250, CodeLines: 200, LanguageBreakdown: map[string]int{"go": 3}},
		FilesScanned: 3,
		LinesScanned: 250,
		Duration:     2 * time.Second,
	}
	return Input{
		Assessor:    engagement.Assessor{Name: "Test Assessor", Company: "Bastion Security"},
		Project:     engagement.Project{Name: "Avora", Client: "Avora Inc."},
		Result:      res,
		Scope:       "local: /src/avora",
		ToolName:    "Bastion",
		ToolVersion: "1.0.0",
		GeneratedAt: time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC),
	}
}

func TestFromInputCounts(t *testing.T) {
	m := FromInput(sampleInput())
	if m.Summary.Total != 2 || m.Summary.Critical != 1 || m.Summary.Low != 1 {
		t.Errorf("counts wrong: %+v", m.Summary)
	}
	// Sorted critical-first.
	if m.Findings[0].Severity != "critical" {
		t.Errorf("expected critical first, got %q", m.Findings[0].Severity)
	}
	// Roadmap ordered by severity weight.
	if len(m.Roadmap) != 2 || m.Roadmap[0].Severity != "critical" {
		t.Errorf("roadmap wrong: %+v", m.Roadmap)
	}
}

func TestRenderHTMLContent(t *testing.T) {
	b, err := RenderHTML(FromInput(sampleInput()))
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)
	for _, want := range []string{
		"Avora Inc.", "Executive Summary", "SQL Injection in query builder",
		"CWE-89", "internal/db/query.go:42", "Use parameterized queries.",
		"9.8 (Critical)", "Remediation Roadmap",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
	// Evidence snippet preserved verbatim (including the > marker).
	if !strings.Contains(html, "&gt;   42 |") {
		t.Errorf("evidence snippet not rendered verbatim")
	}
	// Self-contained: has inline styles, no scripts or remote assets.
	if !strings.Contains(html, "<style") {
		t.Error("expected inline <style>")
	}
	for _, bad := range []string{"<script", "cdn.", "https://cdn", "src=\"http"} {
		if strings.Contains(html, bad) {
			t.Errorf("HTML not self-contained: contains %q", bad)
		}
	}
}

func TestRenderMarkdownContent(t *testing.T) {
	b, err := RenderMarkdown(FromInput(sampleInput()))
	if err != nil {
		t.Fatal(err)
	}
	md := string(b)
	for _, want := range []string{
		"# Security Assessment Report", "| Severity | Count |",
		"SQL Injection in query builder", "CWE-89", "9.8 (Critical)",
		"`````", "## Remediation Roadmap",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("Markdown missing %q", want)
		}
	}
}

func TestRenderCleanScan(t *testing.T) {
	in := sampleInput()
	in.Result.Vulnerabilities = nil
	b, err := RenderHTML(FromInput(in))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "No findings were identified") {
		t.Error("clean scan should report no findings")
	}
}
