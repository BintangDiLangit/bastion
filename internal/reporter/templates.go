package reporter

// Default HTML template for reports
const defaultHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - {{.Repository.FullName}}</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --border-color: #30363d;
            --critical: #f85149;
            --high: #db6d28;
            --medium: #d29922;
            --low: #3fb950;
            --info: #58a6ff;
            --accent: #238636;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        header {
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
            padding: 2rem;
            border-radius: 12px;
            margin-bottom: 2rem;
            border: 1px solid var(--border-color);
        }
        
        h1 {
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }
        
        h2 {
            font-size: 1.5rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border-color);
        }
        
        h3 {
            font-size: 1.2rem;
            margin-bottom: 0.5rem;
        }
        
        .meta {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: var(--bg-secondary);
            padding: 1.5rem;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            text-align: center;
        }
        
        .stat-value {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
        }
        
        .stat-label {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }
        
        .severity-critical { color: var(--critical); }
        .severity-high { color: var(--high); }
        .severity-medium { color: var(--medium); }
        .severity-low { color: var(--low); }
        .severity-info { color: var(--info); }
        
        .grade {
            display: inline-block;
            padding: 0.5rem 1.5rem;
            border-radius: 8px;
            font-size: 2rem;
            font-weight: bold;
        }
        
        .grade-a { background: var(--low); color: #000; }
        .grade-b { background: #3fb950; color: #000; }
        .grade-c { background: var(--medium); color: #000; }
        .grade-d { background: var(--high); color: #fff; }
        .grade-f { background: var(--critical); color: #fff; }
        
        .section {
            background: var(--bg-secondary);
            padding: 1.5rem;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            margin-bottom: 1.5rem;
        }
        
        .vulnerability {
            background: var(--bg-tertiary);
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1rem;
            border-left: 4px solid var(--border-color);
        }
        
        .vulnerability.critical { border-left-color: var(--critical); }
        .vulnerability.high { border-left-color: var(--high); }
        .vulnerability.medium { border-left-color: var(--medium); }
        .vulnerability.low { border-left-color: var(--low); }
        .vulnerability.info { border-left-color: var(--info); }
        
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 0.5rem;
        }
        
        .badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .badge-critical { background: var(--critical); color: #fff; }
        .badge-high { background: var(--high); color: #fff; }
        .badge-medium { background: var(--medium); color: #000; }
        .badge-low { background: var(--low); color: #000; }
        .badge-info { background: var(--info); color: #fff; }
        
        .file-location {
            color: var(--text-secondary);
            font-family: monospace;
            font-size: 0.9rem;
            margin-bottom: 0.5rem;
        }
        
        .code-snippet {
            background: var(--bg-primary);
            padding: 1rem;
            border-radius: 4px;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.85rem;
            overflow-x: auto;
            margin: 1rem 0;
            white-space: pre-wrap;
        }
        
        .remediation {
            background: rgba(35, 134, 54, 0.1);
            border: 1px solid var(--accent);
            padding: 1rem;
            border-radius: 4px;
            margin-top: 1rem;
        }
        
        .remediation h4 {
            color: var(--accent);
            margin-bottom: 0.5rem;
        }
        
        footer {
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }
        
        @media (max-width: 768px) {
            .summary-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Security Report</h1>
            <p class="meta">Repository: <strong>{{.Repository.FullName}}</strong></p>
            <p class="meta">Branch: {{.Scan.Branch}} | Commit: {{.Scan.CommitSHA}}</p>
            <p class="meta">Generated: {{.GeneratedAt}}</p>
        </header>
        
        <section class="section">
            <h2>Summary</h2>
            <div class="summary-grid">
                <div class="stat-card">
                    <div class="stat-value">{{.Summary.TotalVulnerabilities}}</div>
                    <div class="stat-label">Total Issues</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value severity-critical">{{index .Summary.VulnsBySeverity "critical"}}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value severity-high">{{index .Summary.VulnsBySeverity "high"}}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value severity-medium">{{index .Summary.VulnsBySeverity "medium"}}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value severity-low">{{index .Summary.VulnsBySeverity "low"}}</div>
                    <div class="stat-label">Low</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{.Summary.FilesScanned}}</div>
                    <div class="stat-label">Files Scanned</div>
                </div>
            </div>
            
            <div style="text-align: center; margin-top: 1rem;">
                <p class="meta" style="margin-bottom: 0.5rem;">Security Grade</p>
                <span class="grade grade-{{.Summary.Grade | lower}}">{{.Summary.Grade}}</span>
                <p class="meta" style="margin-top: 0.5rem;">Risk Score: {{printf "%.1f" .Summary.RiskScore}}/100</p>
            </div>
        </section>
        
        {{if .AIInsights}}
        <section class="section">
            <h2>AI Analysis</h2>
            <p>{{.AIInsights.ExecutiveSummary}}</p>
            
            {{if .AIInsights.KeyFindings}}
            <h3 style="margin-top: 1rem;">Key Findings</h3>
            <ul>
                {{range .AIInsights.KeyFindings}}
                <li>{{.}}</li>
                {{end}}
            </ul>
            {{end}}
        </section>
        {{end}}
        
        <section class="section">
            <h2>Vulnerabilities ({{len .Vulnerabilities}})</h2>
            
            {{range .Vulnerabilities}}
            <div class="vulnerability {{.Severity}}">
                <div class="vuln-header">
                    <h3>{{.Title}}</h3>
                    <span class="badge badge-{{.Severity}}">{{.Severity}}</span>
                </div>
                <p class="file-location">📁 {{.FilePath}}:{{.LineStart}}</p>
                <p>{{.Description}}</p>
                
                {{if .CodeSnippet}}
                <div class="code-snippet">{{.CodeSnippet}}</div>
                {{end}}
                
                {{if .Remediation}}
                <div class="remediation">
                    <h4>🔧 Remediation</h4>
                    <p>{{.Remediation}}</p>
                </div>
                {{end}}
            </div>
            {{end}}
        </section>
        
        <footer>
            <p>Generated by Code Security Auditor</p>
        </footer>
    </div>
</body>
</html>`

// Default Markdown template for reports
const defaultMarkdownTemplate = `# Security Report

## Repository: {{.Repository.FullName}}

**Branch:** {{.Scan.Branch}}  
**Commit:** {{.Scan.CommitSHA}}  
**Generated:** {{.GeneratedAt}}

---

## Summary

| Metric | Value |
|--------|-------|
| Total Vulnerabilities | {{.Summary.TotalVulnerabilities}} |
| Critical | {{index .Summary.VulnsBySeverity "critical"}} |
| High | {{index .Summary.VulnsBySeverity "high"}} |
| Medium | {{index .Summary.VulnsBySeverity "medium"}} |
| Low | {{index .Summary.VulnsBySeverity "low"}} |
| Files Scanned | {{.Summary.FilesScanned}} |
| Lines Scanned | {{.Summary.LinesScanned}} |
| Risk Score | {{printf "%.1f" .Summary.RiskScore}}/100 |
| Grade | {{.Summary.Grade}} |

{{if .AIInsights}}
---

## AI Analysis

### Executive Summary
{{.AIInsights.ExecutiveSummary}}

### Key Findings
{{range .AIInsights.KeyFindings}}
- {{.}}
{{end}}

### Recommendations
{{range .AIInsights.Recommendations}}
{{.Priority}}. **{{.Title}}**: {{.Description}}
{{end}}
{{end}}

---

## Vulnerabilities

{{range .Vulnerabilities}}
### {{.Title}}

| Property | Value |
|----------|-------|
| Severity | **{{.Severity}}** |
| Category | {{.Category}} |
| File | ` + "`{{.FilePath}}:{{.LineStart}}`" + ` |
| Confidence | {{printf "%.0f" (mul .Confidence 100)}}% |

{{.Description}}

{{if .CodeSnippet}}
**Code:**
` + "```" + `
{{.CodeSnippet}}
` + "```" + `
{{end}}

{{if .Remediation}}
**Remediation:**
{{.Remediation}}
{{end}}

{{if .References.CWE}}
**References:** {{range .References.CWE}}CWE-{{.}} {{end}}
{{end}}

---

{{end}}

*Generated by Code Security Auditor*
`
