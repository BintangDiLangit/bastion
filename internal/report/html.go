package report

import (
	"bytes"
	_ "embed"
	"html/template"
)

//go:embed templates/report.html.tmpl
var htmlTemplateSrc string

// htmlTmpl is parsed once at init. A broken template is a build/programming
// error, so panicking here (fail fast) is correct.
var htmlTmpl = template.Must(template.New("report.html").Funcs(funcMap).Parse(htmlTemplateSrc))

// RenderHTML renders a self-contained HTML report. Auto-escaping is ON: every
// finding-derived string (code snippets, remediation, paths) is attacker-
// controlled and is never wrapped in template.HTML.
func RenderHTML(m ReportModel) ([]byte, error) {
	var buf bytes.Buffer
	if err := htmlTmpl.Execute(&buf, m); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
