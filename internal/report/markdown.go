package report

import (
	"bytes"
	_ "embed"
	"text/template"
)

//go:embed templates/report.md.tmpl
var mdTemplateSrc string

var mdTmpl = template.Must(template.New("report.md").Funcs(funcMap).Parse(mdTemplateSrc))

// RenderMarkdown renders a GitHub-flavored Markdown report from the same model.
func RenderMarkdown(m ReportModel) ([]byte, error) {
	var buf bytes.Buffer
	if err := mdTmpl.Execute(&buf, m); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
