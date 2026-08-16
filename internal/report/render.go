package report

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"strings"
)

// Supported report formats.
const (
	FormatHTML     = "html"
	FormatMarkdown = "md"
	FormatPDF      = "pdf"
)

// Formats lists every renderable format (used by the CLI's "all").
var Formats = []string{FormatHTML, FormatMarkdown, FormatPDF}

// Render assembles the model and writes one format to w. For PDF it renders the
// HTML and converts it through a headless browser; if none is found it returns
// ErrNoBrowser so the caller can degrade to the HTML file.
func Render(ctx context.Context, w io.Writer, in Input, format string) error {
	m := FromInput(in)
	switch strings.ToLower(format) {
	case FormatHTML:
		b, err := RenderHTML(m)
		if err != nil {
			return err
		}
		_, err = w.Write(b)
		return err
	case FormatMarkdown, "markdown":
		b, err := RenderMarkdown(m)
		if err != nil {
			return err
		}
		_, err = w.Write(b)
		return err
	case FormatPDF:
		html, err := RenderHTML(m)
		if err != nil {
			return err
		}
		pdf, err := RenderPDF(ctx, html)
		if err != nil {
			return err // includes ErrNoBrowser
		}
		_, err = w.Write(pdf)
		return err
	default:
		return fmt.Errorf("unknown report format %q (want html|md|pdf)", format)
	}
}

// funcMap is shared by the HTML and Markdown templates. Declared as an unnamed
// map type so it is assignable to both html/template.FuncMap and
// text/template.FuncMap.
var funcMap = map[string]any{
	"sevClass":  func(s string) string { return "sev-" + strings.ToLower(s) },
	"upper":     strings.ToUpper,
	"title":     titleCase,
	"join":      strings.Join,
	"cvssBand":  cvssBand,
	"confPct":   func(f float64) string { return fmt.Sprintf("%.0f%%", f*100) },
	"barPct":    barPct,
	"cvssLabel": cvssLabel,
	"dash":      dash,
	// safeURL trusts a self-built data: URI (assessor logo) so html/template's
	// URL filter doesn't neutralize it. Only ever fed CLI-built data URIs.
	"safeURL": func(s string) template.URL { return template.URL(s) },
}

// cvssBand maps a base score to its qualitative rating.
func cvssBand(score float64) string {
	switch {
	case score >= 9.0:
		return "Critical"
	case score >= 7.0:
		return "High"
	case score >= 4.0:
		return "Medium"
	case score > 0.0:
		return "Low"
	default:
		return "None"
	}
}

// cvssLabel renders a score cell, e.g. "9.8 (Critical)" or "—" when unscored.
func cvssLabel(score float64) string {
	if score <= 0 {
		return "—"
	}
	return fmt.Sprintf("%.1f (%s)", score, cvssBand(score))
}

// barPct returns an integer 0..100 width for a CSS severity bar.
func barPct(count, total int) int {
	if total <= 0 {
		return 0
	}
	return count * 100 / total
}

// dash renders "—" for an empty string (report cells never read blank).
func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func titleCase(s string) string {
	s = strings.ReplaceAll(s, "_", " ")
	if s == "" {
		return s
	}
	parts := strings.Fields(s)
	for i, p := range parts {
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, " ")
}
