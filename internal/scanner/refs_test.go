package scanner

import (
	"testing"

	"github.com/google/uuid"

	"github.com/BintangDiLangit/bastion/internal/models"
	"github.com/BintangDiLangit/bastion/internal/scanner/rules"
)

// Regression for the data-loss bug: convertFindingsToVulnerabilities used to
// drop CWE, References, and never set CVSS or a valid category.
func TestConvertFindingsCarriesCWEAndCVSS(t *testing.T) {
	findings := []rules.Finding{{
		RuleID:      "sql_injection",
		Title:       "SQL Injection",
		Severity:    "critical",
		Category:    "sql_injection",
		FilePath:    "db.go",
		Line:        1,
		CWE:         "CWE-89",
		CodeSnippet: ">    1 | q := \"SELECT \" + name",
		References:  []string{"https://owasp.org/Top10/A03_2021-Injection/", "https://example.com/ref"},
	}}

	v := convertFindingsToVulnerabilities(findings, uuid.New())[0]

	if len(v.References.CWE) != 1 || v.References.CWE[0] != "CWE-89" {
		t.Errorf("CWE not carried: %+v", v.References.CWE)
	}
	if len(v.References.OWASP) != 1 {
		t.Errorf("OWASP not classified: %+v", v.References.OWASP)
	}
	if len(v.References.URLs) != 1 || v.References.URLs[0] != "https://example.com/ref" {
		t.Errorf("plain URL not classified: %+v", v.References.URLs)
	}
	if v.CVSSScore != 9.8 || v.CVSSVector == "" {
		t.Errorf("CVSS not set: score=%v vector=%q", v.CVSSScore, v.CVSSVector)
	}
	if v.Category != models.CategoryInjection {
		t.Errorf("category = %q, want injection", v.Category)
	}
}

// The secrets rule puts the literal "CWE-798" in References AND in CWE. Both
// must fold to a single deduped CWE entry, not leak into OWASP/URLs.
func TestBuildReferencesDedupesSecretsCase(t *testing.T) {
	r := buildReferences(rules.Finding{
		CWE:        "CWE-798",
		References: []string{"CWE-798"},
	})
	if len(r.CWE) != 1 || r.CWE[0] != "CWE-798" {
		t.Errorf("CWE = %+v, want single CWE-798", r.CWE)
	}
	if len(r.OWASP) != 0 || len(r.URLs) != 0 {
		t.Errorf("CWE leaked into OWASP/URLs: %+v", r)
	}
}

func TestMapCategory(t *testing.T) {
	cases := map[string]models.VulnerabilityCategory{
		"sql_injection":            models.CategoryInjection,
		"command_injection":        models.CategoryInjection,
		"insecure_deserialization": models.CategoryInjection,
		"path_traversal":           models.CategoryInjection,
		"xss":                      models.CategoryXSS,
		"secrets":                  models.CategorySecrets,
		"hardcoded_credentials":    models.CategorySecrets,
		"dependency":               models.CategoryDependency,
		"weak_crypto":              models.CategoryCryptography,
		"insecure_random":          models.CategoryCryptography,
		"misconfiguration":         models.CategoryConfiguration,
		"ssrf":                     models.CategoryOther,
		"code_quality":             models.CategoryCodeQuality,
		"totally_unknown":          models.CategoryOther,
	}
	for in, want := range cases {
		if got := mapCategory(in); got != want {
			t.Errorf("mapCategory(%q) = %q, want %q", in, got, want)
		}
	}
}
