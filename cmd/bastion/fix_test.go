package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BintangDiLangit/bastion/internal/models"
)

// A safe-replace finding with a column span emits a SARIF fixes array; a
// guidance finding does not (SARIF fixes implies applicability).
func TestSARIFEmitsFixesForSafeReplaceOnly(t *testing.T) {
	col := func(n int) *int { return &n }
	out := ScanOutput{Vulnerabilities: []VulnOutput{
		{
			RuleID: "RULE-TLS-001", FilePath: "a.go", LineStart: 5,
			ColumnStart: col(21), ColumnEnd: col(45),
			Fix: &models.Fix{Kind: models.FixSafeReplace, Summary: "Re-enable TLS verification.", Replacement: "InsecureSkipVerify: false"},
		},
		{
			RuleID: "sql_injection", FilePath: "a.go", LineStart: 7,
			Fix: &models.Fix{Kind: models.FixGuidance, Summary: "Parameterize."},
		},
	}}

	data, err := toSARIF(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID string          `json:"ruleId"`
				Fixes  json.RawMessage `json:"fixes"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for _, r := range doc.Runs[0].Results {
		switch r.RuleID {
		case "RULE-TLS-001":
			if len(r.Fixes) == 0 {
				t.Error("safe_replace finding should carry a SARIF fixes array")
			}
		case "sql_injection":
			if len(r.Fixes) != 0 {
				t.Errorf("guidance finding must not carry fixes, got %s", r.Fixes)
			}
		}
	}
}

// bastion fix --write flips a safe finding and leaves guidance-only code alone.
func TestFixWriteAppliesSafeOnly(t *testing.T) {
	dir := t.TempDir()
	goFile := filepath.Join(dir, "main.go")
	src := "package x\n\nimport \"crypto/tls\"\n\nvar c = &tls.Config{InsecureSkipVerify: true}\n\nfunc q(db DB, id string) { db.Query(\"SELECT * FROM u WHERE id = \" + id) }\n"
	if err := os.WriteFile(goFile, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := runFix(dir, scanOptions{maxFiles: 100, timeout: time.Minute}, true); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(goFile)
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	if !strings.Contains(s, "InsecureSkipVerify: false") {
		t.Error("TLS flag was not flipped to false")
	}
	if strings.Contains(s, "InsecureSkipVerify: true") {
		t.Error("TLS flag still true after --write")
	}
	// The SQL injection line is guidance-only and must be left verbatim.
	if !strings.Contains(s, `db.Query("SELECT * FROM u WHERE id = " + id)`) {
		t.Error("guidance-only SQL line was modified")
	}
}

// Preview (write=false) must not touch the file.
func TestFixPreviewDoesNotWrite(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "net.py")
	src := "import requests\nrequests.get(url, verify = False)\n"
	if err := os.WriteFile(f, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runFix(dir, scanOptions{maxFiles: 100, timeout: time.Minute}, false); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(f)
	if string(got) != src {
		t.Errorf("preview modified the file:\n%s", got)
	}
}
