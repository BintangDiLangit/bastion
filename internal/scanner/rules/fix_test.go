package rules

import (
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/BintangDiLangit/bastion/internal/config"
	"github.com/BintangDiLangit/bastion/internal/models"
)

// Every rule the engine can emit must have a fix entry, so a new rule can't ship
// with no suggested remediation. Mirrors TestAllRulesHaveCVSS.
func TestAllRulesHaveFix(t *testing.T) {
	log := logrus.New()
	eng := NewEngine(config.ScannerConfig{}, log)
	eng.Register(NewSQLInjectionRule())
	eng.Register(NewXSSRule())
	eng.Register(NewSecretsRule())
	eng.Register(NewDependencyRule())

	check := func(id string) {
		if _, ok := fixByRule[id]; !ok {
			t.Errorf("rule %q has no fixByRule entry", id)
		}
	}
	for _, r := range eng.ListRules() {
		check(r.ID())
	}
	for _, p := range eng.ListPatterns() {
		check(p.ID)
	}
}

func TestFixForRuleUnknown(t *testing.T) {
	if f := FixForRule("RULE-DOES-NOT-EXIST", "whatever"); f != nil {
		t.Fatalf("unknown rule should be nil, got %+v", f)
	}
}

func TestFixForRuleGuidance(t *testing.T) {
	f := FixForRule("sql_injection", `db.Query("..." + id)`)
	if f == nil {
		t.Fatal("expected a fix")
	}
	if f.Kind != models.FixGuidance {
		t.Errorf("kind = %q, want guidance", f.Kind)
	}
	if f.Replacement != "" {
		t.Errorf("guidance fix must not carry a replacement, got %q", f.Replacement)
	}
	if f.Before != `db.Query("..." + id)` {
		t.Errorf("before should be the real matched code, got %q", f.Before)
	}
}

func TestFixForRuleTLSSafeReplace(t *testing.T) {
	cases := []struct{ in, want string }{
		{"InsecureSkipVerify: true", "InsecureSkipVerify: false"},
		{"InsecureSkipVerify:true", "InsecureSkipVerify:false"},
		{"rejectUnauthorized: false", "rejectUnauthorized: true"},
		{"verify = False", "verify = True"},
		{"CURLOPT_SSL_VERIFYPEER, 0", "CURLOPT_SSL_VERIFYPEER, 1"},
	}
	for _, c := range cases {
		f := FixForRule("RULE-TLS-001", c.in)
		if f == nil {
			t.Fatalf("%q: expected a fix", c.in)
		}
		if f.Kind != models.FixSafeReplace {
			t.Errorf("%q: kind = %q, want safe_replace", c.in, f.Kind)
		}
		if f.Replacement != c.want {
			t.Errorf("%q: replacement = %q, want %q", c.in, f.Replacement, c.want)
		}
	}
}

// A TLS match with no known safe token flip (e.g. the unverified-context helper)
// stays guidance-only rather than being rewritten blindly.
func TestFixForRuleTLSNoSafeFlipStaysGuidance(t *testing.T) {
	f := FixForRule("RULE-TLS-001", "ssl._create_unverified_context")
	if f == nil {
		t.Fatal("expected a fix")
	}
	if f.Kind != models.FixGuidance {
		t.Errorf("kind = %q, want guidance", f.Kind)
	}
	if f.Replacement != "" {
		t.Errorf("no safe flip should mean no replacement, got %q", f.Replacement)
	}
}
