package rules

import (
	"testing"

	"github.com/sirupsen/logrus"

	"code-security-auditor/internal/config"
)

// Every rule the engine can emit must have a CVSS base score + vector, or a
// finding reaches a client report with an empty score. This guards against
// adding a rule and forgetting its entry in cvssByRule.
func TestAllRulesHaveCVSS(t *testing.T) {
	log := logrus.New()
	eng := NewEngine(config.ScannerConfig{}, log) // registers pattern rules
	eng.Register(NewSQLInjectionRule())
	eng.Register(NewXSSRule())
	eng.Register(NewSecretsRule())
	eng.Register(NewDependencyRule())

	check := func(id string) {
		score, vector := CVSSForRule(id)
		if score <= 0 || vector == "" {
			t.Errorf("rule %q has no CVSS (score=%v vector=%q)", id, score, vector)
		}
	}
	for _, r := range eng.ListRules() {
		check(r.ID())
	}
	for _, p := range eng.ListPatterns() {
		check(p.ID)
	}
}

func TestCVSSForRuleUnknown(t *testing.T) {
	if s, v := CVSSForRule("RULE-DOES-NOT-EXIST"); s != 0 || v != "" {
		t.Fatalf("unknown rule should be (0, \"\"), got (%v, %q)", s, v)
	}
}
