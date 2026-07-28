package rules

import "testing"

func TestApplySuppressions(t *testing.T) {
	lines := []string{
		"// bastion:ignore-next-line RULE-XSS-001",
		"element.innerHTML = input",
		"danger() // bastion:ignore secrets",
		"keep()",
	}
	findings := []Finding{
		{RuleID: "RULE-XSS-001", Line: 2},
		{RuleID: "secrets", Line: 3},
		{RuleID: "sql_injection", Line: 4},
	}
	got := applySuppressions(lines, findings)
	if len(got) != 1 || got[0].RuleID != "sql_injection" {
		t.Fatalf("got %#v", got)
	}
}

func TestApplyFileSuppression(t *testing.T) {
	lines := []string{"// bastion:ignore-file xss,RULE-DESER-001", "code"}
	findings := []Finding{
		{RuleID: "xss", Line: 2},
		{RuleID: "RULE-DESER-001", Line: 2},
		{RuleID: "secrets", Line: 2},
	}
	got := applySuppressions(lines, findings)
	if len(got) != 1 || got[0].RuleID != "secrets" {
		t.Fatalf("got %#v", got)
	}
}

func TestSuppressionMustBeComment(t *testing.T) {
	lines := []string{`value := "bastion:ignore all"`}
	got := applySuppressions(lines, []Finding{{RuleID: "secrets", Line: 1}})
	if len(got) != 1 {
		t.Fatal("string literal suppressed finding")
	}
}
