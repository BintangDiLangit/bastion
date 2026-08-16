package scanner

import (
	"testing"

	"github.com/google/uuid"

	"github.com/BintangDiLangit/bastion/internal/scanner/rules"
)

func TestFindingFingerprintIgnoresLineNumber(t *testing.T) {
	first := rules.Finding{RuleID: "xss", FilePath: "web/app.js", CodeSnippet: ">   10 | element.innerHTML = input\n"}
	moved := rules.Finding{RuleID: "xss", FilePath: "web/app.js", CodeSnippet: ">   99 | element.innerHTML = input\n"}
	if findingFingerprint(first) != findingFingerprint(moved) {
		t.Fatal("fingerprint changed after line move")
	}
}

func TestDuplicateFindingsGetUniqueFingerprints(t *testing.T) {
	finding := rules.Finding{RuleID: "secrets", FilePath: "compose.yml", CodeSnippet: ">   10 | password=secret\n"}
	vulnerabilities := convertFindingsToVulnerabilities([]rules.Finding{finding, finding}, uuid.New())
	if vulnerabilities[0].Fingerprint == vulnerabilities[1].Fingerprint {
		t.Fatal("duplicate findings share fingerprint")
	}
}
