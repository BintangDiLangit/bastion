// bastion:ignore-file RULE-SSRF-001,RULE-PATH-001,RULE-RAND-001,RULE-CRYPTO-002,RULE-CRYPTO-003,RULE-TLS-001 test fixtures are data, not execution
package rules

import (
	"testing"

	"github.com/sirupsen/logrus"

	"code-security-auditor/internal/config"
)

func ruleIDs(findings []Finding) []string {
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.RuleID
	}
	return ids
}

func hasRuleID(findings []Finding, id string) bool {
	for _, f := range findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

// Each new pattern rule fires on a representative vulnerable line, and a clearly
// safe line does not trip it.
func TestNewPatternRulesDetect(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.PanicLevel)
	eng := NewEngine(config.ScannerConfig{}, log)

	positive := []struct {
		line, want, lang string
	}{
		{`resp = requests.get(user_url)`, "RULE-SSRF-001", "python"},
		{`data = open(req.params.file)`, "RULE-PATH-001", "python"},
		{`token = str(random.randint(0, 9999))`, "RULE-RAND-001", "python"},
		{`h = hashlib.sha1(payload)`, "RULE-CRYPTO-002", "python"},
		{`c = Cipher.getInstance("DES")`, "RULE-CRYPTO-003", "java"},
		{`r = requests.get(u, verify=False)`, "RULE-TLS-001", "python"},
	}
	for _, c := range positive {
		af := &ParsedFileAdapter{Path: "t." + c.lang, Language: c.lang, Lines: []string{c.line}}
		got := eng.Analyze(af)
		if !hasRuleID(got, c.want) {
			t.Errorf("line %q: want %s, got %v", c.line, c.want, ruleIDs(got))
		}
	}

	negative := []string{
		`total = getUserCount()`,           // no http/file/crypto
		`hash = sha256(payload)`,           // strong hash, not sha1
		`r = requests.get(u, verify=True)`, // verification enabled
	}
	for _, line := range negative {
		af := &ParsedFileAdapter{Path: "t.py", Language: "python", Lines: []string{line}}
		if got := eng.Analyze(af); len(got) != 0 {
			t.Errorf("line %q: expected no findings, got %v", line, ruleIDs(got))
		}
	}
}
