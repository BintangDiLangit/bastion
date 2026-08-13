package rules

// CVSS v3.1 base scores and vectors, hand-authored per rule.
//
// These are deliberately static, not derived from severity: a severity->number
// lookup would fabricate precision. Twelve rules, twelve reviewed values. The
// score prints in client-facing reports, so treat each as signed off, not
// generated. Adjust here when a rule's exploitability profile changes.
//
// Keyed by rule ID across BOTH namespaces: the interface rules (sql_injection,
// xss, secrets, dependency) and the RULE-XXX-NNN pattern rules.
type cvssInfo struct {
	score  float64
	vector string
}

const (
	vecNetworkFullImpact = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" // 9.8
	vecXSS               = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" // 6.1
	vecWeakHash          = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" // 5.3
	vecConfImpact        = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" // 7.5
)

var cvssByRule = map[string]cvssInfo{
	// Interface rules
	"sql_injection": {9.8, vecNetworkFullImpact},
	"xss":           {6.1, vecXSS},
	"secrets":       {9.8, vecNetworkFullImpact},
	"dependency":    {7.5, vecConfImpact},

	// Pattern rules
	"RULE-SQL-001":    {9.8, vecNetworkFullImpact},
	"RULE-XSS-001":    {6.1, vecXSS},
	"RULE-SEC-001":    {9.8, vecNetworkFullImpact},
	"RULE-SEC-002":    {9.8, vecNetworkFullImpact},
	"RULE-SEC-003":    {9.8, vecNetworkFullImpact},
	"RULE-CMD-001":    {9.8, vecNetworkFullImpact},
	"RULE-CRYPTO-001": {5.3, vecWeakHash},
	"RULE-DESER-001":  {9.8, vecNetworkFullImpact},
}

// CVSSForRule returns the CVSS v3.1 base score and vector for a rule ID.
// Returns (0, "") for an unknown rule; callers render that as "not scored".
func CVSSForRule(ruleID string) (float64, string) {
	if info, ok := cvssByRule[ruleID]; ok {
		return info.score, info.vector
	}
	return 0, ""
}
