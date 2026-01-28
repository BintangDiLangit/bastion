package scanner

import (
	"fmt"
	"math"
	"strings"
)

// CyclomaticComplexity calculates the cyclomatic complexity of a function.
func CyclomaticComplexity(code string, language string) int {
	complexity := 1 // Base complexity

	// Decision points by language
	var decisionKeywords []string

	switch language {
	case "go":
		decisionKeywords = []string{"if ", "else if ", "for ", "case ", "&&", "||", "select {", "go func"}
	case "javascript", "typescript":
		decisionKeywords = []string{"if ", "else if ", "for ", "while ", "case ", "catch ", "&&", "||", "?", "?."}
	case "python":
		decisionKeywords = []string{"if ", "elif ", "for ", "while ", "except ", "and ", "or ", "if not "}
	case "java", "kotlin":
		decisionKeywords = []string{"if ", "else if ", "for ", "while ", "case ", "catch ", "&&", "||", "?"}
	case "c", "cpp", "csharp":
		decisionKeywords = []string{"if ", "else if ", "for ", "while ", "case ", "catch ", "&&", "||", "?"}
	case "ruby":
		decisionKeywords = []string{"if ", "elsif ", "unless ", "while ", "until ", "when ", "rescue ", "&&", "||", "and ", "or "}
	default:
		decisionKeywords = []string{"if ", "for ", "while ", "case ", "&&", "||"}
	}

	// Count occurrences
	for _, keyword := range decisionKeywords {
		complexity += strings.Count(code, keyword)
	}

	return complexity
}

// HalsteadMetrics holds Halstead complexity metrics.
type HalsteadMetrics struct {
	UniqueOperators  int     `json:"unique_operators"`
	UniqueOperands   int     `json:"unique_operands"`
	TotalOperators   int     `json:"total_operators"`
	TotalOperands    int     `json:"total_operands"`
	Vocabulary       int     `json:"vocabulary"`
	Length           int     `json:"length"`
	Volume           float64 `json:"volume"`
	Difficulty       float64 `json:"difficulty"`
	Effort           float64 `json:"effort"`
	EstimatedBugs    float64 `json:"estimated_bugs"`
	TimeToProgram    float64 `json:"time_to_program"` // seconds
}

// CalculateHalsteadMetrics calculates Halstead metrics for code.
func CalculateHalsteadMetrics(code string, language string) HalsteadMetrics {
	operators := make(map[string]int)
	operands := make(map[string]int)

	// Get language-specific operators
	langOperators := getLanguageOperators(language)
	
	// Count operators
	for _, op := range langOperators {
		count := strings.Count(code, op)
		if count > 0 {
			operators[op] = count
		}
	}

	// Count operands (simplified - count identifiers and literals)
	words := strings.Fields(code)
	for _, word := range words {
		// Skip if it's an operator
		isOp := false
		for _, op := range langOperators {
			if word == op {
				isOp = true
				break
			}
		}
		if !isOp && isIdentifierOrLiteral(word) {
			operands[word]++
		}
	}

	// Calculate metrics
	n1 := len(operators)  // unique operators
	n2 := len(operands)   // unique operands
	N1 := sumCounts(operators) // total operators
	N2 := sumCounts(operands)  // total operands

	vocabulary := n1 + n2
	length := N1 + N2

	var volume, difficulty, effort, bugs, time float64

	if vocabulary > 0 {
		volume = float64(length) * math.Log2(float64(vocabulary))
	}

	if n2 > 0 {
		difficulty = (float64(n1) / 2) * (float64(N2) / float64(n2))
	}

	effort = difficulty * volume
	bugs = volume / 3000
	time = effort / 18 // Stroud number

	return HalsteadMetrics{
		UniqueOperators:  n1,
		UniqueOperands:   n2,
		TotalOperators:   N1,
		TotalOperands:    N2,
		Vocabulary:       vocabulary,
		Length:           length,
		Volume:           volume,
		Difficulty:       difficulty,
		Effort:           effort,
		EstimatedBugs:    bugs,
		TimeToProgram:    time,
	}
}

// getLanguageOperators returns common operators for a language.
func getLanguageOperators(language string) []string {
	common := []string{"+", "-", "*", "/", "%", "=", "==", "!=", "<", ">", "<=", ">=", "&&", "||", "!", "&", "|", "^", "~", "<<", ">>", "++", "--", "+=", "-=", "*=", "/="}
	
	switch language {
	case "go":
		return append(common, ":=", "<-", "...", "func", "return", "if", "else", "for", "switch", "case", "default", "break", "continue", "defer", "go", "select", "range", "type", "struct", "interface", "map", "chan")
	case "javascript", "typescript":
		return append(common, "===", "!==", "=>", "?.", "??", "...", "function", "return", "if", "else", "for", "while", "switch", "case", "default", "break", "continue", "try", "catch", "throw", "async", "await", "class", "extends", "new", "typeof", "instanceof")
	case "python":
		return append(common, "**", "//", "in", "not in", "is", "is not", "and", "or", "not", "lambda", "def", "return", "if", "elif", "else", "for", "while", "try", "except", "finally", "raise", "class", "import", "from", "as", "with", "yield")
	default:
		return common
	}
}

// isIdentifierOrLiteral checks if a word is an identifier or literal.
func isIdentifierOrLiteral(word string) bool {
	if len(word) == 0 {
		return false
	}
	
	// Check for string literal
	if strings.HasPrefix(word, `"`) || strings.HasPrefix(word, `'`) || strings.HasPrefix(word, "`") {
		return true
	}
	
	// Check for number literal
	if word[0] >= '0' && word[0] <= '9' {
		return true
	}
	
	// Check for identifier (starts with letter or underscore)
	c := word[0]
	if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' {
		return true
	}
	
	return false
}

// sumCounts sums all values in a map.
func sumCounts(m map[string]int) int {
	sum := 0
	for _, v := range m {
		sum += v
	}
	return sum
}

// MaintainabilityIndex calculates the maintainability index.
func MaintainabilityIndex(halstead HalsteadMetrics, cyclomaticComplexity int, linesOfCode int) float64 {
	// MI = 171 - 5.2 * ln(HV) - 0.23 * CC - 16.2 * ln(LOC)
	// Normalized to 0-100

	if halstead.Volume <= 0 || linesOfCode <= 0 {
		return 100
	}

	mi := 171 - 5.2*math.Log(halstead.Volume) - 0.23*float64(cyclomaticComplexity) - 16.2*math.Log(float64(linesOfCode))

	// Normalize to 0-100
	mi = mi * 100 / 171

	if mi < 0 {
		mi = 0
	}
	if mi > 100 {
		mi = 100
	}

	return mi
}

// TechnicalDebt estimates technical debt in minutes.
type TechnicalDebt struct {
	TotalMinutes     int            `json:"total_minutes"`
	ByCategory       map[string]int `json:"by_category"`
	Ratio            float64        `json:"ratio"` // debt ratio
	Rating           string         `json:"rating"` // A, B, C, D, E
}

// CalculateTechnicalDebt calculates technical debt metrics.
func CalculateTechnicalDebt(issues []QualityIssue, linesOfCode int) TechnicalDebt {
	debt := TechnicalDebt{
		ByCategory: make(map[string]int),
	}

	// Estimated remediation time per issue type (in minutes)
	remediationTime := map[string]int{
		"long_line":       5,
		"large_function":  30,
		"todo_comment":    15,
		"debug_statement": 5,
		"code_smell":      10,
		"duplication":     20,
		"security":        60,
	}

	for _, issue := range issues {
		time := remediationTime[issue.Type]
		if time == 0 {
			time = 10 // default
		}
		debt.TotalMinutes += time
		debt.ByCategory[issue.Type] += time
	}

	// Calculate ratio (debt per 1000 lines of code)
	if linesOfCode > 0 {
		debt.Ratio = float64(debt.TotalMinutes) / float64(linesOfCode) * 1000
	}

	// Calculate rating
	debt.Rating = calculateDebtRating(debt.Ratio)

	return debt
}

// calculateDebtRating calculates a rating based on debt ratio.
func calculateDebtRating(ratio float64) string {
	switch {
	case ratio <= 5:
		return "A"
	case ratio <= 10:
		return "B"
	case ratio <= 20:
		return "C"
	case ratio <= 50:
		return "D"
	default:
		return "E"
	}
}

// SecurityScore calculates an overall security score.
type SecurityScore struct {
	Score           float64           `json:"score"` // 0-100
	Grade           string            `json:"grade"` // A-F
	CategoryScores  map[string]float64 `json:"category_scores"`
	RiskLevel       string            `json:"risk_level"` // low, medium, high, critical
	Recommendations []string          `json:"recommendations"`
}

// CalculateSecurityScore calculates the security score from vulnerabilities.
func CalculateSecurityScore(vulnCounts map[string]int) SecurityScore {
	score := SecurityScore{
		CategoryScores: make(map[string]float64),
	}

	// Weights for each severity
	weights := map[string]float64{
		"critical": 25.0,
		"high":     15.0,
		"medium":   7.0,
		"low":      3.0,
		"info":     1.0,
	}

	// Calculate base score (start at 100)
	baseScore := 100.0
	for severity, count := range vulnCounts {
		if weight, ok := weights[severity]; ok {
			baseScore -= float64(count) * weight
		}
	}

	if baseScore < 0 {
		baseScore = 0
	}

	score.Score = baseScore
	score.Grade = calculateSecurityGrade(baseScore)
	score.RiskLevel = calculateRiskLevel(vulnCounts)
	score.Recommendations = generateRecommendations(vulnCounts)

	return score
}

func calculateSecurityGrade(score float64) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

func calculateRiskLevel(vulnCounts map[string]int) string {
	if vulnCounts["critical"] > 0 {
		return "critical"
	}
	if vulnCounts["high"] > 0 {
		return "high"
	}
	if vulnCounts["medium"] > 0 {
		return "medium"
	}
	return "low"
}

func generateRecommendations(vulnCounts map[string]int) []string {
	var recommendations []string

	if vulnCounts["critical"] > 0 {
		recommendations = append(recommendations, 
			fmt.Sprintf("Address %d critical vulnerabilities immediately", vulnCounts["critical"]))
	}
	if vulnCounts["high"] > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("Fix %d high severity issues within the next sprint", vulnCounts["high"]))
	}
	if vulnCounts["medium"] > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("Plan to resolve %d medium severity issues", vulnCounts["medium"]))
	}
	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Continue regular security reviews to maintain good security posture")
	}

	return recommendations
}
