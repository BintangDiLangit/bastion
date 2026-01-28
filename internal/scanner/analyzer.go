package scanner

import (
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/code-security-auditor/internal/config"
)

// Analyzer performs static code analysis.
type Analyzer struct {
	config config.ScannerConfig
	logger *logrus.Logger
}

// NewAnalyzer creates a new Analyzer.
func NewAnalyzer(cfg config.ScannerConfig, logger *logrus.Logger) *Analyzer {
	return &Analyzer{
		config: cfg,
		logger: logger,
	}
}

// CodeMetrics holds code quality metrics.
type CodeMetrics struct {
	TotalFiles         int                    `json:"total_files"`
	TotalLines         int                    `json:"total_lines"`
	CodeLines          int                    `json:"code_lines"`
	CommentLines       int                    `json:"comment_lines"`
	BlankLines         int                    `json:"blank_lines"`
	LanguageBreakdown  map[string]int         `json:"language_breakdown"`
	FileTypeBreakdown  map[string]int         `json:"file_type_breakdown"`
	AverageFileSize    float64                `json:"average_file_size"`
	LargestFiles       []FileSizeInfo         `json:"largest_files"`
	ComplexityScore    float64                `json:"complexity_score"`
	DuplicationScore   float64                `json:"duplication_score"`
	FunctionMetrics    FunctionMetrics        `json:"function_metrics"`
}

// FileSizeInfo holds size information for a file.
type FileSizeInfo struct {
	Path  string `json:"path"`
	Lines int    `json:"lines"`
	Size  int64  `json:"size"`
}

// FunctionMetrics holds function-related metrics.
type FunctionMetrics struct {
	TotalFunctions      int     `json:"total_functions"`
	AverageFunctionSize float64 `json:"average_function_size"`
	LargestFunction     int     `json:"largest_function"`
	ExportedFunctions   int     `json:"exported_functions"`
}

// CalculateMetrics calculates code metrics for parsed files.
func (a *Analyzer) CalculateMetrics(files []*ParsedFile) CodeMetrics {
	metrics := CodeMetrics{
		TotalFiles:        len(files),
		LanguageBreakdown: make(map[string]int),
		FileTypeBreakdown: make(map[string]int),
		LargestFiles:      make([]FileSizeInfo, 0),
	}

	var totalSize int64
	var totalFunctions int
	var totalFunctionLines int
	var largestFunction int
	var exportedFunctions int

	for _, file := range files {
		// Count lines
		metrics.TotalLines += file.LineCount
		totalSize += file.Size

		// Count by type
		codeLines, commentLines, blankLines := countLineTypes(file)
		metrics.CodeLines += codeLines
		metrics.CommentLines += commentLines
		metrics.BlankLines += blankLines

		// Language breakdown
		metrics.LanguageBreakdown[file.Language]++

		// Track largest files
		metrics.LargestFiles = insertSorted(metrics.LargestFiles, FileSizeInfo{
			Path:  file.Path,
			Lines: file.LineCount,
			Size:  file.Size,
		}, 10)

		// Function metrics
		for _, fn := range file.Functions {
			totalFunctions++
			fnLines := fn.EndLine - fn.StartLine + 1
			totalFunctionLines += fnLines
			if fnLines > largestFunction {
				largestFunction = fnLines
			}
			if fn.IsExported {
				exportedFunctions++
			}
		}
	}

	// Calculate averages
	if metrics.TotalFiles > 0 {
		metrics.AverageFileSize = float64(totalSize) / float64(metrics.TotalFiles)
	}

	// Function metrics
	metrics.FunctionMetrics = FunctionMetrics{
		TotalFunctions:    totalFunctions,
		LargestFunction:   largestFunction,
		ExportedFunctions: exportedFunctions,
	}
	if totalFunctions > 0 {
		metrics.FunctionMetrics.AverageFunctionSize = float64(totalFunctionLines) / float64(totalFunctions)
	}

	// Calculate complexity score (simplified)
	metrics.ComplexityScore = a.calculateComplexityScore(files)

	return metrics
}

// countLineTypes counts code, comment, and blank lines.
func countLineTypes(file *ParsedFile) (code, comments, blank int) {
	inBlockComment := false

	for _, line := range file.Lines {
		trimmed := strings.TrimSpace(line)

		if trimmed == "" {
			blank++
			continue
		}

		// Check for comments based on language
		switch file.Language {
		case "go", "java", "javascript", "typescript", "c", "cpp", "csharp", "rust", "kotlin", "swift":
			if inBlockComment {
				comments++
				if strings.Contains(trimmed, "*/") {
					inBlockComment = false
				}
				continue
			}
			if strings.HasPrefix(trimmed, "//") {
				comments++
				continue
			}
			if strings.HasPrefix(trimmed, "/*") {
				comments++
				if !strings.Contains(trimmed, "*/") {
					inBlockComment = true
				}
				continue
			}
		case "python", "ruby":
			if strings.HasPrefix(trimmed, "#") {
				comments++
				continue
			}
		case "shell":
			if strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "#!") {
				comments++
				continue
			}
		case "html", "xml":
			if strings.HasPrefix(trimmed, "<!--") {
				comments++
				if !strings.Contains(trimmed, "-->") {
					inBlockComment = true
				}
				continue
			}
			if inBlockComment {
				comments++
				if strings.Contains(trimmed, "-->") {
					inBlockComment = false
				}
				continue
			}
		}

		code++
	}

	return code, comments, blank
}

// insertSorted inserts a file info into a sorted slice, keeping only top N.
func insertSorted(slice []FileSizeInfo, item FileSizeInfo, maxLen int) []FileSizeInfo {
	// Find insertion point
	i := 0
	for i < len(slice) && slice[i].Lines > item.Lines {
		i++
	}

	// Insert
	slice = append(slice, FileSizeInfo{})
	copy(slice[i+1:], slice[i:])
	slice[i] = item

	// Trim to max length
	if len(slice) > maxLen {
		slice = slice[:maxLen]
	}

	return slice
}

// calculateComplexityScore calculates a simplified complexity score.
func (a *Analyzer) calculateComplexityScore(files []*ParsedFile) float64 {
	var totalComplexity float64
	var count int

	for _, file := range files {
		complexity := a.calculateFileComplexity(file)
		totalComplexity += complexity
		count++
	}

	if count == 0 {
		return 0
	}

	// Normalize to 0-100 scale
	avgComplexity := totalComplexity / float64(count)
	// Lower is better, so invert for score
	score := 100 - (avgComplexity * 10)
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}

// calculateFileComplexity calculates complexity for a single file.
func (a *Analyzer) calculateFileComplexity(file *ParsedFile) float64 {
	var complexity float64

	// Count complexity indicators
	for _, line := range file.Lines {
		trimmed := strings.TrimSpace(line)

		// Control flow complexity
		keywords := []string{"if", "else", "for", "while", "switch", "case", "try", "catch", "except", "finally"}
		for _, kw := range keywords {
			if strings.Contains(trimmed, kw+" ") || strings.Contains(trimmed, kw+"(") {
				complexity++
			}
		}

		// Nested depth indicator
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if indent > 16 { // Deep nesting
			complexity += 0.5
		}
	}

	// Normalize by file size
	if file.LineCount > 0 {
		complexity = complexity / float64(file.LineCount) * 100
	}

	return complexity
}

// AnalyzeCodeQuality analyzes code quality issues.
func (a *Analyzer) AnalyzeCodeQuality(file *ParsedFile) []QualityIssue {
	var issues []QualityIssue

	// Check for long lines
	for i, line := range file.Lines {
		if len(line) > 120 {
			issues = append(issues, QualityIssue{
				Type:    "long_line",
				Message: "Line exceeds 120 characters",
				Line:    i + 1,
				Column:  121,
			})
		}
	}

	// Check for large functions
	for _, fn := range file.Functions {
		fnSize := fn.EndLine - fn.StartLine
		if fnSize > 100 {
			issues = append(issues, QualityIssue{
				Type:    "large_function",
				Message: "Function is too large (>100 lines)",
				Line:    fn.StartLine,
				Context: fn.Name,
			})
		}
	}

	// Check for TODO/FIXME comments
	for i, line := range file.Lines {
		if strings.Contains(strings.ToUpper(line), "TODO") ||
			strings.Contains(strings.ToUpper(line), "FIXME") ||
			strings.Contains(strings.ToUpper(line), "HACK") {
			issues = append(issues, QualityIssue{
				Type:    "todo_comment",
				Message: "Found TODO/FIXME comment",
				Line:    i + 1,
			})
		}
	}

	// Check for debugging statements
	debugPatterns := map[string][]string{
		"go":         {"fmt.Print", "log.Print", "debug"},
		"javascript": {"console.log", "console.debug", "debugger"},
		"typescript": {"console.log", "console.debug", "debugger"},
		"python":     {"print(", "pdb.set_trace", "breakpoint()"},
	}

	if patterns, ok := debugPatterns[file.Language]; ok {
		for i, line := range file.Lines {
			for _, pattern := range patterns {
				if strings.Contains(line, pattern) {
					issues = append(issues, QualityIssue{
						Type:    "debug_statement",
						Message: "Found debugging statement: " + pattern,
						Line:    i + 1,
					})
				}
			}
		}
	}

	return issues
}

// QualityIssue represents a code quality issue.
type QualityIssue struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Line    int    `json:"line"`
	Column  int    `json:"column,omitempty"`
	Context string `json:"context,omitempty"`
}

// CalculateDuplication detects code duplication.
func (a *Analyzer) CalculateDuplication(files []*ParsedFile) float64 {
	// Simplified duplication detection
	// A full implementation would use more sophisticated algorithms (e.g., Rabin-Karp)

	lineHashes := make(map[string]int)
	duplicateLines := 0
	totalLines := 0

	for _, file := range files {
		for _, line := range file.Lines {
			trimmed := strings.TrimSpace(line)
			if len(trimmed) < 10 { // Skip short lines
				continue
			}

			totalLines++
			lineHashes[trimmed]++
		}
	}

	// Count duplicates
	for _, count := range lineHashes {
		if count > 1 {
			duplicateLines += count - 1
		}
	}

	if totalLines == 0 {
		return 100 // No duplication
	}

	// Calculate score (100 = no duplication, 0 = all duplicated)
	duplicationRatio := float64(duplicateLines) / float64(totalLines)
	score := (1 - duplicationRatio) * 100

	return score
}
