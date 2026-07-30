// Package scanner provides code scanning and analysis functionality.
// bastion:ignore-file xss,RULE-DESER-001 detector signatures are data, not execution
package scanner

import (
	"strings"

	"github.com/sirupsen/logrus"

	"code-security-auditor/internal/config"
)

// Analyzer computes code metrics for parsed files.
// Security detection lives in internal/scanner/rules, not here.
type Analyzer struct {
	config config.ScannerConfig
	logger *logrus.Logger
}

// NewAnalyzer creates a new Analyzer.
func NewAnalyzer(cfg config.ScannerConfig, logger *logrus.Logger) *Analyzer {
	return &Analyzer{config: cfg, logger: logger}
}

// CodeMetrics holds code quality metrics.
type CodeMetrics struct {
	TotalFiles        int             `json:"total_files"`
	TotalLines        int             `json:"total_lines"`
	CodeLines         int             `json:"code_lines"`
	CommentLines      int             `json:"comment_lines"`
	BlankLines        int             `json:"blank_lines"`
	LanguageBreakdown map[string]int  `json:"language_breakdown"`
	FileTypeBreakdown map[string]int  `json:"file_type_breakdown"`
	AverageFileSize   float64         `json:"average_file_size"`
	LargestFiles      []FileSizeInfo  `json:"largest_files"`
	ComplexityScore   float64         `json:"complexity_score"`
	DuplicationScore  float64         `json:"duplication_score"`
	FunctionMetrics   FunctionMetrics `json:"function_metrics"`
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
	AverageComplexity   float64 `json:"average_complexity"`
}

// CalculateMetrics calculates code metrics for parsed files.
func (a *Analyzer) CalculateMetrics(files []*ParsedFile) *CodeMetrics {
	metrics := &CodeMetrics{
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
	var totalComplexity int

	for _, file := range files {
		metrics.TotalLines += file.LineCount
		totalSize += file.Size

		// Count line types
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
			if fnLines < 1 {
				fnLines = 1
			}
			totalFunctionLines += fnLines
			if fnLines > largestFunction {
				largestFunction = fnLines
			}
			if fn.IsExported {
				exportedFunctions++
			}
			totalComplexity += fn.Complexity
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
		metrics.FunctionMetrics.AverageComplexity = float64(totalComplexity) / float64(totalFunctions)
	}

	// Calculate scores
	metrics.ComplexityScore = a.calculateComplexityScore(files)
	metrics.DuplicationScore = a.CalculateDuplication(files)

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
	i := 0
	for i < len(slice) && slice[i].Lines > item.Lines {
		i++
	}

	slice = append(slice, FileSizeInfo{})
	copy(slice[i+1:], slice[i:])
	slice[i] = item

	if len(slice) > maxLen {
		slice = slice[:maxLen]
	}

	return slice
}

// calculateComplexityScore calculates a complexity score.
func (a *Analyzer) calculateComplexityScore(files []*ParsedFile) float64 {
	if len(files) == 0 {
		return 100
	}

	var totalComplexity float64
	var fileCount int

	for _, file := range files {
		complexity := a.calculateFileComplexity(file)
		totalComplexity += complexity
		fileCount++
	}

	avgComplexity := totalComplexity / float64(fileCount)
	score := 100 - (avgComplexity * 5)
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

	for _, line := range file.Lines {
		trimmed := strings.TrimSpace(line)

		// Count control flow complexity
		keywords := []string{"if ", "else ", "for ", "while ", "switch ", "case ", "try ", "catch ", "except ", "finally "}
		for _, kw := range keywords {
			if strings.Contains(trimmed, kw) || strings.HasPrefix(trimmed, kw) {
				complexity++
			}
		}

		// Deep nesting indicator
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if indent > 16 {
			complexity += 0.5
		}
	}

	// Normalize by file size
	if file.LineCount > 0 {
		complexity = complexity / float64(file.LineCount) * 100
	}

	return complexity
}

// CalculateDuplication detects code duplication.
func (a *Analyzer) CalculateDuplication(files []*ParsedFile) float64 {
	lineHashes := make(map[string]int)
	duplicateLines := 0
	totalLines := 0

	for _, file := range files {
		for _, line := range file.Lines {
			trimmed := strings.TrimSpace(line)
			if len(trimmed) < 10 {
				continue
			}

			totalLines++
			lineHashes[trimmed]++
		}
	}

	for _, count := range lineHashes {
		if count > 1 {
			duplicateLines += count - 1
		}
	}

	if totalLines == 0 {
		return 100
	}

	duplicationRatio := float64(duplicateLines) / float64(totalLines)
	score := (1 - duplicationRatio) * 100

	return score
}
