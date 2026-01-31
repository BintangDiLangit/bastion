// Package scanner provides code scanning and analysis functionality.
package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"unicode"

	"github.com/sirupsen/logrus"

	"code-security-auditor/internal/config"
)

// LanguageParser interface for language-specific parsers.
type LanguageParser interface {
	Parse(ctx context.Context, filePath string, content []byte) (*AST, error)
	GetLanguage() string
	SupportsFile(filePath string) bool
}

// Parser handles source code parsing with multi-language support.
type Parser struct {
	config  config.ScannerConfig
	logger  *logrus.Logger
	parsers map[string]LanguageParser
}

// NewParser creates a new Parser.
func NewParser(cfg config.ScannerConfig, logger *logrus.Logger) *Parser {
	p := &Parser{
		config:  cfg,
		logger:  logger,
		parsers: make(map[string]LanguageParser),
	}

	// Register built-in parsers
	p.RegisterParser(&GoParser{})
	p.RegisterParser(&PythonParser{})
	p.RegisterParser(&JavaScriptParser{})
	p.RegisterParser(&TypeScriptParser{})
	p.RegisterParser(&JavaParser{})
	p.RegisterParser(&PHPParser{})
	p.RegisterParser(&RubyParser{})
	p.RegisterParser(&GenericParser{})

	return p
}

// RegisterParser registers a language-specific parser.
func (p *Parser) RegisterParser(parser LanguageParser) {
	p.parsers[parser.GetLanguage()] = parser
}

// AST represents a parsed abstract syntax tree.
type AST struct {
	Language     string            `json:"language"`
	FilePath     string            `json:"file_path"`
	Functions    []Function        `json:"functions"`
	Classes      []Class           `json:"classes"`
	Imports      []Import          `json:"imports"`
	Variables    []Variable        `json:"variables"`
	Comments     []Comment         `json:"comments"`
	Strings      []StringLiteral   `json:"strings"`
	CallSites    []CallSite        `json:"call_sites"`
	Annotations  []Annotation      `json:"annotations,omitempty"`
	RawAST       interface{}       `json:"-"` // Language-specific AST
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// Function represents a function definition.
type Function struct {
	Name         string      `json:"name"`
	Parameters   []Parameter `json:"parameters"`
	ReturnType   string      `json:"return_type,omitempty"`
	Body         string      `json:"-"` // Not serialized to JSON
	LineStart    int         `json:"line_start"`
	LineEnd      int         `json:"line_end"`
	Complexity   int         `json:"complexity"`
	IsExported   bool        `json:"is_exported"`
	IsAsync      bool        `json:"is_async,omitempty"`
	Receiver     string      `json:"receiver,omitempty"` // For Go methods
	DocString    string      `json:"doc_string,omitempty"`
	Annotations  []string    `json:"annotations,omitempty"`
}

// Parameter represents a function parameter.
type Parameter struct {
	Name     string `json:"name"`
	Type     string `json:"type,omitempty"`
	Default  string `json:"default,omitempty"`
	Variadic bool   `json:"variadic,omitempty"`
}

// Class represents a class/struct definition.
type Class struct {
	Name        string     `json:"name"`
	Methods     []Function `json:"methods"`
	Fields      []Field    `json:"fields"`
	LineStart   int        `json:"line_start"`
	LineEnd     int        `json:"line_end"`
	IsExported  bool       `json:"is_exported"`
	Extends     string     `json:"extends,omitempty"`
	Implements  []string   `json:"implements,omitempty"`
	DocString   string     `json:"doc_string,omitempty"`
	Annotations []string   `json:"annotations,omitempty"`
}

// Field represents a class/struct field.
type Field struct {
	Name       string `json:"name"`
	Type       string `json:"type,omitempty"`
	Line       int    `json:"line"`
	IsExported bool   `json:"is_exported"`
	Tags       string `json:"tags,omitempty"` // For Go struct tags
}

// Import represents an import statement.
type Import struct {
	Path   string `json:"path"`
	Alias  string `json:"alias,omitempty"`
	Line   int    `json:"line"`
	IsStd  bool   `json:"is_std,omitempty"` // Is standard library
}

// Variable represents a variable declaration.
type Variable struct {
	Name       string `json:"name"`
	Type       string `json:"type,omitempty"`
	Value      string `json:"value,omitempty"`
	Line       int    `json:"line"`
	IsConstant bool   `json:"is_constant"`
	IsExported bool   `json:"is_exported"`
	Scope      string `json:"scope,omitempty"` // global, local, class
}

// Comment represents a code comment.
type Comment struct {
	Text      string `json:"text"`
	Line      int    `json:"line"`
	LineEnd   int    `json:"line_end,omitempty"`
	IsBlock   bool   `json:"is_block"`
	IsDoc     bool   `json:"is_doc"`
}

// StringLiteral represents a string literal in code.
type StringLiteral struct {
	Value      string `json:"value"`
	Line       int    `json:"line"`
	Column     int    `json:"column"`
	IsRaw      bool   `json:"is_raw,omitempty"`
	IsTemplate bool   `json:"is_template,omitempty"`
}

// CallSite represents a function/method call.
type CallSite struct {
	Name       string   `json:"name"`
	Receiver   string   `json:"receiver,omitempty"`
	Arguments  []string `json:"arguments,omitempty"`
	Line       int      `json:"line"`
	Column     int      `json:"column"`
	IsMethod   bool     `json:"is_method"`
}

// Annotation represents a code annotation/decorator.
type Annotation struct {
	Name      string   `json:"name"`
	Arguments []string `json:"arguments,omitempty"`
	Line      int      `json:"line"`
}

// ParsedFile represents a parsed source file with additional metadata.
type ParsedFile struct {
	Path            string          `json:"path"`
	Content         []byte          `json:"-"`
	Lines           []string        `json:"-"`
	Language        string          `json:"language"`
	LineCount       int             `json:"line_count"`
	Size            int64           `json:"size"`
	AST             *AST            `json:"ast,omitempty"`
	Functions       []FunctionInfo  `json:"functions,omitempty"`
	Imports         []ImportInfo    `json:"imports,omitempty"`
	Strings         []StringLiteral `json:"strings,omitempty"`
	SecurityMarkers []SecurityMarker `json:"security_markers,omitempty"`
	Checksum        string          `json:"checksum,omitempty"`
}

// FunctionInfo holds simplified function information.
type FunctionInfo struct {
	Name       string   `json:"name"`
	StartLine  int      `json:"start_line"`
	EndLine    int      `json:"end_line"`
	Parameters []string `json:"parameters,omitempty"`
	ReturnType string   `json:"return_type,omitempty"`
	IsExported bool     `json:"is_exported"`
	Complexity int      `json:"complexity,omitempty"`
}

// ImportInfo holds simplified import information.
type ImportInfo struct {
	Path  string `json:"path"`
	Alias string `json:"alias,omitempty"`
	Line  int    `json:"line"`
}

// SecurityMarker represents security-sensitive code markers.
type SecurityMarker struct {
	Type        string `json:"type"` // sql_query, exec, eval, etc.
	Description string `json:"description"`
	Line        int    `json:"line"`
	Column      int    `json:"column"`
	Snippet     string `json:"snippet"`
}

// ParseRepository parses all files in a repository.
func (p *Parser) ParseRepository(ctx context.Context, repoPath string, excludedPaths []string) ([]*ParsedFile, error) {
	var files []*ParsedFile
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	// Create a semaphore to limit concurrent parsing
	sem := make(chan struct{}, p.config.MaxConcurrent)
	if p.config.MaxConcurrent <= 0 {
		sem = make(chan struct{}, 4) // Default to 4 concurrent parsers
	}

	fileCount := 0

	err := filepath.Walk(repoPath, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files with errors
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Skip directories
		if info.IsDir() {
			relPath, _ := filepath.Rel(repoPath, filePath)
			for _, excluded := range excludedPaths {
				excluded = strings.TrimSuffix(excluded, "/")
				if strings.HasPrefix(relPath, excluded) || relPath == excluded {
					return filepath.SkipDir
				}
			}
			return nil
		}

		// Check file count limit
		if p.config.MaxFilesPerScan > 0 && fileCount >= p.config.MaxFilesPerScan {
			return filepath.SkipAll
		}

		// Check file size
		if info.Size() > p.config.MaxFileSize {
			return nil
		}

		// Check if file should be excluded
		relPath, _ := filepath.Rel(repoPath, filePath)
		for _, excluded := range excludedPaths {
			if strings.Contains(relPath, excluded) {
				return nil
			}
		}

		// Check extension
		for _, excludedExt := range p.config.ExcludedExtensions {
			if strings.HasSuffix(filePath, excludedExt) {
				return nil
			}
		}

		// Detect language
		language := DetectLanguage(filePath)
		if language == "" {
			return nil
		}

		fileCount++

		// Parse file concurrently
		wg.Add(1)
		go func(fp, rp, lang string, size int64) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			parsedFile, err := p.ParseFile(fp, lang)
			if err != nil {
				p.logger.WithError(err).Debugf("Failed to parse file: %s", fp)
				return
			}

			parsedFile.Path = rp
			parsedFile.Size = size

			mu.Lock()
			files = append(files, parsedFile)
			mu.Unlock()
		}(filePath, relPath, language, info.Size())

		return nil
	})

	wg.Wait()
	return files, err
}

// ParseFile parses a single file.
func (p *Parser) ParseFile(path, language string) (*ParsedFile, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Check for binary content
	if IsBinaryFile(content) {
		return nil, fmt.Errorf("binary file: %s", path)
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")

	file := &ParsedFile{
		Path:            path,
		Content:         content,
		Lines:           lines,
		Language:        language,
		LineCount:       len(lines),
		Size:            info.Size(),
		Functions:       make([]FunctionInfo, 0),
		Imports:         make([]ImportInfo, 0),
		Strings:         make([]StringLiteral, 0),
		SecurityMarkers: make([]SecurityMarker, 0),
	}

	// Parse based on language
	switch language {
	case "go":
		p.parseGo(file)
	case "javascript", "typescript":
		p.parseJS(file)
	case "python":
		p.parsePython(file)
	case "java":
		p.parseJava(file)
	case "php":
		p.parsePHP(file)
	case "ruby":
		p.parseRuby(file)
	default:
		p.parseGeneric(file)
	}

	// Detect security-sensitive patterns
	p.detectSecurityMarkers(file)

	return file, nil
}

// parseGo parses Go source code.
func (p *Parser) parseGo(file *ParsedFile) {
	fset := token.NewFileSet()
	astFile, err := parser.ParseFile(fset, file.Path, file.Content, parser.ParseComments)
	if err != nil {
		return
	}

	file.AST = &AST{
		Language: "go",
		FilePath: file.Path,
		RawAST:   astFile,
	}

	// Extract imports
	for _, imp := range astFile.Imports {
		importInfo := ImportInfo{
			Path: strings.Trim(imp.Path.Value, `"`),
			Line: fset.Position(imp.Pos()).Line,
		}
		if imp.Name != nil {
			importInfo.Alias = imp.Name.Name
		}
		file.Imports = append(file.Imports, importInfo)
	}

	// Extract functions and collect call sites
	ast.Inspect(astFile, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			funcInfo := FunctionInfo{
				Name:       node.Name.Name,
				StartLine:  fset.Position(node.Pos()).Line,
				EndLine:    fset.Position(node.End()).Line,
				IsExported: ast.IsExported(node.Name.Name),
			}

			// Calculate complexity
			funcInfo.Complexity = calculateGoComplexity(node)

			// Extract parameters
			if node.Type.Params != nil {
				for _, param := range node.Type.Params.List {
					for _, name := range param.Names {
						funcInfo.Parameters = append(funcInfo.Parameters, name.Name)
					}
				}
			}

			// Extract return type
			if node.Type.Results != nil {
				var returns []string
				for _, result := range node.Type.Results.List {
					returns = append(returns, formatGoType(result.Type))
				}
				funcInfo.ReturnType = strings.Join(returns, ", ")
			}

			file.Functions = append(file.Functions, funcInfo)

		case *ast.BasicLit:
			if node.Kind == token.STRING {
				value := node.Value
				// Remove quotes
				if len(value) >= 2 {
					if value[0] == '"' || value[0] == '`' {
						value = value[1 : len(value)-1]
					}
				}
				file.Strings = append(file.Strings, StringLiteral{
					Value:  value,
					Line:   fset.Position(node.Pos()).Line,
					Column: fset.Position(node.Pos()).Column,
					IsRaw:  node.Value[0] == '`',
				})
			}

		case *ast.CallExpr:
			// Track call sites for security analysis
			callSite := extractGoCallSite(node, fset)
			if callSite != nil && file.AST != nil {
				file.AST.CallSites = append(file.AST.CallSites, *callSite)
			}
		}
		return true
	})
}

// calculateGoComplexity calculates cyclomatic complexity for a Go function.
func calculateGoComplexity(fn *ast.FuncDecl) int {
	complexity := 1 // Base complexity

	ast.Inspect(fn, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt,
			*ast.CaseClause, *ast.CommClause:
			complexity++
		case *ast.BinaryExpr:
			if be, ok := n.(*ast.BinaryExpr); ok {
				if be.Op == token.LAND || be.Op == token.LOR {
					complexity++
				}
			}
		}
		return true
	})

	return complexity
}

// formatGoType formats a Go type expression as a string.
func formatGoType(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + formatGoType(t.X)
	case *ast.ArrayType:
		return "[]" + formatGoType(t.Elt)
	case *ast.MapType:
		return fmt.Sprintf("map[%s]%s", formatGoType(t.Key), formatGoType(t.Value))
	case *ast.SelectorExpr:
		return fmt.Sprintf("%s.%s", formatGoType(t.X), t.Sel.Name)
	case *ast.InterfaceType:
		return "interface{}"
	default:
		return "unknown"
	}
}

// extractGoCallSite extracts call site information from a Go call expression.
func extractGoCallSite(call *ast.CallExpr, fset *token.FileSet) *CallSite {
	cs := &CallSite{
		Line:   fset.Position(call.Pos()).Line,
		Column: fset.Position(call.Pos()).Column,
	}

	switch fn := call.Fun.(type) {
	case *ast.Ident:
		cs.Name = fn.Name
	case *ast.SelectorExpr:
		cs.IsMethod = true
		cs.Name = fn.Sel.Name
		if ident, ok := fn.X.(*ast.Ident); ok {
			cs.Receiver = ident.Name
		}
	default:
		return nil
	}

	return cs
}

// parseJS parses JavaScript/TypeScript source code.
func (p *Parser) parseJS(file *ParsedFile) {
	p.parseGeneric(file)

	// Enhanced import extraction
	importPatterns := []*regexp.Regexp{
		regexp.MustCompile(`import\s+(?:{[^}]+}|\*\s+as\s+\w+|\w+)\s+from\s+['"]([^'"]+)['"]`),
		regexp.MustCompile(`import\s+['"]([^'"]+)['"]`),
		regexp.MustCompile(`require\s*\(\s*['"]([^'"]+)['"]\s*\)`),
	}

	for i, line := range file.Lines {
		for _, pattern := range importPatterns {
			if matches := pattern.FindStringSubmatch(line); len(matches) > 1 {
				file.Imports = append(file.Imports, ImportInfo{
					Path: matches[1],
					Line: i + 1,
				})
			}
		}
	}

	// Extract functions
	funcPatterns := []*regexp.Regexp{
		regexp.MustCompile(`function\s+(\w+)\s*\(`),
		regexp.MustCompile(`(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>)`),
		regexp.MustCompile(`(\w+)\s*:\s*(?:async\s+)?function\s*\(`),
		regexp.MustCompile(`async\s+function\s+(\w+)\s*\(`),
	}

	for i, line := range file.Lines {
		for _, pattern := range funcPatterns {
			if matches := pattern.FindStringSubmatch(line); len(matches) > 1 {
				file.Functions = append(file.Functions, FunctionInfo{
					Name:       matches[1],
					StartLine:  i + 1,
					IsExported: strings.Contains(line, "export"),
				})
			}
		}
	}
}

// parsePython parses Python source code.
func (p *Parser) parsePython(file *ParsedFile) {
	p.parseGeneric(file)

	// Extract imports
	importPatterns := []*regexp.Regexp{
		regexp.MustCompile(`^import\s+([\w.]+)`),
		regexp.MustCompile(`^from\s+([\w.]+)\s+import`),
	}

	for i, line := range file.Lines {
		trimmed := strings.TrimSpace(line)
		for _, pattern := range importPatterns {
			if matches := pattern.FindStringSubmatch(trimmed); len(matches) > 1 {
				file.Imports = append(file.Imports, ImportInfo{
					Path: matches[1],
					Line: i + 1,
				})
			}
		}
	}

	// Extract functions and classes
	funcPattern := regexp.MustCompile(`^(\s*)def\s+(\w+)\s*\(([^)]*)\)`)
	classPattern := regexp.MustCompile(`^(\s*)class\s+(\w+)`)
	decoratorPattern := regexp.MustCompile(`^(\s*)@(\w+)`)

	var currentDecorators []string
	var classIndent = -1
	var currentClass string

	for i, line := range file.Lines {
		// Track decorators
		if matches := decoratorPattern.FindStringSubmatch(line); len(matches) > 2 {
			currentDecorators = append(currentDecorators, matches[2])
			continue
		}

		// Track class scope
		if matches := classPattern.FindStringSubmatch(line); len(matches) > 2 {
			classIndent = len(matches[1])
			currentClass = matches[2]
			currentDecorators = nil
			continue
		}

		// Extract functions
		if matches := funcPattern.FindStringSubmatch(line); len(matches) > 3 {
			indent := len(matches[1])
			name := matches[2]

			// Check if we're still in a class
			if classIndent >= 0 && indent <= classIndent {
				classIndent = -1
				currentClass = ""
			}

			file.Functions = append(file.Functions, FunctionInfo{
				Name:       name,
				StartLine:  i + 1,
				IsExported: !strings.HasPrefix(name, "_"),
			})

			currentDecorators = nil
		}

		// Reset decorators if line is not a decorator or function
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine != "" && !strings.HasPrefix(trimmedLine, "@") && !strings.HasPrefix(trimmedLine, "def ") {
			currentDecorators = nil
		}
	}
	
	_ = currentClass // Silence unused variable
	_ = currentDecorators
}

// parseJava parses Java source code.
func (p *Parser) parseJava(file *ParsedFile) {
	p.parseGeneric(file)

	// Extract imports
	importPattern := regexp.MustCompile(`^import\s+(static\s+)?([\w.]+(?:\.\*)?);`)

	for i, line := range file.Lines {
		if matches := importPattern.FindStringSubmatch(strings.TrimSpace(line)); len(matches) > 2 {
			file.Imports = append(file.Imports, ImportInfo{
				Path: matches[2],
				Line: i + 1,
			})
		}
	}

	// Extract methods and classes
	methodPattern := regexp.MustCompile(`(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{`)
	classPattern := regexp.MustCompile(`(?:public|private|protected)?\s*(?:abstract|final)?\s*class\s+(\w+)`)

	for i, line := range file.Lines {
		if matches := methodPattern.FindStringSubmatch(line); len(matches) > 1 {
			name := matches[1]
			if name != "if" && name != "for" && name != "while" && name != "switch" {
				file.Functions = append(file.Functions, FunctionInfo{
					Name:       name,
					StartLine:  i + 1,
					IsExported: strings.Contains(line, "public"),
				})
			}
		}

		if matches := classPattern.FindStringSubmatch(line); len(matches) > 1 {
			// Track class for context
			_ = matches[1]
		}
	}
}

// parsePHP parses PHP source code.
func (p *Parser) parsePHP(file *ParsedFile) {
	p.parseGeneric(file)

	// Extract includes/requires
	includePattern := regexp.MustCompile(`(?:include|require|include_once|require_once)\s*\(?['"]([^'"]+)['"]\)?`)

	for i, line := range file.Lines {
		if matches := includePattern.FindStringSubmatch(line); len(matches) > 1 {
			file.Imports = append(file.Imports, ImportInfo{
				Path: matches[1],
				Line: i + 1,
			})
		}
	}

	// Extract functions
	funcPattern := regexp.MustCompile(`function\s+(\w+)\s*\(`)

	for i, line := range file.Lines {
		if matches := funcPattern.FindStringSubmatch(line); len(matches) > 1 {
			file.Functions = append(file.Functions, FunctionInfo{
				Name:      matches[1],
				StartLine: i + 1,
			})
		}
	}
}

// parseRuby parses Ruby source code.
func (p *Parser) parseRuby(file *ParsedFile) {
	p.parseGeneric(file)

	// Extract requires
	requirePattern := regexp.MustCompile(`require\s+['"]([^'"]+)['"]`)

	for i, line := range file.Lines {
		if matches := requirePattern.FindStringSubmatch(line); len(matches) > 1 {
			file.Imports = append(file.Imports, ImportInfo{
				Path: matches[1],
				Line: i + 1,
			})
		}
	}

	// Extract methods
	methodPattern := regexp.MustCompile(`def\s+(\w+)`)

	for i, line := range file.Lines {
		if matches := methodPattern.FindStringSubmatch(strings.TrimSpace(line)); len(matches) > 1 {
			file.Functions = append(file.Functions, FunctionInfo{
				Name:       matches[1],
				StartLine:  i + 1,
				IsExported: !strings.HasPrefix(matches[1], "_"),
			})
		}
	}
}

// parseGeneric provides basic parsing for any text file.
func (p *Parser) parseGeneric(file *ParsedFile) {
	scanner := bufio.NewScanner(bytes.NewReader(file.Content))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Find string literals
		p.extractStrings(file, line, lineNum)
	}
}

// extractStrings extracts string literals from a line.
func (p *Parser) extractStrings(file *ParsedFile, line string, lineNum int) {
	inString := false
	stringStart := 0
	quote := byte(0)
	escaped := false

	for i := 0; i < len(line); i++ {
		c := line[i]

		if escaped {
			escaped = false
			continue
		}

		if c == '\\' {
			escaped = true
			continue
		}

		if !inString && (c == '"' || c == '\'' || c == '`') {
			inString = true
			stringStart = i
			quote = c
		} else if inString && c == quote {
			value := line[stringStart+1 : i]
			if len(value) > 0 {
				file.Strings = append(file.Strings, StringLiteral{
					Value:      value,
					Line:       lineNum,
					Column:     stringStart + 1,
					IsRaw:      quote == '`',
					IsTemplate: quote == '`' && strings.Contains(value, "${"),
				})
			}
			inString = false
		}
	}
}

// detectSecurityMarkers identifies security-sensitive code patterns.
func (p *Parser) detectSecurityMarkers(file *ParsedFile) {
	securityPatterns := map[string]*regexp.Regexp{
		"sql_query":    regexp.MustCompile(`(?i)(execute|query|exec)\s*\(`),
		"exec":         regexp.MustCompile(`(?i)(exec|system|popen|subprocess|spawn)\s*\(`),
		"eval":         regexp.MustCompile(`(?i)\beval\s*\(`),
		"shell":        regexp.MustCompile(`(?i)(shell_exec|passthru|backtick)\s*\(`),
		"file_read":    regexp.MustCompile(`(?i)(readFile|read_file|file_get_contents|open)\s*\(`),
		"file_write":   regexp.MustCompile(`(?i)(writeFile|write_file|file_put_contents)\s*\(`),
		"http_request": regexp.MustCompile(`(?i)(fetch|axios|http\.get|requests\.get|curl)\s*\(`),
		"crypto":       regexp.MustCompile(`(?i)(md5|sha1|encrypt|decrypt)\s*\(`),
		"auth":         regexp.MustCompile(`(?i)(password|token|secret|api_key|apikey)\s*[=:]`),
		"serialization": regexp.MustCompile(`(?i)(pickle\.load|unserialize|yaml\.load|deserialize)\s*\(`),
	}

	for i, line := range file.Lines {
		for markerType, pattern := range securityPatterns {
			if loc := pattern.FindStringIndex(line); loc != nil {
				file.SecurityMarkers = append(file.SecurityMarkers, SecurityMarker{
					Type:        markerType,
					Description: fmt.Sprintf("Potential %s usage", strings.ReplaceAll(markerType, "_", " ")),
					Line:        i + 1,
					Column:      loc[0] + 1,
					Snippet:     strings.TrimSpace(line),
				})
			}
		}
	}
}

// DetectLanguage detects the programming language from file path.
func DetectLanguage(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	base := strings.ToLower(filepath.Base(path))

	// Extension mapping
	extensionMap := map[string]string{
		".go":    "go",
		".js":    "javascript",
		".mjs":   "javascript",
		".cjs":   "javascript",
		".jsx":   "javascript",
		".ts":    "typescript",
		".tsx":   "typescript",
		".py":    "python",
		".pyw":   "python",
		".rb":    "ruby",
		".java":  "java",
		".kt":    "kotlin",
		".kts":   "kotlin",
		".scala": "scala",
		".c":     "c",
		".h":     "c",
		".cpp":   "cpp",
		".cc":    "cpp",
		".cxx":   "cpp",
		".hpp":   "cpp",
		".hxx":   "cpp",
		".cs":    "csharp",
		".rs":    "rust",
		".swift": "swift",
		".php":   "php",
		".sh":    "shell",
		".bash":  "shell",
		".sql":   "sql",
		".yaml":  "yaml",
		".yml":   "yaml",
		".json":  "json",
		".xml":   "xml",
		".html":  "html",
		".htm":   "html",
		".css":   "css",
		".scss":  "scss",
		".sass":  "sass",
		".less":  "less",
	}

	if lang, ok := extensionMap[ext]; ok {
		return lang
	}

	// Check special filenames
	filenameMap := map[string]string{
		"dockerfile":   "dockerfile",
		"makefile":     "makefile",
		".env":         "env",
		".env.example": "env",
		".env.local":   "env",
		"gemfile":      "ruby",
		"rakefile":     "ruby",
	}

	if lang, ok := filenameMap[base]; ok {
		return lang
	}

	return ""
}

// GetLanguageExtensions returns all extensions for a language.
func GetLanguageExtensions(language string) []string {
	extensions := map[string][]string{
		"go":         {".go"},
		"javascript": {".js", ".jsx", ".mjs", ".cjs"},
		"typescript": {".ts", ".tsx"},
		"python":     {".py", ".pyw"},
		"ruby":       {".rb"},
		"java":       {".java"},
		"kotlin":     {".kt", ".kts"},
		"c":          {".c", ".h"},
		"cpp":        {".cpp", ".cc", ".cxx", ".hpp", ".hxx"},
		"csharp":     {".cs"},
		"rust":       {".rs"},
		"swift":      {".swift"},
		"php":        {".php"},
		"shell":      {".sh", ".bash"},
		"sql":        {".sql"},
	}

	if exts, ok := extensions[language]; ok {
		return exts
	}
	return nil
}

// IsBinaryFile checks if content is binary.
func IsBinaryFile(content []byte) bool {
	if len(content) == 0 {
		return false
	}

	// Check first 8KB for null bytes
	checkLen := min(8000, len(content))
	for _, b := range content[:checkLen] {
		if b == 0 {
			return true
		}
	}

	// Check for high ratio of non-printable characters
	nonPrintable := 0
	for _, b := range content[:checkLen] {
		if b < 32 && b != '\n' && b != '\r' && b != '\t' {
			nonPrintable++
		}
	}

	return float64(nonPrintable)/float64(checkLen) > 0.3
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ============================================================================
// Language-Specific Parser Implementations
// ============================================================================

// GoParser implements LanguageParser for Go.
type GoParser struct{}

func (p *GoParser) GetLanguage() string { return "go" }
func (p *GoParser) SupportsFile(path string) bool {
	return strings.HasSuffix(path, ".go")
}
func (p *GoParser) Parse(ctx context.Context, filePath string, content []byte) (*AST, error) {
	fset := token.NewFileSet()
	astFile, err := parser.ParseFile(fset, filePath, content, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	return &AST{
		Language: "go",
		FilePath: filePath,
		RawAST:   astFile,
	}, nil
}

// PythonParser implements LanguageParser for Python.
type PythonParser struct{}

func (p *PythonParser) GetLanguage() string { return "python" }
func (p *PythonParser) SupportsFile(path string) bool {
	return strings.HasSuffix(path, ".py") || strings.HasSuffix(path, ".pyw")
}
func (p *PythonParser) Parse(ctx context.Context, filePath string, content []byte) (*AST, error) {
	return &AST{Language: "python", FilePath: filePath}, nil
}

// JavaScriptParser implements LanguageParser for JavaScript.
type JavaScriptParser struct{}

func (p *JavaScriptParser) GetLanguage() string { return "javascript" }
func (p *JavaScriptParser) SupportsFile(path string) bool {
	exts := []string{".js", ".jsx", ".mjs", ".cjs"}
	for _, ext := range exts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}
func (p *JavaScriptParser) Parse(ctx context.Context, filePath string, content []byte) (*AST, error) {
	return &AST{Language: "javascript", FilePath: filePath}, nil
}

// TypeScriptParser implements LanguageParser for TypeScript.
type TypeScriptParser struct{}

func (p *TypeScriptParser) GetLanguage() string { return "typescript" }
func (p *TypeScriptParser) SupportsFile(path string) bool {
	return strings.HasSuffix(path, ".ts") || strings.HasSuffix(path, ".tsx")
}
func (p *TypeScriptParser) Parse(ctx context.Context, filePath string, content []byte) (*AST, error) {
	return &AST{Language: "typescript", FilePath: filePath}, nil
}

// JavaParser implements LanguageParser for Java.
type JavaParser struct{}

func (p *JavaParser) GetLanguage() string { return "java" }
func (p *JavaParser) SupportsFile(path string) bool {
	return strings.HasSuffix(path, ".java")
}
func (p *JavaParser) Parse(ctx context.Context, filePath string, content []byte) (*AST, error) {
	return &AST{Language: "java", FilePath: filePath}, nil
}

// PHPParser implements LanguageParser for PHP.
type PHPParser struct{}

func (p *PHPParser) GetLanguage() string { return "php" }
func (p *PHPParser) SupportsFile(path string) bool {
	return strings.HasSuffix(path, ".php")
}
func (p *PHPParser) Parse(ctx context.Context, filePath string, content []byte) (*AST, error) {
	return &AST{Language: "php", FilePath: filePath}, nil
}

// RubyParser implements LanguageParser for Ruby.
type RubyParser struct{}

func (p *RubyParser) GetLanguage() string { return "ruby" }
func (p *RubyParser) SupportsFile(path string) bool {
	return strings.HasSuffix(path, ".rb")
}
func (p *RubyParser) Parse(ctx context.Context, filePath string, content []byte) (*AST, error) {
	return &AST{Language: "ruby", FilePath: filePath}, nil
}

// GenericParser implements LanguageParser for unknown languages.
type GenericParser struct{}

func (p *GenericParser) GetLanguage() string        { return "generic" }
func (p *GenericParser) SupportsFile(path string) bool { return true }
func (p *GenericParser) Parse(ctx context.Context, filePath string, content []byte) (*AST, error) {
	return &AST{Language: "generic", FilePath: filePath}, nil
}

// IsExportedName checks if a name is exported (starts with uppercase).
func IsExportedName(name string) bool {
	if name == "" {
		return false
	}
	return unicode.IsUpper(rune(name[0]))
}
