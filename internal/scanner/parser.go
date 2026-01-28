package scanner

import (
	"bufio"
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/code-security-auditor/internal/config"
)

// Parser handles source code parsing.
type Parser struct {
	config config.ScannerConfig
	logger *logrus.Logger
}

// NewParser creates a new Parser.
func NewParser(cfg config.ScannerConfig, logger *logrus.Logger) *Parser {
	return &Parser{
		config: cfg,
		logger: logger,
	}
}

// ParsedFile represents a parsed source file.
type ParsedFile struct {
	Path      string
	Content   []byte
	Lines     []string
	Language  string
	LineCount int
	Size      int64
	AST       interface{} // Language-specific AST
	Functions []FunctionInfo
	Imports   []ImportInfo
	Strings   []StringLiteral
}

// FunctionInfo holds information about a function.
type FunctionInfo struct {
	Name       string
	StartLine  int
	EndLine    int
	Parameters []string
	ReturnType string
	IsExported bool
}

// ImportInfo holds information about an import.
type ImportInfo struct {
	Path   string
	Alias  string
	Line   int
}

// StringLiteral holds information about a string literal.
type StringLiteral struct {
	Value string
	Line  int
	Col   int
}

// ParseRepository parses all files in a repository.
func (p *Parser) ParseRepository(ctx context.Context, path string, excludedPaths []string) ([]*ParsedFile, error) {
	var files []*ParsedFile

	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
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
			// Check if directory should be excluded
			relPath, _ := filepath.Rel(path, filePath)
			for _, excluded := range excludedPaths {
				if strings.Contains(relPath, excluded) || strings.HasPrefix(relPath, excluded) {
					return filepath.SkipDir
				}
			}
			return nil
		}

		// Check file size
		if info.Size() > p.config.MaxFileSize {
			return nil
		}

		// Check if file should be excluded
		relPath, _ := filepath.Rel(path, filePath)
		for _, excluded := range excludedPaths {
			if strings.Contains(relPath, excluded) {
				return nil
			}
		}

		// Check extension
		ext := filepath.Ext(filePath)
		for _, excludedExt := range p.config.ExcludedExtensions {
			if ext == excludedExt || strings.HasSuffix(filePath, excludedExt) {
				return nil
			}
		}

		// Parse supported files
		language := detectLanguage(filePath)
		if language == "" {
			return nil
		}

		parsedFile, err := p.ParseFile(filePath, language)
		if err != nil {
			p.logger.WithError(err).Debugf("Failed to parse file: %s", filePath)
			return nil
		}

		// Use relative path
		parsedFile.Path = relPath
		files = append(files, parsedFile)

		return nil
	})

	return files, err
}

// ParseFile parses a single file.
func (p *Parser) ParseFile(path, language string) (*ParsedFile, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")

	file := &ParsedFile{
		Path:      path,
		Content:   content,
		Lines:     lines,
		Language:  language,
		LineCount: len(lines),
		Size:      info.Size(),
		Functions: make([]FunctionInfo, 0),
		Imports:   make([]ImportInfo, 0),
		Strings:   make([]StringLiteral, 0),
	}

	// Parse based on language
	switch language {
	case "go":
		p.parseGo(file)
	case "javascript", "typescript":
		p.parseJS(file)
	case "python":
		p.parsePython(file)
	default:
		// Basic parsing for other languages
		p.parseGeneric(file)
	}

	return file, nil
}

// parseGo parses Go source code.
func (p *Parser) parseGo(file *ParsedFile) {
	fset := token.NewFileSet()
	astFile, err := parser.ParseFile(fset, file.Path, file.Content, parser.ParseComments)
	if err != nil {
		return
	}

	file.AST = astFile

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

	// Extract functions
	ast.Inspect(astFile, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			funcInfo := FunctionInfo{
				Name:       node.Name.Name,
				StartLine:  fset.Position(node.Pos()).Line,
				EndLine:    fset.Position(node.End()).Line,
				IsExported: ast.IsExported(node.Name.Name),
			}

			// Extract parameters
			if node.Type.Params != nil {
				for _, param := range node.Type.Params.List {
					for _, name := range param.Names {
						funcInfo.Parameters = append(funcInfo.Parameters, name.Name)
					}
				}
			}

			file.Functions = append(file.Functions, funcInfo)

		case *ast.BasicLit:
			if node.Kind == token.STRING {
				file.Strings = append(file.Strings, StringLiteral{
					Value: node.Value,
					Line:  fset.Position(node.Pos()).Line,
					Col:   fset.Position(node.Pos()).Column,
				})
			}
		}
		return true
	})
}

// parseJS parses JavaScript/TypeScript source code.
func (p *Parser) parseJS(file *ParsedFile) {
	// Basic parsing for JS/TS
	// A full implementation would use a proper JS parser
	p.parseGeneric(file)

	// Extract imports
	for i, line := range file.Lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "import ") || strings.HasPrefix(trimmed, "require(") {
			// Extract import path
			if idx := strings.Index(line, "from"); idx != -1 {
				path := strings.TrimSpace(line[idx+4:])
				path = strings.Trim(path, `"';`)
				file.Imports = append(file.Imports, ImportInfo{
					Path: path,
					Line: i + 1,
				})
			} else if idx := strings.Index(line, "require("); idx != -1 {
				start := idx + 8
				end := strings.Index(line[start:], ")")
				if end != -1 {
					path := strings.Trim(line[start:start+end], `"'`)
					file.Imports = append(file.Imports, ImportInfo{
						Path: path,
						Line: i + 1,
					})
				}
			}
		}
	}
}

// parsePython parses Python source code.
func (p *Parser) parsePython(file *ParsedFile) {
	p.parseGeneric(file)

	// Extract imports
	for i, line := range file.Lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "import ") || strings.HasPrefix(trimmed, "from ") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				path := parts[1]
				file.Imports = append(file.Imports, ImportInfo{
					Path: path,
					Line: i + 1,
				})
			}
		}
	}

	// Extract functions
	for i, line := range file.Lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "def ") {
			// Extract function name
			end := strings.Index(trimmed, "(")
			if end != -1 {
				name := trimmed[4:end]
				file.Functions = append(file.Functions, FunctionInfo{
					Name:       name,
					StartLine:  i + 1,
					IsExported: !strings.HasPrefix(name, "_"),
				})
			}
		}
	}
}

// parseGeneric provides basic parsing for any text file.
func (p *Parser) parseGeneric(file *ParsedFile) {
	// Extract string literals
	scanner := bufio.NewScanner(bytes.NewReader(file.Content))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Find string literals (basic detection)
		inString := false
		stringStart := 0
		quote := byte(0)

		for i := 0; i < len(line); i++ {
			c := line[i]
			if !inString && (c == '"' || c == '\'' || c == '`') {
				inString = true
				stringStart = i
				quote = c
			} else if inString && c == quote && (i == 0 || line[i-1] != '\\') {
				file.Strings = append(file.Strings, StringLiteral{
					Value: line[stringStart+1 : i],
					Line:  lineNum,
					Col:   stringStart + 1,
				})
				inString = false
			}
		}
	}
}

// detectLanguage detects the programming language from file extension.
func detectLanguage(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	
	// Also check for specific filenames
	base := strings.ToLower(filepath.Base(path))

	// Language mapping
	switch ext {
	case ".go":
		return "go"
	case ".js", ".mjs", ".cjs":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".jsx":
		return "javascript"
	case ".py", ".pyw":
		return "python"
	case ".rb":
		return "ruby"
	case ".java":
		return "java"
	case ".kt", ".kts":
		return "kotlin"
	case ".scala":
		return "scala"
	case ".c", ".h":
		return "c"
	case ".cpp", ".cc", ".cxx", ".hpp", ".hxx":
		return "cpp"
	case ".cs":
		return "csharp"
	case ".rs":
		return "rust"
	case ".swift":
		return "swift"
	case ".php":
		return "php"
	case ".sh", ".bash":
		return "shell"
	case ".sql":
		return "sql"
	case ".yaml", ".yml":
		return "yaml"
	case ".json":
		return "json"
	case ".xml":
		return "xml"
	case ".html", ".htm":
		return "html"
	case ".css", ".scss", ".sass", ".less":
		return "css"
	}

	// Check specific files
	switch base {
	case "dockerfile":
		return "dockerfile"
	case "makefile":
		return "makefile"
	case ".env", ".env.example", ".env.local":
		return "env"
	case "package.json", "tsconfig.json", "composer.json":
		return "json"
	case "requirements.txt", "pipfile":
		return "python"
	case "gemfile":
		return "ruby"
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

// IsBinaryFile checks if a file is binary.
func IsBinaryFile(content []byte) bool {
	// Check for null bytes (common in binary files)
	for _, b := range content[:min(8000, len(content))] {
		if b == 0 {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
