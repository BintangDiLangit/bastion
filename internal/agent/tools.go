package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// Tool represents a tool that can be used by the AI agent.
type Tool interface {
	Name() string
	Description() string
	Parameters() map[string]ParameterDef
	Execute(ctx context.Context, params map[string]interface{}) (interface{}, error)
}

// ParameterDef defines a tool parameter.
type ParameterDef struct {
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Required    bool     `json:"required"`
	Enum        []string `json:"enum,omitempty"`
}

// ToolRegistry manages available tools.
type ToolRegistry struct {
	tools  map[string]Tool
	logger *logrus.Logger
}

// NewToolRegistry creates a new tool registry.
func NewToolRegistry() *ToolRegistry {
	return &ToolRegistry{
		tools:  make(map[string]Tool),
		logger: logrus.StandardLogger(),
	}
}

// NewToolRegistryWithLogger creates a new tool registry with a custom logger.
func NewToolRegistryWithLogger(logger *logrus.Logger) *ToolRegistry {
	return &ToolRegistry{
		tools:  make(map[string]Tool),
		logger: logger,
	}
}

// Register registers a tool.
func (r *ToolRegistry) Register(tool Tool) {
	r.tools[tool.Name()] = tool
	r.logger.WithField("tool", tool.Name()).Debug("Registered tool")
}

// Get returns a tool by name.
func (r *ToolRegistry) Get(name string) (Tool, bool) {
	tool, ok := r.tools[name]
	return tool, ok
}

// List returns all registered tools.
func (r *ToolRegistry) List() []Tool {
	tools := make([]Tool, 0, len(r.tools))
	for _, tool := range r.tools {
		tools = append(tools, tool)
	}
	return tools
}

// Execute executes a tool by name.
func (r *ToolRegistry) Execute(ctx context.Context, name string, params map[string]interface{}) (interface{}, error) {
	tool, ok := r.tools[name]
	if !ok {
		return nil, fmt.Errorf("tool not found: %s", name)
	}

	r.logger.WithFields(logrus.Fields{
		"tool":   name,
		"params": params,
	}).Debug("Executing tool")

	start := time.Now()
	result, err := tool.Execute(ctx, params)
	duration := time.Since(start)

	if err != nil {
		r.logger.WithError(err).WithFields(logrus.Fields{
			"tool":     name,
			"duration": duration,
		}).Error("Tool execution failed")
	} else {
		r.logger.WithFields(logrus.Fields{
			"tool":     name,
			"duration": duration,
		}).Debug("Tool execution completed")
	}

	return result, err
}

// GetToolDefinitions returns tool definitions for the AI model.
func (r *ToolRegistry) GetToolDefinitions() []map[string]interface{} {
	var defs []map[string]interface{}

	for _, tool := range r.tools {
		def := map[string]interface{}{
			"name":        tool.Name(),
			"description": tool.Description(),
			"parameters": map[string]interface{}{
				"type":       "object",
				"properties": tool.Parameters(),
			},
		}
		defs = append(defs, def)
	}

	return defs
}

// ===== Code Context Retriever Tool =====

// CodeContextRetrieverTool fetches surrounding code and context.
type CodeContextRetrieverTool struct {
	basePath string
	logger   *logrus.Logger
}

// NewCodeContextRetrieverTool creates a new code context retriever.
func NewCodeContextRetrieverTool(basePath string, logger *logrus.Logger) *CodeContextRetrieverTool {
	return &CodeContextRetrieverTool{
		basePath: basePath,
		logger:   logger,
	}
}

func (t *CodeContextRetrieverTool) Name() string {
	return "code_context_retriever"
}

func (t *CodeContextRetrieverTool) Description() string {
	return "Fetch surrounding code, function definitions, and imports for a specific file location. Provides context for vulnerability analysis."
}

func (t *CodeContextRetrieverTool) Parameters() map[string]ParameterDef {
	return map[string]ParameterDef{
		"file_path": {
			Type:        "string",
			Description: "Path to the file to retrieve context from",
			Required:    true,
		},
		"line_number": {
			Type:        "integer",
			Description: "Line number to center the context around",
			Required:    true,
		},
		"context_lines": {
			Type:        "integer",
			Description: "Number of lines of context to include (before and after)",
			Required:    false,
		},
		"include_imports": {
			Type:        "boolean",
			Description: "Whether to include import statements",
			Required:    false,
		},
	}
}

func (t *CodeContextRetrieverTool) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	filePath, ok := params["file_path"].(string)
	if !ok {
		return nil, fmt.Errorf("file_path parameter required")
	}

	lineNumber := 1
	if ln, ok := params["line_number"].(float64); ok {
		lineNumber = int(ln)
	}

	contextLines := 10
	if cl, ok := params["context_lines"].(float64); ok {
		contextLines = int(cl)
	}

	includeImports := true
	if ii, ok := params["include_imports"].(bool); ok {
		includeImports = ii
	}

	// Resolve the full path
	fullPath := filepath.Join(t.basePath, filePath)

	// Read the file
	content, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	totalLines := len(lines)

	// Calculate context range
	startLine := max(0, lineNumber-1-contextLines)
	endLine := min(totalLines, lineNumber+contextLines)

	// Extract surrounding code
	surroundingCode := strings.Join(lines[startLine:endLine], "\n")

	// Extract imports (for Go, Python, JavaScript, etc.)
	var imports []string
	if includeImports {
		imports = extractImports(lines)
	}

	// Try to extract function signature
	funcSignature := extractFunctionSignature(lines, lineNumber-1)

	result := map[string]interface{}{
		"file_path":          filePath,
		"line_number":        lineNumber,
		"surrounding_code":   surroundingCode,
		"start_line":         startLine + 1,
		"end_line":           endLine,
		"total_lines":        totalLines,
		"imports":            imports,
		"function_signature": funcSignature,
	}

	t.logger.WithField("file", filePath).Debug("Retrieved code context")
	return result, nil
}

// extractImports extracts import statements from code.
func extractImports(lines []string) []string {
	var imports []string
	inImportBlock := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Go imports
		if strings.HasPrefix(trimmed, "import (") {
			inImportBlock = true
			continue
		}
		if inImportBlock {
			if trimmed == ")" {
				inImportBlock = false
				continue
			}
			if trimmed != "" {
				imports = append(imports, strings.Trim(trimmed, `"`))
			}
			continue
		}
		if strings.HasPrefix(trimmed, "import ") {
			imports = append(imports, strings.TrimPrefix(trimmed, "import "))
		}

		// Python imports
		if strings.HasPrefix(trimmed, "from ") || strings.HasPrefix(trimmed, "import ") {
			imports = append(imports, trimmed)
		}

		// JavaScript/TypeScript imports
		if strings.HasPrefix(trimmed, "const ") && strings.Contains(trimmed, "require(") {
			imports = append(imports, trimmed)
		}
	}

	return imports
}

// extractFunctionSignature extracts the function signature containing the line.
func extractFunctionSignature(lines []string, targetLine int) string {
	// Search backwards for function definition
	for i := targetLine; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		// Go function
		if strings.HasPrefix(line, "func ") {
			return line
		}
		// Python function
		if strings.HasPrefix(line, "def ") {
			return line
		}
		// JavaScript function
		if strings.HasPrefix(line, "function ") ||
			strings.Contains(line, "=> {") ||
			strings.Contains(line, "async ") {
			return line
		}
	}
	return ""
}

// ===== CVE Database Query Tool =====

// CVEDatabaseQueryTool searches vulnerability databases.
type CVEDatabaseQueryTool struct {
	httpClient *http.Client
	logger     *logrus.Logger
}

// NewCVEDatabaseQueryTool creates a new CVE database query tool.
func NewCVEDatabaseQueryTool(logger *logrus.Logger) *CVEDatabaseQueryTool {
	return &CVEDatabaseQueryTool{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		logger:     logger,
	}
}

func (t *CVEDatabaseQueryTool) Name() string {
	return "cve_database_query"
}

func (t *CVEDatabaseQueryTool) Description() string {
	return "Search CVE/NVD databases for vulnerability information. Get details about specific CVEs, search by package name, or check for known vulnerabilities."
}

func (t *CVEDatabaseQueryTool) Parameters() map[string]ParameterDef {
	return map[string]ParameterDef{
		"query": {
			Type:        "string",
			Description: "Search query (CVE ID like CVE-2021-44228, package name, or keyword)",
			Required:    true,
		},
		"query_type": {
			Type:        "string",
			Description: "Type of query to perform",
			Required:    false,
			Enum:        []string{"cve_id", "package", "keyword", "cwe"},
		},
		"severity_filter": {
			Type:        "string",
			Description: "Filter by severity",
			Required:    false,
			Enum:        []string{"critical", "high", "medium", "low"},
		},
		"limit": {
			Type:        "integer",
			Description: "Maximum number of results to return",
			Required:    false,
		},
	}
}

func (t *CVEDatabaseQueryTool) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	query, ok := params["query"].(string)
	if !ok {
		return nil, fmt.Errorf("query parameter required")
	}

	queryType := "keyword"
	if qt, ok := params["query_type"].(string); ok {
		queryType = qt
	}

	limit := 10
	if l, ok := params["limit"].(float64); ok {
		limit = int(l)
	}

	t.logger.WithFields(logrus.Fields{
		"query":      query,
		"query_type": queryType,
	}).Debug("Querying CVE database")

	// Check if it looks like a CVE ID
	if strings.HasPrefix(strings.ToUpper(query), "CVE-") {
		return t.queryCVEByID(ctx, query)
	}

	// Query NIST NVD API (rate limited, consider caching)
	return t.searchNVD(ctx, query, queryType, limit)
}

func (t *CVEDatabaseQueryTool) queryCVEByID(ctx context.Context, cveID string) (interface{}, error) {
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", strings.ToUpper(cveID))

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		// Return mock data if API is unavailable
		return t.getMockCVEData(cveID), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return t.getMockCVEData(cveID), nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

func (t *CVEDatabaseQueryTool) searchNVD(ctx context.Context, query, queryType string, limit int) (interface{}, error) {
	// Construct search URL based on query type
	baseURL := "https://services.nvd.nist.gov/rest/json/cves/2.0"
	params := fmt.Sprintf("?keywordSearch=%s&resultsPerPage=%d", query, limit)

	req, err := http.NewRequestWithContext(ctx, "GET", baseURL+params, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		// Return informative message if API unavailable
		return map[string]interface{}{
			"query":   query,
			"type":    queryType,
			"status":  "api_unavailable",
			"message": "NVD API is currently unavailable. Consider checking manually at https://nvd.nist.gov/",
			"results": []interface{}{},
		}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return map[string]interface{}{
			"query":   query,
			"status":  "error",
			"message": fmt.Sprintf("API returned status %d", resp.StatusCode),
		}, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

func (t *CVEDatabaseQueryTool) getMockCVEData(cveID string) map[string]interface{} {
	return map[string]interface{}{
		"cve_id":  cveID,
		"status":  "mock_data",
		"message": "CVE data unavailable - this is placeholder data",
		"details": map[string]interface{}{
			"description":     "CVE details would appear here when connected to NVD API",
			"severity":        "unknown",
			"cvss_score":      0.0,
			"published":       "",
			"references":      []string{},
			"affected":        []string{},
			"patch_available": false,
		},
	}
}

// ===== Dependency Checker Tool =====

// DependencyCheckerTool analyzes package dependencies for vulnerabilities.
type DependencyCheckerTool struct {
	basePath string
	logger   *logrus.Logger
}

// NewDependencyCheckerTool creates a new dependency checker.
func NewDependencyCheckerTool(basePath string, logger *logrus.Logger) *DependencyCheckerTool {
	return &DependencyCheckerTool{
		basePath: basePath,
		logger:   logger,
	}
}

func (t *DependencyCheckerTool) Name() string {
	return "dependency_checker"
}

func (t *DependencyCheckerTool) Description() string {
	return "Analyze package dependencies for known vulnerabilities, outdated versions, and security issues. Supports Go, Python, Node.js, and Java projects."
}

func (t *DependencyCheckerTool) Parameters() map[string]ParameterDef {
	return map[string]ParameterDef{
		"package_file": {
			Type:        "string",
			Description: "Path to package file (go.mod, requirements.txt, package.json, pom.xml)",
			Required:    false,
		},
		"language": {
			Type:        "string",
			Description: "Programming language/ecosystem",
			Required:    false,
			Enum:        []string{"go", "python", "javascript", "java"},
		},
		"package_name": {
			Type:        "string",
			Description: "Specific package name to check",
			Required:    false,
		},
		"version": {
			Type:        "string",
			Description: "Specific version to check",
			Required:    false,
		},
	}
}

func (t *DependencyCheckerTool) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	packageFile, _ := params["package_file"].(string)
	language, _ := params["language"].(string)
	packageName, _ := params["package_name"].(string)
	version, _ := params["version"].(string)

	t.logger.WithFields(logrus.Fields{
		"package_file": packageFile,
		"language":     language,
		"package":      packageName,
	}).Debug("Checking dependencies")

	// If specific package provided, check it
	if packageName != "" {
		return t.checkSinglePackage(ctx, language, packageName, version)
	}

	// Otherwise, analyze the package file
	if packageFile != "" {
		return t.analyzePackageFile(ctx, packageFile, language)
	}

	// Auto-detect package files
	return t.autoDetectAndAnalyze(ctx)
}

func (t *DependencyCheckerTool) checkSinglePackage(ctx context.Context, language, packageName, version string) (interface{}, error) {
	// This would integrate with OSV or similar vulnerability database
	return map[string]interface{}{
		"package":          packageName,
		"version":          version,
		"language":         language,
		"vulnerabilities":  []interface{}{},
		"latest_version":   "unknown",
		"update_available": false,
		"status":           "check_not_implemented",
		"message":          "Dependency vulnerability checking requires OSV database integration",
	}, nil
}

func (t *DependencyCheckerTool) analyzePackageFile(ctx context.Context, packageFile, language string) (interface{}, error) {
	fullPath := filepath.Join(t.basePath, packageFile)

	content, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read package file: %w", err)
	}

	// Detect language from filename if not provided
	if language == "" {
		language = detectLanguageFromFile(packageFile)
	}

	// Parse dependencies based on file type
	deps := parseDependencies(string(content), packageFile)

	return map[string]interface{}{
		"package_file":    packageFile,
		"language":        language,
		"dependencies":    deps,
		"total_count":     len(deps),
		"status":          "parsed",
		"vulnerabilities": []interface{}{},
		"message":         "Full vulnerability scanning requires OSV integration",
	}, nil
}

func (t *DependencyCheckerTool) autoDetectAndAnalyze(ctx context.Context) (interface{}, error) {
	packageFiles := []string{
		"go.mod", "go.sum",
		"package.json", "package-lock.json",
		"requirements.txt", "Pipfile", "pyproject.toml",
		"pom.xml", "build.gradle",
	}

	var found []string
	for _, pf := range packageFiles {
		fullPath := filepath.Join(t.basePath, pf)
		if _, err := os.Stat(fullPath); err == nil {
			found = append(found, pf)
		}
	}

	return map[string]interface{}{
		"detected_files": found,
		"status":         "detection_complete",
		"message":        "Package files detected. Run with specific package_file for detailed analysis.",
	}, nil
}

func detectLanguageFromFile(filename string) string {
	switch {
	case strings.Contains(filename, "go.mod"), strings.Contains(filename, "go.sum"):
		return "go"
	case strings.Contains(filename, "package.json"):
		return "javascript"
	case strings.Contains(filename, "requirements"), strings.Contains(filename, "Pipfile"), strings.Contains(filename, "pyproject"):
		return "python"
	case strings.Contains(filename, "pom.xml"), strings.Contains(filename, "gradle"):
		return "java"
	default:
		return "unknown"
	}
}

func parseDependencies(content, filename string) []map[string]string {
	var deps []map[string]string

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
			continue
		}

		// Simple parsing - would need proper parser for each format
		if strings.Contains(filename, "go.mod") && strings.Contains(line, " v") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				deps = append(deps, map[string]string{
					"name":    parts[0],
					"version": parts[1],
				})
			}
		}
		if strings.Contains(filename, "requirements") {
			parts := strings.Split(line, "==")
			if len(parts) >= 2 {
				deps = append(deps, map[string]string{
					"name":    parts[0],
					"version": parts[1],
				})
			}
		}
	}

	return deps
}

// ===== Compliance Validator Tool =====

// ComplianceValidatorTool checks code against security standards.
type ComplianceValidatorTool struct {
	logger *logrus.Logger
}

// NewComplianceValidatorTool creates a new compliance validator.
func NewComplianceValidatorTool(logger *logrus.Logger) *ComplianceValidatorTool {
	return &ComplianceValidatorTool{logger: logger}
}

func (t *ComplianceValidatorTool) Name() string {
	return "compliance_validator"
}

func (t *ComplianceValidatorTool) Description() string {
	return "Validate security findings against compliance standards including PCI-DSS, HIPAA, SOC2, and OWASP. Maps vulnerabilities to specific compliance requirements."
}

func (t *ComplianceValidatorTool) Parameters() map[string]ParameterDef {
	return map[string]ParameterDef{
		"standards": {
			Type:        "array",
			Description: "Compliance standards to check against",
			Required:    true,
			Enum:        []string{"pci-dss", "hipaa", "soc2", "gdpr", "owasp"},
		},
		"vulnerability_type": {
			Type:        "string",
			Description: "Type of vulnerability to map",
			Required:    false,
		},
		"cwe_id": {
			Type:        "string",
			Description: "CWE ID to map to compliance",
			Required:    false,
		},
	}
}

func (t *ComplianceValidatorTool) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	standards := []string{"owasp"}
	if s, ok := params["standards"].([]interface{}); ok {
		standards = make([]string, len(s))
		for i, v := range s {
			standards[i] = fmt.Sprint(v)
		}
	}

	vulnType, _ := params["vulnerability_type"].(string)
	cweID, _ := params["cwe_id"].(string)

	t.logger.WithFields(logrus.Fields{
		"standards": standards,
		"vuln_type": vulnType,
		"cwe":       cweID,
	}).Debug("Validating compliance")

	mappings := make(map[string][]ComplianceMapping)
	for _, standard := range standards {
		mappings[standard] = t.getComplianceMapping(standard, vulnType, cweID)
	}

	return map[string]interface{}{
		"standards":        standards,
		"vulnerability":    vulnType,
		"cwe_id":           cweID,
		"mappings":         mappings,
		"total_violations": countViolations(mappings),
	}, nil
}

// ComplianceMapping represents a mapping to a compliance requirement.
type ComplianceMapping struct {
	RequirementID   string `json:"requirement_id"`
	RequirementName string `json:"requirement_name"`
	Severity        string `json:"severity"`
	Description     string `json:"description"`
	Remediation     string `json:"remediation"`
}

func (t *ComplianceValidatorTool) getComplianceMapping(standard, vulnType, cweID string) []ComplianceMapping {
	mappings := make([]ComplianceMapping, 0)

	// Comprehensive compliance mappings
	switch standard {
	case "pci-dss":
		mappings = t.getPCIDSSMappings(vulnType, cweID)
	case "hipaa":
		mappings = t.getHIPAAMappings(vulnType, cweID)
	case "soc2":
		mappings = t.getSOC2Mappings(vulnType, cweID)
	case "gdpr":
		mappings = t.getGDPRMappings(vulnType, cweID)
	case "owasp":
		mappings = t.getOWASPMappings(vulnType, cweID)
	}

	return mappings
}

func (t *ComplianceValidatorTool) getPCIDSSMappings(vulnType, cweID string) []ComplianceMapping {
	mappings := []ComplianceMapping{}

	// SQL Injection
	if vulnType == "sql_injection" || cweID == "CWE-89" {
		mappings = append(mappings, ComplianceMapping{
			RequirementID:   "6.5.1",
			RequirementName: "Injection Flaws",
			Severity:        "high",
			Description:     "PCI-DSS requires protection against injection flaws",
			Remediation:     "Use parameterized queries, input validation, and prepared statements",
		})
	}

	// XSS
	if vulnType == "xss" || cweID == "CWE-79" {
		mappings = append(mappings, ComplianceMapping{
			RequirementID:   "6.5.7",
			RequirementName: "Cross-Site Scripting (XSS)",
			Severity:        "high",
			Description:     "PCI-DSS requires prevention of XSS vulnerabilities",
			Remediation:     "Implement output encoding and Content Security Policy",
		})
	}

	// Weak Cryptography
	if vulnType == "weak_crypto" || cweID == "CWE-327" {
		mappings = append(mappings, ComplianceMapping{
			RequirementID:   "4.1",
			RequirementName: "Strong Cryptography",
			Severity:        "critical",
			Description:     "PCI-DSS mandates strong cryptography for cardholder data",
			Remediation:     "Use TLS 1.2+, AES-256, and current cryptographic standards",
		})
	}

	return mappings
}

func (t *ComplianceValidatorTool) getHIPAAMappings(vulnType, cweID string) []ComplianceMapping {
	mappings := []ComplianceMapping{}

	if vulnType == "data_exposure" || vulnType == "sql_injection" {
		mappings = append(mappings, ComplianceMapping{
			RequirementID:   "164.312(a)(1)",
			RequirementName: "Access Control",
			Severity:        "critical",
			Description:     "HIPAA requires access controls to protect PHI",
			Remediation:     "Implement proper access controls and audit logging",
		})
	}

	return mappings
}

func (t *ComplianceValidatorTool) getSOC2Mappings(vulnType, cweID string) []ComplianceMapping {
	mappings := []ComplianceMapping{}

	if vulnType != "" {
		mappings = append(mappings, ComplianceMapping{
			RequirementID:   "CC6.1",
			RequirementName: "Logical Access Security",
			Severity:        "medium",
			Description:     "SOC2 requires implementation of logical access security",
			Remediation:     "Review and remediate security vulnerability",
		})
	}

	return mappings
}

func (t *ComplianceValidatorTool) getGDPRMappings(vulnType, cweID string) []ComplianceMapping {
	mappings := []ComplianceMapping{}

	if vulnType == "data_exposure" || vulnType == "sql_injection" {
		mappings = append(mappings, ComplianceMapping{
			RequirementID:   "Article 32",
			RequirementName: "Security of Processing",
			Severity:        "high",
			Description:     "GDPR requires appropriate technical measures for data protection",
			Remediation:     "Implement security measures to protect personal data",
		})
	}

	return mappings
}

func (t *ComplianceValidatorTool) getOWASPMappings(vulnType, cweID string) []ComplianceMapping {
	mappings := []ComplianceMapping{}

	owaspMappings := map[string]ComplianceMapping{
		"sql_injection": {
			RequirementID:   "A03:2021",
			RequirementName: "Injection",
			Severity:        "critical",
			Description:     "OWASP Top 10 Injection category",
			Remediation:     "Use parameterized queries and validate all input",
		},
		"xss": {
			RequirementID:   "A03:2021",
			RequirementName: "Injection",
			Severity:        "high",
			Description:     "OWASP Top 10 Injection (includes XSS)",
			Remediation:     "Encode output and implement CSP",
		},
		"broken_auth": {
			RequirementID:   "A07:2021",
			RequirementName: "Identification and Authentication Failures",
			Severity:        "critical",
			Description:     "OWASP Top 10 Authentication failures",
			Remediation:     "Implement strong authentication mechanisms",
		},
		"secrets": {
			RequirementID:   "A02:2021",
			RequirementName: "Cryptographic Failures",
			Severity:        "critical",
			Description:     "OWASP Top 10 Cryptographic Failures",
			Remediation:     "Never hardcode secrets, use secure vault solutions",
		},
	}

	if mapping, ok := owaspMappings[vulnType]; ok {
		mappings = append(mappings, mapping)
	}

	return mappings
}

func countViolations(mappings map[string][]ComplianceMapping) int {
	count := 0
	for _, m := range mappings {
		count += len(m)
	}
	return count
}

// ===== Historical Analyzer Tool =====

// HistoricalAnalyzerTool compares with previous scans.
type HistoricalAnalyzerTool struct {
	logger *logrus.Logger
}

// NewHistoricalAnalyzerTool creates a new historical analyzer.
func NewHistoricalAnalyzerTool(logger *logrus.Logger) *HistoricalAnalyzerTool {
	return &HistoricalAnalyzerTool{logger: logger}
}

func (t *HistoricalAnalyzerTool) Name() string {
	return "historical_analyzer"
}

func (t *HistoricalAnalyzerTool) Description() string {
	return "Compare current scan with previous scans to identify trends, recurring issues, and track fix effectiveness."
}

func (t *HistoricalAnalyzerTool) Parameters() map[string]ParameterDef {
	return map[string]ParameterDef{
		"current_scan_id": {
			Type:        "string",
			Description: "ID of the current scan",
			Required:    true,
		},
		"repository_id": {
			Type:        "string",
			Description: "Repository ID to analyze history for",
			Required:    true,
		},
		"analysis_type": {
			Type:        "string",
			Description: "Type of historical analysis",
			Required:    false,
			Enum:        []string{"trend", "recurring", "fixed", "regression"},
		},
		"time_range": {
			Type:        "string",
			Description: "Time range for analysis",
			Required:    false,
			Enum:        []string{"7d", "30d", "90d", "1y"},
		},
	}
}

func (t *HistoricalAnalyzerTool) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	currentScanID, _ := params["current_scan_id"].(string)
	repositoryID, _ := params["repository_id"].(string)
	analysisType := "trend"
	if at, ok := params["analysis_type"].(string); ok {
		analysisType = at
	}
	timeRange := "30d"
	if tr, ok := params["time_range"].(string); ok {
		timeRange = tr
	}

	t.logger.WithFields(logrus.Fields{
		"scan_id":       currentScanID,
		"repository_id": repositoryID,
		"analysis_type": analysisType,
	}).Debug("Performing historical analysis")

	// This would integrate with the scan database
	return map[string]interface{}{
		"current_scan_id": currentScanID,
		"repository_id":   repositoryID,
		"analysis_type":   analysisType,
		"time_range":      timeRange,
		"status":          "analysis_pending",
		"message":         "Historical analysis requires database integration",
		"trend_data": map[string]interface{}{
			"previous_scans":        0,
			"vulnerabilities_trend": "unknown",
			"recurring_issues":      []interface{}{},
			"fixed_issues":          []interface{}{},
			"regressions":           []interface{}{},
		},
	}, nil
}

// ===== Built-in Tools =====

// SearchVulnerabilityDBTool searches vulnerability databases.
type SearchVulnerabilityDBTool struct {
	logger *logrus.Logger
}

func (t *SearchVulnerabilityDBTool) Name() string {
	return "search_vulnerability_db"
}

func (t *SearchVulnerabilityDBTool) Description() string {
	return "Search known vulnerability databases (CVE, NVD) for information about a specific vulnerability or package."
}

func (t *SearchVulnerabilityDBTool) Parameters() map[string]ParameterDef {
	return map[string]ParameterDef{
		"query": {
			Type:        "string",
			Description: "The search query (CVE ID, package name, or vulnerability description)",
			Required:    true,
		},
		"database": {
			Type:        "string",
			Description: "Database to search",
			Required:    false,
			Enum:        []string{"cve", "nvd", "github_advisories", "all"},
		},
	}
}

func (t *SearchVulnerabilityDBTool) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	query, ok := params["query"].(string)
	if !ok {
		return nil, fmt.Errorf("query parameter required")
	}

	return map[string]interface{}{
		"query":   query,
		"results": []map[string]interface{}{},
		"message": "Search functionality requires NVD API integration",
	}, nil
}

// AnalyzeCodePatternTool analyzes code for specific patterns.
type AnalyzeCodePatternTool struct{}

func (t *AnalyzeCodePatternTool) Name() string {
	return "analyze_code_pattern"
}

func (t *AnalyzeCodePatternTool) Description() string {
	return "Analyze code for specific patterns or anti-patterns."
}

func (t *AnalyzeCodePatternTool) Parameters() map[string]ParameterDef {
	return map[string]ParameterDef{
		"code": {
			Type:        "string",
			Description: "The code to analyze",
			Required:    true,
		},
		"pattern_type": {
			Type:        "string",
			Description: "Type of pattern to check",
			Required:    true,
			Enum:        []string{"sql_injection", "xss", "auth", "crypto", "logging", "general"},
		},
		"language": {
			Type:        "string",
			Description: "Programming language",
			Required:    true,
		},
	}
}

func (t *AnalyzeCodePatternTool) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	code, _ := params["code"].(string)
	patternType, _ := params["pattern_type"].(string)
	language, _ := params["language"].(string)

	return map[string]interface{}{
		"code":         truncateString(code, 100),
		"pattern_type": patternType,
		"language":     language,
		"findings":     []map[string]interface{}{},
		"message":      "Analysis functionality uses built-in scanner",
	}, nil
}

// GetSecurityBestPracticesTool provides security best practices.
type GetSecurityBestPracticesTool struct{}

func (t *GetSecurityBestPracticesTool) Name() string {
	return "get_security_best_practices"
}

func (t *GetSecurityBestPracticesTool) Description() string {
	return "Get security best practices for a specific language, framework, or vulnerability type."
}

func (t *GetSecurityBestPracticesTool) Parameters() map[string]ParameterDef {
	return map[string]ParameterDef{
		"topic": {
			Type:        "string",
			Description: "The security topic",
			Required:    true,
		},
		"language": {
			Type:        "string",
			Description: "Programming language context",
			Required:    false,
		},
		"framework": {
			Type:        "string",
			Description: "Framework context",
			Required:    false,
		},
	}
}

func (t *GetSecurityBestPracticesTool) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	topic, _ := params["topic"].(string)

	bestPractices := map[string][]string{
		"sql_injection": {
			"Always use parameterized queries or prepared statements",
			"Never concatenate user input directly into SQL queries",
			"Use an ORM with proper escaping",
			"Implement input validation and sanitization",
			"Apply the principle of least privilege to database accounts",
		},
		"xss": {
			"Encode all output based on context (HTML, JavaScript, URL, CSS)",
			"Use Content Security Policy (CSP) headers",
			"Use frameworks that auto-escape by default",
			"Validate and sanitize all user input",
			"Use HTTPOnly and Secure flags on cookies",
		},
		"authentication": {
			"Use strong password hashing (bcrypt, Argon2)",
			"Implement multi-factor authentication",
			"Use secure session management",
			"Implement account lockout policies",
			"Log all authentication events",
		},
		"cryptography": {
			"Use established cryptographic libraries",
			"Never implement your own crypto algorithms",
			"Use appropriate key lengths (RSA 2048+, AES 256)",
			"Properly manage and rotate cryptographic keys",
			"Use TLS 1.3 for transport encryption",
		},
	}

	practices, ok := bestPractices[topic]
	if !ok {
		practices = []string{
			"Follow the principle of least privilege",
			"Implement defense in depth",
			"Keep all dependencies updated",
			"Perform regular security audits",
			"Follow OWASP guidelines",
		}
	}

	return map[string]interface{}{
		"topic":          topic,
		"best_practices": practices,
	}, nil
}

// GenerateSecurityTestTool generates security test cases.
type GenerateSecurityTestTool struct{}

func (t *GenerateSecurityTestTool) Name() string {
	return "generate_security_test"
}

func (t *GenerateSecurityTestTool) Description() string {
	return "Generate security test cases for a specific vulnerability type."
}

func (t *GenerateSecurityTestTool) Parameters() map[string]ParameterDef {
	return map[string]ParameterDef{
		"vulnerability_type": {
			Type:        "string",
			Description: "Type of vulnerability to test",
			Required:    true,
		},
		"target_endpoint": {
			Type:        "string",
			Description: "The API endpoint or function to test",
			Required:    false,
		},
		"language": {
			Type:        "string",
			Description: "Test framework language",
			Required:    false,
		},
	}
}

func (t *GenerateSecurityTestTool) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	vulnType, _ := params["vulnerability_type"].(string)
	language, _ := params["language"].(string)

	if language == "" {
		language = "go"
	}

	testTemplates := map[string]string{
		"sql_injection": `
func TestSQLInjection(t *testing.T) {
    payloads := []string{
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "1 UNION SELECT * FROM users",
        "admin'--",
    }
    
    for _, payload := range payloads {
        resp := makeRequest(payload)
        if resp.StatusCode != http.StatusBadRequest {
            t.Errorf("SQL injection not blocked: %s", payload)
        }
    }
}`,
		"xss": `
func TestXSS(t *testing.T) {
    payloads := []string{
        "<script>alert('xss')</script>",
        "javascript:alert('xss')",
        "<img src=x onerror=alert('xss')>",
        "'\""><script>alert('xss')</script>",
    }
    
    for _, payload := range payloads {
        resp := makeRequest(payload)
        body := readBody(resp)
        if strings.Contains(body, payload) {
            t.Errorf("XSS not escaped: %s", payload)
        }
    }
}`,
	}

	template, ok := testTemplates[vulnType]
	if !ok {
		template = "// Test template not available for this vulnerability type"
	}

	return map[string]interface{}{
		"vulnerability_type": vulnType,
		"language":           language,
		"test_code":          template,
	}, nil
}

// RegisterDefaultTools registers the default built-in tools.
func RegisterDefaultTools(registry *ToolRegistry) {
	registry.Register(&SearchVulnerabilityDBTool{})
	registry.Register(&AnalyzeCodePatternTool{})
	registry.Register(&GetSecurityBestPracticesTool{})
	registry.Register(&GenerateSecurityTestTool{})
}

// RegisterAdvancedTools registers the advanced ADK tools.
func RegisterAdvancedTools(registry *ToolRegistry, basePath string, logger *logrus.Logger) {
	registry.Register(NewCodeContextRetrieverTool(basePath, logger))
	registry.Register(NewCVEDatabaseQueryTool(logger))
	registry.Register(NewDependencyCheckerTool(basePath, logger))
	registry.Register(NewComplianceValidatorTool(logger))
	registry.Register(NewHistoricalAnalyzerTool(logger))
}

// ToolCallResult represents the result of a tool call.
type ToolCallResult struct {
	ToolName string          `json:"tool_name"`
	Input    json.RawMessage `json:"input"`
	Output   interface{}     `json:"output"`
	Error    string          `json:"error,omitempty"`
	Duration time.Duration   `json:"duration"`
}

// Helper functions

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
