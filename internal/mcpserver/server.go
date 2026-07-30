package mcpserver

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sirupsen/logrus"

	"code-security-auditor/internal/config"
	"code-security-auditor/internal/models"
	"code-security-auditor/internal/scanner"
)

const maxFindings = 200

type ScanInput struct {
	Path                 string   `json:"path,omitempty" jsonschema:"relative directory within configured project root; defaults to ."`
	Rules                []string `json:"rules,omitempty" jsonschema:"optional rule IDs to enable"`
	MaxFiles             int      `json:"max_files,omitempty" jsonschema:"maximum files to scan,1,10000"`
	BaselineFingerprints []string `json:"baseline_fingerprints,omitempty" jsonschema:"fingerprints from a previous scan; enables new and resolved finding comparison"`
}

type ScanSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type ScanOutput struct {
	Path          string                 `json:"path"`
	FilesScanned  int                    `json:"files_scanned"`
	LinesScanned  int                    `json:"lines_scanned"`
	DurationMS    int64                  `json:"duration_ms"`
	TotalFindings int                    `json:"total_findings"`
	Truncated     bool                   `json:"truncated"`
	Summary       ScanSummary            `json:"summary"`
	Findings      []models.Vulnerability `json:"findings"`
	Delta         *FingerprintDelta      `json:"delta,omitempty"`
}

type FingerprintDelta struct {
	New                  []models.Vulnerability `json:"new"`
	ResolvedFingerprints []string               `json:"resolved_fingerprints"`
	Unchanged            int                    `json:"unchanged"`
}

type Service struct {
	root    string
	logger  *logrus.Logger
	manager *scanner.Manager
}

func New(root string, logger *logrus.Logger) (*Service, error) {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve root: %w", err)
	}
	resolvedRoot, err = filepath.Abs(resolvedRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve root: %w", err)
	}

	scannerConfig := config.ScannerConfig{
		MaxConcurrent:      4,
		Timeout:            10 * time.Minute,
		MaxFileSize:        1024 * 1024,
		MaxFilesPerScan:    10000,
		ExcludedPaths:      []string{".git", "node_modules", "vendor", "dist", "build"},
		ExcludedExtensions: []string{".min.js", ".min.css", ".map"},
	}
	gitConfig := config.GitConfig{TempDir: os.TempDir(), CloneTimeout: time.Minute}

	return &Service{
		root:    resolvedRoot,
		logger:  logger,
		manager: scanner.NewManager(scannerConfig, gitConfig, logger),
	}, nil
}

func (s *Service) Server() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "bastion",
		Version: "1.0.0",
	}, nil)

	closedWorld := false
	mcp.AddTool(server, &mcp.Tool{
		Name:        "bastion_scan",
		Title:       "Scan local code with Bastion",
		Description: "Read-only static security scan of code inside the configured project root.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:  true,
			OpenWorldHint: &closedWorld,
		},
	}, s.Scan)
	return server
}

func (s *Service) Scan(ctx context.Context, _ *mcp.CallToolRequest, input ScanInput) (*mcp.CallToolResult, ScanOutput, error) {
	path, prefix, err := s.resolveDirectory(input.Path)
	if err != nil {
		return nil, ScanOutput{}, err
	}
	if input.MaxFiles == 0 {
		input.MaxFiles = 1000
	}
	if input.MaxFiles < 1 || input.MaxFiles > 10000 {
		return nil, ScanOutput{}, fmt.Errorf("max_files must be between 1 and 10000")
	}
	if len(input.BaselineFingerprints) > 10000 {
		return nil, ScanOutput{}, fmt.Errorf("baseline_fingerprints cannot exceed 10000 entries")
	}
	for _, fingerprint := range input.BaselineFingerprints {
		if !fingerprintPattern.MatchString(fingerprint) {
			return nil, ScanOutput{}, fmt.Errorf("invalid baseline fingerprint")
		}
	}

	result, err := s.manager.ScanPath(ctx, uuid.New(), path, scanner.ScanOptions{
		EnabledRules: input.Rules,
		MaxFiles:     input.MaxFiles,
		PathPrefix:   prefix,
	})
	if err != nil {
		return nil, ScanOutput{}, err
	}

	output := ScanOutput{
		Path:          path,
		FilesScanned:  result.FilesScanned,
		LinesScanned:  result.LinesScanned,
		DurationMS:    result.Duration.Milliseconds(),
		TotalFindings: len(result.Vulnerabilities),
		Findings:      result.Vulnerabilities,
	}
	for _, finding := range result.Vulnerabilities {
		switch finding.Severity {
		case models.SeverityCritical:
			output.Summary.Critical++
		case models.SeverityHigh:
			output.Summary.High++
		case models.SeverityMedium:
			output.Summary.Medium++
		case models.SeverityLow:
			output.Summary.Low++
		case models.SeverityInfo:
			output.Summary.Info++
		}
	}
	if input.BaselineFingerprints != nil {
		output.Delta = compareFingerprints(result.Vulnerabilities, input.BaselineFingerprints)
		if len(output.Delta.New) > maxFindings {
			output.Delta.New = output.Delta.New[:maxFindings]
		}
	}
	if len(output.Findings) > maxFindings {
		output.Findings = output.Findings[:maxFindings]
		output.Truncated = true
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(
			"Bastion scanned %d files; found %d issues (%d critical, %d high).",
			output.FilesScanned, output.TotalFindings, output.Summary.Critical, output.Summary.High,
		)}},
	}, output, nil
}

var fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func compareFingerprints(findings []models.Vulnerability, baseline []string) *FingerprintDelta {
	baselineSet := make(map[string]bool, len(baseline))
	for _, fingerprint := range baseline {
		baselineSet[fingerprint] = true
	}
	currentSet := make(map[string]bool, len(findings))
	delta := &FingerprintDelta{
		New:                  make([]models.Vulnerability, 0),
		ResolvedFingerprints: make([]string, 0),
	}
	for _, finding := range findings {
		currentSet[finding.Fingerprint] = true
		if baselineSet[finding.Fingerprint] {
			delta.Unchanged++
		} else {
			delta.New = append(delta.New, finding)
		}
	}
	for fingerprint := range baselineSet {
		if !currentSet[fingerprint] {
			delta.ResolvedFingerprints = append(delta.ResolvedFingerprints, fingerprint)
		}
	}
	sort.Slice(delta.New, func(i, j int) bool {
		return delta.New[i].Fingerprint < delta.New[j].Fingerprint
	})
	sort.Strings(delta.ResolvedFingerprints)
	return delta
}

// resolveDirectory returns the absolute directory to scan and its path relative
// to the configured root. The relative form becomes the reported path prefix so
// that a subdirectory scan and a full-tree scan produce the same fingerprints
// for the same finding.
func (s *Service) resolveDirectory(requested string) (string, string, error) {
	if requested == "" {
		requested = "."
	}
	if filepath.IsAbs(requested) {
		return "", "", fmt.Errorf("path must be relative to configured root")
	}

	candidate, err := filepath.EvalSymlinks(filepath.Join(s.root, requested))
	if err != nil {
		return "", "", fmt.Errorf("resolve scan path: %w", err)
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return "", "", fmt.Errorf("resolve scan path: %w", err)
	}
	relative, err := filepath.Rel(s.root, candidate)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("path escapes configured root")
	}
	info, err := os.Stat(candidate)
	if err != nil {
		return "", "", fmt.Errorf("inspect scan path: %w", err)
	}
	if !info.IsDir() {
		return "", "", fmt.Errorf("path must be a directory")
	}
	if relative == "." {
		relative = ""
	}
	return candidate, filepath.ToSlash(relative), nil
}
