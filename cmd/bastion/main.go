// Package main provides the CLI entry point.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/BintangDiLangit/bastion/internal/config"
	"github.com/BintangDiLangit/bastion/internal/engagement"
	"github.com/BintangDiLangit/bastion/internal/models"
	"github.com/BintangDiLangit/bastion/internal/report"
	"github.com/BintangDiLangit/bastion/internal/scanner"
	"github.com/BintangDiLangit/bastion/internal/scanner/rules"
)

// gitHosts is the clone allowlist for the CLI's git targets. The API server
// keeps its own stricter, public-only validation.
var gitHosts = []string{"github.com", "gitlab.com", "bitbucket.org"}

// Build metadata. Overridden at link time with -X main.<name>=<value>; see the
// ldflags in the Makefile and .goreleaser.yaml.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"

	cfgFile string
	verbose bool
	output  string
	format  string
)

// init fills the build metadata from the Go module build info when no ldflags
// were supplied. `go install <module>/cmd/bastion@latest` links without them, so
// without this every go-installed binary would report itself as "dev".
func init() {
	if version != "dev" {
		return // ldflags won
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		version = info.Main.Version
	}
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			commit = setting.Value
		case "vcs.time":
			date = setting.Value
		}
	}
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "bastion",
		Short: "Bastion - local-first security review for developers and AI agents",
		Long: `Bastion scans source code with deterministic rules and produces stable
finding fingerprints, so a scan can be compared with its baseline.

It detects SQL injection, XSS, hardcoded secrets, vulnerable dependencies,
command injection, weak crypto, insecure deserialization, SSRF, path
traversal, insecure randomness, and disabled TLS verification.`,
		Version: version,
	}

	// Global flags
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file path")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "", "output file path")
	rootCmd.PersistentFlags().StringVarP(&format, "format", "f", "json", "output format (json, sarif, text)")

	rootCmd.PersistentFlags().StringSliceVar(&gitHosts, "git-host", gitHosts, "allowed git clone hosts (repeatable)")

	// Add commands
	rootCmd.AddCommand(scanCmd())
	rootCmd.AddCommand(reportCmd())
	rootCmd.AddCommand(rulesCmd())
	rootCmd.AddCommand(versionCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// scanCmd creates the scan command.
func scanCmd() *cobra.Command {
	var (
		excludePaths   []string
		enableRules    []string
		maxFiles       int
		timeout        int
		failOnCritical bool
	)

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a directory or repository for security vulnerabilities",
		Long: `Scan a local directory or Git repository for security vulnerabilities.

Examples:
  # Scan current directory
  bastion scan .

  # Scan a specific directory
  bastion scan /path/to/project

  # Scan with specific rules
  bastion scan . --rules sql_injection,xss,secrets

  # Output in SARIF format
  bastion scan . --format sarif --output results.sarif

  # Exclude paths
  bastion scan . --exclude vendor,node_modules`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}

			return runScan(path, scanOptions{
				excludePaths:   excludePaths,
				enableRules:    enableRules,
				maxFiles:       maxFiles,
				timeout:        time.Duration(timeout) * time.Minute,
				failOnCritical: failOnCritical,
			})
		},
	}

	cmd.Flags().BoolVar(&failOnCritical, "fail-on-critical", true, "fail execution if critical vulnerabilities are found")
	cmd.Flags().StringSliceVarP(&excludePaths, "exclude", "e", nil, "paths to exclude (comma-separated)")
	cmd.Flags().StringSliceVarP(&enableRules, "rules", "r", nil, "rules to enable (comma-separated)")
	cmd.Flags().IntVarP(&maxFiles, "max-files", "m", 1000, "maximum files to scan")
	cmd.Flags().IntVarP(&timeout, "timeout", "t", 30, "scan timeout in minutes")

	return cmd
}

// scanOptions holds scan configuration.
type scanOptions struct {
	excludePaths   []string
	enableRules    []string
	maxFiles       int
	timeout        time.Duration
	failOnCritical bool
}

// runScan executes a scan of a local path and prints findings.
func runScan(path string, opts scanOptions) error {
	log := newLogger()

	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("path does not exist: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory")
	}
	log.WithField("path", absPath).Info("Starting security scan")

	result, err := scanTarget(scanner.Target{Type: scanner.TargetSourceLocal, Path: absPath}, opts, log)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}
	return outputResults(result, log, opts)
}

// newLogger builds the CLI logger, honouring the --verbose flag.
func newLogger() *logrus.Logger {
	log := logrus.New()
	if verbose {
		log.SetLevel(logrus.DebugLevel)
	} else {
		log.SetLevel(logrus.InfoLevel)
	}
	log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	return log
}

// newManager builds a scan Manager with CLI-appropriate scanner and git config.
func newManager(opts scanOptions, log *logrus.Logger) *scanner.Manager {
	cfg := config.ScannerConfig{
		MaxFileSize:        1048576, // 1MB
		MaxFilesPerScan:    opts.maxFiles,
		Timeout:            opts.timeout,
		MaxConcurrent:      4,
		ExcludedPaths:      append(defaultExcludedPaths(), opts.excludePaths...),
		ExcludedExtensions: defaultExcludedExtensions(),
	}
	if len(opts.enableRules) > 0 {
		cfg.EnabledRules = opts.enableRules
	}
	gitCfg := config.GitConfig{
		TempDir:        filepath.Join(os.TempDir(), "bastion", "repos"),
		CloneTimeout:   5 * time.Minute,
		CloneDepth:     1,
		MaxRepoSize:    104857600, // 100MB
		SupportedHosts: gitHosts,
	}
	return scanner.NewManager(cfg, gitCfg, log)
}

// scanTarget runs a scan against any target type and returns the result.
func scanTarget(target scanner.Target, opts scanOptions, log *logrus.Logger) (*scanner.ScanResult, error) {
	mgr := newManager(opts, log)
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()
	return mgr.ScanTarget(ctx, uuid.New(), target, scanner.ScanOptions{
		EnabledRules:  opts.enableRules,
		ExcludedPaths: opts.excludePaths,
		MaxFiles:      opts.maxFiles,
		Timeout:       opts.timeout,
		Branch:        target.Branch,
	})
}

// sourceToTarget maps an engagement source (local dir or git repo) to a scan
// target, resolving a private-repo token from the environment when configured.
func sourceToTarget(src engagement.Source) (scanner.Target, error) {
	if err := src.Validate(); err != nil {
		return scanner.Target{}, err
	}
	switch src.Type {
	case "local":
		abs, err := filepath.Abs(src.Path)
		if err != nil {
			return scanner.Target{}, fmt.Errorf("invalid source path: %w", err)
		}
		return scanner.Target{Type: scanner.TargetSourceLocal, Path: abs}, nil
	case "git":
		t := scanner.Target{Type: scanner.TargetSourceGit, URL: src.URL, Branch: src.Branch}
		envName := src.TokenEnv
		if envName == "" {
			envName = "BASTION_GIT_TOKEN"
		}
		if tok := os.Getenv(envName); tok != "" {
			t.Auth = scanner.TokenAuth(tok)
		}
		return t, nil
	default:
		return scanner.Target{}, fmt.Errorf("unknown source type %q", src.Type)
	}
}

func scopeOf(target scanner.Target) string {
	switch target.Type {
	case scanner.TargetSourceLocal:
		return "local: " + target.Path
	case scanner.TargetSourceGit:
		if target.Branch != "" {
			return "git: " + target.URL + "@" + target.Branch
		}
		return "git: " + target.URL
	default:
		return string(target.Type)
	}
}

// reportCmd creates the report command.
func reportCmd() *cobra.Command {
	var (
		project      string
		configPath   string
		reportFormat string
		excludePaths []string
		enableRules  []string
		maxFiles     int
		timeout      int
	)

	cmd := &cobra.Command{
		Use:   "report --project NAME",
		Short: "Scan a configured project and produce a professional pentest report",
		Long: `Scan an application configured in bastion.yaml and generate a client-grade
security assessment report (HTML, Markdown, and/or PDF).

Examples:
  # HTML report for the 'avora' project
  bastion report --project avora -o avora-report

  # All formats (PDF needs a system Chrome/Chromium/Edge)
  bastion report --project airapay --report-format all -o airapay-report`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReport(project, configPath, reportFormat, scanOptions{
				excludePaths: excludePaths,
				enableRules:  enableRules,
				maxFiles:     maxFiles,
				timeout:      time.Duration(timeout) * time.Minute,
			})
		},
	}

	cmd.Flags().StringVar(&project, "project", "", "project name from the engagement config (required)")
	cmd.Flags().StringVar(&configPath, "config-file", "bastion.yaml", "engagement config file")
	cmd.Flags().StringVar(&reportFormat, "report-format", "html", "report format (html, md, pdf, all)")
	cmd.Flags().StringSliceVarP(&excludePaths, "exclude", "e", nil, "paths to exclude (comma-separated)")
	cmd.Flags().StringSliceVarP(&enableRules, "rules", "r", nil, "rules to enable (comma-separated)")
	cmd.Flags().IntVarP(&maxFiles, "max-files", "m", 1000, "maximum files to scan")
	cmd.Flags().IntVarP(&timeout, "timeout", "t", 30, "scan timeout in minutes")
	_ = cmd.MarkFlagRequired("project")

	return cmd
}

// runReport scans a configured project and writes the requested report formats.
func runReport(projectName, configPath, formatArg string, opts scanOptions) error {
	log := newLogger()

	base := output
	if strings.TrimSpace(base) == "" {
		base = "report-" + projectName
	}

	formats, err := reportFormats(formatArg)
	if err != nil {
		return err
	}

	eng, err := engagement.Load(configPath)
	if err != nil {
		return err
	}
	proj, err := eng.Project(projectName)
	if err != nil {
		return err
	}
	target, err := sourceToTarget(proj.Source)
	if err != nil {
		return err
	}

	log.WithField("project", proj.Name).Info("Starting assessment")
	result, err := scanTarget(target, opts, log)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	logoURI, err := logoDataURI(eng.Assessor.Logo)
	if err != nil {
		return fmt.Errorf("logo: %w", err)
	}

	in := report.Input{
		Assessor:    eng.Assessor,
		Project:     *proj,
		Result:      result,
		Scope:       scopeOf(target),
		ToolName:    "Bastion",
		ToolVersion: version,
		GeneratedAt: time.Now(),
		LogoDataURI: logoURI,
		BrandColor:  eng.Assessor.BrandColor,
	}

	ctx := context.Background()
	for _, f := range formats {
		var buf bytes.Buffer
		if err := report.Render(ctx, &buf, in, f); err != nil {
			if f == report.FormatPDF && errors.Is(err, report.ErrNoBrowser) {
				log.Warn("PDF skipped: no Chrome/Chromium/Edge found; other formats still written")
				continue
			}
			return fmt.Errorf("render %s: %w", f, err)
		}
		path := base + "." + f
		if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		log.WithField("file", path).Info("Report written")
	}
	return nil
}

// logoDataURI reads an assessor logo file and encodes it as a self-contained
// data: URI. Empty path -> empty URI (default Bastion mark is used).
func logoDataURI(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	const maxLogo = 2 << 20 // 2MB keeps the report from bloating
	if len(data) > maxLogo {
		return "", fmt.Errorf("logo too large (%d bytes, max %d)", len(data), maxLogo)
	}
	var mime string
	switch strings.ToLower(filepath.Ext(path)) {
	case ".png":
		mime = "image/png"
	case ".jpg", ".jpeg":
		mime = "image/jpeg"
	case ".svg":
		mime = "image/svg+xml"
	case ".gif":
		mime = "image/gif"
	case ".webp":
		mime = "image/webp"
	default:
		return "", fmt.Errorf("unsupported logo type %q (want png/jpg/svg/gif/webp)", filepath.Ext(path))
	}
	return "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(data), nil
}

// reportFormats expands the --report-format value into concrete formats.
func reportFormats(arg string) ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(arg)) {
	case "", "html":
		return []string{report.FormatHTML}, nil
	case "md", "markdown":
		return []string{report.FormatMarkdown}, nil
	case "pdf":
		return []string{report.FormatPDF}, nil
	case "all":
		return report.Formats, nil
	default:
		return nil, fmt.Errorf("unknown report format %q (want html|md|pdf|all)", arg)
	}
}

// outputResults outputs the scan results.
func outputResults(result *scanner.ScanResult, log *logrus.Logger, opts scanOptions) error {
	// Build output
	scanOut := ScanOutput{
		ScanID:       uuid.New().String(),
		Timestamp:    time.Now().UTC(),
		Duration:     result.Duration.String(),
		FilesScanned: result.FilesScanned,
		LinesScanned: result.LinesScanned,
		Summary:      buildSummary(result),
		Metrics:      result.Metrics,
		// Initialized, not nil: a clean scan must emit [] rather than null, or
		// every consumer that iterates the field breaks on the good case.
		Vulnerabilities: []VulnOutput{},
	}

	for _, v := range result.Vulnerabilities {
		scanOut.Vulnerabilities = append(scanOut.Vulnerabilities, VulnOutput{
			RuleID:      v.RuleID,
			Fingerprint: v.Fingerprint,
			Title:       v.Title,
			Description: v.Description,
			Severity:    string(v.Severity),
			Category:    string(v.Category),
			FilePath:    v.FilePath,
			LineStart:   v.LineStart,
			LineEnd:     v.LineEnd,
			CodeSnippet: v.CodeSnippet,
			Remediation: v.Remediation,
			Confidence:  v.Confidence,
			CWE:         v.References.CWE,
			OWASP:       v.References.OWASP,
			CVSSScore:   v.CVSSScore,
			CVSSVector:  v.CVSSVector,
		})
	}

	// Format output
	var data []byte
	var err error

	switch format {
	case "json":
		data, err = json.MarshalIndent(scanOut, "", "  ")
	case "sarif":
		data, err = toSARIF(scanOut)
	case "text":
		data = toText(scanOut)
	default:
		data, err = json.MarshalIndent(scanOut, "", "  ")
	}

	if err != nil {
		return fmt.Errorf("failed to format output: %w", err)
	}

	// Write output
	if output != "" {
		// Write to file
		if err := os.WriteFile(output, data, 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
	}

	// Print to stdout
	fmt.Println(string(data))

	// Print summary
	printSummary(scanOut.Summary, log)

	if shouldFail(scanOut.Summary, opts.failOnCritical) {
		os.Exit(1)
	}

	return nil
}

// shouldFail reports whether the scan should exit non-zero.
//
// Critical only. The flag is named --fail-on-critical and the docs promise
// exactly that; blocking on high as well made CI red on regex-only findings
// and pushed people to --fail-on-critical=false, which disables the gate
// entirely.
func shouldFail(summary ScanSummary, failOnCritical bool) bool {
	return failOnCritical && summary.Critical > 0
}

// ScanOutput represents CLI scan output.
type ScanOutput struct {
	ScanID          string              `json:"scan_id"`
	Timestamp       time.Time           `json:"timestamp"`
	Duration        string              `json:"duration"`
	FilesScanned    int                 `json:"files_scanned"`
	LinesScanned    int                 `json:"lines_scanned"`
	Summary         ScanSummary         `json:"summary"`
	Metrics         scanner.CodeMetrics `json:"metrics"`
	Vulnerabilities []VulnOutput        `json:"vulnerabilities"`
}

// ScanSummary represents scan summary.
type ScanSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// VulnOutput represents vulnerability output.
type VulnOutput struct {
	RuleID      string   `json:"rule_id"`
	Fingerprint string   `json:"fingerprint"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	FilePath    string   `json:"file_path"`
	LineStart   int      `json:"line_start"`
	LineEnd     int      `json:"line_end"`
	CodeSnippet string   `json:"code_snippet,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Confidence  float64  `json:"confidence"`
	CWE         []string `json:"cwe,omitempty"`
	OWASP       []string `json:"owasp,omitempty"`
	CVSSScore   float64  `json:"cvss_score,omitempty"`
	CVSSVector  string   `json:"cvss_vector,omitempty"`
}

// buildSummary builds the scan summary.
func buildSummary(result *scanner.ScanResult) ScanSummary {
	summary := ScanSummary{
		Total: len(result.Vulnerabilities),
	}

	for _, v := range result.Vulnerabilities {
		switch v.Severity {
		case models.SeverityCritical:
			summary.Critical++
		case models.SeverityHigh:
			summary.High++
		case models.SeverityMedium:
			summary.Medium++
		case models.SeverityLow:
			summary.Low++
		case models.SeverityInfo:
			summary.Info++
		}
	}

	return summary
}

// printSummary prints a summary to the console.
func printSummary(summary ScanSummary, log *logrus.Logger) {
	fmt.Println("\n" + "═══════════════════════════════════════════")
	fmt.Println("                SCAN SUMMARY")
	fmt.Println("═══════════════════════════════════════════")
	fmt.Printf("  Total Issues:  %d\n", summary.Total)
	fmt.Printf("  🔴 Critical:   %d\n", summary.Critical)
	fmt.Printf("  🟠 High:       %d\n", summary.High)
	fmt.Printf("  🟡 Medium:     %d\n", summary.Medium)
	fmt.Printf("  🟢 Low:        %d\n", summary.Low)
	fmt.Printf("  🔵 Info:       %d\n", summary.Info)
	fmt.Println("═══════════════════════════════════════════")

	if summary.Critical > 0 {
		fmt.Println("⚠️  Critical severity issues found!")
	} else if summary.High > 0 {
		fmt.Println("⚠️  High severity issues found (does not fail the command).")
	} else if summary.Total == 0 {
		fmt.Println("✅ No vulnerabilities found!")
	}
}

// toSARIF converts output to SARIF format.
func toSARIF(output ScanOutput) ([]byte, error) {
	sarif := map[string]interface{}{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":    "Bastion",
						"version": version,
					},
				},
				"results": buildSARIFResults(output.Vulnerabilities),
			},
		},
	}

	return json.MarshalIndent(sarif, "", "  ")
}

// buildSARIFResults builds SARIF results.
//
// The slice is initialized rather than declared: a nil slice marshals to
// "results": null, which upload-sarif rejects. A clean scan is the common case.
func buildSARIFResults(vulns []VulnOutput) []map[string]interface{} {
	results := []map[string]interface{}{}

	for _, v := range vulns {
		level := "warning"
		switch v.Severity {
		case "critical", "high":
			level = "error"
		case "low", "info":
			level = "note"
		}

		// SARIF requires startLine >= 1. endLine is optional, and emitting the
		// zero value produced endLine < startLine, which is schema-invalid.
		startLine := v.LineStart
		if startLine < 1 {
			startLine = 1
		}
		region := map[string]int{"startLine": startLine}
		if v.LineEnd >= startLine {
			region["endLine"] = v.LineEnd
		}

		results = append(results, map[string]interface{}{
			"ruleId": v.RuleID,
			"level":  level,
			"partialFingerprints": map[string]string{
				"bastion/v1": v.Fingerprint,
			},
			"message": map[string]string{
				"text": v.Description,
			},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]string{
							"uri": v.FilePath,
						},
						"region": region,
					},
				},
			},
		})
	}

	return results
}

// toText converts output to text format.
func toText(output ScanOutput) []byte {
	var text string

	text += fmt.Sprintf("Security Scan Results\n")
	text += fmt.Sprintf("=====================\n\n")
	text += fmt.Sprintf("Files Scanned: %d\n", output.FilesScanned)
	text += fmt.Sprintf("Lines Scanned: %d\n", output.LinesScanned)
	text += fmt.Sprintf("Duration: %s\n\n", output.Duration)

	text += fmt.Sprintf("Summary:\n")
	text += fmt.Sprintf("  Total: %d\n", output.Summary.Total)
	text += fmt.Sprintf("  Critical: %d\n", output.Summary.Critical)
	text += fmt.Sprintf("  High: %d\n", output.Summary.High)
	text += fmt.Sprintf("  Medium: %d\n", output.Summary.Medium)
	text += fmt.Sprintf("  Low: %d\n\n", output.Summary.Low)

	if len(output.Vulnerabilities) > 0 {
		text += fmt.Sprintf("Vulnerabilities:\n")
		text += fmt.Sprintf("----------------\n\n")

		for i, v := range output.Vulnerabilities {
			text += fmt.Sprintf("%d. [%s] %s\n", i+1, v.Severity, v.Title)
			text += fmt.Sprintf("   File: %s:%d\n", v.FilePath, v.LineStart)
			text += fmt.Sprintf("   %s\n\n", v.Description)
		}
	}

	return []byte(text)
}

// rulesCmd creates the rules command.
func rulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "List available security rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			log := logrus.New()
			log.SetLevel(logrus.WarnLevel)

			engine := rules.NewEngine(config.ScannerConfig{}, log)
			engine.Register(rules.NewSQLInjectionRule())
			engine.Register(rules.NewXSSRule())
			engine.Register(rules.NewSecretsRule())
			engine.Register(rules.NewDependencyRule())

			fmt.Println("Available Security Rules:")
			fmt.Println("=========================")
			fmt.Println()
			fmt.Println("Any ID below works with --rules and in a bastion:ignore comment.")
			fmt.Println("A category selects every rule in it.")
			fmt.Println()

			for _, rule := range engine.ListRules() {
				info := rules.GetRuleInfo(rule)
				fmt.Printf("ID:        %s\n", info.ID)
				fmt.Printf("Name:      %s\n", info.Name)
				fmt.Printf("Severity:  %s\n", info.Severity)
				fmt.Printf("Category:  %s\n", info.Category)
				if len(info.Languages) > 0 {
					fmt.Printf("Languages: %v\n", info.Languages)
				} else {
					fmt.Printf("Languages: All\n")
				}
				fmt.Println()
			}

			for _, pattern := range engine.ListPatterns() {
				fmt.Printf("ID:        %s\n", pattern.ID)
				fmt.Printf("Name:      %s\n", pattern.Title)
				fmt.Printf("Severity:  %s\n", pattern.Severity)
				fmt.Printf("Category:  %s\n", pattern.Category)
				if len(pattern.Languages) > 0 {
					fmt.Printf("Languages: %v\n", pattern.Languages)
				} else {
					fmt.Printf("Languages: All\n")
				}
				fmt.Println()
			}

			return nil
		},
	}

	return cmd
}

// versionCmd creates the version command.
func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Bastion %s\n", version)
			fmt.Printf("  commit:   %s\n", commit)
			fmt.Printf("  built:    %s\n", date)
			fmt.Printf("  built by: %s\n", builtBy)
			fmt.Printf("  go:       %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
		},
	}
}

// defaultExcludedPaths returns default excluded paths.
func defaultExcludedPaths() []string {
	return []string{
		"vendor/",
		"node_modules/",
		".git/",
		"__pycache__/",
		".idea/",
		".vscode/",
		"dist/",
		"build/",
		".cache/",
	}
}

// defaultExcludedExtensions returns default excluded extensions.
func defaultExcludedExtensions() []string {
	return []string{
		".min.js",
		".min.css",
		".lock",
		".sum",
		".map",
	}
}
