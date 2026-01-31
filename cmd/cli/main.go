// Package main provides the CLI entry point.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"code-security-auditor/internal/config"
	"code-security-auditor/internal/models"
	"code-security-auditor/internal/scanner"
	"code-security-auditor/internal/scanner/rules"
)

var (
	version = "1.0.0"
	cfgFile string
	verbose bool
	output  string
	format  string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "bastion",
		Short: "🏰 Bastion - Your Code's Last Line of Defense",
		Long: `🏰 BASTION - Your Code's Last Line of Defense
Dependency Security Scanner v` + version + `

Bastion is a powerful tool for automated security scanning and 
vulnerability detection in code repositories and dependencies.

It can detect various security issues including SQL injection, XSS,
hardcoded secrets, vulnerable dependencies, and more.`,
		Version: version,
	}

	// Global flags
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file path")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "", "output file path")
	rootCmd.PersistentFlags().StringVarP(&format, "format", "f", "json", "output format (json, sarif, text)")

	// Add commands
	rootCmd.AddCommand(scanCmd())
	rootCmd.AddCommand(rulesCmd())
	rootCmd.AddCommand(versionCmd())
	rootCmd.AddCommand(dependencyCmd())
	rootCmd.AddCommand(sbomCmd())
	rootCmd.AddCommand(licenseCmd())

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
		apiKey         string
		scanType       string
	)

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a directory or repository for security vulnerabilities",
		Long: `Scan a local directory or Git repository for security vulnerabilities.

Examples:
  # Scan current directory
  csa scan .

  # Scan a specific directory
  csa scan /path/to/project

  # Scan with specific rules
  csa scan . --rules sql_injection,xss,secrets

  # Output in SARIF format
  csa scan . --format sarif --output results.sarif

  # Exclude paths
  csa scan . --exclude vendor,node_modules`,
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
				apiKey:         apiKey,
				scanType:       scanType,
			})
		},
	}

	cmd.Flags().BoolVar(&failOnCritical, "fail-on-critical", true, "fail execution if critical vulnerabilities are found")
	cmd.Flags().StringVar(&apiKey, "api-key", "", "API key for reporting")
	cmd.Flags().StringVar(&scanType, "scan-type", "full", "scan type (full, quick)")
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
	apiKey         string
	scanType       string
}

// runScan executes the scan.
func runScan(path string, opts scanOptions) error {
	// Setup logger
	log := logrus.New()
	if verbose {
		log.SetLevel(logrus.DebugLevel)
	} else {
		log.SetLevel(logrus.InfoLevel)
	}
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	// Resolve path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	// Check path exists
	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("path does not exist: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory")
	}

	log.WithField("path", absPath).Info("Starting security scan")

	// Load config
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
		TempDir:      os.TempDir(),
		CloneTimeout: 5 * time.Minute,
	}

	// Initialize scanner
	mgr := scanner.NewManager(cfg, gitCfg, log)

	// Create scan ID
	scanID := uuid.New()

	// Run scan
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()

	result, err := mgr.ScanPath(ctx, scanID, absPath, scanner.ScanOptions{
		EnabledRules:  opts.enableRules,
		ExcludedPaths: opts.excludePaths,
		MaxFiles:      opts.maxFiles,
		Timeout:       opts.timeout,
		Branch:        "main", // Default branch for local scan if needed, though ScanPath handles local
	})
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Output results
	return outputResults(result, log, opts)
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
	}

	for _, v := range result.Vulnerabilities {
		scanOut.Vulnerabilities = append(scanOut.Vulnerabilities, VulnOutput{
			RuleID:      v.RuleID,
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

	// Exit with error code if vulnerabilities found
	// Exit with error code if vulnerabilities found and fail-on-critical is set
	if opts.failOnCritical && (scanOut.Summary.Critical > 0 || scanOut.Summary.High > 0) {
		os.Exit(1)
	}

	return nil
}

// ScanOutput represents CLI scan output.
type ScanOutput struct {
	ScanID          string       `json:"scan_id"`
	Timestamp       time.Time    `json:"timestamp"`
	Duration        string       `json:"duration"`
	FilesScanned    int          `json:"files_scanned"`
	LinesScanned    int          `json:"lines_scanned"`
	Summary         ScanSummary  `json:"summary"`
	Vulnerabilities []VulnOutput `json:"vulnerabilities"`
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
	RuleID      string  `json:"rule_id"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	Category    string  `json:"category"`
	FilePath    string  `json:"file_path"`
	LineStart   int     `json:"line_start"`
	LineEnd     int     `json:"line_end"`
	CodeSnippet string  `json:"code_snippet,omitempty"`
	Remediation string  `json:"remediation,omitempty"`
	Confidence  float64 `json:"confidence"`
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

	if summary.Critical > 0 || summary.High > 0 {
		fmt.Println("⚠️  Critical or high severity issues found!")
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
						"name":    "Code Security Auditor",
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
func buildSARIFResults(vulns []VulnOutput) []map[string]interface{} {
	var results []map[string]interface{}

	for _, v := range vulns {
		level := "warning"
		switch v.Severity {
		case "critical", "high":
			level = "error"
		case "low", "info":
			level = "note"
		}

		results = append(results, map[string]interface{}{
			"ruleId": v.RuleID,
			"level":  level,
			"message": map[string]string{
				"text": v.Description,
			},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]string{
							"uri": v.FilePath,
						},
						"region": map[string]int{
							"startLine": v.LineStart,
							"endLine":   v.LineEnd,
						},
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
			fmt.Println("=========================\n")

			for _, rule := range engine.ListRules() {
				info := rules.GetRuleInfo(rule)
				fmt.Printf("ID:       %s\n", info.ID)
				fmt.Printf("Name:     %s\n", info.Name)
				fmt.Printf("Severity: %s\n", info.Severity)
				fmt.Printf("Category: %s\n", info.Category)
				if len(info.Languages) > 0 {
					fmt.Printf("Languages: %v\n", info.Languages)
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
			fmt.Printf("Code Security Auditor v%s\n", version)
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

// dependencyCmd creates the dependency command group.
func dependencyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dependency",
		Short: "Dependency scanning and management commands",
		Aliases: []string{"dep", "dependencies"},
	}

	cmd.AddCommand(dependencyCheckCmd())
	cmd.AddCommand(dependencyVulnerabilitiesCmd())
	cmd.AddCommand(dependencyUpgradePlanCmd())

	return cmd
}

// dependencyCheckCmd creates the dependency check command.
func dependencyCheckCmd() *cobra.Command {
	var packageManager, name, version string

	cmd := &cobra.Command{
		Use:   "check [package-manager] [name] [version]",
		Short: "Check a single dependency for vulnerabilities",
		Long: `Check a specific dependency for known vulnerabilities.

Examples:
  bastion dependency check npm lodash 4.17.20
  bastion dependency check pip django 4.1.0
  bastion dependency check go github.com/gin-gonic/gin v1.9.0`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			pm := args[0]
			pkgName := args[1]
			pkgVersion := args[2]

			return runDependencyCheck(pm, pkgName, pkgVersion)
		},
	}

	cmd.Flags().StringVarP(&packageManager, "package-manager", "p", "", "package manager (npm, pip, go)")
	cmd.Flags().StringVarP(&name, "name", "n", "", "package name")
	cmd.Flags().StringVarP(&version, "version", "v", "", "package version")

	return cmd
}

// dependencyVulnerabilitiesCmd creates the vulnerabilities list command.
func dependencyVulnerabilitiesCmd() *cobra.Command {
	var severity string
	var path string

	cmd := &cobra.Command{
		Use:   "vulnerabilities [path]",
		Short: "List vulnerabilities in dependencies",
		Long: `List all vulnerabilities found in project dependencies.

Examples:
  bastion dependencies vulnerabilities .
  bastion dependencies vulnerabilities --severity critical,high
  bastion dependencies vulnerabilities ./my-project`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scanPath := "."
			if len(args) > 0 {
				scanPath = args[0]
			}

			return runDependencyVulnerabilities(scanPath, severity)
		},
	}

	cmd.Flags().StringVarP(&severity, "severity", "s", "", "filter by severity (critical,high,medium,low)")
	cmd.Flags().StringVarP(&path, "path", "p", ".", "project path to scan")

	return cmd
}

// dependencyUpgradePlanCmd creates the upgrade plan command.
func dependencyUpgradePlanCmd() *cobra.Command {
	var path string

	cmd := &cobra.Command{
		Use:   "upgrade-plan [path]",
		Short: "Generate an upgrade plan for dependencies",
		Long: `Generate a detailed upgrade plan to fix vulnerabilities.

Examples:
  bastion dependencies upgrade-plan .
  bastion dependencies upgrade-plan ./my-project`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scanPath := "."
			if len(args) > 0 {
				scanPath = args[0]
			}

			return runDependencyUpgradePlan(scanPath)
		},
	}

	cmd.Flags().StringVarP(&path, "path", "p", ".", "project path to scan")

	return cmd
}

// sbomCmd creates the SBOM command group.
func sbomCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sbom",
		Short: "Software Bill of Materials commands",
	}

	cmd.AddCommand(sbomGenerateCmd())

	return cmd
}

// sbomGenerateCmd creates the SBOM generate command.
func sbomGenerateCmd() *cobra.Command {
	var format, output string
	var path string

	cmd := &cobra.Command{
		Use:   "generate [path]",
		Short: "Generate a Software Bill of Materials",
		Long: `Generate a Software Bill of Materials (SBOM) for a project.

Examples:
  bastion sbom generate .
  bastion sbom generate --format cyclonedx --output sbom.json
  bastion sbom generate ./my-project --format spdx`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scanPath := "."
			if len(args) > 0 {
				scanPath = args[0]
			}

			return runSBOMGenerate(scanPath, format, output)
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "cyclonedx", "SBOM format (cyclonedx, spdx)")
	cmd.Flags().StringVarP(&output, "output", "o", "sbom.json", "output file path")
	cmd.Flags().StringVarP(&path, "path", "p", ".", "project path to scan")

	return cmd
}

// licenseCmd creates the license audit command.
func licenseCmd() *cobra.Command {
	var path, policy string

	cmd := &cobra.Command{
		Use:   "license [path]",
		Short: "Audit dependencies for license compliance",
		Long: `Audit project dependencies for license compliance issues.

Examples:
  bastion license audit .
  bastion license audit --policy strict
  bastion license audit ./my-project`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scanPath := "."
			if len(args) > 0 {
				scanPath = args[0]
			}

			return runLicenseAudit(scanPath, policy)
		},
	}

	cmd.Flags().StringVarP(&path, "path", "p", ".", "project path to scan")
	cmd.Flags().StringVarP(&policy, "policy", "", "default", "license policy (strict, default, permissive)")

	return cmd
}

// Implementation functions (simplified for now - would need full implementation)

func runDependencyCheck(pm, name, version string) error {
	fmt.Printf("🏰 Bastion Dependency Checker\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("Checking: %s@%s (%s)\n\n", name, version, pm)
	fmt.Printf("⚠️  Dependency checking not yet fully implemented\n")
	fmt.Printf("This would check %s %s@%s against vulnerability databases\n", pm, name, version)
	return nil
}

func runDependencyVulnerabilities(path, severity string) error {
	fmt.Printf("🏰 Bastion Dependency Scanner\n")
	fmt.Printf("📦 Scanning dependencies in: %s\n", path)
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("⚠️  Vulnerability scanning not yet fully implemented\n")
	fmt.Printf("This would scan dependencies and list vulnerabilities\n")
	return nil
}

func runDependencyUpgradePlan(path string) error {
	fmt.Printf("🏰 Bastion Dependency Upgrade Planner\n")
	fmt.Printf("📦 Analyzing dependencies in: %s\n", path)
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("⚠️  Upgrade plan generation not yet fully implemented\n")
	fmt.Printf("This would generate a detailed upgrade plan\n")
	return nil
}

func runSBOMGenerate(path, format, output string) error {
	fmt.Printf("🏰 Bastion SBOM Generator\n")
	fmt.Printf("📦 Generating SBOM for: %s\n", path)
	fmt.Printf("Format: %s\n", format)
	fmt.Printf("Output: %s\n", output)
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("⚠️  SBOM generation not yet fully implemented\n")
	fmt.Printf("This would generate a %s SBOM\n", format)
	return nil
}

func runLicenseAudit(path, policy string) error {
	fmt.Printf("🏰 Bastion License Auditor\n")
	fmt.Printf("⚖️  Auditing licenses in: %s\n", path)
	fmt.Printf("Policy: %s\n", policy)
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("⚠️  License auditing not yet fully implemented\n")
	fmt.Printf("This would audit dependencies for license compliance\n")
	return nil
}
