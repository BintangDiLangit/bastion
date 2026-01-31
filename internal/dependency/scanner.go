// Package dependency provides dependency scanning and analysis functionality.
package dependency

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"code-security-auditor/internal/agent"
	"code-security-auditor/internal/config"
	"code-security-auditor/internal/database"
)

// VulnerabilityClient interface for checking dependencies
type VulnerabilityClient interface {
	CheckDependencies(ctx context.Context, deps []Dependency) ([]VulnerabilityReport, error)
}

// LicenseIssue represents a license compliance issue (local type to avoid import cycle).
type LicenseIssue struct {
	Dependency     Dependency `json:"dependency"`
	License        string     `json:"license"`
	IssueType      string     `json:"issue_type"`
	Severity       string     `json:"severity"`
	Explanation    string     `json:"explanation"`
	Recommendation string     `json:"recommendation"`
}

// LicenseChecker interface for checking license compliance
type LicenseChecker interface {
	CheckDependencies(ctx context.Context, deps []Dependency) ([]LicenseIssue, error)
}

// SBOMGenerator interface for generating SBOMs
type SBOMGenerator interface {
	Generate(ctx context.Context, manifest *DependencyManifest, vulnReports []VulnerabilityReport, opts SBOMOptions) ([]byte, error)
}

// DependencyScanner orchestrates the complete dependency scanning workflow.
type DependencyScanner struct {
	detector       *DependencyFileDetector
	parserManager  *ParserManager
	vulnClient     VulnerabilityClient
	licenseChecker LicenseChecker
	sbomGenerator  SBOMGenerator
	adkClient      *agent.ADKClient
	db             *database.PostgresDB
	logger         *logrus.Logger
	config         config.ScannerConfig
}

// NewDependencyScanner creates a new DependencyScanner.
func NewDependencyScanner(
	detector *DependencyFileDetector,
	parserManager *ParserManager,
	vulnClient VulnerabilityClient,
	licenseChecker LicenseChecker,
	sbomGenerator SBOMGenerator,
	adkClient *agent.ADKClient,
	db *database.PostgresDB,
	logger *logrus.Logger,
	cfg config.ScannerConfig,
) *DependencyScanner {
	return &DependencyScanner{
		detector:       detector,
		parserManager:  parserManager,
		vulnClient:     vulnClient,
		licenseChecker: licenseChecker,
		sbomGenerator:  sbomGenerator,
		adkClient:      adkClient,
		db:             db,
		logger:         logger,
		config:         cfg,
	}
}

// ScanOptions contains options for dependency scanning.
type ScanOptions struct {
	SBOMOptions       SBOMOptions
	IncludeTransitive bool
	CheckLicenses     bool
	GenerateSBOM      bool
	UseADK            bool
	ProjectContext    agent.ProjectContext
}

// SBOMOptions contains options for SBOM generation.
type SBOMOptions struct {
	Format      string // cyclonedx-json, spdx-json, etc.
	IncludeDev  bool
	IncludeTest bool
}

// DependencyScanResult contains the complete results of a dependency scan.
type DependencyScanResult struct {
	ScanID                 string                `json:"scan_id"`
	Timestamp              time.Time             `json:"timestamp"`
	TotalDependencies      int                   `json:"total_dependencies"`
	DirectDependencies     int                   `json:"direct_dependencies"`
	TransitiveDependencies int                   `json:"transitive_dependencies"`
	VulnerablePackages     int                   `json:"vulnerable_packages"`
	TotalVulnerabilities   int                   `json:"total_vulnerabilities"`
	CriticalVulns          int                   `json:"critical_vulns"`
	HighVulns              int                   `json:"high_vulns"`
	MediumVulns            int                   `json:"medium_vulns"`
	LowVulns               int                   `json:"low_vulns"`
	Dependencies           []Dependency          `json:"dependencies"`
	VulnerabilityReports   []VulnerabilityReport `json:"vulnerability_reports"`
	LicenseIssues          []LicenseIssue        `json:"license_issues"`
	SBOM                   []byte                `json:"sbom,omitempty"`
	RiskAnalysis           *agent.RiskAnalysis   `json:"risk_analysis,omitempty"`
	Recommendations        []Recommendation      `json:"recommendations"`
	ScanDuration           time.Duration         `json:"scan_duration"`
}

// RecommendationType represents the type of recommendation.
type RecommendationType string

const (
	RecommendationTypeUpgrade RecommendationType = "upgrade"
	RecommendationTypeReplace RecommendationType = "replace"
	RecommendationTypeRemove  RecommendationType = "remove"
	RecommendationTypeAccept  RecommendationType = "accept"
	RecommendationTypeMonitor RecommendationType = "monitor"
)

// Recommendation represents an actionable recommendation.
type Recommendation struct {
	Type          RecommendationType `json:"type"`
	Dependency    Dependency         `json:"dependency"`
	Action        string             `json:"action"`
	TargetVersion string             `json:"target_version,omitempty"`
	Priority      int                `json:"priority"`
	Effort        string             `json:"effort"` // low, medium, high
	Impact        string             `json:"impact"`
	Details       string             `json:"details"`
	Timeline      string             `json:"timeline,omitempty"`
}

// Scan performs a complete dependency scan.
func (ds *DependencyScanner) Scan(ctx context.Context, repoPath string, opts ScanOptions) (*DependencyScanResult, error) {
	startTime := time.Now()
	scanID := generateScanID()

	ds.logger.WithFields(logrus.Fields{
		"scan_id":   scanID,
		"repo_path": repoPath,
	}).Info("Starting dependency scan")

	// 1. Detect dependency files
	ds.logger.Debug("Step 1: Detecting dependency files")
	files, err := ds.detector.DetectDependencyFiles(ctx, repoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to detect dependency files: %w", err)
	}

	ds.logger.WithField("file_count", len(files)).Debug("Dependency files detected")

	// 2. Parse each dependency file
	ds.logger.Debug("Step 2: Parsing dependency files")
	var allDeps []Dependency
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, ds.config.MaxConcurrent)

	for _, file := range files {
		wg.Add(1)
		go func(f DependencyFile) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			manifest, err := ds.parserManager.Parse(ctx, f)
			if err != nil {
				ds.logger.WithError(err).WithField("file", f.Path).Warn("Failed to parse dependency file")
				return
			}

			mu.Lock()
			allDeps = append(allDeps, manifest.AllDependencies...)
			mu.Unlock()
		}(file)
	}

	wg.Wait()

	ds.logger.WithField("dependency_count", len(allDeps)).Debug("Dependencies parsed")

	// Filter dependencies
	directDeps := filterDependencies(allDeps, func(d Dependency) bool {
		return d.IsDirect
	})
	transitiveDeps := filterDependencies(allDeps, func(d Dependency) bool {
		return d.IsTransitive
	})

	// 3. Check for vulnerabilities (concurrent with worker pool)
	ds.logger.Debug("Step 3: Checking for vulnerabilities")
	var vulnReports []VulnerabilityReport
	if ds.vulnClient != nil {
		reports, err := ds.vulnClient.CheckDependencies(ctx, allDeps)
		if err != nil {
			ds.logger.WithError(err).Warn("Failed to check some vulnerabilities")
		} else {
			vulnReports = reports
		}
	}

	ds.logger.WithField("vulnerability_count", len(vulnReports)).Debug("Vulnerability check completed")

	// 4. Check license compliance
	ds.logger.Debug("Step 4: Checking license compliance")
	var licenseIssues []LicenseIssue
	if opts.CheckLicenses && ds.licenseChecker != nil {
		issues, err := ds.licenseChecker.CheckDependencies(ctx, allDeps)
		if err != nil {
			ds.logger.WithError(err).Warn("Failed to check some licenses")
		} else {
			licenseIssues = issues
		}
	}

	// 5. Generate SBOM
	ds.logger.Debug("Step 5: Generating SBOM")
	var sbom []byte
	if opts.GenerateSBOM && ds.sbomGenerator != nil {
		// Create a manifest from all dependencies
		manifest := &DependencyManifest{
			AllDependencies: allDeps,
		}
		generated, err := ds.sbomGenerator.Generate(ctx, manifest, vulnReports, opts.SBOMOptions)
		if err != nil {
			ds.logger.WithError(err).Warn("Failed to generate SBOM")
		} else {
			sbom = generated
		}
	}

	// 6. ADK intelligent analysis
	ds.logger.Debug("Step 6: Running ADK intelligent analysis")
	var riskAnalysis *agent.RiskAnalysis
	if opts.UseADK && ds.adkClient != nil {
		// Convert dependencies to agent format
		agentDeps := convertDependenciesToAgent(allDeps)
		agentVulns := convertVulnReportsToAgent(vulnReports)

		analysis, err := agent.AnalyzeDependencyRisks(ctx, ds.adkClient, agentDeps, agentVulns, opts.ProjectContext)
		if err != nil {
			ds.logger.WithError(err).Warn("Failed to run ADK analysis")
		} else {
			riskAnalysis = analysis
		}
	}

	// 7. Generate recommendations
	ds.logger.Debug("Step 7: Generating recommendations")
	recommendations := ds.generateRecommendations(vulnReports, riskAnalysis)

	// 8. Create result
	result := &DependencyScanResult{
		ScanID:                 scanID,
		Timestamp:              time.Now(),
		TotalDependencies:      len(allDeps),
		DirectDependencies:     len(directDeps),
		TransitiveDependencies: len(transitiveDeps),
		VulnerablePackages:     countVulnerablePackages(vulnReports),
		TotalVulnerabilities:   countTotalVulnerabilities(vulnReports),
		CriticalVulns:          countBySeverity(vulnReports, "critical"),
		HighVulns:              countBySeverity(vulnReports, "high"),
		MediumVulns:            countBySeverity(vulnReports, "medium"),
		LowVulns:               countBySeverity(vulnReports, "low"),
		Dependencies:           allDeps,
		VulnerabilityReports:   vulnReports,
		LicenseIssues:          licenseIssues,
		SBOM:                   sbom,
		RiskAnalysis:           riskAnalysis,
		Recommendations:        recommendations,
		ScanDuration:           time.Since(startTime),
	}

	// 9. Store in database
	if ds.db != nil {
		ds.logger.Debug("Step 8: Storing scan results in database")
		if err := ds.storeDependencyScan(ctx, result); err != nil {
			ds.logger.WithError(err).Warn("Failed to store scan results")
		}
	}

	ds.logger.WithFields(logrus.Fields{
		"scan_id":            scanID,
		"total_dependencies": result.TotalDependencies,
		"vulnerabilities":    result.TotalVulnerabilities,
		"duration":           result.ScanDuration,
	}).Info("Dependency scan completed")

	return result, nil
}

// generateRecommendations generates actionable recommendations based on vulnerabilities and risk analysis.
func (ds *DependencyScanner) generateRecommendations(
	vulnReports []VulnerabilityReport,
	riskAnalysis *agent.RiskAnalysis,
) []Recommendation {
	var recommendations []Recommendation

	// If we have risk analysis, use prioritized vulnerabilities
	if riskAnalysis != nil && len(riskAnalysis.PriorityOrder) > 0 {
		for _, pv := range riskAnalysis.PriorityOrder {
			// Convert agent.Dependency to dependency.Dependency
			dep := convertAgentDependencyToDependency(pv.Dependency)

			rec := Recommendation{
				Type:          RecommendationTypeUpgrade,
				Dependency:    dep,
				Action:        "upgrade",
				TargetVersion: pv.Vulnerability.FixedVersion,
				Priority:      pv.Priority,
				Effort:        estimateEffortFromAgent(pv.Vulnerability),
				Impact:        pv.Impact,
				Details:       pv.Reasoning,
			}

			if pv.Urgency == "immediate" {
				rec.Timeline = "ASAP"
			} else if pv.Urgency == "high" {
				rec.Timeline = "Within 1 week"
			} else if pv.Urgency == "medium" {
				rec.Timeline = "Within 1 month"
			} else {
				rec.Timeline = "Within 3 months"
			}

			recommendations = append(recommendations, rec)
		}
	} else {
		// Fallback: generate recommendations from vulnerabilities directly
		for i, vulnReport := range vulnReports {
			if len(vulnReport.Vulnerabilities) == 0 {
				continue
			}

			// Use the first vulnerability for the recommendation
			vuln := vulnReport.Vulnerabilities[0]

			rec := Recommendation{
				Type:          RecommendationTypeUpgrade,
				Dependency:    vulnReport.Dependency,
				Action:        "upgrade",
				TargetVersion: vuln.FixedIn,
				Priority:      i + 1,
				Effort:        estimateEffort(vuln),
				Impact:        mapSeverityToImpact(vuln.Severity),
				Details:       vuln.Description,
			}

			recommendations = append(recommendations, rec)
		}
	}

	return recommendations
}

// storeDependencyScan stores the scan result in the database.
func (ds *DependencyScanner) storeDependencyScan(ctx context.Context, result *DependencyScanResult) error {
	// This would store the scan result in the database
	// Implementation depends on your database schema
	// For now, we'll just log it
	ds.logger.WithField("scan_id", result.ScanID).Debug("Storing dependency scan result")
	return nil
}

// Helper functions

func generateScanID() string {
	return fmt.Sprintf("dep-scan-%d", time.Now().UnixNano())
}

func filterDependencies(deps []Dependency, filter func(Dependency) bool) []Dependency {
	var filtered []Dependency
	for _, dep := range deps {
		if filter(dep) {
			filtered = append(filtered, dep)
		}
	}
	return filtered
}

// Conversion functions between dependency and agent types

func convertDependenciesToAgent(deps []Dependency) []agent.Dependency {
	agentDeps := make([]agent.Dependency, len(deps))
	for i, dep := range deps {
		agentDeps[i] = agent.Dependency{
			Name:       dep.Name,
			Version:    dep.Version,
			Type:       mapDependencyType(dep.IsDirect, dep.IsTransitive),
			Source:     string(dep.Type), // Using DependencyType as source
			License:    dep.License,
			Repository: dep.Repository,
			Metadata:   make(map[string]string),
		}
		if dep.Parent != "" {
			agentDeps[i].Metadata["parent"] = dep.Parent
		}
	}
	return agentDeps
}

func convertVulnReportsToAgent(reports []VulnerabilityReport) []agent.VulnerabilityReport {
	var agentVulns []agent.VulnerabilityReport
	for _, report := range reports {
		for _, vuln := range report.Vulnerabilities {
			agentVuln := agent.VulnerabilityReport{
				CVE:             vuln.ID,
				Severity:        vuln.Severity,
				Title:           vuln.Title,
				Description:     vuln.Description,
				AffectedVersion: report.Dependency.Version,
				FixedVersion:    vuln.FixedIn,
				CVSS:            vuln.CVSS,
				Metadata: map[string]string{
					"package": report.Dependency.Name,
				},
			}
			agentVulns = append(agentVulns, agentVuln)
		}
	}
	return agentVulns
}

func convertAgentDependencyToDependency(agentDep agent.Dependency) Dependency {
	return Dependency{
		Name:         agentDep.Name,
		Version:      agentDep.Version,
		License:      agentDep.License,
		Repository:   agentDep.Repository,
		IsDirect:     agentDep.Type == "direct",
		IsTransitive: agentDep.Type == "transitive",
	}
}

func mapDependencyType(isDirect, isTransitive bool) string {
	if isDirect {
		return "direct"
	}
	if isTransitive {
		return "transitive"
	}
	return "unknown"
}

func countVulnerablePackages(vulnReports []VulnerabilityReport) int {
	packages := make(map[string]bool)
	for _, report := range vulnReports {
		packages[report.Dependency.Name] = true
	}
	return len(packages)
}

func countTotalVulnerabilities(vulnReports []VulnerabilityReport) int {
	total := 0
	for _, report := range vulnReports {
		total += report.TotalCount
	}
	return total
}

func countBySeverity(vulnReports []VulnerabilityReport, severity string) int {
	count := 0
	for _, report := range vulnReports {
		switch severity {
		case "critical":
			count += report.CriticalCount
		case "high":
			count += report.HighCount
		case "medium":
			count += report.MediumCount
		case "low":
			count += report.LowCount
		}
	}
	return count
}

func estimateEffort(vuln Vulnerability) string {
	// Simple heuristic based on severity
	switch vuln.Severity {
	case "critical", "high":
		return "low" // High priority, but usually straightforward upgrade
	case "medium":
		return "medium"
	case "low":
		return "high" // Low priority, can take time
	default:
		return "medium"
	}
}

func estimateEffortFromAgent(vuln agent.VulnerabilityReport) string {
	switch vuln.Severity {
	case "critical", "high":
		return "low"
	case "medium":
		return "medium"
	case "low":
		return "high"
	default:
		return "medium"
	}
}

func mapSeverityToImpact(severity string) string {
	switch severity {
	case "critical":
		return "severe"
	case "high":
		return "moderate"
	case "medium":
		return "limited"
	case "low":
		return "minimal"
	default:
		return "unknown"
	}
}
