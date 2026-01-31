// Package handlers provides HTTP handlers for dependency scanning.
package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"code-security-auditor/internal/dependency"
)

// DependencyService defines the interface for dependency scanning operations.
type DependencyService interface {
	TriggerDependencyScan(ctx context.Context, scanID uuid.UUID, opts dependency.ScanOptions) (*dependency.DependencyScanResult, error)
	GetDependencyScan(ctx context.Context, scanID, dependencyScanID uuid.UUID) (*dependency.DependencyScanResult, error)
	GetSBOM(ctx context.Context, scanID, dependencyScanID uuid.UUID, format string) ([]byte, string, error)
	GetVulnerabilityDetails(ctx context.Context, cveID string) (*VulnerabilityDetails, error)
	CheckSingleDependency(ctx context.Context, req CheckDependencyRequest) (*DependencyCheckResult, error)
	GenerateUpgradePlan(ctx context.Context, scanID, dependencyScanID uuid.UUID) (*UpgradePlan, error)
}

// DependencyHandler handles dependency scanning HTTP requests.
type DependencyHandler struct {
	service DependencyService
	logger  *logrus.Logger
}

// NewDependencyHandler creates a new DependencyHandler.
func NewDependencyHandler(service DependencyService, logger *logrus.Logger) *DependencyHandler {
	return &DependencyHandler{
		service: service,
		logger:  logger,
	}
}

// TriggerDependencyScanRequest represents the request to trigger a dependency scan.
type TriggerDependencyScanRequest struct {
	IncludeDevDependencies bool   `json:"include_dev_dependencies"`
	CheckLicenses          bool   `json:"check_licenses"`
	GenerateSBOM           bool   `json:"generate_sbom"`
	SBOMFormat             string `json:"sbom_format"` // cyclonedx, spdx
	UseADK                 bool   `json:"use_adk"`
}

// TriggerDependencyScanResponse represents the response from triggering a scan.
type TriggerDependencyScanResponse struct {
	DependencyScanID   string `json:"dependency_scan_id"`
	Status             string `json:"status"`
	EstimatedDuration  string `json:"estimated_duration"`
	Message            string `json:"message"`
}

// TriggerDependencyScan triggers a dependency scan for a given scan.
// POST /api/v1/scans/:scan_id/dependencies
func (h *DependencyHandler) TriggerDependencyScan(c *gin.Context) {
	scanIDStr := c.Param("scan_id")
	scanID, err := uuid.Parse(scanIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scan_id"})
		return
	}

	var req TriggerDependencyScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set defaults
	if req.SBOMFormat == "" {
		req.SBOMFormat = "cyclonedx"
	}

	// Convert to ScanOptions
	opts := dependency.ScanOptions{
		IncludeTransitive: req.IncludeDevDependencies, // Map include_dev to include_transitive
		CheckLicenses:     req.CheckLicenses,
		GenerateSBOM:      req.GenerateSBOM,
		UseADK:            req.UseADK,
		SBOMOptions: dependency.SBOMOptions{
			Format:     req.SBOMFormat,
			IncludeDev: req.IncludeDevDependencies,
		},
	}

	ctx := c.Request.Context()
	result, err := h.service.TriggerDependencyScan(ctx, scanID, opts)
	if err != nil {
		h.logger.WithError(err).Error("Failed to trigger dependency scan")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to trigger scan"})
		return
	}

	response := TriggerDependencyScanResponse{
		DependencyScanID:  result.ScanID,
		Status:            "running",
		EstimatedDuration: "3m",
		Message:           "Dependency scan started successfully",
	}

	c.JSON(http.StatusAccepted, response)
}

// GetDependencyScanResults retrieves dependency scan results.
// GET /api/v1/scans/:scan_id/dependencies/:dependency_scan_id
func (h *DependencyHandler) GetDependencyScanResults(c *gin.Context) {
	scanIDStr := c.Param("scan_id")
	scanID, err := uuid.Parse(scanIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scan_id"})
		return
	}

	dependencyScanIDStr := c.Param("dependency_scan_id")
	dependencyScanID, err := uuid.Parse(dependencyScanIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid dependency_scan_id"})
		return
	}

	ctx := c.Request.Context()
	result, err := h.service.GetDependencyScan(ctx, scanID, dependencyScanID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get dependency scan results")
		c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
		return
	}

	// Build response
	response := gin.H{
		"id":                   result.ScanID,
		"total_dependencies":  result.TotalDependencies,
		"vulnerable_packages":  result.VulnerablePackages,
		"vulnerabilities":     result.VulnerabilityReports,
		"license_issues":       result.LicenseIssues,
		"recommendations":      result.Recommendations,
		"risk_score":           calculateRiskScore(result),
		"timestamp":            result.Timestamp,
		"scan_duration":       result.ScanDuration.String(),
	}

	c.JSON(http.StatusOK, response)
}

// GetSBOM retrieves the SBOM for a dependency scan.
// GET /api/v1/scans/:scan_id/dependencies/:dependency_scan_id/sbom?format=cyclonedx
func (h *DependencyHandler) GetSBOM(c *gin.Context) {
	scanIDStr := c.Param("scan_id")
	scanID, err := uuid.Parse(scanIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scan_id"})
		return
	}

	dependencyScanIDStr := c.Param("dependency_scan_id")
	dependencyScanID, err := uuid.Parse(dependencyScanIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid dependency_scan_id"})
		return
	}

	format := c.DefaultQuery("format", "cyclonedx")

	ctx := c.Request.Context()
	sbom, formatType, err := h.service.GetSBOM(ctx, scanID, dependencyScanID, format)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get SBOM")
		c.JSON(http.StatusNotFound, gin.H{"error": "SBOM not found"})
		return
	}

	// Set appropriate content type
	contentType := "application/json"
	if formatType == "spdx" {
		contentType = "text/yaml"
	}

	c.Data(http.StatusOK, contentType, sbom)
}

// GetVulnerabilityDetails retrieves detailed information about a vulnerability.
// GET /api/v1/dependencies/vulnerabilities/:cve_id
func (h *DependencyHandler) GetVulnerabilityDetails(c *gin.Context) {
	cveID := c.Param("cve_id")
	if cveID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cve_id is required"})
		return
	}

	ctx := c.Request.Context()
	details, err := h.service.GetVulnerabilityDetails(ctx, cveID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get vulnerability details")
		c.JSON(http.StatusNotFound, gin.H{"error": "vulnerability not found"})
		return
	}

	c.JSON(http.StatusOK, details)
}

// VulnerabilityDetails represents detailed vulnerability information.
type VulnerabilityDetails struct {
	CVEID            string   `json:"cve_id"`
	Severity         string   `json:"severity"`
	CVSSScore        float64  `json:"cvss_score"`
	Description      string   `json:"description"`
	AffectedPackages []string `json:"affected_packages"`
	References       []string `json:"references"`
	PublishedAt      string   `json:"published_at"`
	FixedIn          string   `json:"fixed_in,omitempty"`
}

// CheckDependencyRequest represents a request to check a single dependency.
type CheckDependencyRequest struct {
	PackageManager string `json:"package_manager" binding:"required"`
	Name           string `json:"name" binding:"required"`
	Version        string `json:"version" binding:"required"`
}

// DependencyCheckResult represents the result of checking a single dependency.
type DependencyCheckResult struct {
	Vulnerabilities    []VulnerabilityInfo `json:"vulnerabilities"`
	LatestSafeVersion  string              `json:"latest_safe_version"`
	Recommendation     string              `json:"recommendation"`
	IsVulnerable       bool                `json:"is_vulnerable"`
	VulnerabilityCount int                 `json:"vulnerability_count"`
}

// VulnerabilityInfo represents basic vulnerability information.
type VulnerabilityInfo struct {
	ID          string  `json:"id"`
	Severity    string  `json:"severity"`
	CVSSScore   float64 `json:"cvss_score"`
	Title       string  `json:"title"`
	FixedIn     string  `json:"fixed_in,omitempty"`
}

// CheckSingleDependency checks a single dependency for vulnerabilities.
// POST /api/v1/dependencies/check
func (h *DependencyHandler) CheckSingleDependency(c *gin.Context) {
	var req CheckDependencyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	result, err := h.service.CheckSingleDependency(ctx, req)
	if err != nil {
		h.logger.WithError(err).Error("Failed to check dependency")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check dependency"})
		return
	}

	c.JSON(http.StatusOK, result)
}

// UpgradePlan represents an upgrade plan for dependencies.
type UpgradePlan struct {
	Plan            []UpgradeItem `json:"plan"`
	EstimatedTime   string        `json:"estimated_time"`
	AutomatedPRAvailable bool     `json:"automated_pr_available"`
	TotalVulnerabilitiesFixed int `json:"total_vulnerabilities_fixed"`
}

// UpgradeItem represents a single upgrade recommendation.
type UpgradeItem struct {
	Dependency           string   `json:"dependency"`
	From                 string   `json:"from"`
	To                   string   `json:"to"`
	FixesVulnerabilities int      `json:"fixes_vulnerabilities"`
	BreakingChanges      bool     `json:"breaking_changes"`
	Effort               string   `json:"effort"`
	VulnerabilityIDs     []string `json:"vulnerability_ids"`
}

// GenerateUpgradePlan generates an upgrade plan for dependencies.
// POST /api/v1/scans/:scan_id/dependencies/:dependency_scan_id/upgrade-plan
func (h *DependencyHandler) GenerateUpgradePlan(c *gin.Context) {
	scanIDStr := c.Param("scan_id")
	scanID, err := uuid.Parse(scanIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scan_id"})
		return
	}

	dependencyScanIDStr := c.Param("dependency_scan_id")
	dependencyScanID, err := uuid.Parse(dependencyScanIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid dependency_scan_id"})
		return
	}

	ctx := c.Request.Context()
	plan, err := h.service.GenerateUpgradePlan(ctx, scanID, dependencyScanID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to generate upgrade plan")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate upgrade plan"})
		return
	}

	c.JSON(http.StatusOK, plan)
}

// Helper functions

func calculateRiskScore(result *dependency.DependencyScanResult) float64 {
	// Simple risk score calculation based on vulnerabilities
	if result.TotalVulnerabilities == 0 {
		return 0.0
	}

	criticalWeight := 10.0
	highWeight := 7.0
	mediumWeight := 4.0
	lowWeight := 1.0

	totalWeight := float64(result.CriticalVulns)*criticalWeight +
		float64(result.HighVulns)*highWeight +
		float64(result.MediumVulns)*mediumWeight +
		float64(result.LowVulns)*lowWeight

	maxPossible := float64(result.TotalDependencies) * criticalWeight
	if maxPossible == 0 {
		return 0.0
	}

	score := (totalWeight / maxPossible) * 10.0
	if score > 10.0 {
		score = 10.0
	}

	return score
}
