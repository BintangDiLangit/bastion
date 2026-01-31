package handlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"code-security-auditor/internal/models"
	"code-security-auditor/internal/scanner/rules"
)

// ScanService defines the interface for scan operations.
type ScanService interface {
	CreateRepository(ctx context.Context, req models.RepositoryCreateRequest) (*models.Repository, error)
	GetRepository(ctx context.Context, id uuid.UUID) (*models.Repository, error)
	ListRepositories(ctx context.Context, filter models.RepositoryFilter) ([]models.Repository, error)
	UpdateRepository(ctx context.Context, id uuid.UUID, req models.RepositoryUpdateRequest) (*models.Repository, error)
	DeleteRepository(ctx context.Context, id uuid.UUID) error
	GetRepositoryStats(ctx context.Context, id uuid.UUID) (*models.RepositoryStats, error)

	CreateScan(ctx context.Context, req models.ScanRequest) (*models.Scan, error)
	GetScan(ctx context.Context, id uuid.UUID) (*models.Scan, error)
	GetScanProgress(ctx context.Context, id uuid.UUID) (*models.ScanProgress, error)
	CancelScan(ctx context.Context, id uuid.UUID) error
	ListScansByRepository(ctx context.Context, repoID uuid.UUID, limit, offset int) ([]models.Scan, error)
	GetScanSummary(ctx context.Context, id uuid.UUID) (*models.ScanSummary, error)

	GetVulnerability(ctx context.Context, id uuid.UUID) (*models.Vulnerability, error)
	ListVulnerabilities(ctx context.Context, filter models.VulnerabilityFilter) ([]models.Vulnerability, error)
	UpdateVulnerability(ctx context.Context, id uuid.UUID, update models.VulnerabilityUpdate) error
}

// AIService defines the interface for AI operations.
type AIService interface {
	AnalyzeVulnerability(ctx context.Context, vuln *models.Vulnerability) (*models.AIAnalysis, error)
}

// ScanHandler handles scan-related HTTP requests.
type ScanHandler struct {
	service    ScanService
	aiService  AIService
	ruleEngine *rules.Engine
	logger     *logrus.Logger
}

// NewScanHandler creates a new ScanHandler.
func NewScanHandler(service ScanService, aiService AIService, ruleEngine *rules.Engine, logger *logrus.Logger) *ScanHandler {
	return &ScanHandler{
		service:    service,
		aiService:  aiService,
		ruleEngine: ruleEngine,
		logger:     logger,
	}
}

// CreateRepository creates a new repository.
func (h *ScanHandler) CreateRepository(c *gin.Context) {
	var req models.RepositoryCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid request body: " + err.Error(),
		})
		return
	}

	repo, err := h.service.CreateRepository(c.Request.Context(), req)
	if err != nil {
		h.logger.WithError(err).Error("Failed to create repository")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to create repository",
		})
		return
	}

	c.JSON(http.StatusCreated, repo)
}

// GetRepository retrieves a repository by ID.
func (h *ScanHandler) GetRepository(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid repository ID",
		})
		return
	}

	repo, err := h.service.GetRepository(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "Not Found",
			"message": "Repository not found",
		})
		return
	}

	c.JSON(http.StatusOK, repo)
}

// ListRepositories lists all repositories.
func (h *ScanHandler) ListRepositories(c *gin.Context) {
	var filter models.RepositoryFilter
	if err := c.ShouldBindQuery(&filter); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid query parameters",
		})
		return
	}

	// Set defaults
	if filter.Limit == 0 {
		filter.Limit = 20
	}
	if filter.Limit > 100 {
		filter.Limit = 100
	}

	repos, err := h.service.ListRepositories(c.Request.Context(), filter)
	if err != nil {
		h.logger.WithError(err).Error("Failed to list repositories")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to list repositories",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":   repos,
		"limit":  filter.Limit,
		"offset": filter.Offset,
	})
}

// UpdateRepository updates a repository.
func (h *ScanHandler) UpdateRepository(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid repository ID",
		})
		return
	}

	var req models.RepositoryUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid request body",
		})
		return
	}

	repo, err := h.service.UpdateRepository(c.Request.Context(), id, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to update repository",
		})
		return
	}

	c.JSON(http.StatusOK, repo)
}

// DeleteRepository deletes a repository.
func (h *ScanHandler) DeleteRepository(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid repository ID",
		})
		return
	}

	if err := h.service.DeleteRepository(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to delete repository",
		})
		return
	}

	c.Status(http.StatusNoContent)
}

// GetRepositoryStats retrieves repository statistics.
func (h *ScanHandler) GetRepositoryStats(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid repository ID",
		})
		return
	}

	stats, err := h.service.GetRepositoryStats(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to get repository stats",
		})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// GetRepositoryScans retrieves scans for a repository.
func (h *ScanHandler) GetRepositoryScans(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid repository ID",
		})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	scans, err := h.service.ListScansByRepository(c.Request.Context(), id, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to list scans",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":   scans,
		"limit":  limit,
		"offset": offset,
	})
}

// CreateScan creates a new scan.
func (h *ScanHandler) CreateScan(c *gin.Context) {
	var req models.ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid request body: " + err.Error(),
		})
		return
	}

	scan, err := h.service.CreateScan(c.Request.Context(), req)
	if err != nil {
		h.logger.WithError(err).Error("Failed to create scan")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to create scan",
		})
		return
	}

	c.JSON(http.StatusAccepted, models.ScanResponse{
		ScanID:  scan.ID,
		Status:  scan.Status,
		Message: "Scan queued successfully",
	})
}

// GetScan retrieves a scan by ID.
func (h *ScanHandler) GetScan(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid scan ID",
		})
		return
	}

	scan, err := h.service.GetScan(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "Not Found",
			"message": "Scan not found",
		})
		return
	}

	c.JSON(http.StatusOK, scan)
}

// GetScanProgress retrieves the progress of a scan.
func (h *ScanHandler) GetScanProgress(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid scan ID",
		})
		return
	}

	progress, err := h.service.GetScanProgress(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to get scan progress",
		})
		return
	}

	c.JSON(http.StatusOK, progress)
}

// CancelScan cancels a running scan.
func (h *ScanHandler) CancelScan(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid scan ID",
		})
		return
	}

	if err := h.service.CancelScan(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to cancel scan",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Scan cancelled",
	})
}

// GetScanVulnerabilities retrieves vulnerabilities for a scan.
func (h *ScanHandler) GetScanVulnerabilities(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid scan ID",
		})
		return
	}

	filter := models.VulnerabilityFilter{
		ScanID: &id,
	}

	if err := c.ShouldBindQuery(&filter); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid query parameters",
		})
		return
	}

	if filter.Limit == 0 {
		filter.Limit = 50
	}

	vulns, err := h.service.ListVulnerabilities(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to list vulnerabilities",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":   vulns,
		"limit":  filter.Limit,
		"offset": filter.Offset,
	})
}

// GetScanSummary retrieves the summary of a scan.
func (h *ScanHandler) GetScanSummary(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid scan ID",
		})
		return
	}

	summary, err := h.service.GetScanSummary(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to get scan summary",
		})
		return
	}

	c.JSON(http.StatusOK, summary)
}

// GetVulnerability retrieves a vulnerability by ID.
func (h *ScanHandler) GetVulnerability(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid vulnerability ID",
		})
		return
	}

	vuln, err := h.service.GetVulnerability(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "Not Found",
			"message": "Vulnerability not found",
		})
		return
	}

	c.JSON(http.StatusOK, vuln)
}

// UpdateVulnerability updates a vulnerability (e.g., mark as false positive).
func (h *ScanHandler) UpdateVulnerability(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid vulnerability ID",
		})
		return
	}

	var update models.VulnerabilityUpdate
	if err := c.ShouldBindJSON(&update); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid request body",
		})
		return
	}

	if err := h.service.UpdateVulnerability(c.Request.Context(), id, update); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to update vulnerability",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Vulnerability updated",
	})
}

// AnalyzeVulnerability uses AI to analyze a vulnerability.
func (h *ScanHandler) AnalyzeVulnerability(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid vulnerability ID",
		})
		return
	}

	vuln, err := h.service.GetVulnerability(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "Not Found",
			"message": "Vulnerability not found",
		})
		return
	}

	if h.aiService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":   "Service Unavailable",
			"message": "AI service not configured",
		})
		return
	}

	analysis, err := h.aiService.AnalyzeVulnerability(c.Request.Context(), vuln)
	if err != nil {
		h.logger.WithError(err).Error("AI analysis failed")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to analyze vulnerability",
		})
		return
	}

	c.JSON(http.StatusOK, analysis)
}

// ListRules lists all available security rules.
func (h *ScanHandler) ListRules(c *gin.Context) {
	rulesList := h.ruleEngine.ListRules()

	ruleInfos := make([]rules.RuleInfo, 0, len(rulesList))
	for _, rule := range rulesList {
		ruleInfos = append(ruleInfos, rules.GetRuleInfo(rule))
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  ruleInfos,
		"count": len(ruleInfos),
	})
}

// GetRule retrieves a specific rule by ID.
func (h *ScanHandler) GetRule(c *gin.Context) {
	ruleID := c.Param("id")

	rule, exists := h.ruleEngine.GetRule(ruleID)
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "Not Found",
			"message": "Rule not found",
		})
		return
	}

	c.JSON(http.StatusOK, rules.GetRuleInfo(rule))
}
