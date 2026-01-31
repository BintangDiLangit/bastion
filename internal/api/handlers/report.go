package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"code-security-auditor/internal/models"
)

// ReportService defines the interface for report operations.
type ReportService interface {
	CreateReport(ctx context.Context, req models.ReportRequest) (*models.Report, error)
	GetReport(ctx context.Context, id uuid.UUID) (*models.Report, error)
	ListReports(ctx context.Context, filter models.ReportFilter) ([]models.Report, error)
	GetReportDownloadURL(ctx context.Context, id uuid.UUID) (string, error)
}

// ReportHandler handles report-related HTTP requests.
type ReportHandler struct {
	service ReportService
	logger  *logrus.Logger
}

// NewReportHandler creates a new ReportHandler.
func NewReportHandler(service ReportService, logger *logrus.Logger) *ReportHandler {
	return &ReportHandler{
		service: service,
		logger:  logger,
	}
}

// CreateReport creates a new report.
func (h *ReportHandler) CreateReport(c *gin.Context) {
	var req models.ReportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid request body: " + err.Error(),
		})
		return
	}

	report, err := h.service.CreateReport(c.Request.Context(), req)
	if err != nil {
		h.logger.WithError(err).Error("Failed to create report")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to create report",
		})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"report_id": report.ID,
		"status":    report.Status,
		"message":   "Report generation started",
	})
}

// GetReport retrieves a report by ID.
func (h *ReportHandler) GetReport(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid report ID",
		})
		return
	}

	report, err := h.service.GetReport(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "Not Found",
			"message": "Report not found",
		})
		return
	}

	// Add download URL if completed
	if report.Status == models.ReportStatusCompleted {
		downloadURL, err := h.service.GetReportDownloadURL(c.Request.Context(), id)
		if err == nil {
			report.DownloadURL = downloadURL
		}
	}

	c.JSON(http.StatusOK, report)
}

// ListReports lists reports with optional filters.
func (h *ReportHandler) ListReports(c *gin.Context) {
	var filter models.ReportFilter
	if err := c.ShouldBindQuery(&filter); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid query parameters",
		})
		return
	}

	if filter.Limit == 0 {
		filter.Limit = 20
	}
	if filter.Limit > 100 {
		filter.Limit = 100
	}

	reports, err := h.service.ListReports(c.Request.Context(), filter)
	if err != nil {
		h.logger.WithError(err).Error("Failed to list reports")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to list reports",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":   reports,
		"limit":  filter.Limit,
		"offset": filter.Offset,
	})
}

// DownloadReport downloads a report file.
func (h *ReportHandler) DownloadReport(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid report ID",
		})
		return
	}

	report, err := h.service.GetReport(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "Not Found",
			"message": "Report not found",
		})
		return
	}

	if report.Status != models.ReportStatusCompleted {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Report is not ready for download",
			"status":  report.Status,
		})
		return
	}

	// Get download URL
	downloadURL, err := h.service.GetReportDownloadURL(c.Request.Context(), id)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get download URL")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "Failed to get download URL",
		})
		return
	}

	// Redirect to download URL or serve file directly
	if downloadURL != "" {
		c.Redirect(http.StatusFound, downloadURL)
		return
	}

	// Serve file directly
	contentType := getContentTypeForFormat(report.Format)
	filename := getFilenameForReport(report)

	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.Header("Content-Type", contentType)
	c.File(report.FilePath)
}

// getContentTypeForFormat returns the content type for a report format.
func getContentTypeForFormat(format models.ReportFormat) string {
	switch format {
	case models.ReportFormatJSON:
		return "application/json"
	case models.ReportFormatPDF:
		return "application/pdf"
	case models.ReportFormatHTML:
		return "text/html"
	case models.ReportFormatMarkdown:
		return "text/markdown"
	case models.ReportFormatSARIF:
		return "application/sarif+json"
	default:
		return "application/octet-stream"
	}
}

// getFilenameForReport generates a filename for a report.
func getFilenameForReport(report *models.Report) string {
	base := "security-report-" + report.ID.String()

	switch report.Format {
	case models.ReportFormatJSON:
		return base + ".json"
	case models.ReportFormatPDF:
		return base + ".pdf"
	case models.ReportFormatHTML:
		return base + ".html"
	case models.ReportFormatMarkdown:
		return base + ".md"
	case models.ReportFormatSARIF:
		return base + ".sarif.json"
	default:
		return base
	}
}
