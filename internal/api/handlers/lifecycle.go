package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"code-security-auditor/internal/models"
	"code-security-auditor/internal/service"
)

type ScanLifecycleHandler struct {
	scans *service.Scans
	log   *logrus.Logger
}

func NewScanLifecycleHandler(scans *service.Scans, log *logrus.Logger) *ScanLifecycleHandler {
	return &ScanLifecycleHandler{scans: scans, log: log}
}

func (h *ScanLifecycleHandler) Create(c *gin.Context) {
	var request models.ScanRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	scan, err := h.scans.Create(c.Request.Context(), request)
	if err != nil {
		if errors.Is(err, service.ErrInvalidRepository) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		h.log.WithError(err).Error("Create scan")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "create scan"})
		return
	}
	c.JSON(http.StatusAccepted, models.ScanResponse{
		ScanID:  scan.ID,
		Status:  scan.Status,
		Message: "scan started",
	})
}

func (h *ScanLifecycleHandler) Get(c *gin.Context) {
	id, ok := scanID(c)
	if !ok {
		return
	}
	scan, err := h.scans.Get(c.Request.Context(), id)
	if errors.Is(err, service.ErrNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "load scan"})
		return
	}
	c.JSON(http.StatusOK, scan)
}

func (h *ScanLifecycleHandler) Findings(c *gin.Context) {
	id, ok := scanID(c)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	findings, err := h.scans.Findings(c.Request.Context(), id, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "load findings"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": findings, "limit": limit, "offset": offset})
}

func (h *ScanLifecycleHandler) Delta(c *gin.Context) {
	id, ok := scanID(c)
	if !ok {
		return
	}
	var baselineID *uuid.UUID
	if raw := c.Query("baseline_scan_id"); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid baseline scan ID"})
			return
		}
		baselineID = &parsed
	}
	delta, err := h.scans.Delta(c.Request.Context(), id, baselineID)
	if errors.Is(err, service.ErrNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, delta)
}

func (h *ScanLifecycleHandler) Cancel(c *gin.Context) {
	id, ok := scanID(c)
	if !ok {
		return
	}
	if err := h.scans.Cancel(c.Request.Context(), id); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, service.ErrNotFound) {
			status = http.StatusConflict
		}
		c.JSON(status, gin.H{"error": "scan is not cancellable"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "scan cancelled"})
}

func scanID(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scan ID"})
		return uuid.Nil, false
	}
	return id, true
}
