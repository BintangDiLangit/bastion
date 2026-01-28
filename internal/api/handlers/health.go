// Package handlers provides HTTP request handlers.
package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// HealthChecker interface for components that can be health checked.
type HealthChecker interface {
	Health(ctx context.Context) error
}

// HealthHandler handles health check endpoints.
type HealthHandler struct {
	logger    *logrus.Logger
	database  HealthChecker
	redis     HealthChecker
	startTime time.Time
	version   string
}

// NewHealthHandler creates a new HealthHandler.
func NewHealthHandler(logger *logrus.Logger, database, redis HealthChecker, version string) *HealthHandler {
	return &HealthHandler{
		logger:    logger,
		database:  database,
		redis:     redis,
		startTime: time.Now(),
		version:   version,
	}
}

// HealthResponse represents the health check response.
type HealthResponse struct {
	Status    string            `json:"status"`
	Version   string            `json:"version"`
	Uptime    string            `json:"uptime"`
	Timestamp string            `json:"timestamp"`
	Checks    map[string]string `json:"checks,omitempty"`
}

// Health returns the overall health status.
func (h *HealthHandler) Health(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	checks := make(map[string]string)
	status := "healthy"

	// Check database
	if h.database != nil {
		if err := h.database.Health(ctx); err != nil {
			checks["database"] = "unhealthy: " + err.Error()
			status = "unhealthy"
		} else {
			checks["database"] = "healthy"
		}
	}

	// Check Redis
	if h.redis != nil {
		if err := h.redis.Health(ctx); err != nil {
			checks["redis"] = "unhealthy: " + err.Error()
			status = "unhealthy"
		} else {
			checks["redis"] = "healthy"
		}
	}

	response := HealthResponse{
		Status:    status,
		Version:   h.version,
		Uptime:    time.Since(h.startTime).String(),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Checks:    checks,
	}

	statusCode := http.StatusOK
	if status != "healthy" {
		statusCode = http.StatusServiceUnavailable
	}

	c.JSON(statusCode, response)
}

// Liveness returns the liveness probe status.
// This indicates if the application is running.
func (h *HealthHandler) Liveness(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "alive",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// Readiness returns the readiness probe status.
// This indicates if the application is ready to serve traffic.
func (h *HealthHandler) Readiness(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	// Check critical dependencies
	ready := true
	checks := make(map[string]string)

	// Database must be ready
	if h.database != nil {
		if err := h.database.Health(ctx); err != nil {
			checks["database"] = "not ready"
			ready = false
		} else {
			checks["database"] = "ready"
		}
	}

	// Redis must be ready
	if h.redis != nil {
		if err := h.redis.Health(ctx); err != nil {
			checks["redis"] = "not ready"
			ready = false
		} else {
			checks["redis"] = "ready"
		}
	}

	response := gin.H{
		"status":    "ready",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"checks":    checks,
	}

	if !ready {
		response["status"] = "not ready"
		c.JSON(http.StatusServiceUnavailable, response)
		return
	}

	c.JSON(http.StatusOK, response)
}

// Metrics returns basic application metrics.
func (h *HealthHandler) Metrics(c *gin.Context) {
	// In production, this would return Prometheus-formatted metrics
	c.JSON(http.StatusOK, gin.H{
		"uptime_seconds": time.Since(h.startTime).Seconds(),
		"version":        h.version,
		"timestamp":      time.Now().UTC().Format(time.RFC3339),
	})
}
