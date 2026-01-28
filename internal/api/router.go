// Package api provides the HTTP API for the code security auditor.
package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/code-security-auditor/internal/api/handlers"
	"github.com/code-security-auditor/internal/api/middleware"
	"github.com/code-security-auditor/internal/config"
)

// Router holds the HTTP router and its dependencies.
type Router struct {
	engine         *gin.Engine
	config         *config.Config
	logger         *logrus.Logger
	healthHandler  *handlers.HealthHandler
	scanHandler    *handlers.ScanHandler
	reportHandler  *handlers.ReportHandler
	webhookHandler *handlers.WebhookHandler
}

// RouterDeps holds dependencies for the router.
type RouterDeps struct {
	Config         *config.Config
	Logger         *logrus.Logger
	HealthHandler  *handlers.HealthHandler
	ScanHandler    *handlers.ScanHandler
	ReportHandler  *handlers.ReportHandler
	WebhookHandler *handlers.WebhookHandler
}

// NewRouter creates a new Router with all routes configured.
func NewRouter(deps RouterDeps) *Router {
	// Set Gin mode
	switch deps.Config.Server.Mode {
	case "debug":
		gin.SetMode(gin.DebugMode)
	case "test":
		gin.SetMode(gin.TestMode)
	default:
		gin.SetMode(gin.ReleaseMode)
	}

	engine := gin.New()

	router := &Router{
		engine:         engine,
		config:         deps.Config,
		logger:         deps.Logger,
		healthHandler:  deps.HealthHandler,
		scanHandler:    deps.ScanHandler,
		reportHandler:  deps.ReportHandler,
		webhookHandler: deps.WebhookHandler,
	}

	router.setupMiddleware()
	router.setupRoutes()

	return router
}

// setupMiddleware configures middleware for the router.
func (r *Router) setupMiddleware() {
	// Recovery middleware
	r.engine.Use(gin.Recovery())

	// Request logging
	r.engine.Use(middleware.RequestLogger(r.logger))

	// CORS
	r.engine.Use(middleware.CORS())

	// Request ID
	r.engine.Use(middleware.RequestID())
}

// setupRoutes configures all API routes.
func (r *Router) setupRoutes() {
	// Health check endpoints (no auth required)
	r.engine.GET("/health", r.healthHandler.Health)
	r.engine.GET("/health/live", r.healthHandler.Liveness)
	r.engine.GET("/health/ready", r.healthHandler.Readiness)

	// API v1 routes
	v1 := r.engine.Group("/api/v1")
	{
		// Apply rate limiting to API routes
		if r.config.RateLimit.Enabled {
			v1.Use(middleware.RateLimiter(middleware.RateLimiterConfig{
				Requests: r.config.RateLimit.Requests,
				Window:   r.config.RateLimit.Window,
				Burst:    r.config.RateLimit.BurstSize,
			}))
		}

		// Webhooks (with signature verification)
		webhooks := v1.Group("/webhooks")
		{
			webhooks.POST("/github", r.webhookHandler.HandleGitHub)
			webhooks.POST("/gitlab", r.webhookHandler.HandleGitLab)
		}

		// Protected routes (require API key)
		protected := v1.Group("")
		protected.Use(middleware.APIKeyAuth())
		{
			// Repositories
			repos := protected.Group("/repositories")
			{
				repos.GET("", r.scanHandler.ListRepositories)
				repos.POST("", r.scanHandler.CreateRepository)
				repos.GET("/:id", r.scanHandler.GetRepository)
				repos.PUT("/:id", r.scanHandler.UpdateRepository)
				repos.DELETE("/:id", r.scanHandler.DeleteRepository)
				repos.GET("/:id/scans", r.scanHandler.GetRepositoryScans)
				repos.GET("/:id/stats", r.scanHandler.GetRepositoryStats)
			}

			// Scans
			scans := protected.Group("/scans")
			{
				scans.POST("", r.scanHandler.CreateScan)
				scans.GET("/:id", r.scanHandler.GetScan)
				scans.GET("/:id/progress", r.scanHandler.GetScanProgress)
				scans.POST("/:id/cancel", r.scanHandler.CancelScan)
				scans.GET("/:id/vulnerabilities", r.scanHandler.GetScanVulnerabilities)
				scans.GET("/:id/summary", r.scanHandler.GetScanSummary)
			}

			// Vulnerabilities
			vulns := protected.Group("/vulnerabilities")
			{
				vulns.GET("/:id", r.scanHandler.GetVulnerability)
				vulns.PATCH("/:id", r.scanHandler.UpdateVulnerability)
				vulns.POST("/:id/analyze", r.scanHandler.AnalyzeVulnerability)
			}

			// Reports
			reports := protected.Group("/reports")
			{
				reports.POST("", r.reportHandler.CreateReport)
				reports.GET("/:id", r.reportHandler.GetReport)
				reports.GET("/:id/download", r.reportHandler.DownloadReport)
				reports.GET("", r.reportHandler.ListReports)
			}

			// Rules
			rules := protected.Group("/rules")
			{
				rules.GET("", r.scanHandler.ListRules)
				rules.GET("/:id", r.scanHandler.GetRule)
			}
		}
	}

	// Catch-all for 404
	r.engine.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "Not Found",
			"message": "The requested resource was not found",
		})
	})
}

// Handler returns the HTTP handler.
func (r *Router) Handler() http.Handler {
	return r.engine
}

// Engine returns the Gin engine.
func (r *Router) Engine() *gin.Engine {
	return r.engine
}
