// Package api provides the HTTP API for the code security auditor.
package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"code-security-auditor/internal/api/handlers"
	"code-security-auditor/internal/api/middleware"
	"code-security-auditor/internal/config"
)

// Router holds the HTTP router and its dependencies.
type Router struct {
	engine         *gin.Engine
	config         *config.Config
	logger         *logrus.Logger
	healthHandler       *handlers.HealthHandler
	scanHandler         *handlers.ScanHandler
	reportHandler       *handlers.ReportHandler
	webhookHandler      *handlers.WebhookHandler
	dependencyHandler   *handlers.DependencyHandler
}

// RouterDeps holds dependencies for the router.
type RouterDeps struct {
	Config         *config.Config
	Logger         *logrus.Logger
	HealthHandler       *handlers.HealthHandler
	ScanHandler         *handlers.ScanHandler
	ReportHandler       *handlers.ReportHandler
	WebhookHandler      *handlers.WebhookHandler
	DependencyHandler   *handlers.DependencyHandler
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

	// Add dependency handler if provided
	if deps.DependencyHandler != nil {
		router.dependencyHandler = deps.DependencyHandler
	}

	router.setupMiddleware()
	router.setupRoutes()

	return router
}

// setupMiddleware configures middleware for the router.
func (r *Router) setupMiddleware() {
	// Recovery middleware with logger
	r.engine.Use(middleware.Recovery(r.logger))

	// Request logging
	r.engine.Use(middleware.RequestLogger(r.logger))

	// CORS and Security Headers
	r.engine.Use(middleware.CORS())
	r.engine.Use(middleware.SecurityHeaders())

	// Request validation
	r.engine.Use(middleware.MaxBodySize(10 * 1024 * 1024)) // 10MB limit

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

				// Dependency scanning endpoints
				if r.dependencyHandler != nil {
					depScans := scans.Group("/:id/dependencies")
					{
						depScans.POST("", r.dependencyHandler.TriggerDependencyScan)
						depScans.GET("/:dependency_scan_id", r.dependencyHandler.GetDependencyScanResults)
						depScans.GET("/:dependency_scan_id/sbom", r.dependencyHandler.GetSBOM)
						depScans.POST("/:dependency_scan_id/upgrade-plan", r.dependencyHandler.GenerateUpgradePlan)
					}
				}
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

			// Dependency endpoints
			if r.dependencyHandler != nil {
				deps := protected.Group("/dependencies")
				{
					deps.POST("/check", r.dependencyHandler.CheckSingleDependency)
					deps.GET("/vulnerabilities/:cve_id", r.dependencyHandler.GetVulnerabilityDetails)
				}
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
