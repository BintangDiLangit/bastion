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
	engine        *gin.Engine
	config        *config.Config
	logger        *logrus.Logger
	healthHandler *handlers.HealthHandler
	scanHandler   *handlers.ScanLifecycleHandler
}

// RouterDeps holds dependencies for the router.
type RouterDeps struct {
	Config        *config.Config
	Logger        *logrus.Logger
	HealthHandler *handlers.HealthHandler
	ScanHandler   *handlers.ScanLifecycleHandler
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

	// ClientIP() honours X-Forwarded-For / X-Real-IP for trusted proxies, and
	// gin trusts every proxy by default. The rate limiter keys on ClientIP, so
	// a caller could rotate that header and get an unlimited number of buckets.
	// Trust nothing: ClientIP() then returns the real socket address.
	// ponytail: if you deploy behind a load balancer, set this to that
	// balancer's address rather than removing the call.
	if err := engine.SetTrustedProxies(nil); err != nil {
		deps.Logger.WithError(err).Warn("failed to clear trusted proxies")
	}

	router := &Router{
		engine:        engine,
		config:        deps.Config,
		logger:        deps.Logger,
		healthHandler: deps.HealthHandler,
		scanHandler:   deps.ScanHandler,
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
	r.engine.Use(middleware.CORS(r.config.Server.CORSAllowedOrigins))
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

		// Protected routes (require API key)
		protected := v1.Group("")
		protected.Use(middleware.APIKeyAuth(r.config.Server.APIKey))
		{
			// Scans
			scans := protected.Group("/scans")
			{
				scans.POST("", r.scanHandler.Create)
				scans.GET("/:id", r.scanHandler.Get)
				scans.POST("/:id/cancel", r.scanHandler.Cancel)
				scans.GET("/:id/vulnerabilities", r.scanHandler.Findings)
				scans.GET("/:id/delta", r.scanHandler.Delta)
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
