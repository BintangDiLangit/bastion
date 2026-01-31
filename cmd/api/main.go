// Package main provides the API server entry point.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"code-security-auditor/internal/api"
	"code-security-auditor/internal/api/handlers"
	"code-security-auditor/internal/config"
	"code-security-auditor/internal/database"
	"code-security-auditor/internal/scanner/rules"
	"code-security-auditor/pkg/logger"
)

func main() {
	// Load configuration
	cfg, err := config.Load("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	log := logger.New(cfg.Logging)
	log.Info("Starting Code Security Auditor API Server")

	// Initialize database
	db, err := database.NewPostgresDB(cfg.Database, log)
	if err != nil {
		log.WithError(err).Fatal("Failed to connect to database")
	}
	defer db.Close()

	// Run migrations
	if err := db.RunMigrations(context.Background()); err != nil {
		log.WithError(err).Fatal("Failed to run migrations")
	}

	// Initialize Redis
	redis, err := database.NewRedisClient(cfg.Redis, log)
	if err != nil {
		log.WithError(err).Fatal("Failed to connect to Redis")
	}
	defer redis.Close()

	// Initialize rule engine
	ruleEngine := rules.NewEngine(cfg.Scanner, log)
	ruleEngine.Register(rules.NewSQLInjectionRule())
	ruleEngine.Register(rules.NewXSSRule())
	ruleEngine.Register(rules.NewSecretsRule())
	ruleEngine.Register(rules.NewDependencyRule())

	// Initialize handlers
	healthHandler := handlers.NewHealthHandler(log, db, redis, "1.0.0")

	// Note: In production, these would be properly injected services
	var scanService handlers.ScanService // = services.NewScanService(...)
	var aiService handlers.AIService     // = services.NewAIService(...)

	scanHandler := handlers.NewScanHandler(scanService, aiService, ruleEngine, log)

	var reportService handlers.ReportService // = services.NewReportService(...)
	reportHandler := handlers.NewReportHandler(reportService, log)

	var webhookService handlers.WebhookService // = services.NewWebhookService(...)
	webhookHandler := handlers.NewWebhookHandler(webhookService, log)

	// Initialize router
	router := api.NewRouter(api.RouterDeps{
		Config:         cfg,
		Logger:         log,
		HealthHandler:  healthHandler,
		ScanHandler:    scanHandler,
		ReportHandler:  reportHandler,
		WebhookHandler: webhookHandler,
	})

	// Create HTTP server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	server := &http.Server{
		Addr:         addr,
		Handler:      router.Handler(),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	// Start server in goroutine
	go func() {
		log.WithField("address", addr).Info("Starting HTTP server")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.WithError(err).Fatal("HTTP server error")
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.WithError(err).Error("Server forced to shutdown")
	}

	log.Info("Server stopped")
}
