// Package config provides configuration management for the application.
// It uses Viper for flexible configuration from multiple sources.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for the application.
type Config struct {
	Server    ServerConfig    `mapstructure:"server"`
	Database  DatabaseConfig  `mapstructure:"database"`
	Redis     RedisConfig     `mapstructure:"redis"`
	Git       GitConfig       `mapstructure:"git"`
	Agent     AgentConfig     `mapstructure:"agent"`
	Scanner   ScannerConfig   `mapstructure:"scanner"`
	Reporter  ReporterConfig  `mapstructure:"reporter"`
	Queue     QueueConfig     `mapstructure:"queue"`
	Logger    LoggerConfig    `mapstructure:"logger"`
	RateLimit RateLimitConfig `mapstructure:"rate_limit"`
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
	Mode            string        `mapstructure:"mode"` // debug, release, test
}

// DatabaseConfig holds PostgreSQL database configuration.
type DatabaseConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	User            string        `mapstructure:"user"`
	Password        string        `mapstructure:"password"`
	Database        string        `mapstructure:"database"`
	SSLMode         string        `mapstructure:"ssl_mode"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

// DSN returns the database connection string.
func (c DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.Database, c.SSLMode,
	)
}

// RedisConfig holds Redis configuration.
type RedisConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	Password     string        `mapstructure:"password"`
	DB           int           `mapstructure:"db"`
	PoolSize     int           `mapstructure:"pool_size"`
	MinIdleConns int           `mapstructure:"min_idle_conns"`
	DialTimeout  time.Duration `mapstructure:"dial_timeout"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
}

// Addr returns the Redis address.
func (c RedisConfig) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// GitConfig holds Git operations configuration.
type GitConfig struct {
	CloneDir     string        `mapstructure:"clone_dir"`
	CloneTimeout time.Duration `mapstructure:"clone_timeout"`
	MaxRepoSize  int64         `mapstructure:"max_repo_size"` // in bytes
}

// AgentConfig holds Google ADK agent configuration.
type AgentConfig struct {
	ProjectID   string        `mapstructure:"project_id"`
	Location    string        `mapstructure:"location"`
	Model       string        `mapstructure:"model"`
	APIKey      string        `mapstructure:"api_key"`
	MaxTokens   int           `mapstructure:"max_tokens"`
	Temperature float32       `mapstructure:"temperature"`
	Timeout     time.Duration `mapstructure:"timeout"`
}

// ScannerConfig holds code scanner configuration.
type ScannerConfig struct {
	MaxFileSize       int64         `mapstructure:"max_file_size"` // in bytes
	MaxFilesPerScan   int           `mapstructure:"max_files_per_scan"`
	ScanTimeout       time.Duration `mapstructure:"scan_timeout"`
	EnabledRules      []string      `mapstructure:"enabled_rules"`
	ExcludedPaths     []string      `mapstructure:"excluded_paths"`
	ExcludedExtensions []string     `mapstructure:"excluded_extensions"`
	ConcurrentWorkers int           `mapstructure:"concurrent_workers"`
}

// ReporterConfig holds report generation configuration.
type ReporterConfig struct {
	OutputDir       string `mapstructure:"output_dir"`
	TemplateDir     string `mapstructure:"template_dir"`
	EnablePDF       bool   `mapstructure:"enable_pdf"`
	EnableGitHubPR  bool   `mapstructure:"enable_github_pr"`
	GitHubToken     string `mapstructure:"github_token"`
	GitLabToken     string `mapstructure:"gitlab_token"`
}

// QueueConfig holds job queue configuration.
type QueueConfig struct {
	Concurrency     int           `mapstructure:"concurrency"`
	RetryLimit      int           `mapstructure:"retry_limit"`
	RetryDelay      time.Duration `mapstructure:"retry_delay"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
}

// LoggerConfig holds logging configuration.
type LoggerConfig struct {
	Level      string `mapstructure:"level"` // debug, info, warn, error
	Format     string `mapstructure:"format"` // json, text
	Output     string `mapstructure:"output"` // stdout, file
	FilePath   string `mapstructure:"file_path"`
	MaxSize    int    `mapstructure:"max_size"`    // megabytes
	MaxBackups int    `mapstructure:"max_backups"`
	MaxAge     int    `mapstructure:"max_age"` // days
}

// RateLimitConfig holds rate limiting configuration.
type RateLimitConfig struct {
	Enabled     bool          `mapstructure:"enabled"`
	Requests    int           `mapstructure:"requests"`
	Window      time.Duration `mapstructure:"window"`
	BurstSize   int           `mapstructure:"burst_size"`
}

// Load loads configuration from file and environment variables.
func Load(configPath string) (*Config, error) {
	v := viper.New()

	// Set default values
	setDefaults(v)

	// Set config file
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("./configs")
		v.AddConfigPath("/etc/code-security-auditor")
	}

	// Read config file
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found; use defaults and environment variables
	}

	// Environment variables
	v.SetEnvPrefix("CSA")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Unmarshal config
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

// setDefaults sets default configuration values.
func setDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.read_timeout", "30s")
	v.SetDefault("server.write_timeout", "30s")
	v.SetDefault("server.shutdown_timeout", "10s")
	v.SetDefault("server.mode", "release")

	// Database defaults
	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.user", "postgres")
	v.SetDefault("database.password", "postgres")
	v.SetDefault("database.database", "code_security_auditor")
	v.SetDefault("database.ssl_mode", "disable")
	v.SetDefault("database.max_open_conns", 25)
	v.SetDefault("database.max_idle_conns", 5)
	v.SetDefault("database.conn_max_lifetime", "5m")

	// Redis defaults
	v.SetDefault("redis.host", "localhost")
	v.SetDefault("redis.port", 6379)
	v.SetDefault("redis.password", "")
	v.SetDefault("redis.db", 0)
	v.SetDefault("redis.pool_size", 10)
	v.SetDefault("redis.min_idle_conns", 3)
	v.SetDefault("redis.dial_timeout", "5s")
	v.SetDefault("redis.read_timeout", "3s")
	v.SetDefault("redis.write_timeout", "3s")

	// Git defaults
	v.SetDefault("git.clone_dir", "/tmp/code-security-auditor/repos")
	v.SetDefault("git.clone_timeout", "5m")
	v.SetDefault("git.max_repo_size", 104857600) // 100MB

	// Agent defaults
	v.SetDefault("agent.location", "us-central1")
	v.SetDefault("agent.model", "gemini-2.0-flash")
	v.SetDefault("agent.max_tokens", 8192)
	v.SetDefault("agent.temperature", 0.1)
	v.SetDefault("agent.timeout", "2m")

	// Scanner defaults
	v.SetDefault("scanner.max_file_size", 1048576) // 1MB
	v.SetDefault("scanner.max_files_per_scan", 1000)
	v.SetDefault("scanner.scan_timeout", "30m")
	v.SetDefault("scanner.concurrent_workers", 4)
	v.SetDefault("scanner.enabled_rules", []string{
		"sql_injection",
		"xss",
		"secrets",
		"dependency",
		"hardcoded_credentials",
		"path_traversal",
		"command_injection",
	})
	v.SetDefault("scanner.excluded_paths", []string{
		"vendor/",
		"node_modules/",
		".git/",
		"__pycache__/",
		".idea/",
		".vscode/",
	})
	v.SetDefault("scanner.excluded_extensions", []string{
		".min.js",
		".min.css",
		".lock",
		".sum",
	})

	// Reporter defaults
	v.SetDefault("reporter.output_dir", "/tmp/code-security-auditor/reports")
	v.SetDefault("reporter.template_dir", "./templates")
	v.SetDefault("reporter.enable_pdf", true)
	v.SetDefault("reporter.enable_github_pr", true)

	// Queue defaults
	v.SetDefault("queue.concurrency", 5)
	v.SetDefault("queue.retry_limit", 3)
	v.SetDefault("queue.retry_delay", "10s")
	v.SetDefault("queue.shutdown_timeout", "30s")

	// Logger defaults
	v.SetDefault("logger.level", "info")
	v.SetDefault("logger.format", "json")
	v.SetDefault("logger.output", "stdout")
	v.SetDefault("logger.file_path", "/var/log/code-security-auditor/app.log")
	v.SetDefault("logger.max_size", 100)
	v.SetDefault("logger.max_backups", 3)
	v.SetDefault("logger.max_age", 28)

	// Rate limit defaults
	v.SetDefault("rate_limit.enabled", true)
	v.SetDefault("rate_limit.requests", 100)
	v.SetDefault("rate_limit.window", "1m")
	v.SetDefault("rate_limit.burst_size", 10)
}

// MustLoad loads configuration and panics on error.
func MustLoad(configPath string) *Config {
	cfg, err := Load(configPath)
	if err != nil {
		panic(fmt.Sprintf("failed to load config: %v", err))
	}
	return cfg
}
