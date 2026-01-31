// Package config provides configuration management for the application.
// It uses Viper for flexible configuration from multiple sources including
// environment variables, YAML files, and command-line flags.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

// Environment represents the application environment.
type Environment string

const (
	EnvDevelopment Environment = "development"
	EnvStaging     Environment = "staging"
	EnvProduction  Environment = "production"
	EnvTest        Environment = "test"
)

// Config holds all configuration for the application.
// It is designed to be loaded from multiple sources with proper validation.
type Config struct {
	// Environment specifies the application environment (development, staging, production, test).
	Environment Environment `mapstructure:"environment"`

	// Server contains HTTP server configuration.
	Server ServerConfig `mapstructure:"server"`

	// Database contains PostgreSQL database configuration.
	Database DatabaseConfig `mapstructure:"database"`

	// Redis contains Redis cache and queue configuration.
	Redis RedisConfig `mapstructure:"redis"`

	// Git contains Git operations configuration.
	Git GitConfig `mapstructure:"git"`

	// Scanner contains code scanner configuration.
	Scanner ScannerConfig `mapstructure:"scanner"`

	// ADK contains Google ADK/AI agent configuration.
	ADK ADKConfig `mapstructure:"adk"`

	// GitHub contains GitHub integration configuration.
	GitHub GitHubConfig `mapstructure:"github"`

	// Queue contains job queue configuration.
	Queue QueueConfig `mapstructure:"queue"`

	// Logging contains logging configuration.
	Logging LoggingConfig `mapstructure:"logging"`

	// Reporter contains report generation configuration.
	Reporter ReporterConfig `mapstructure:"reporter"`

	// RateLimit contains rate limiting configuration.
	RateLimit RateLimitConfig `mapstructure:"rate_limit"`

	// mu protects the config during hot reload.
	mu sync.RWMutex
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	// Port is the HTTP server port (1-65535).
	Port int `mapstructure:"port"`

	// Host is the HTTP server bind address.
	Host string `mapstructure:"host"`

	// ReadTimeout is the maximum duration for reading the entire request.
	ReadTimeout time.Duration `mapstructure:"read_timeout"`

	// WriteTimeout is the maximum duration before timing out writes of the response.
	WriteTimeout time.Duration `mapstructure:"write_timeout"`

	// IdleTimeout is the maximum amount of time to wait for the next request.
	IdleTimeout time.Duration `mapstructure:"idle_timeout"`

	// ShutdownTimeout is the maximum duration to wait for active connections to close.
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`

	// Mode is the server mode (debug, release, test).
	Mode string `mapstructure:"mode"`

	// TLSEnabled enables HTTPS.
	TLSEnabled bool `mapstructure:"tls_enabled"`

	// TLSCertFile is the path to the TLS certificate file.
	TLSCertFile string `mapstructure:"tls_cert_file"`

	// TLSKeyFile is the path to the TLS key file.
	TLSKeyFile string `mapstructure:"tls_key_file"`

	// CORSAllowedOrigins is a list of allowed CORS origins.
	CORSAllowedOrigins []string `mapstructure:"cors_allowed_origins"`
}

// DatabaseConfig holds PostgreSQL database configuration.
type DatabaseConfig struct {
	// Host is the PostgreSQL server host.
	Host string `mapstructure:"host"`

	// Port is the PostgreSQL server port.
	Port int `mapstructure:"port"`

	// User is the database user.
	User string `mapstructure:"user"`

	// Password is the database password.
	Password string `mapstructure:"password"`

	// DBName is the database name.
	DBName string `mapstructure:"dbname"`

	// SSLMode is the SSL mode (disable, require, verify-ca, verify-full).
	SSLMode string `mapstructure:"ssl_mode"`

	// MaxOpenConns is the maximum number of open connections.
	MaxOpenConns int `mapstructure:"max_open_conns"`

	// MaxIdleConns is the maximum number of idle connections.
	MaxIdleConns int `mapstructure:"max_idle_conns"`

	// ConnMaxLifetime is the maximum connection lifetime.
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`

	// ConnMaxIdleTime is the maximum idle time for a connection.
	ConnMaxIdleTime time.Duration `mapstructure:"conn_max_idle_time"`

	// MigrationsPath is the path to database migration files.
	MigrationsPath string `mapstructure:"migrations_path"`

	// AutoMigrate enables automatic migration on startup.
	AutoMigrate bool `mapstructure:"auto_migrate"`
}

// DSN returns the PostgreSQL connection string.
func (c DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.DBName, c.SSLMode,
	)
}

// RedisConfig holds Redis configuration.
type RedisConfig struct {
	// Host is the Redis server host.
	Host string `mapstructure:"host"`

	// Port is the Redis server port.
	Port int `mapstructure:"port"`

	// Password is the Redis password.
	Password string `mapstructure:"password"`

	// DB is the Redis database number.
	DB int `mapstructure:"db"`

	// PoolSize is the connection pool size.
	PoolSize int `mapstructure:"pool_size"`

	// MinIdleConns is the minimum number of idle connections.
	MinIdleConns int `mapstructure:"min_idle_conns"`

	// DialTimeout is the timeout for establishing new connections.
	DialTimeout time.Duration `mapstructure:"dial_timeout"`

	// ReadTimeout is the timeout for socket reads.
	ReadTimeout time.Duration `mapstructure:"read_timeout"`

	// WriteTimeout is the timeout for socket writes.
	WriteTimeout time.Duration `mapstructure:"write_timeout"`

	// MaxRetries is the maximum number of retries.
	MaxRetries int `mapstructure:"max_retries"`

	// TLSEnabled enables TLS for Redis connections.
	TLSEnabled bool `mapstructure:"tls_enabled"`
}

// Addr returns the Redis address.
func (c RedisConfig) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// GitConfig holds Git operations configuration.
type GitConfig struct {
	// TempDir is the temporary directory for cloning repositories.
	TempDir string `mapstructure:"temp_dir"`

	// CloneTimeout is the maximum duration for cloning a repository.
	CloneTimeout time.Duration `mapstructure:"clone_timeout"`

	// MaxRepoSize is the maximum allowed repository size in bytes.
	MaxRepoSize int64 `mapstructure:"max_repo_size"`

	// SupportedHosts is a list of allowed Git hosts (e.g., github.com, gitlab.com).
	SupportedHosts []string `mapstructure:"supported_hosts"`

	// SSHKeyPath is the path to the SSH private key for Git operations.
	SSHKeyPath string `mapstructure:"ssh_key_path"`

	// CloneDepth is the depth for shallow clones (0 for full clone).
	CloneDepth int `mapstructure:"clone_depth"`

	// MaxConcurrentClones is the maximum number of concurrent clone operations.
	MaxConcurrentClones int `mapstructure:"max_concurrent_clones"`
}

// ScannerConfig holds code scanner configuration.
type ScannerConfig struct {
	// MaxConcurrent is the maximum number of concurrent scans.
	MaxConcurrent int `mapstructure:"max_concurrent"`

	// Timeout is the maximum duration for a single scan.
	Timeout time.Duration `mapstructure:"timeout"`

	// EnabledLanguages is a list of programming languages to scan.
	EnabledLanguages []string `mapstructure:"enabled_languages"`

	// RulesPath is the path to the security rules configuration.
	RulesPath string `mapstructure:"rules_path"`

	// MaxFileSize is the maximum file size to scan in bytes.
	MaxFileSize int64 `mapstructure:"max_file_size"`

	// MaxFilesPerScan is the maximum number of files to scan per repository.
	MaxFilesPerScan int `mapstructure:"max_files_per_scan"`

	// ExcludedPaths is a list of paths to exclude from scanning.
	ExcludedPaths []string `mapstructure:"excluded_paths"`

	// ExcludedExtensions is a list of file extensions to exclude.
	ExcludedExtensions []string `mapstructure:"excluded_extensions"`

	// EnableGosec enables gosec security scanner integration.
	EnableGosec bool `mapstructure:"enable_gosec"`

	// EnableStaticcheck enables staticcheck linter integration.
	EnableStaticcheck bool `mapstructure:"enable_staticcheck"`

	// EnabledRules is a list of enabled security rules.
	EnabledRules []string `mapstructure:"enabled_rules"`

	// CustomRulesPath is the path to custom security rules.
	CustomRulesPath string `mapstructure:"custom_rules_path"`
}

// ADKConfig holds Google ADK/AI agent configuration.
type ADKConfig struct {
	// ProjectID is the Google Cloud project ID.
	ProjectID string `mapstructure:"project_id"`

	// Location is the Google Cloud region.
	Location string `mapstructure:"location"`

	// Model is the AI model to use (e.g., gemini-2.0-flash).
	Model string `mapstructure:"model"`

	// APIKey is the Google API key.
	APIKey string `mapstructure:"api_key"`

	// MaxTokens is the maximum number of tokens in the response.
	MaxTokens int `mapstructure:"max_tokens"`

	// Temperature controls the randomness of the output (0.0-1.0).
	Temperature float64 `mapstructure:"temperature"`

	// Timeout is the maximum duration for AI requests.
	Timeout time.Duration `mapstructure:"timeout"`

	// MaxRetries is the maximum number of retries for failed requests.
	MaxRetries int `mapstructure:"max_retries"`

	// RetryDelay is the delay between retries.
	RetryDelay time.Duration `mapstructure:"retry_delay"`

	// Enabled enables the AI agent features.
	Enabled bool `mapstructure:"enabled"`
}

// GitHubConfig holds GitHub integration configuration.
type GitHubConfig struct {
	// AppID is the GitHub App ID.
	AppID int64 `mapstructure:"app_id"`

	// InstallationID is the GitHub App installation ID.
	InstallationID int64 `mapstructure:"installation_id"`

	// PrivateKeyPath is the path to the GitHub App private key.
	PrivateKeyPath string `mapstructure:"private_key_path"`

	// WebhookSecret is the secret for verifying GitHub webhooks.
	WebhookSecret string `mapstructure:"webhook_secret"`

	// Token is a personal access token (alternative to App authentication).
	Token string `mapstructure:"token"`

	// APIURL is the GitHub API base URL (for GitHub Enterprise).
	APIURL string `mapstructure:"api_url"`

	// EnablePRComments enables posting comments on pull requests.
	EnablePRComments bool `mapstructure:"enable_pr_comments"`

	// EnableCheckRuns enables creating GitHub check runs.
	EnableCheckRuns bool `mapstructure:"enable_check_runs"`
}

// QueueConfig holds job queue configuration.
type QueueConfig struct {
	// Concurrency is the number of concurrent workers.
	Concurrency int `mapstructure:"concurrency"`

	// MaxRetries is the maximum number of retries for failed jobs.
	MaxRetries int `mapstructure:"max_retries"`

	// RetryDelay is the delay between retries.
	RetryDelay time.Duration `mapstructure:"retry_delay"`

	// ShutdownTimeout is the maximum duration to wait for jobs to complete on shutdown.
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`

	// DefaultPriority is the default job priority.
	DefaultPriority int `mapstructure:"default_priority"`

	// EnableScheduler enables the job scheduler.
	EnableScheduler bool `mapstructure:"enable_scheduler"`
}

// LoggingConfig holds logging configuration.
type LoggingConfig struct {
	// Level is the log level (debug, info, warn, error).
	Level string `mapstructure:"level"`

	// Format is the log format (json, text).
	Format string `mapstructure:"format"`

	// Output is the log output (stdout, stderr, file).
	Output string `mapstructure:"output"`

	// FilePath is the log file path when Output is "file".
	FilePath string `mapstructure:"file_path"`

	// MaxSize is the maximum log file size in MB.
	MaxSize int `mapstructure:"max_size"`

	// MaxBackups is the maximum number of old log files to retain.
	MaxBackups int `mapstructure:"max_backups"`

	// MaxAge is the maximum number of days to retain old log files.
	MaxAge int `mapstructure:"max_age"`

	// Compress enables log file compression.
	Compress bool `mapstructure:"compress"`

	// IncludeCaller includes caller information in logs.
	IncludeCaller bool `mapstructure:"include_caller"`
}

// ReporterConfig holds report generation configuration.
type ReporterConfig struct {
	// OutputDir is the directory for generated reports.
	OutputDir string `mapstructure:"output_dir"`

	// TemplateDir is the directory containing report templates.
	TemplateDir string `mapstructure:"template_dir"`

	// EnablePDF enables PDF report generation.
	EnablePDF bool `mapstructure:"enable_pdf"`

	// EnableHTML enables HTML report generation.
	EnableHTML bool `mapstructure:"enable_html"`

	// EnableJSON enables JSON report generation.
	EnableJSON bool `mapstructure:"enable_json"`

	// EnableSARIF enables SARIF report generation.
	EnableSARIF bool `mapstructure:"enable_sarif"`

	// EnableGitHubPR enables GitHub PR comment reports.
	EnableGitHubPR bool `mapstructure:"enable_github_pr"`

	// RetentionDays is the number of days to retain reports.
	RetentionDays int `mapstructure:"retention_days"`
}

// RateLimitConfig holds rate limiting configuration.
type RateLimitConfig struct {
	// Enabled enables rate limiting.
	Enabled bool `mapstructure:"enabled"`

	// Requests is the number of requests allowed per window.
	Requests int `mapstructure:"requests"`

	// Window is the time window for rate limiting.
	Window time.Duration `mapstructure:"window"`

	// BurstSize is the maximum burst size.
	BurstSize int `mapstructure:"burst_size"`

	// ByIP enables rate limiting by IP address.
	ByIP bool `mapstructure:"by_ip"`

	// ByAPIKey enables rate limiting by API key.
	ByAPIKey bool `mapstructure:"by_api_key"`

	// WhitelistedIPs is a list of IPs exempt from rate limiting.
	WhitelistedIPs []string `mapstructure:"whitelisted_ips"`
}

// ConfigManager manages configuration loading and hot reloading.
type ConfigManager struct {
	config     *Config
	viper      *viper.Viper
	mu         sync.RWMutex
	onChange   []func(*Config)
	configPath string
}

// NewConfigManager creates a new ConfigManager.
func NewConfigManager() *ConfigManager {
	return &ConfigManager{
		config:   &Config{},
		viper:    viper.New(),
		onChange: make([]func(*Config), 0),
	}
}

// Load loads configuration from file and environment variables.
func Load(configPath string) (*Config, error) {
	cm := NewConfigManager()
	if err := cm.Load(configPath); err != nil {
		return nil, err
	}
	return cm.config, nil
}

// Load loads configuration from the specified path.
func (cm *ConfigManager) Load(configPath string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.configPath = configPath

	// Set default values
	cm.setDefaults()

	// Determine environment
	env := os.Getenv("APP_ENV")
	if env == "" {
		env = string(EnvDevelopment)
	}

	// Set config file
	if configPath != "" {
		cm.viper.SetConfigFile(configPath)
	} else {
		cm.viper.SetConfigName("config")
		cm.viper.SetConfigType("yaml")
		cm.viper.AddConfigPath(".")
		cm.viper.AddConfigPath("./configs")
		cm.viper.AddConfigPath("/etc/code-security-auditor")
		cm.viper.AddConfigPath("$HOME/.code-security-auditor")

		// Load environment-specific config
		cm.viper.SetConfigName(fmt.Sprintf("config.%s", env))
	}

	// Read config file
	if err := cm.viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found; use defaults and environment variables
	}

	// Environment variables
	cm.viper.SetEnvPrefix("CSA")
	cm.viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	cm.viper.AutomaticEnv()

	// Bind specific environment variables
	cm.bindEnvVariables()

	// Unmarshal config
	if err := cm.viper.Unmarshal(cm.config); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Set environment
	cm.config.Environment = Environment(env)

	// Validate configuration
	if err := cm.config.Validate(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	return nil
}

// Get returns the current configuration (thread-safe).
func (cm *ConfigManager) Get() *Config {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.config
}

// EnableHotReload enables hot reloading of configuration.
func (cm *ConfigManager) EnableHotReload() {
	cm.viper.WatchConfig()
	cm.viper.OnConfigChange(func(e fsnotify.Event) {
		cm.mu.Lock()
		defer cm.mu.Unlock()

		// Reload configuration
		var newConfig Config
		if err := cm.viper.Unmarshal(&newConfig); err != nil {
			// Log error but keep old config
			return
		}

		// Validate new configuration
		if err := newConfig.Validate(); err != nil {
			// Log error but keep old config
			return
		}

		cm.config = &newConfig

		// Notify listeners
		for _, fn := range cm.onChange {
			go fn(cm.config)
		}
	})
}

// OnChange registers a callback for configuration changes.
func (cm *ConfigManager) OnChange(fn func(*Config)) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.onChange = append(cm.onChange, fn)
}

// setDefaults sets default configuration values.
func (cm *ConfigManager) setDefaults() {
	v := cm.viper

	// Environment
	v.SetDefault("environment", string(EnvDevelopment))

	// Server defaults
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.read_timeout", "30s")
	v.SetDefault("server.write_timeout", "30s")
	v.SetDefault("server.idle_timeout", "120s")
	v.SetDefault("server.shutdown_timeout", "30s")
	v.SetDefault("server.mode", "release")
	v.SetDefault("server.tls_enabled", false)
	v.SetDefault("server.cors_allowed_origins", []string{"*"})

	// Database defaults
	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.user", "postgres")
	v.SetDefault("database.password", "postgres")
	v.SetDefault("database.dbname", "code_security_auditor")
	v.SetDefault("database.ssl_mode", "disable")
	v.SetDefault("database.max_open_conns", 25)
	v.SetDefault("database.max_idle_conns", 10)
	v.SetDefault("database.conn_max_lifetime", "5m")
	v.SetDefault("database.conn_max_idle_time", "5m")
	v.SetDefault("database.migrations_path", "./internal/database/migrations")
	v.SetDefault("database.auto_migrate", true)

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
	v.SetDefault("redis.max_retries", 3)
	v.SetDefault("redis.tls_enabled", false)

	// Git defaults
	v.SetDefault("git.temp_dir", "/tmp/code-security-auditor/repos")
	v.SetDefault("git.clone_timeout", "5m")
	v.SetDefault("git.max_repo_size", 104857600) // 100MB
	v.SetDefault("git.supported_hosts", []string{"github.com", "gitlab.com", "bitbucket.org"})
	v.SetDefault("git.clone_depth", 1)
	v.SetDefault("git.max_concurrent_clones", 5)

	// Scanner defaults
	v.SetDefault("scanner.max_concurrent", 4)
	v.SetDefault("scanner.timeout", "30m")
	v.SetDefault("scanner.enabled_languages", []string{"go", "python", "javascript", "typescript", "java", "php", "ruby"})
	v.SetDefault("scanner.rules_path", "./configs/rules.yaml")
	v.SetDefault("scanner.max_file_size", 1048576) // 1MB
	v.SetDefault("scanner.max_files_per_scan", 10000)
	v.SetDefault("scanner.excluded_paths", []string{
		"vendor/", "node_modules/", ".git/", "__pycache__/",
		".idea/", ".vscode/", "dist/", "build/", "target/",
	})
	v.SetDefault("scanner.excluded_extensions", []string{
		".min.js", ".min.css", ".lock", ".sum", ".map",
	})
	v.SetDefault("scanner.enable_gosec", true)
	v.SetDefault("scanner.enable_staticcheck", true)
	v.SetDefault("scanner.enabled_rules", []string{
		"sql_injection", "xss", "secrets", "dependency",
		"path_traversal", "command_injection", "ssrf",
		"insecure_deserialization", "weak_crypto",
	})

	// ADK defaults
	v.SetDefault("adk.location", "us-central1")
	v.SetDefault("adk.model", "gemini-2.0-flash")
	v.SetDefault("adk.max_tokens", 8192)
	v.SetDefault("adk.temperature", 0.1)
	v.SetDefault("adk.timeout", "2m")
	v.SetDefault("adk.max_retries", 3)
	v.SetDefault("adk.retry_delay", "1s")
	v.SetDefault("adk.enabled", true)

	// GitHub defaults
	v.SetDefault("github.api_url", "https://api.github.com")
	v.SetDefault("github.enable_pr_comments", true)
	v.SetDefault("github.enable_check_runs", true)

	// Queue defaults
	v.SetDefault("queue.concurrency", 10)
	v.SetDefault("queue.max_retries", 3)
	v.SetDefault("queue.retry_delay", "30s")
	v.SetDefault("queue.shutdown_timeout", "30s")
	v.SetDefault("queue.default_priority", 0)
	v.SetDefault("queue.enable_scheduler", true)

	// Logging defaults
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.output", "stdout")
	v.SetDefault("logging.file_path", "/var/log/code-security-auditor/app.log")
	v.SetDefault("logging.max_size", 100)
	v.SetDefault("logging.max_backups", 3)
	v.SetDefault("logging.max_age", 28)
	v.SetDefault("logging.compress", true)
	v.SetDefault("logging.include_caller", false)

	// Reporter defaults
	v.SetDefault("reporter.output_dir", "/tmp/code-security-auditor/reports")
	v.SetDefault("reporter.template_dir", "./templates")
	v.SetDefault("reporter.enable_pdf", true)
	v.SetDefault("reporter.enable_html", true)
	v.SetDefault("reporter.enable_json", true)
	v.SetDefault("reporter.enable_sarif", true)
	v.SetDefault("reporter.enable_github_pr", true)
	v.SetDefault("reporter.retention_days", 30)

	// Rate limit defaults
	v.SetDefault("rate_limit.enabled", true)
	v.SetDefault("rate_limit.requests", 100)
	v.SetDefault("rate_limit.window", "1m")
	v.SetDefault("rate_limit.burst_size", 20)
	v.SetDefault("rate_limit.by_ip", true)
	v.SetDefault("rate_limit.by_api_key", true)
	v.SetDefault("rate_limit.whitelisted_ips", []string{})
}

// bindEnvVariables binds specific environment variables.
func (cm *ConfigManager) bindEnvVariables() {
	// Database
	_ = cm.viper.BindEnv("database.host", "CSA_DATABASE_HOST", "POSTGRES_HOST")
	_ = cm.viper.BindEnv("database.port", "CSA_DATABASE_PORT", "POSTGRES_PORT")
	_ = cm.viper.BindEnv("database.user", "CSA_DATABASE_USER", "POSTGRES_USER")
	_ = cm.viper.BindEnv("database.password", "CSA_DATABASE_PASSWORD", "POSTGRES_PASSWORD")
	_ = cm.viper.BindEnv("database.dbname", "CSA_DATABASE_DBNAME", "POSTGRES_DB")

	// Redis
	_ = cm.viper.BindEnv("redis.host", "CSA_REDIS_HOST", "REDIS_HOST")
	_ = cm.viper.BindEnv("redis.port", "CSA_REDIS_PORT", "REDIS_PORT")
	_ = cm.viper.BindEnv("redis.password", "CSA_REDIS_PASSWORD", "REDIS_PASSWORD")

	// ADK
	_ = cm.viper.BindEnv("adk.project_id", "CSA_ADK_PROJECT_ID", "GOOGLE_CLOUD_PROJECT")
	_ = cm.viper.BindEnv("adk.api_key", "CSA_ADK_API_KEY", "GOOGLE_API_KEY")

	// GitHub
	_ = cm.viper.BindEnv("github.token", "CSA_GITHUB_TOKEN", "GITHUB_TOKEN")
	_ = cm.viper.BindEnv("github.webhook_secret", "CSA_GITHUB_WEBHOOK_SECRET", "GITHUB_WEBHOOK_SECRET")
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	var errs []error

	// Validate server config
	if err := c.Server.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("server: %w", err))
	}

	// Validate database config
	if err := c.Database.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("database: %w", err))
	}

	// Validate Redis config
	if err := c.Redis.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("redis: %w", err))
	}

	// Validate Git config
	if err := c.Git.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("git: %w", err))
	}

	// Validate Scanner config
	if err := c.Scanner.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("scanner: %w", err))
	}

	// Validate ADK config
	if err := c.ADK.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("adk: %w", err))
	}

	// Validate Queue config
	if err := c.Queue.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("queue: %w", err))
	}

	// Validate Logging config
	if err := c.Logging.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("logging: %w", err))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

// Validate validates the server configuration.
func (c ServerConfig) Validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", c.Port)
	}

	if c.ReadTimeout <= 0 {
		return errors.New("read_timeout must be positive")
	}

	if c.WriteTimeout <= 0 {
		return errors.New("write_timeout must be positive")
	}

	if c.TLSEnabled {
		if c.TLSCertFile == "" {
			return errors.New("tls_cert_file is required when TLS is enabled")
		}
		if c.TLSKeyFile == "" {
			return errors.New("tls_key_file is required when TLS is enabled")
		}
	}

	validModes := map[string]bool{"debug": true, "release": true, "test": true}
	if !validModes[c.Mode] {
		return fmt.Errorf("invalid mode: %s (must be debug, release, or test)", c.Mode)
	}

	return nil
}

// Validate validates the database configuration.
func (c DatabaseConfig) Validate() error {
	if c.Host == "" {
		return errors.New("host is required")
	}

	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", c.Port)
	}

	if c.User == "" {
		return errors.New("user is required")
	}

	if c.DBName == "" {
		return errors.New("dbname is required")
	}

	validSSLModes := map[string]bool{
		"disable": true, "require": true, "verify-ca": true, "verify-full": true,
	}
	if !validSSLModes[c.SSLMode] {
		return fmt.Errorf("invalid ssl_mode: %s", c.SSLMode)
	}

	if c.MaxOpenConns < 1 {
		return errors.New("max_open_conns must be at least 1")
	}

	if c.MaxIdleConns < 0 {
		return errors.New("max_idle_conns cannot be negative")
	}

	if c.MaxIdleConns > c.MaxOpenConns {
		return errors.New("max_idle_conns cannot exceed max_open_conns")
	}

	return nil
}

// Validate validates the Redis configuration.
func (c RedisConfig) Validate() error {
	if c.Host == "" {
		return errors.New("host is required")
	}

	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", c.Port)
	}

	if c.DB < 0 || c.DB > 15 {
		return fmt.Errorf("db must be between 0 and 15, got %d", c.DB)
	}

	if c.PoolSize < 1 {
		return errors.New("pool_size must be at least 1")
	}

	return nil
}

// Validate validates the Git configuration.
func (c GitConfig) Validate() error {
	if c.TempDir == "" {
		return errors.New("temp_dir is required")
	}

	if c.CloneTimeout <= 0 {
		return errors.New("clone_timeout must be positive")
	}

	if c.MaxRepoSize <= 0 {
		return errors.New("max_repo_size must be positive")
	}

	if len(c.SupportedHosts) == 0 {
		return errors.New("at least one supported_host is required")
	}

	// Validate supported hosts are valid hostnames
	for _, host := range c.SupportedHosts {
		if _, err := url.Parse("https://" + host); err != nil {
			return fmt.Errorf("invalid supported_host: %s", host)
		}
	}

	return nil
}

// Validate validates the Scanner configuration.
func (c ScannerConfig) Validate() error {
	if c.MaxConcurrent < 1 {
		return errors.New("max_concurrent must be at least 1")
	}

	if c.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}

	if c.MaxFileSize <= 0 {
		return errors.New("max_file_size must be positive")
	}

	if c.MaxFilesPerScan <= 0 {
		return errors.New("max_files_per_scan must be positive")
	}

	return nil
}

// Validate validates the ADK configuration.
func (c ADKConfig) Validate() error {
	if !c.Enabled {
		return nil // Skip validation if ADK is disabled
	}

	if c.ProjectID == "" && c.APIKey == "" {
		return errors.New("either project_id or api_key is required")
	}

	if c.Model == "" {
		return errors.New("model is required")
	}

	if c.Temperature < 0 || c.Temperature > 1 {
		return fmt.Errorf("temperature must be between 0 and 1, got %f", c.Temperature)
	}

	if c.MaxTokens < 1 {
		return errors.New("max_tokens must be at least 1")
	}

	if c.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}

	return nil
}

// Validate validates the Queue configuration.
func (c QueueConfig) Validate() error {
	if c.Concurrency < 1 {
		return errors.New("concurrency must be at least 1")
	}

	if c.MaxRetries < 0 {
		return errors.New("max_retries cannot be negative")
	}

	if c.RetryDelay < 0 {
		return errors.New("retry_delay cannot be negative")
	}

	if c.ShutdownTimeout <= 0 {
		return errors.New("shutdown_timeout must be positive")
	}

	return nil
}

// Validate validates the Logging configuration.
func (c LoggingConfig) Validate() error {
	validLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true, "fatal": true,
	}
	if !validLevels[c.Level] {
		return fmt.Errorf("invalid level: %s", c.Level)
	}

	validFormats := map[string]bool{"json": true, "text": true}
	if !validFormats[c.Format] {
		return fmt.Errorf("invalid format: %s", c.Format)
	}

	validOutputs := map[string]bool{"stdout": true, "stderr": true, "file": true}
	if !validOutputs[c.Output] {
		return fmt.Errorf("invalid output: %s", c.Output)
	}

	if c.Output == "file" {
		if c.FilePath == "" {
			return errors.New("file_path is required when output is 'file'")
		}

		// Ensure directory exists or can be created
		dir := filepath.Dir(c.FilePath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("cannot create log directory: %w", err)
		}
	}

	return nil
}

// IsDevelopment returns true if the environment is development.
func (c *Config) IsDevelopment() bool {
	return c.Environment == EnvDevelopment
}

// IsProduction returns true if the environment is production.
func (c *Config) IsProduction() bool {
	return c.Environment == EnvProduction
}

// IsTest returns true if the environment is test.
func (c *Config) IsTest() bool {
	return c.Environment == EnvTest
}

// MustLoad loads configuration and panics on error.
func MustLoad(configPath string) *Config {
	cfg, err := Load(configPath)
	if err != nil {
		panic(fmt.Sprintf("failed to load config: %v", err))
	}
	return cfg
}
