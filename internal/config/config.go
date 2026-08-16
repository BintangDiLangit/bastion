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

	// Git contains Git operations configuration.
	Git GitConfig `mapstructure:"git"`

	// Scanner contains code scanner configuration.
	Scanner ScannerConfig `mapstructure:"scanner"`

	// Logging contains logging configuration.
	Logging LoggingConfig `mapstructure:"logging"`

	// RateLimit contains rate limiting configuration.
	RateLimit RateLimitConfig `mapstructure:"rate_limit"`

	// mu protects the config during hot reload.
	mu sync.RWMutex
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	// APIKey authenticates API requests. Set with CSA_SERVER_API_KEY.
	APIKey string `mapstructure:"api_key"`
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

	// MaxFileSize is the maximum file size to scan in bytes.
	MaxFileSize int64 `mapstructure:"max_file_size"`

	// MaxFilesPerScan is the maximum number of files to scan per repository.
	MaxFilesPerScan int `mapstructure:"max_files_per_scan"`

	// ExcludedPaths is a list of paths to exclude from scanning.
	ExcludedPaths []string `mapstructure:"excluded_paths"`

	// ExcludedExtensions is a list of file extensions to exclude.
	ExcludedExtensions []string `mapstructure:"excluded_extensions"`

	// EnabledRules is a list of enabled security rules.
	EnabledRules []string `mapstructure:"enabled_rules"`
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
		cm.viper.AddConfigPath("/etc/bastion")
		cm.viper.AddConfigPath("$HOME/.bastion")

		// Load environment-specific config
		cm.viper.SetConfigName(fmt.Sprintf("config.%s", env))
	}

	// Read config file
	if err := cm.viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return fmt.Errorf("failed to read config file: %w", err)
		}
		if configPath == "" {
			cm.viper.SetConfigName("config")
			if err := cm.viper.ReadInConfig(); err != nil {
				if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
					return fmt.Errorf("failed to read config file: %w", err)
				}
			}
		}
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

	// Git defaults
	v.SetDefault("git.temp_dir", "/tmp/bastion/repos")
	v.SetDefault("git.clone_timeout", "5m")
	v.SetDefault("git.max_repo_size", 104857600) // 100MB
	v.SetDefault("git.supported_hosts", []string{"github.com", "gitlab.com", "bitbucket.org"})
	v.SetDefault("git.clone_depth", 1)
	v.SetDefault("git.max_concurrent_clones", 5)

	// Scanner defaults
	v.SetDefault("scanner.max_concurrent", 4)
	v.SetDefault("scanner.timeout", "30m")
	v.SetDefault("scanner.max_file_size", 1048576) // 1MB
	v.SetDefault("scanner.max_files_per_scan", 10000)
	v.SetDefault("scanner.excluded_paths", []string{
		"vendor/", "node_modules/", ".git/", "__pycache__/",
		".idea/", ".vscode/", "dist/", "build/", "target/",
	})
	v.SetDefault("scanner.excluded_extensions", []string{
		".min.js", ".min.css", ".lock", ".sum", ".map",
	})
	// Empty means every rule runs. A non-empty list is a filter, so a default
	// listing rule IDs would silently disable anything not on it.
	v.SetDefault("scanner.enabled_rules", []string{})

	// Logging defaults
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.output", "stdout")
	v.SetDefault("logging.file_path", "/var/log/bastion/app.log")
	v.SetDefault("logging.max_size", 100)
	v.SetDefault("logging.max_backups", 3)
	v.SetDefault("logging.max_age", 28)
	v.SetDefault("logging.compress", true)
	v.SetDefault("logging.include_caller", false)

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
	_ = cm.viper.BindEnv("server.api_key", "CSA_SERVER_API_KEY")

	// Database
	_ = cm.viper.BindEnv("database.host", "CSA_DATABASE_HOST", "POSTGRES_HOST")
	_ = cm.viper.BindEnv("database.port", "CSA_DATABASE_PORT", "POSTGRES_PORT")
	_ = cm.viper.BindEnv("database.user", "CSA_DATABASE_USER", "POSTGRES_USER")
	_ = cm.viper.BindEnv("database.password", "CSA_DATABASE_PASSWORD", "POSTGRES_PASSWORD")
	_ = cm.viper.BindEnv("database.dbname", "CSA_DATABASE_DBNAME", "POSTGRES_DB")

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

	// Validate Git config
	if err := c.Git.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("git: %w", err))
	}

	// Validate Scanner config
	if err := c.Scanner.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("scanner: %w", err))
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
