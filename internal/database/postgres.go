// Package database provides database connection and operations.
package database

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"

	"code-security-auditor/internal/config"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

var (
	// ErrNotFound is returned when a record is not found.
	ErrNotFound = errors.New("record not found")

	// ErrDuplicateKey is returned when a unique constraint is violated.
	ErrDuplicateKey = errors.New("duplicate key violation")

	// ErrForeignKey is returned when a foreign key constraint is violated.
	ErrForeignKey = errors.New("foreign key violation")
)

// PostgresDB wraps the sqlx.DB with additional functionality.
type PostgresDB struct {
	*sqlx.DB
	logger     *logrus.Logger
	config     config.DatabaseConfig
	mu         sync.RWMutex
	healthOnce sync.Once
	healthy    bool
}

// NewPostgresDB creates a new PostgreSQL database connection with connection pooling.
func NewPostgresDB(cfg config.DatabaseConfig, logger *logrus.Logger) (*PostgresDB, error) {
	// Build connection string
	dsn := cfg.DSN()

	logger.WithFields(logrus.Fields{
		"host":     cfg.Host,
		"port":     cfg.Port,
		"database": cfg.DBName,
		"user":     cfg.User,
		"ssl_mode": cfg.SSLMode,
	}).Debug("Connecting to PostgreSQL database")

	// Connect to database
	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	if cfg.ConnMaxIdleTime > 0 {
		db.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)
	}

	pgDB := &PostgresDB{
		DB:     db,
		logger: logger,
		config: cfg,
	}

	// Verify connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := pgDB.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	logger.Info("Successfully connected to PostgreSQL database")

	// Run migrations if auto-migrate is enabled
	if cfg.AutoMigrate {
		if err := pgDB.RunMigrations(ctx); err != nil {
			logger.WithError(err).Warn("Failed to run migrations automatically")
		}
	}

	return pgDB, nil
}

// Close closes the database connection gracefully.
func (db *PostgresDB) Close() error {
	db.logger.Info("Closing PostgreSQL database connection")

	db.mu.Lock()
	defer db.mu.Unlock()

	return db.DB.Close()
}

// Health checks the database health.
func (db *PostgresDB) Health(ctx context.Context) error {
	return db.PingContext(ctx)
}

// HealthCheck performs a comprehensive health check.
func (db *PostgresDB) HealthCheck(ctx context.Context) (*HealthStatus, error) {
	status := &HealthStatus{
		Status:    "healthy",
		Timestamp: time.Now(),
	}

	// Check connection
	start := time.Now()
	if err := db.PingContext(ctx); err != nil {
		status.Status = "unhealthy"
		status.Error = err.Error()
		return status, err
	}
	status.Latency = time.Since(start)

	// Get pool stats
	stats := db.Stats()
	status.Connections = ConnectionStats{
		MaxOpenConnections: stats.MaxOpenConnections,
		OpenConnections:    stats.OpenConnections,
		InUse:              stats.InUse,
		Idle:               stats.Idle,
		WaitCount:          stats.WaitCount,
		WaitDuration:       stats.WaitDuration,
	}

	// Check if we're near connection limit
	if float64(stats.OpenConnections)/float64(stats.MaxOpenConnections) > 0.9 {
		status.Status = "degraded"
		status.Warning = "connection pool nearly exhausted"
	}

	return status, nil
}

// HealthStatus represents the database health status.
type HealthStatus struct {
	Status      string          `json:"status"`
	Timestamp   time.Time       `json:"timestamp"`
	Latency     time.Duration   `json:"latency"`
	Connections ConnectionStats `json:"connections"`
	Error       string          `json:"error,omitempty"`
	Warning     string          `json:"warning,omitempty"`
}

// ConnectionStats represents database connection pool statistics.
type ConnectionStats struct {
	MaxOpenConnections int           `json:"max_open_connections"`
	OpenConnections    int           `json:"open_connections"`
	InUse              int           `json:"in_use"`
	Idle               int           `json:"idle"`
	WaitCount          int64         `json:"wait_count"`
	WaitDuration       time.Duration `json:"wait_duration"`
}

// RunMigrations runs database migrations.
func (db *PostgresDB) RunMigrations(ctx context.Context) error {
	db.logger.Info("Running database migrations")

	// Create migrations table if not exists
	createMigrationsTable := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version VARCHAR(255) PRIMARY KEY,
			name VARCHAR(255),
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			checksum VARCHAR(64)
		)
	`
	if _, err := db.ExecContext(ctx, createMigrationsTable); err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Read migration files
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("failed to read migrations directory: %w", err)
	}

	// Sort migrations by name
	var migrations []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			migrations = append(migrations, entry.Name())
		}
	}
	sort.Strings(migrations)

	// Apply migrations
	for _, version := range migrations {
		// Check if migration already applied
		var count int
		err := db.GetContext(ctx, &count, "SELECT COUNT(*) FROM schema_migrations WHERE version = $1", version)
		if err != nil {
			return fmt.Errorf("failed to check migration status: %w", err)
		}

		if count > 0 {
			db.logger.Debugf("Migration %s already applied, skipping", version)
			continue
		}

		// Read and execute migration
		content, err := migrationsFS.ReadFile("migrations/" + version)
		if err != nil {
			return fmt.Errorf("failed to read migration %s: %w", version, err)
		}

		// Execute in transaction
		tx, err := db.BeginTxx(ctx, nil)
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}

		if _, err := tx.ExecContext(ctx, string(content)); err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to execute migration %s: %w", version, err)
		}

		// Record migration
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO schema_migrations (version, name) VALUES ($1, $2)",
			version, version,
		); err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to record migration %s: %w", version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit migration %s: %w", version, err)
		}

		db.logger.Infof("Applied migration: %s", version)
	}

	db.logger.Info("All migrations completed successfully")
	return nil
}

// RollbackMigration rolls back the last migration.
func (db *PostgresDB) RollbackMigration(ctx context.Context) error {
	db.logger.Info("Rolling back last migration")

	// Get last applied migration
	var version string
	err := db.GetContext(ctx, &version,
		"SELECT version FROM schema_migrations ORDER BY applied_at DESC LIMIT 1",
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("no migrations to rollback")
		}
		return fmt.Errorf("failed to get last migration: %w", err)
	}

	// Look for rollback file
	rollbackFile := strings.Replace(version, ".sql", "_rollback.sql", 1)
	content, err := migrationsFS.ReadFile("migrations/" + rollbackFile)
	if err != nil {
		return fmt.Errorf("rollback file not found for %s", version)
	}

	// Execute rollback in transaction
	tx, err := db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	if _, err := tx.ExecContext(ctx, string(content)); err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to execute rollback: %w", err)
	}

	if _, err := tx.ExecContext(ctx, "DELETE FROM schema_migrations WHERE version = $1", version); err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to remove migration record: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit rollback: %w", err)
	}

	db.logger.Infof("Rolled back migration: %s", version)
	return nil
}

// WithTransaction executes a function within a transaction.
func (db *PostgresDB) WithTransaction(ctx context.Context, fn func(tx *sqlx.Tx) error) error {
	tx, err := db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			db.logger.WithError(rbErr).Error("Failed to rollback transaction")
			return fmt.Errorf("tx error: %v, rollback error: %w", err, rbErr)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// WithTransactionOptions executes a function within a transaction with custom options.
func (db *PostgresDB) WithTransactionOptions(ctx context.Context, opts *sql.TxOptions, fn func(tx *sqlx.Tx) error) error {
	tx, err := db.BeginTxx(ctx, opts)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			db.logger.WithError(rbErr).Error("Failed to rollback transaction")
			return fmt.Errorf("tx error: %v, rollback error: %w", err, rbErr)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// Stats returns database pool statistics.
func (db *PostgresDB) Stats() sql.DBStats {
	return db.DB.Stats()
}

// DBStats represents database connection pool statistics (JSON-friendly).
type DBStats struct {
	MaxOpenConnections int           `json:"max_open_connections"`
	OpenConnections    int           `json:"open_connections"`
	InUse              int           `json:"in_use"`
	Idle               int           `json:"idle"`
	WaitCount          int64         `json:"wait_count"`
	WaitDuration       time.Duration `json:"wait_duration"`
	MaxIdleClosed      int64         `json:"max_idle_closed"`
	MaxLifetimeClosed  int64         `json:"max_lifetime_closed"`
}

// GetStats returns database statistics as a struct.
func (db *PostgresDB) GetStats() DBStats {
	stats := db.DB.Stats()
	return DBStats{
		MaxOpenConnections: stats.MaxOpenConnections,
		OpenConnections:    stats.OpenConnections,
		InUse:              stats.InUse,
		Idle:               stats.Idle,
		WaitCount:          stats.WaitCount,
		WaitDuration:       stats.WaitDuration,
		MaxIdleClosed:      stats.MaxIdleClosed,
		MaxLifetimeClosed:  stats.MaxLifetimeClosed,
	}
}

// IsNotFoundError checks if an error is a "not found" error.
func IsNotFoundError(err error) bool {
	return errors.Is(err, sql.ErrNoRows) || errors.Is(err, ErrNotFound)
}

// IsDuplicateKeyError checks if an error is a duplicate key error.
func IsDuplicateKeyError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "duplicate key") ||
		strings.Contains(err.Error(), "unique constraint")
}

// IsForeignKeyError checks if an error is a foreign key error.
func IsForeignKeyError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "foreign key constraint")
}

// WrapError wraps database errors with more descriptive messages.
func WrapError(err error, operation string) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%s: %w", operation, ErrNotFound)
	}

	if IsDuplicateKeyError(err) {
		return fmt.Errorf("%s: %w: %v", operation, ErrDuplicateKey, err)
	}

	if IsForeignKeyError(err) {
		return fmt.Errorf("%s: %w: %v", operation, ErrForeignKey, err)
	}

	return fmt.Errorf("%s: %w", operation, err)
}

// Pagination represents pagination parameters.
type Pagination struct {
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
	Offset   int `json:"-"`
}

// NewPagination creates a new Pagination with defaults.
func NewPagination(page, pageSize int) Pagination {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}

	return Pagination{
		Page:     page,
		PageSize: pageSize,
		Offset:   (page - 1) * pageSize,
	}
}

// PaginatedResult represents a paginated query result.
type PaginatedResult[T any] struct {
	Items      []T   `json:"items"`
	Total      int64 `json:"total"`
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
	TotalPages int   `json:"total_pages"`
}

// NewPaginatedResult creates a new PaginatedResult.
func NewPaginatedResult[T any](items []T, total int64, pagination Pagination) PaginatedResult[T] {
	totalPages := int(total) / pagination.PageSize
	if int(total)%pagination.PageSize > 0 {
		totalPages++
	}

	return PaginatedResult[T]{
		Items:      items,
		Total:      total,
		Page:       pagination.Page,
		PageSize:   pagination.PageSize,
		TotalPages: totalPages,
	}
}

// QueryBuilder helps build dynamic SQL queries safely.
type QueryBuilder struct {
	baseQuery  string
	conditions []string
	args       []interface{}
	orderBy    string
	limit      int
	offset     int
}

// NewQueryBuilder creates a new QueryBuilder.
func NewQueryBuilder(baseQuery string) *QueryBuilder {
	return &QueryBuilder{
		baseQuery:  baseQuery,
		conditions: make([]string, 0),
		args:       make([]interface{}, 0),
	}
}

// Where adds a WHERE condition.
func (qb *QueryBuilder) Where(condition string, args ...interface{}) *QueryBuilder {
	qb.conditions = append(qb.conditions, condition)
	qb.args = append(qb.args, args...)
	return qb
}

// OrderBy sets the ORDER BY clause.
func (qb *QueryBuilder) OrderBy(orderBy string) *QueryBuilder {
	qb.orderBy = orderBy
	return qb
}

// Limit sets the LIMIT clause.
func (qb *QueryBuilder) Limit(limit int) *QueryBuilder {
	qb.limit = limit
	return qb
}

// Offset sets the OFFSET clause.
func (qb *QueryBuilder) Offset(offset int) *QueryBuilder {
	qb.offset = offset
	return qb
}

// Paginate sets both LIMIT and OFFSET from pagination.
func (qb *QueryBuilder) Paginate(p Pagination) *QueryBuilder {
	qb.limit = p.PageSize
	qb.offset = p.Offset
	return qb
}

// Build builds the final query and returns it with args.
func (qb *QueryBuilder) Build() (string, []interface{}) {
	query := qb.baseQuery

	if len(qb.conditions) > 0 {
		query += " WHERE " + strings.Join(qb.conditions, " AND ")
	}

	if qb.orderBy != "" {
		query += " ORDER BY " + qb.orderBy
	}

	if qb.limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", qb.limit)
	}

	if qb.offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", qb.offset)
	}

	return query, qb.args
}

// BuildCount builds a count query from the builder.
func (qb *QueryBuilder) BuildCount() (string, []interface{}) {
	// Extract table from base query (simple approach)
	query := "SELECT COUNT(*) FROM"

	// Find FROM clause in base query
	baseUpper := strings.ToUpper(qb.baseQuery)
	fromIdx := strings.Index(baseUpper, "FROM")
	if fromIdx != -1 {
		// Extract table part
		tablePart := qb.baseQuery[fromIdx+5:]
		// Remove any ORDER BY, LIMIT, etc if present
		for _, clause := range []string{" ORDER ", " LIMIT ", " OFFSET "} {
			if idx := strings.Index(strings.ToUpper(tablePart), clause); idx != -1 {
				tablePart = tablePart[:idx]
			}
		}
		query += " " + tablePart
	}

	if len(qb.conditions) > 0 {
		query += " WHERE " + strings.Join(qb.conditions, " AND ")
	}

	return query, qb.args
}

// Queryable interface for common query operations.
type Queryable interface {
	GetContext(ctx context.Context, dest interface{}, query string, args ...interface{}) error
	SelectContext(ctx context.Context, dest interface{}, query string, args ...interface{}) error
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	NamedExecContext(ctx context.Context, query string, arg interface{}) (sql.Result, error)
	QueryxContext(ctx context.Context, query string, args ...interface{}) (*sqlx.Rows, error)
}

// EnsureQueryable returns either the transaction or the database, implementing Queryable.
func (db *PostgresDB) EnsureQueryable(tx *sqlx.Tx) Queryable {
	if tx != nil {
		return tx
	}
	return db.DB
}
