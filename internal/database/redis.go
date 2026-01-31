// Package database provides database connection and operations.
package database

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"

	"code-security-auditor/internal/config"
)

var (
	// ErrLockNotAcquired is returned when a lock cannot be acquired.
	ErrLockNotAcquired = errors.New("lock not acquired")

	// ErrLockExpired is returned when a lock has expired.
	ErrLockExpired = errors.New("lock expired")
)

// RedisClient wraps the Redis client with additional functionality.
type RedisClient struct {
	*redis.Client
	logger     *logrus.Logger
	config     config.RedisConfig
	mu         sync.RWMutex
	pubsub     *redis.PubSub
	subscribers map[string][]chan []byte
}

// NewRedisClient creates a new Redis client with connection retry.
func NewRedisClient(cfg config.RedisConfig, logger *logrus.Logger) (*RedisClient, error) {
	logger.WithFields(logrus.Fields{
		"host": cfg.Host,
		"port": cfg.Port,
		"db":   cfg.DB,
	}).Debug("Connecting to Redis")

	client := redis.NewClient(&redis.Options{
		Addr:         cfg.Addr(),
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		MaxRetries:   cfg.MaxRetries,
	})

	// Verify connection with retry
	var err error
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = client.Ping(ctx).Err()
		cancel()

		if err == nil {
			break
		}

		logger.WithError(err).Warnf("Failed to connect to Redis (attempt %d/3)", i+1)
		time.Sleep(time.Second * time.Duration(i+1))
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to Redis after 3 attempts: %w", err)
	}

	logger.Info("Successfully connected to Redis")

	return &RedisClient{
		Client:      client,
		logger:      logger,
		config:      cfg,
		subscribers: make(map[string][]chan []byte),
	}, nil
}

// Close closes the Redis connection.
func (r *RedisClient) Close() error {
	r.logger.Info("Closing Redis connection")

	r.mu.Lock()
	defer r.mu.Unlock()

	// Close pubsub if active
	if r.pubsub != nil {
		r.pubsub.Close()
	}

	// Close all subscriber channels
	for _, channels := range r.subscribers {
		for _, ch := range channels {
			close(ch)
		}
	}

	return r.Client.Close()
}

// Health checks the Redis health.
func (r *RedisClient) Health(ctx context.Context) error {
	return r.Ping(ctx).Err()
}

// HealthCheck performs a comprehensive health check.
func (r *RedisClient) HealthCheck(ctx context.Context) (*RedisHealthStatus, error) {
	status := &RedisHealthStatus{
		Status:    "healthy",
		Timestamp: time.Now(),
	}

	// Ping check
	start := time.Now()
	if err := r.Ping(ctx).Err(); err != nil {
		status.Status = "unhealthy"
		status.Error = err.Error()
		return status, err
	}
	status.Latency = time.Since(start)

	// Get pool stats
	poolStats := r.PoolStats()
	status.Pool = RedisPoolStats{
		Hits:       poolStats.Hits,
		Misses:     poolStats.Misses,
		Timeouts:   poolStats.Timeouts,
		TotalConns: poolStats.TotalConns,
		IdleConns:  poolStats.IdleConns,
		StaleConns: poolStats.StaleConns,
	}

	// Get server info
	info, err := r.Info(ctx, "server", "memory").Result()
	if err == nil {
		status.Info = info
	}

	return status, nil
}

// RedisHealthStatus represents Redis health status.
type RedisHealthStatus struct {
	Status    string         `json:"status"`
	Timestamp time.Time      `json:"timestamp"`
	Latency   time.Duration  `json:"latency"`
	Pool      RedisPoolStats `json:"pool"`
	Info      string         `json:"info,omitempty"`
	Error     string         `json:"error,omitempty"`
}

// RedisPoolStats represents Redis connection pool statistics.
type RedisPoolStats struct {
	Hits       uint32 `json:"hits"`
	Misses     uint32 `json:"misses"`
	Timeouts   uint32 `json:"timeouts"`
	TotalConns uint32 `json:"total_conns"`
	IdleConns  uint32 `json:"idle_conns"`
	StaleConns uint32 `json:"stale_conns"`
}

// ============================================================================
// Cache Operations
// ============================================================================

// SetJSON stores a JSON-serializable value with expiration.
func (r *RedisClient) SetJSON(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %w", err)
	}
	return r.Set(ctx, key, data, expiration).Err()
}

// GetJSON retrieves and unmarshals a JSON value.
func (r *RedisClient) GetJSON(ctx context.Context, key string, dest interface{}) error {
	data, err := r.Get(ctx, key).Bytes()
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dest)
}

// SetWithTTL stores a value with a specific TTL.
func (r *RedisClient) SetWithTTL(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	return r.SetJSON(ctx, key, value, ttl)
}

// GetOrSet retrieves a value or sets it using the provided function.
func (r *RedisClient) GetOrSet(ctx context.Context, key string, dest interface{}, ttl time.Duration, fn func() (interface{}, error)) error {
	// Try to get from cache
	err := r.GetJSON(ctx, key, dest)
	if err == nil {
		return nil
	}

	if !errors.Is(err, redis.Nil) {
		return err
	}

	// Cache miss, call the function
	value, err := fn()
	if err != nil {
		return err
	}

	// Store in cache
	if err := r.SetJSON(ctx, key, value, ttl); err != nil {
		r.logger.WithError(err).Warnf("Failed to cache value for key %s", key)
	}

	// Unmarshal into dest
	data, _ := json.Marshal(value)
	return json.Unmarshal(data, dest)
}

// Delete deletes a single key.
func (r *RedisClient) DeleteKey(ctx context.Context, key string) error {
	return r.Del(ctx, key).Err()
}

// DeletePattern deletes all keys matching a pattern.
func (r *RedisClient) DeletePattern(ctx context.Context, pattern string) error {
	iter := r.Scan(ctx, 0, pattern, 100).Iterator()
	var keys []string

	for iter.Next(ctx) {
		keys = append(keys, iter.Val())

		// Delete in batches of 100
		if len(keys) >= 100 {
			if err := r.Del(ctx, keys...).Err(); err != nil {
				return fmt.Errorf("failed to delete keys: %w", err)
			}
			keys = keys[:0]
		}
	}

	if err := iter.Err(); err != nil {
		return fmt.Errorf("failed to scan keys: %w", err)
	}

	if len(keys) > 0 {
		if err := r.Del(ctx, keys...).Err(); err != nil {
			return fmt.Errorf("failed to delete keys: %w", err)
		}
	}

	return nil
}

// Exists checks if a key exists.
func (r *RedisClient) Exists(ctx context.Context, key string) (bool, error) {
	n, err := r.Client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// Expire sets a key's TTL.
func (r *RedisClient) SetExpire(ctx context.Context, key string, ttl time.Duration) error {
	return r.Client.Expire(ctx, key, ttl).Err()
}

// TTL returns a key's remaining TTL.
func (r *RedisClient) GetTTL(ctx context.Context, key string) (time.Duration, error) {
	return r.Client.TTL(ctx, key).Result()
}

// ============================================================================
// Distributed Locking
// ============================================================================

// Lock represents a distributed lock.
type Lock struct {
	key    string
	token  string
	client *RedisClient
}

// AcquireLock attempts to acquire a distributed lock with a unique token.
func (r *RedisClient) AcquireLock(ctx context.Context, key string, ttl time.Duration) (*Lock, error) {
	lockKey := "lock:" + key
	token := generateToken()

	acquired, err := r.SetNX(ctx, lockKey, token, ttl).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}

	if !acquired {
		return nil, ErrLockNotAcquired
	}

	return &Lock{
		key:    lockKey,
		token:  token,
		client: r,
	}, nil
}

// TryAcquireLock attempts to acquire a lock with retries.
func (r *RedisClient) TryAcquireLock(ctx context.Context, key string, ttl time.Duration, timeout time.Duration) (*Lock, error) {
	deadline := time.Now().Add(timeout)
	backoff := 50 * time.Millisecond

	for time.Now().Before(deadline) {
		lock, err := r.AcquireLock(ctx, key, ttl)
		if err == nil {
			return lock, nil
		}

		if !errors.Is(err, ErrLockNotAcquired) {
			return nil, err
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
			// Exponential backoff with max of 1 second
			backoff = backoff * 2
			if backoff > time.Second {
				backoff = time.Second
			}
		}
	}

	return nil, ErrLockNotAcquired
}

// Release releases the lock.
func (l *Lock) Release(ctx context.Context) error {
	// Use Lua script to ensure we only release our own lock
	script := `
		if redis.call("get", KEYS[1]) == ARGV[1] then
			return redis.call("del", KEYS[1])
		else
			return 0
		end
	`
	result, err := l.client.Eval(ctx, script, []string{l.key}, l.token).Int64()
	if err != nil {
		return fmt.Errorf("failed to release lock: %w", err)
	}

	if result == 0 {
		return ErrLockExpired
	}

	return nil
}

// Extend extends the lock TTL.
func (l *Lock) Extend(ctx context.Context, ttl time.Duration) error {
	// Use Lua script to ensure we only extend our own lock
	script := `
		if redis.call("get", KEYS[1]) == ARGV[1] then
			return redis.call("pexpire", KEYS[1], ARGV[2])
		else
			return 0
		end
	`
	result, err := l.client.Eval(ctx, script, []string{l.key}, l.token, int64(ttl.Milliseconds())).Int64()
	if err != nil {
		return fmt.Errorf("failed to extend lock: %w", err)
	}

	if result == 0 {
		return ErrLockExpired
	}

	return nil
}

// WithLock executes a function with a distributed lock.
func (r *RedisClient) WithLock(ctx context.Context, key string, ttl time.Duration, fn func() error) error {
	lock, err := r.AcquireLock(ctx, key, ttl)
	if err != nil {
		return err
	}

	defer func() {
		if err := lock.Release(ctx); err != nil && !errors.Is(err, ErrLockExpired) {
			r.logger.WithError(err).Warn("Failed to release lock")
		}
	}()

	return fn()
}

// generateToken generates a unique token for lock ownership.
func generateToken() string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Nanosecond())))
	return hex.EncodeToString(hash[:16])
}

// ============================================================================
// Rate Limiting
// ============================================================================

// RateLimitResult represents the result of a rate limit check.
type RateLimitResult struct {
	Allowed   bool          `json:"allowed"`
	Remaining int           `json:"remaining"`
	Reset     time.Duration `json:"reset"`
	Total     int           `json:"total"`
}

// CheckRateLimit checks and updates rate limit using sliding window.
func (r *RedisClient) CheckRateLimit(ctx context.Context, key string, limit int, window time.Duration) (*RateLimitResult, error) {
	now := time.Now()
	windowStart := now.Add(-window).UnixMilli()
	nowMs := now.UnixMilli()

	rateLimitKey := "ratelimit:" + key

	// Lua script for atomic rate limiting
	script := `
		local key = KEYS[1]
		local now = tonumber(ARGV[1])
		local window_start = tonumber(ARGV[2])
		local limit = tonumber(ARGV[3])
		local window_ms = tonumber(ARGV[4])
		
		-- Remove old entries
		redis.call('zremrangebyscore', key, '-inf', window_start)
		
		-- Count current requests
		local current = redis.call('zcard', key)
		
		if current < limit then
			-- Add new request
			redis.call('zadd', key, now, now .. '-' .. math.random())
			redis.call('pexpire', key, window_ms)
			return {1, limit - current - 1}
		else
			return {0, 0}
		end
	`

	result, err := r.Eval(ctx, script, []string{rateLimitKey},
		nowMs, windowStart, limit, int64(window.Milliseconds()),
	).Int64Slice()

	if err != nil {
		return nil, fmt.Errorf("rate limit check failed: %w", err)
	}

	return &RateLimitResult{
		Allowed:   result[0] == 1,
		Remaining: int(result[1]),
		Reset:     window,
		Total:     limit,
	}, nil
}

// CheckRateLimitSimple performs simple counter-based rate limiting.
func (r *RedisClient) CheckRateLimitSimple(ctx context.Context, key string, limit int, window time.Duration) (bool, int, error) {
	rateLimitKey := "ratelimit:" + key

	pipe := r.Pipeline()
	incrCmd := pipe.Incr(ctx, rateLimitKey)
	pipe.Expire(ctx, rateLimitKey, window)
	_, err := pipe.Exec(ctx)

	if err != nil {
		return false, 0, err
	}

	count := int(incrCmd.Val())
	allowed := count <= limit
	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}

	return allowed, remaining, nil
}

// ============================================================================
// Scan Progress Tracking
// ============================================================================

// ScanProgress represents scan progress data.
type ScanProgress struct {
	ScanID          string    `json:"scan_id"`
	Status          string    `json:"status"`
	Progress        float64   `json:"progress"`
	FilesScanned    int       `json:"files_scanned"`
	TotalFiles      int       `json:"total_files"`
	Vulnerabilities int       `json:"vulnerabilities"`
	CurrentFile     string    `json:"current_file"`
	StartedAt       time.Time `json:"started_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	Message         string    `json:"message,omitempty"`
}

// SetScanProgress stores scan progress.
func (r *RedisClient) SetScanProgress(ctx context.Context, scanID string, progress *ScanProgress) error {
	key := CacheKey(CacheKeyPrefixScanProgress, scanID)
	progress.UpdatedAt = time.Now()
	return r.SetJSON(ctx, key, progress, 24*time.Hour)
}

// GetScanProgress retrieves scan progress.
func (r *RedisClient) GetScanProgress(ctx context.Context, scanID string) (*ScanProgress, error) {
	key := CacheKey(CacheKeyPrefixScanProgress, scanID)
	var progress ScanProgress
	err := r.GetJSON(ctx, key, &progress)
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &progress, nil
}

// DeleteScanProgress removes scan progress.
func (r *RedisClient) DeleteScanProgress(ctx context.Context, scanID string) error {
	key := CacheKey(CacheKeyPrefixScanProgress, scanID)
	return r.Del(ctx, key).Err()
}

// ============================================================================
// Pub/Sub Operations
// ============================================================================

// Publish publishes a message to a channel.
func (r *RedisClient) PublishEvent(ctx context.Context, channel string, message interface{}) error {
	data, err := json.Marshal(message)
	if err != nil {
		return err
	}
	return r.Publish(ctx, channel, data).Err()
}

// Subscribe creates a subscription to a channel.
func (r *RedisClient) SubscribeToChannel(ctx context.Context, channel string) *redis.PubSub {
	return r.Subscribe(ctx, channel)
}

// SubscribeWithHandler subscribes to a channel with a message handler.
func (r *RedisClient) SubscribeWithHandler(ctx context.Context, channel string, handler func([]byte)) error {
	pubsub := r.Subscribe(ctx, channel)

	go func() {
		defer pubsub.Close()

		for {
			select {
			case <-ctx.Done():
				return
			default:
				msg, err := pubsub.ReceiveMessage(ctx)
				if err != nil {
					if !errors.Is(err, context.Canceled) {
						r.logger.WithError(err).Error("Error receiving pubsub message")
					}
					return
				}

				handler([]byte(msg.Payload))
			}
		}
	}()

	return nil
}

// PSubscribe creates a pattern subscription.
func (r *RedisClient) PSubscribeToPattern(ctx context.Context, pattern string) *redis.PubSub {
	return r.PSubscribe(ctx, pattern)
}

// ============================================================================
// Queue Operations (for job queue support)
// ============================================================================

// QueuePush pushes an item to the end of a queue.
func (r *RedisClient) QueuePush(ctx context.Context, queue string, item interface{}) error {
	data, err := json.Marshal(item)
	if err != nil {
		return err
	}
	return r.RPush(ctx, "queue:"+queue, data).Err()
}

// QueuePushPriority pushes an item to the front of a queue (high priority).
func (r *RedisClient) QueuePushPriority(ctx context.Context, queue string, item interface{}) error {
	data, err := json.Marshal(item)
	if err != nil {
		return err
	}
	return r.LPush(ctx, "queue:"+queue, data).Err()
}

// QueuePop pops an item from the queue (blocking).
func (r *RedisClient) QueuePop(ctx context.Context, queue string, timeout time.Duration, dest interface{}) error {
	result, err := r.BLPop(ctx, timeout, "queue:"+queue).Result()
	if err != nil {
		return err
	}

	if len(result) < 2 {
		return redis.Nil
	}

	return json.Unmarshal([]byte(result[1]), dest)
}

// QueueLen returns the length of a queue.
func (r *RedisClient) QueueLen(ctx context.Context, queue string) (int64, error) {
	return r.LLen(ctx, "queue:"+queue).Result()
}

// ============================================================================
// Session Management
// ============================================================================

// SetSession stores session data.
func (r *RedisClient) SetSession(ctx context.Context, sessionID string, data interface{}, ttl time.Duration) error {
	key := CacheKey(CacheKeyPrefixSession, sessionID)
	return r.SetJSON(ctx, key, data, ttl)
}

// GetSession retrieves session data.
func (r *RedisClient) GetSession(ctx context.Context, sessionID string, dest interface{}) error {
	key := CacheKey(CacheKeyPrefixSession, sessionID)
	return r.GetJSON(ctx, key, dest)
}

// DeleteSession deletes a session.
func (r *RedisClient) DeleteSession(ctx context.Context, sessionID string) error {
	key := CacheKey(CacheKeyPrefixSession, sessionID)
	return r.Del(ctx, key).Err()
}

// RefreshSession extends session TTL.
func (r *RedisClient) RefreshSession(ctx context.Context, sessionID string, ttl time.Duration) error {
	key := CacheKey(CacheKeyPrefixSession, sessionID)
	return r.Client.Expire(ctx, key, ttl).Err()
}

// ============================================================================
// Stats and Metrics
// ============================================================================

// GetPoolStats returns Redis connection pool statistics.
func (r *RedisClient) GetPoolStats() *redis.PoolStats {
	return r.PoolStats()
}

// ============================================================================
// Cache Key Helpers
// ============================================================================

// CacheKey generates a cache key with prefix.
func CacheKey(prefix string, parts ...string) string {
	key := prefix
	for _, part := range parts {
		key += ":" + part
	}
	return key
}

// Common cache key prefixes.
const (
	CacheKeyPrefixScan         = "scan"
	CacheKeyPrefixScanProgress = "scan:progress"
	CacheKeyPrefixScanResult   = "scan:result"
	CacheKeyPrefixRepo         = "repo"
	CacheKeyPrefixRepoMetadata = "repo:metadata"
	CacheKeyPrefixVuln         = "vuln"
	CacheKeyPrefixReport       = "report"
	CacheKeyPrefixRateLimit    = "ratelimit"
	CacheKeyPrefixSession      = "session"
	CacheKeyPrefixLock         = "lock"
	CacheKeyPrefixQueue        = "queue"
	CacheKeyPrefixAPIKey       = "apikey"
)

// ============================================================================
// Utility Functions
// ============================================================================

// FlushDB flushes the current database (use with caution!).
func (r *RedisClient) FlushDB(ctx context.Context) error {
	return r.Client.FlushDB(ctx).Err()
}

// DBSize returns the number of keys in the database.
func (r *RedisClient) DBSize(ctx context.Context) (int64, error) {
	return r.Client.DBSize(ctx).Result()
}

// Keys returns all keys matching a pattern (use with caution on large databases).
func (r *RedisClient) Keys(ctx context.Context, pattern string) ([]string, error) {
	return r.Client.Keys(ctx, pattern).Result()
}
