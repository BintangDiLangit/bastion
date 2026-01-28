package database

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"

	"github.com/code-security-auditor/internal/config"
)

// RedisClient wraps the Redis client with additional functionality.
type RedisClient struct {
	*redis.Client
	logger *logrus.Logger
	config config.RedisConfig
}

// NewRedisClient creates a new Redis client.
func NewRedisClient(cfg config.RedisConfig, logger *logrus.Logger) (*RedisClient, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         cfg.Addr(),
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	})

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	logger.Info("Successfully connected to Redis")
	return &RedisClient{
		Client: client,
		logger: logger,
		config: cfg,
	}, nil
}

// Close closes the Redis connection.
func (r *RedisClient) Close() error {
	r.logger.Info("Closing Redis connection")
	return r.Client.Close()
}

// Health checks the Redis health.
func (r *RedisClient) Health(ctx context.Context) error {
	return r.Ping(ctx).Err()
}

// Cache operations

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

	if err != redis.Nil {
		return err
	}

	// Cache miss, call the function
	value, err := fn()
	if err != nil {
		return err
	}

	// Store in cache
	if err := r.SetJSON(ctx, key, value, ttl); err != nil {
		r.logger.Warnf("Failed to cache value for key %s: %v", key, err)
	}

	// Unmarshal into dest
	data, _ := json.Marshal(value)
	return json.Unmarshal(data, dest)
}

// DeletePattern deletes all keys matching a pattern.
func (r *RedisClient) DeletePattern(ctx context.Context, pattern string) error {
	iter := r.Scan(ctx, 0, pattern, 0).Iterator()
	var keys []string

	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
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

// Lock operations for distributed locking

// AcquireLock attempts to acquire a distributed lock.
func (r *RedisClient) AcquireLock(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	return r.SetNX(ctx, "lock:"+key, "1", ttl).Result()
}

// ReleaseLock releases a distributed lock.
func (r *RedisClient) ReleaseLock(ctx context.Context, key string) error {
	return r.Del(ctx, "lock:"+key).Err()
}

// WithLock executes a function with a distributed lock.
func (r *RedisClient) WithLock(ctx context.Context, key string, ttl time.Duration, fn func() error) error {
	acquired, err := r.AcquireLock(ctx, key, ttl)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}

	if !acquired {
		return fmt.Errorf("failed to acquire lock: already held")
	}

	defer r.ReleaseLock(ctx, key)

	return fn()
}

// Rate limiting operations

// CheckRateLimit checks and updates rate limit.
func (r *RedisClient) CheckRateLimit(ctx context.Context, key string, limit int, window time.Duration) (bool, int, error) {
	pipe := r.Pipeline()
	
	incrCmd := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window)
	
	_, err := pipe.Exec(ctx)
	if err != nil {
		return false, 0, err
	}

	count := int(incrCmd.Val())
	allowed := count <= limit
	
	return allowed, limit - count, nil
}

// Progress tracking operations

// SetScanProgress stores scan progress.
func (r *RedisClient) SetScanProgress(ctx context.Context, scanID string, progress map[string]interface{}) error {
	key := fmt.Sprintf("scan:progress:%s", scanID)
	return r.SetJSON(ctx, key, progress, 24*time.Hour)
}

// GetScanProgress retrieves scan progress.
func (r *RedisClient) GetScanProgress(ctx context.Context, scanID string) (map[string]interface{}, error) {
	key := fmt.Sprintf("scan:progress:%s", scanID)
	var progress map[string]interface{}
	err := r.GetJSON(ctx, key, &progress)
	if err == redis.Nil {
		return nil, nil
	}
	return progress, err
}

// Pub/Sub operations

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

// Stats returns Redis connection pool statistics.
func (r *RedisClient) Stats() *redis.PoolStats {
	return r.PoolStats()
}

// Cache key helpers

// CacheKey generates a cache key with prefix.
func CacheKey(prefix string, parts ...string) string {
	key := prefix
	for _, part := range parts {
		key += ":" + part
	}
	return key
}

// Common cache key prefixes
const (
	CacheKeyPrefixScan        = "scan"
	CacheKeyPrefixRepo        = "repo"
	CacheKeyPrefixVuln        = "vuln"
	CacheKeyPrefixReport      = "report"
	CacheKeyPrefixRateLimit   = "ratelimit"
	CacheKeyPrefixSession     = "session"
)
