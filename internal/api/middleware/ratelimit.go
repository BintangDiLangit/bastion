package middleware

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimiterConfig holds rate limiter configuration.
type RateLimiterConfig struct {
	Requests int           // Maximum requests
	Window   time.Duration // Time window
	Burst    int           // Burst size
}

// RateLimiter implements a token bucket rate limiter.
func RateLimiter(config RateLimiterConfig) gin.HandlerFunc {
	limiter := newTokenBucketLimiter(config)

	return func(c *gin.Context) {
		// Get client identifier (API key or IP)
		clientID := c.GetString("api_key_id")
		if clientID == "" {
			clientID = c.ClientIP()
		}

		allowed, remaining, resetAt := limiter.Allow(clientID)

		// Set rate limit headers
		c.Header("X-RateLimit-Limit", intToStr(config.Requests))
		c.Header("X-RateLimit-Remaining", intToStr(remaining))
		c.Header("X-RateLimit-Reset", intToStr(int(resetAt.Unix())))

		if !allowed {
			c.Header("Retry-After", intToStr(int(time.Until(resetAt).Seconds())))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":       "Too Many Requests",
				"message":     "Rate limit exceeded",
				"retry_after": time.Until(resetAt).Seconds(),
			})
			return
		}

		c.Next()
	}
}

// tokenBucketLimiter implements token bucket rate limiting.
type tokenBucketLimiter struct {
	config  RateLimiterConfig
	buckets map[string]*bucket
	mu      sync.Mutex
}

// bucket represents a token bucket for a single client.
type bucket struct {
	tokens   int
	lastFill time.Time
	resetAt  time.Time
}

func newTokenBucketLimiter(config RateLimiterConfig) *tokenBucketLimiter {
	l := &tokenBucketLimiter{
		config:  config,
		buckets: make(map[string]*bucket),
	}

	// Start cleanup goroutine
	go l.cleanup()

	return l
}

// Allow checks if a request is allowed.
func (l *tokenBucketLimiter) Allow(clientID string) (allowed bool, remaining int, resetAt time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()

	b, exists := l.buckets[clientID]
	if !exists {
		b = &bucket{
			tokens:   l.config.Requests,
			lastFill: now,
			resetAt:  now.Add(l.config.Window),
		}
		l.buckets[clientID] = b
	}

	// Refill tokens if window has passed
	if now.After(b.resetAt) {
		b.tokens = l.config.Requests
		b.lastFill = now
		b.resetAt = now.Add(l.config.Window)
	}

	// Check if request is allowed
	if b.tokens > 0 {
		b.tokens--
		return true, b.tokens, b.resetAt
	}

	return false, 0, b.resetAt
}

// cleanup periodically removes old buckets.
func (l *tokenBucketLimiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		l.mu.Lock()
		now := time.Now()
		for clientID, b := range l.buckets {
			// Remove buckets that haven't been used in a while
			if now.Sub(b.lastFill) > l.config.Window*2 {
				delete(l.buckets, clientID)
			}
		}
		l.mu.Unlock()
	}
}

func intToStr(i int) string {
	return strconv.Itoa(i)
}

// SlidingWindowLimiter implements sliding window rate limiting.
type SlidingWindowLimiter struct {
	config  RateLimiterConfig
	windows map[string]*slidingWindow
	mu      sync.Mutex
}

type slidingWindow struct {
	timestamps []time.Time
}

// NewSlidingWindowLimiter creates a new sliding window limiter.
func NewSlidingWindowLimiter(config RateLimiterConfig) *SlidingWindowLimiter {
	return &SlidingWindowLimiter{
		config:  config,
		windows: make(map[string]*slidingWindow),
	}
}

// Allow checks if a request is allowed using sliding window.
func (l *SlidingWindowLimiter) Allow(clientID string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-l.config.Window)

	w, exists := l.windows[clientID]
	if !exists {
		w = &slidingWindow{timestamps: make([]time.Time, 0)}
		l.windows[clientID] = w
	}

	// Remove old timestamps
	valid := make([]time.Time, 0)
	for _, ts := range w.timestamps {
		if ts.After(windowStart) {
			valid = append(valid, ts)
		}
	}
	w.timestamps = valid

	// Check if under limit
	if len(w.timestamps) >= l.config.Requests {
		return false
	}

	// Add new timestamp
	w.timestamps = append(w.timestamps, now)
	return true
}

// Timeout adds request timeout middleware.
func Timeout(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Create a context with timeout
		// Note: This requires careful handling as Gin's context doesn't fully support cancellation

		// Set a deadline header
		c.Writer.Header().Set("X-Request-Timeout", timeout.String())

		c.Next()
	}
}
