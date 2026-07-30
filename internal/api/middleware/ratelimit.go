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
		// Keyed on the client IP, and deliberately mounted ahead of API-key
		// auth so unauthenticated requests are throttled too. ClientIP is the
		// real socket address: the router clears gin's trusted proxies, so a
		// caller cannot mint fresh buckets with an X-Forwarded-For header.
		allowed, remaining, resetAt := limiter.Allow(c.ClientIP())

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
