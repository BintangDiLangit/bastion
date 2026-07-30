package middleware

import (
	"bytes"
	"io"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// RequestLogger logs HTTP requests.
func RequestLogger(logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Get or create request ID
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		c.Set("request_id", requestID)
		c.Writer.Header().Set("X-Request-ID", requestID)

		// Read and restore request body for logging (only for debugging)
		var bodyBytes []byte
		if c.Request.Body != nil && logger.Level >= logrus.DebugLevel {
			bodyBytes, _ = io.ReadAll(c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		// Process request
		c.Next()

		// Calculate latency
		latency := time.Since(start)

		// Get response status
		status := c.Writer.Status()
		size := c.Writer.Size()

		// Build log fields
		fields := logrus.Fields{
			"request_id": requestID,
			"status":     status,
			"method":     c.Request.Method,
			"path":       path,
			"latency":    latency.String(),
			"latency_ms": latency.Milliseconds(),
			"ip":         c.ClientIP(),
			"user_agent": c.Request.UserAgent(),
			"size":       size,
		}

		if raw != "" {
			fields["query"] = raw
		}

		// Add error if present
		if len(c.Errors) > 0 {
			fields["errors"] = c.Errors.String()
		}

		// Add API key ID if present
		if keyID, exists := c.Get("api_key_id"); exists {
			fields["api_key_id"] = keyID
		}

		// Log based on status code
		entry := logger.WithFields(fields)
		msg := "Request completed"

		switch {
		case status >= 500:
			entry.Error(msg)
		case status >= 400:
			entry.Warn(msg)
		case status >= 300:
			entry.Info(msg)
		default:
			entry.Info(msg)
		}
	}
}

// RequestID adds a unique request ID to each request.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}

		c.Set("request_id", requestID)
		c.Writer.Header().Set("X-Request-ID", requestID)

		c.Next()
	}
}

// responseWriter wraps gin.ResponseWriter to capture response.
type responseWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w *responseWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

// ResponseLogger logs response bodies (for debugging).
func ResponseLogger(logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		if logger.Level < logrus.DebugLevel {
			c.Next()
			return
		}

		// Wrap response writer
		rw := &responseWriter{
			ResponseWriter: c.Writer,
			body:           bytes.NewBuffer(nil),
		}
		c.Writer = rw

		c.Next()

		// Log response body
		if rw.body.Len() > 0 {
			logger.WithFields(logrus.Fields{
				"request_id": c.GetString("request_id"),
				"response":   rw.body.String()[:min(1000, rw.body.Len())],
			}).Debug("Response body")
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Recovery returns a middleware that recovers from panics.
func Recovery(logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				logger.WithFields(logrus.Fields{
					"request_id": c.GetString("request_id"),
					"error":      err,
					"path":       c.Request.URL.Path,
					"method":     c.Request.Method,
				}).Error("Panic recovered")

				c.AbortWithStatusJSON(500, gin.H{
					"error":   "Internal Server Error",
					"message": "An unexpected error occurred",
				})
			}
		}()

		c.Next()
	}
}
