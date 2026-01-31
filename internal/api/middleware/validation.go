package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// MaxBodySize limits the size of the request body.
func MaxBodySize(limit int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		c.Next()
	}
}

// ContentTypeChecker ensures the Content-Type header matches allowed types.
func ContentTypeChecker(allowed ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodPost || c.Request.Method == http.MethodPut || c.Request.Method == http.MethodPatch {
			ct := c.GetHeader("Content-Type")
			valid := false
			for _, t := range allowed {
				if ct == t {
					valid = true
					break
				}
			}

			if !valid {
				c.AbortWithStatusJSON(http.StatusUnsupportedMediaType, gin.H{
					"error":   "Unsupported Media Type",
					"message": "Content-Type must be one of: " + appendStrings(allowed),
				})
				return
			}
		}
		c.Next()
	}
}

func appendStrings(strs []string) string {
	var result string
	for i, s := range strs {
		if i > 0 {
			result += ", "
		}
		result += s
	}
	return result
}
