// Package middleware provides HTTP middleware for the API.
package middleware

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// APIKeyAuth validates API key authentication.
func APIKeyAuth(expectedKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			// Try Authorization header
			auth := c.GetHeader("Authorization")
			if strings.HasPrefix(auth, "Bearer ") {
				apiKey = strings.TrimPrefix(auth, "Bearer ")
			}
		}

		if apiKey == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": "API key required. Provide via X-API-Key header or Authorization: Bearer <key>",
			})
			return
		}

		// Validate API key
		// In production, this would validate against the database
		valid, keyInfo := validateAPIKey(apiKey, expectedKey)
		if !valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": "Invalid API key",
			})
			return
		}

		// Set key info in context
		c.Set("api_key_id", keyInfo.ID)
		c.Set("api_key_scopes", keyInfo.Scopes)

		c.Next()
	}
}

// APIKeyInfo holds information about an API key.
type APIKeyInfo struct {
	ID     string
	Scopes []string
}

// validateAPIKey validates an API key against the database.
// In production, this would query the database.
func validateAPIKey(key, expectedKey string) (bool, APIKeyInfo) {
	if expectedKey == "" {
		return false, APIKeyInfo{}
	}
	keyHash := sha256.Sum256([]byte(key))
	expectedHash := sha256.Sum256([]byte(expectedKey))
	valid := subtle.ConstantTimeCompare(keyHash[:], expectedHash[:]) == 1
	return valid, APIKeyInfo{ID: "configured-key", Scopes: []string{"admin"}}
}
