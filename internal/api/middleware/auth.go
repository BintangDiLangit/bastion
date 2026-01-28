// Package middleware provides HTTP middleware for the API.
package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// APIKeyAuth validates API key authentication.
func APIKeyAuth() gin.HandlerFunc {
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
		valid, keyInfo := validateAPIKey(apiKey)
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
func validateAPIKey(key string) (bool, APIKeyInfo) {
	// For development/testing, accept any key that looks valid
	// In production, this should validate against the api_keys table
	if len(key) >= 32 {
		return true, APIKeyInfo{
			ID:     "dev-key",
			Scopes: []string{"read", "write", "admin"},
		}
	}
	return false, APIKeyInfo{}
}

// RequireScopes checks if the API key has required scopes.
func RequireScopes(requiredScopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		scopes, exists := c.Get("api_key_scopes")
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "Forbidden",
				"message": "Insufficient permissions",
			})
			return
		}

		keyScopes, ok := scopes.([]string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error":   "Internal Error",
				"message": "Invalid scope configuration",
			})
			return
		}

		// Check if any required scope is present
		hasScope := false
		for _, required := range requiredScopes {
			for _, scope := range keyScopes {
				if scope == required || scope == "admin" {
					hasScope = true
					break
				}
			}
			if hasScope {
				break
			}
		}

		if !hasScope {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "Forbidden",
				"message": "Required scope not present",
			})
			return
		}

		c.Next()
	}
}

// WebhookSignatureAuth validates webhook signatures.
func WebhookSignatureAuth(provider string) gin.HandlerFunc {
	return func(c *gin.Context) {
		switch provider {
		case "github":
			if !validateGitHubSignature(c) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error":   "Unauthorized",
					"message": "Invalid webhook signature",
				})
				return
			}
		case "gitlab":
			if !validateGitLabSignature(c) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error":   "Unauthorized",
					"message": "Invalid webhook token",
				})
				return
			}
		}

		c.Next()
	}
}

// validateGitHubSignature validates GitHub webhook signature.
func validateGitHubSignature(c *gin.Context) bool {
	signature := c.GetHeader("X-Hub-Signature-256")
	if signature == "" {
		return false
	}

	// In production, compute HMAC and compare
	// payload := c.GetRawData()
	// secret := getWebhookSecret(repoID)
	// expectedSig := computeHMACSHA256(payload, secret)
	// return subtle.ConstantTimeCompare([]byte(signature), []byte(expectedSig)) == 1

	// For now, allow if signature header is present
	return len(signature) > 0
}

// validateGitLabSignature validates GitLab webhook token.
func validateGitLabSignature(c *gin.Context) bool {
	token := c.GetHeader("X-Gitlab-Token")
	if token == "" {
		return false
	}

	// In production, validate against stored token
	// expectedToken := getWebhookToken(repoID)
	// return subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) == 1

	return len(token) > 0
}

// BasicAuth provides HTTP Basic authentication.
func BasicAuth(username, password string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, pass, hasAuth := c.Request.BasicAuth()
		if !hasAuth {
			c.Header("WWW-Authenticate", `Basic realm="Restricted"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": "Authentication required",
			})
			return
		}

		if subtle.ConstantTimeCompare([]byte(user), []byte(username)) != 1 ||
			subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": "Invalid credentials",
			})
			return
		}

		c.Next()
	}
}
