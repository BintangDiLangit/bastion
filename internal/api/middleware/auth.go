// Package middleware provides HTTP middleware for the API.
package middleware

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
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
func WebhookSignatureAuth(provider, secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		switch provider {
		case "github":
			if !validateGitHubSignature(c, secret) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error":   "Unauthorized",
					"message": "Invalid webhook signature",
				})
				return
			}
		case "gitlab":
			if !validateGitLabSignature(c, secret) {
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
func validateGitHubSignature(c *gin.Context, secret string) bool {
	signature := c.GetHeader("X-Hub-Signature-256")
	if signature == "" || secret == "" {
		return false
	}

	payload, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return false
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(payload))
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(signature), []byte(expected))
}

// validateGitLabSignature validates GitLab webhook token.
func validateGitLabSignature(c *gin.Context, expectedToken string) bool {
	token := c.GetHeader("X-Gitlab-Token")
	if token == "" || expectedToken == "" {
		return false
	}
	tokenHash := sha256.Sum256([]byte(token))
	expectedHash := sha256.Sum256([]byte(expectedToken))
	return subtle.ConstantTimeCompare(tokenHash[:], expectedHash[:]) == 1
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
