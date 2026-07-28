package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAPIKeyAuthFailsClosed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, test := range []struct {
		configured string
		provided   string
		want       int
	}{
		{"", strings.Repeat("x", 32), http.StatusUnauthorized},
		{"expected", "wrong", http.StatusUnauthorized},
		{"expected", "expected", http.StatusNoContent},
	} {
		router := gin.New()
		router.Use(APIKeyAuth(test.configured))
		router.GET("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header.Set("X-API-Key", test.provided)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != test.want {
			t.Errorf("configured=%q provided=%q: got %d, want %d", test.configured, test.provided, response.Code, test.want)
		}
	}
}

func TestGitHubWebhookSignature(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const secret = "webhook-secret"
	const payload = `{"safe":true}`
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payload))
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	router := gin.New()
	router.Use(WebhookSignatureAuth("github", secret))
	router.POST("/", func(c *gin.Context) {
		body, _ := io.ReadAll(c.Request.Body)
		c.String(http.StatusOK, string(body))
	})

	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(payload))
	request.Header.Set("X-Hub-Signature-256", signature)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != payload {
		t.Fatalf("got status %d body %q", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(payload))
	request.Header.Set("X-Hub-Signature-256", "sha256=wrong")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("invalid signature got status %d", response.Code)
	}
}
