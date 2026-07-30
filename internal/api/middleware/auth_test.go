package middleware

import (
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
