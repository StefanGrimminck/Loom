package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Without TrustProxyHeaders a forged X-Forwarded-For must not change the key.
func TestIPLimitIgnoresForwardedHeadersByDefault(t *testing.T) {
	for _, trust := range []bool{false, true} {
		r := chi.NewRouter()
		if trust {
			r.Use(middleware.RealIP)
		}
		r.Use(newIPRateLimiter(1).Middleware)
		r.Post("/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

		codes := []int{}
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.RemoteAddr = "203.0.113.5:4000"
			req.Header.Set("X-Forwarded-For", []string{"198.51.100.1", "198.51.100.2"}[i])
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			codes = append(codes, rec.Code)
		}
		limited := codes[1] == http.StatusTooManyRequests
		if limited == trust {
			t.Errorf("trust=%v: codes %v", trust, codes)
		}
	}
}
