// jade:ring local
package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// A model broker's quota refusal reaches the worker as a fixed, non-retryable quota answer the
// gateway writes itself; any other provider refusal stays an opaque 502. The provider's body is
// never reflected.
func TestProviderQuotaRefusalIsFixedAndNotRetryable(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		want       int
	}{
		{"quota", `{"error":{"code":"quota_exceeded","message":"monthly model quota of $40.00 is used ($48.02); secret detail"}}`, 429, 429},
		{"throttle", `{"error":{"code":"busy","message":"slow down"}}`, 429, 502},
		{"quota code on another status", `{"error":{"code":"quota_exceeded"}}`, 403, 502},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{Model: "approved", Spool: privateTemp(t), MaxRecords: 16, MaxOfflineSeconds: 60, DevelopmentLoopback: true,
				ProviderURL: "https://provider.test/v1/chat/completions", TimeoutSeconds: 5, ProviderTokenFile: "/unused"}
			_ = os.Chmod(c.Spool, 0700)
			s, err := openSpool(c)
			if err != nil {
				t.Fatal(err)
			}
			g := &Gateway{config: c, spool: s, active: make(chan struct{}, 1), client: &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": {"application/json"}},
					Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})}}
			g.provider.set("token")
			w := httptest.NewRecorder()
			g.ServeHTTP(w, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"approved","messages":[{"role":"user","content":"hi"}]}`)))
			if w.Code != tc.want {
				t.Fatalf("status %d, want %d", w.Code, tc.want)
			}
			if strings.Contains(w.Body.String(), "secret detail") || strings.Contains(w.Body.String(), "$48.02") {
				t.Fatalf("provider body reflected: %q", w.Body.String())
			}
			if tc.want == 429 && (w.Header().Get("X-Should-Retry") != "false" || !strings.Contains(w.Body.String(), "quota exceeded")) {
				t.Fatalf("quota answer not marked final: %v %q", w.Header(), w.Body.String())
			}
		})
	}
}
