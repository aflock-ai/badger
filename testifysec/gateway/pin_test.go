// jade:ring local
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func spkiPin(t *testing.T, s *httptest.Server) string {
	t.Helper()
	sum := sha256.Sum256(s.Certificate().RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// An administrator can pin the provider's certificate (a self-signed edge, for example): the gateway
// then talks to that provider only if it presents exactly that key, and to nothing else unverified.
func TestPinnedProviderCertificate(t *testing.T) {
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[]}`))
	}))
	defer provider.Close()
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer other.Close()
	for name, tc := range map[string]struct {
		pin  string
		want int
	}{
		"pinned":    {spkiPin(t, provider), 200},
		"wrong key": {strings.Repeat("0", 64), 502}, // httptest servers share one certificate
		"no pin":    {"", 502},                      // the test certificate is not in the system roots
	} {
		t.Run(name, func(t *testing.T) {
			c := Config{Model: "approved", Spool: privateTemp(t), MaxRecords: 16, MaxOfflineSeconds: 60, TimeoutSeconds: 5, DevelopmentLoopback: true,
				ProviderURL: provider.URL + "/v1/chat/completions", ProviderCertSHA256: tc.pin,
				CollectorURL: other.URL + "/v1/logs"}
			_ = os.Chmod(c.Spool, 0700)
			s, err := openSpool(c)
			if err != nil {
				t.Fatal(err)
			}
			g := &Gateway{config: c, spool: s, active: make(chan struct{}, 1), client: providerClient(c)}
			w := httptest.NewRecorder()
			g.ServeHTTP(w, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"approved","messages":[{"role":"user","content":"hi"}]}`)))
			if w.Code != tc.want {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
		})
	}
	// The pin is for the provider host only: any other host still needs a certificate the system trusts.
	c := Config{TimeoutSeconds: 5, ProviderURL: provider.URL + "/v1/chat/completions", ProviderCertSHA256: spkiPin(t, provider)}
	if _, err := providerClient(c).Get(strings.Replace(other.URL, "127.0.0.1", "localhost", 1)); err == nil {
		t.Fatal("an unpinned host with an untrusted certificate was accepted")
	}
	if _, err := providerClient(c).Get(provider.URL); err != nil {
		t.Fatal(err)
	}
}

func TestProviderEndpointUnderAPathPrefix(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://edge.example.test/v1/chat/completions":            true,
		"https://edge.example.test/broker/v1/chat/completions":     true,
		"https://edge.example.test/a/b-c/v1/chat/completions":      true,
		"https://edge.example.test/v1/chat/completions/x":          false,
		"https://edge.example.test/broker/v1/chat/completionsx":    false,
		"https://edge.example.test/brokerv1/chat/completions":      false,
		"https://edge.example.test/../v1/chat/completions":         false,
		"https://edge.example.test//v1/chat/completions":           false,
		"https://edge.example.test/br%2Fok/v1/chat/completions":    false,
		"https://edge.example.test/broker/./v1/chat/completions":   false,
		"http://edge.example.test/broker/v1/chat/completions":      false,
		"https://edge.example.test/broker/v1/chat/completions?a=b": false,
	} {
		if err := endpoint(raw, false, "/v1/chat/completions"); (err == nil) != ok {
			t.Errorf("%s: %v", raw, err)
		}
	}
}

func TestProviderPinIsHexForAnASCIIHost(t *testing.T) {
	pin := strings.Repeat("a", 64)
	for name, tc := range map[string]struct {
		pin, url string
		ok       bool
	}{
		"none":        {"", "https://bücher.example/v1/chat/completions", true},
		"pinned":      {pin, "https://edge.example.test/v1/chat/completions", true},
		"upper hex":   {strings.Repeat("A", 64), "https://edge.example.test/v1/chat/completions", false},
		"short":       {"abc", "https://edge.example.test/v1/chat/completions", false},
		"idn host":    {pin, "https://bücher.example/v1/chat/completions", false},
		"punycode ok": {pin, "https://xn--bcher-kva.example/v1/chat/completions", true},
	} {
		if err := validPin(tc.pin, tc.url); (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A collector on the provider's own host is still verified against the system roots: the pin is
// for provider requests only.
func TestCollectorNeverUsesTheProviderPin(t *testing.T) {
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer provider.Close()
	c := Config{TimeoutSeconds: 5, ProviderURL: provider.URL + "/v1/chat/completions", ProviderCertSHA256: spkiPin(t, provider),
		CollectorURL: provider.URL + "/v1/logs"}
	if _, err := collectorClient(c).Get(provider.URL + "/v1/logs"); err == nil {
		t.Fatal("collector accepted the provider's self-signed certificate")
	}
	g := &Gateway{config: c, client: providerClient(c), collector: collectorClient(c)}
	if g.collectorClient() == g.client {
		t.Fatal("collector shares the pinned client")
	}
}

// The pin binds host and port: another port on the provider's host is verified normally.
func TestPinIsForTheProvidersPortOnly(t *testing.T) {
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer provider.Close()
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer other.Close()
	c := Config{TimeoutSeconds: 5, ProviderURL: provider.URL + "/v1/chat/completions", ProviderCertSHA256: spkiPin(t, provider)}
	if _, err := providerClient(c).Get(other.URL); err == nil {
		t.Fatal("the pin was applied to another port on the provider's host")
	}
}
