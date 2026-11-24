// jade:ring local
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// administratorConfig is a v3 gateway with no platform: its identity is what the administrator
// provisioned (the signed profile it admits and the provider credential), over TLS only.
func administratorConfig(t *testing.T) Config {
	t.Helper()
	c, _ := gatewayPlatformFixture(t)
	c.Schema = gatewayV3
	c.PlatformConfigFile = ""
	c.AdministratorIdentity = true
	c.CollectorTokenFile = filepath.Join(filepath.Dir(c.Spool), "collector-token")
	if err := os.WriteFile(c.CollectorTokenFile, []byte("synthetic-collector-token"), 0600); err != nil {
		t.Fatal(err)
	}
	return c
}

func writeConfig(t *testing.T, c Config) string {
	t.Helper()
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(c.Spool), "gateway.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAdministratorIdentityStartsWithoutPlatformOverTLSOnly(t *testing.T) {
	c := administratorConfig(t)
	if _, err := readConfig(writeConfig(t, c)); err != nil {
		t.Fatal("administrator identity refused", err)
	}
	g, err := newGateway(c)
	if err != nil {
		t.Fatal("administrator identity refused at start", err)
	}
	if g.identity != nil {
		t.Fatal("administrator identity fabricated a platform identity")
	}
}

// Each refusal is checked for its own reason, so a fixture broken some other way cannot pass it.
func TestAdministratorIdentityRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(*Config)
		reason string
		// atStart: newGateway refuses too. Endpoints are checked by readConfig, which main runs first.
		atStart bool
	}{
		"cleartext provider":  {func(c *Config) { c.ProviderURL = "http://127.0.0.1:18080/v1/chat/completions" }, "HTTPS required", false},
		"cleartext collector": {func(c *Config) { c.CollectorURL = "http://127.0.0.1:14318/v1/logs" }, "HTTPS required", false},
		"with development":    {func(c *Config) { c.DevelopmentLoopback = true }, "exactly one identity source required", true},
		"with development and cleartext collector": {func(c *Config) {
			c.DevelopmentLoopback = true
			c.CollectorURL = "http://127.0.0.1:14318/v1/logs"
		}, "exactly one identity source required", true},
		"with platform": {func(c *Config) {
			p, _ := gatewayPlatformFixture(t)
			c.PlatformConfigFile = p.PlatformConfigFile
		}, "exactly one identity source required", true},
		"before v3":          {func(c *Config) { c.Schema = "testifysec.hardened-opencode.gateway/v1" }, "requires gateway v3", true},
		"no admission":       {func(c *Config) { c.AdmissionExecutable = "" }, "native admission executable required", true},
		"no signed profile":  {func(c *Config) { c.SignedProfileFile = "" }, "requires gateway v3 and a profile", true},
		"no collector token": {func(c *Config) { c.CollectorTokenFile = "" }, "requires a collector token", true},
		"not chosen":         {func(c *Config) { c.AdministratorIdentity = false }, "live platform identity required", true},
	} {
		t.Run(name, func(t *testing.T) {
			c := administratorConfig(t)
			tc.change(&c)
			if _, err := readConfig(writeConfig(t, c)); err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("configuration refused for the wrong reason or accepted: %v (want %q)", err, tc.reason)
			}
			if !tc.atStart {
				return
			}
			if g, err := newGateway(c); err == nil {
				if g.identity != nil {
					g.identity.Close()
				}
				t.Fatal("gateway started")
			}
		})
	}
}

// The administrator's provisioning is not a model principal: the provider gets the provider
// credential and nothing else, whatever the caller sends; the collector gets its own token, never
// the provider's; the audit names no platform-checked user; and admission still runs per request.
func TestAdministratorIdentityIsNotAModelPrincipal(t *testing.T) {
	g, _ := gatewayV3Fixture(t, []admittedConnector{})
	dir := filepath.Dir(g.config.Spool)
	g.config.DevelopmentLoopback, g.config.AdministratorIdentity = false, true
	g.config.CollectorURL = "https://collector.test/v1/logs"
	g.config.CollectorTokenFile = filepath.Join(dir, "collector-token")
	if err := os.WriteFile(g.config.CollectorTokenFile, []byte("synthetic-collector-token"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := identityConfiguration(g.config); err != nil {
		t.Fatal("fixture is not an administrator identity", err)
	}
	type call struct{ host, auth, forwardedUser, body string }
	var calls []call
	g.client = &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		calls = append(calls, call{r.URL.Host, r.Header.Get("Authorization"), r.Header.Get("X-Forwarded-User"), string(b)})
		if r.URL.Host == "collector.test" {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBufferString(`{}`))}, nil
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"choices":[]}`))}, nil
	})}
	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(chatBody()))
	req.Header.Set("Authorization", "Bearer synthetic-collector-token")
	req.Header.Set("X-Forwarded-User", "administrator")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, req)
	if w.Code != 200 || len(calls) != 1 || calls[0].host != "provider.test" || calls[0].auth != "Bearer fixture-token" || calls[0].forwardedUser != "" {
		t.Fatalf("provider request did not carry exactly the provider credential: %d %s %+v", w.Code, w.Body, calls)
	}
	if err := g.exportOne(context.Background()); err != nil || len(calls) != 2 {
		t.Fatal("audit record not exported", err, calls)
	}
	for _, c := range calls[1:] {
		if c.host != "collector.test" || c.auth != "Bearer synthetic-collector-token" || strings.Contains(c.body, "fixture-token") {
			t.Fatalf("collector export crossed credentials: %+v", c)
		}
		if !strings.Contains(c.body, `"administrator-provisioned"`) || strings.Contains(c.body, "delegation.user_id") || strings.Contains(c.body, "repository.id") {
			t.Fatalf("administrator identity audited as a platform-checked principal: %s", c.body)
		}
	}
	// Admission is not skipped: a native admission whose digest does not match sends nothing.
	g.config.AdmissionSHA256 = strings.Repeat("0", 64)
	sent := len(calls)
	w = httptest.NewRecorder()
	g.ServeHTTP(w, httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(chatBody())))
	if w.Code != 403 || len(calls) != sent {
		t.Fatalf("administrator identity bypassed admission: %d %+v", w.Code, calls[sent:])
	}
}

// The collector credential is a short-lived token the platform renews in place, so every export
// reads the file again; a file the gateway cannot trust stops exports instead of sending without it.
func TestCollectorTokenIsReadForEachExport(t *testing.T) {
	spool := privateTemp(t)
	if err := os.Chmod(spool, 0700); err != nil {
		t.Fatal(err)
	}
	dir := privateTemp(t)
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(dir, "collector.token")
	c := Config{Spool: spool, MaxRecords: 8, MaxOfflineSeconds: 60, CollectorURL: "https://collector.test/v1/logs", CollectorTokenFile: tokenFile}
	s, err := openSpool(c)
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	g := &Gateway{config: c, spool: s, client: &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		seen = append(seen, r.Header.Get("Authorization"))
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBufferString(`{}`))}, nil
	})}}
	record := func() {
		r, err := s.begin(1)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.finish(r, "completed", 200, 1); err != nil {
			t.Fatal(err)
		}
	}
	for i, token := range []string{"first-token", "second-token"} {
		if err := os.WriteFile(tokenFile+".new", []byte(token+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tokenFile+".new", tokenFile); err != nil {
			t.Fatal(err)
		}
		record()
		if err := g.exportOne(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(seen) != i+1 || seen[i] != "Bearer "+token {
			t.Fatalf("export %d sent %q", i, seen)
		}
	}
	if err := os.Chmod(tokenFile, 0644); err != nil {
		t.Fatal(err)
	}
	record()
	if g.exportOne(context.Background()) == nil || len(seen) != 2 {
		t.Fatal("exported with an untrusted collector token file", seen)
	}
	if err := os.Remove(tokenFile); err != nil {
		t.Fatal(err)
	}
	if g.exportOne(context.Background()) == nil || len(seen) != 2 {
		t.Fatal("exported without the collector token", seen)
	}
}
