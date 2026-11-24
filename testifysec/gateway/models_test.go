// jade:ring local
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// unsignedProfileJSON is the unsigned-profile shape, valid for the hour around now: two models, the default
// first, no connectors.
func unsignedProfileJSON(tenant string) string {
	return unsignedProfileWindow(tenant, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
}

func unsignedProfileWindow(tenant string, notBefore, expiresAt time.Time) string {
	return `{"schema":"testifysec.hardened-opencode.profile.unsigned/v1","tenantId":"` + tenant + `",` +
		`"notBefore":"` + notBefore.UTC().Format(time.RFC3339) + `",` +
		`"expiresAt":"` + expiresAt.UTC().Format(time.RFC3339) + `",` +
		`"gateway":{"classification":"CONFIDENTIAL"},"connectors":[],` +
		`"models":[{"id":"gpt-5.6-sol","name":"GPT-5.6 Sol"},{"id":"gpt-5.6-luna","name":"GPT-5.6 Luna","context":65536,"output":8192}]}`
}

// writeUnsignedProfile writes raw as the profile and pins its digest in c.
func writeUnsignedProfile(t *testing.T, c *Config, raw string) {
	t.Helper()
	if c.ProfileFile == "" {
		c.ProfileFile = filepath.Join(filepath.Dir(c.Spool), "profile.json")
	}
	if err := os.WriteFile(c.ProfileFile, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(raw))
	c.ProfileDigest = hex.EncodeToString(sum[:])
}

// unsignedConfig is an administrator-identity gateway v3 whose profile is unsigned: no admission
// executable, the profile's bytes pinned by profileDigest.
func unsignedConfig(t *testing.T) Config {
	t.Helper()
	c := administratorConfig(t)
	c.SignedProfileFile, c.AdmissionExecutable, c.AdmissionSHA256 = "", "", ""
	c.Model, c.MaxRecords = "gpt-5.6-sol", 64
	writeUnsignedProfile(t, &c, unsignedProfileJSON(c.Tenant))
	return c
}

// unsignedGateway is unsignedConfig's gateway with a provider that records each request body.
func unsignedGateway(t *testing.T) (*Gateway, *[]string) {
	t.Helper()
	g, err := newGateway(unsignedConfig(t))
	if err != nil {
		t.Fatal("unsigned profile refused at start:", err)
	}
	var sent []string
	g.client = &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		sent = append(sent, string(b))
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"choices":[]}`))}, nil
	})}
	return g, &sent
}

func modelBody(model string) []byte {
	raw, _ := json.Marshal(map[string]any{"model": model, "messages": []map[string]string{{"role": "user", "content": "hi"}}})
	return raw
}

func spooled(t *testing.T, g *Gateway) []Record {
	t.Helper()
	entries, err := os.ReadDir(g.config.Spool)
	if err != nil {
		t.Fatal(err)
	}
	var records []Record
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(g.config.Spool, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var r Record
		if err = json.Unmarshal(raw, &r); err != nil {
			t.Fatal(err)
		}
		records = append(records, r)
	}
	return records
}

func TestUnsignedProfileConfiguration(t *testing.T) {
	c := unsignedConfig(t)
	if _, err := readConfig(writeConfig(t, c)); err != nil {
		t.Fatal("unsigned profile configuration refused:", err)
	}
	for name, tc := range map[string]struct {
		change func(*Config)
		reason string
	}{
		"signed and unsigned": {func(c *Config) { c.SignedProfileFile = filepath.Join(filepath.Dir(c.Spool), "profile.dsse.json") }, "exactly one profile"},
		"with admission":      {func(c *Config) { c.AdmissionExecutable = "/protected/bin/hardened-admission" }, "takes no admission executable"},
		"with admission pin":  {func(c *Config) { c.AdmissionSHA256 = strings.Repeat("b", 64) }, "takes no admission executable"},
		"no profile":          {func(c *Config) { c.ProfileFile = "" }, "requires gateway v3 and a profile"},
		"relative":            {func(c *Config) { c.ProfileFile = "profile.json" }, "absolute clean unsigned profile path required"},
		"unclean":             {func(c *Config) { c.ProfileFile = filepath.Dir(c.Spool) + "/./profile.json" }, "absolute clean unsigned profile path required"},
		"before v3": {func(c *Config) {
			c.Schema, c.AdministratorIdentity = gatewayV2, false
			c.Backend = &BackendAssignment{"darwin-vz/v1", strings.Repeat("c", 64)}
			c.CollectorTokenFile, c.DevelopmentLoopback = "", true
		}, "an unsigned profile requires gateway v3"},
		"v1": {func(c *Config) {
			c.Schema, c.AdministratorIdentity, c.CollectorTokenFile, c.DevelopmentLoopback = "testifysec.hardened-opencode.gateway/v1", false, "", true
		}, "an unsigned profile requires gateway v3"},
	} {
		t.Run(name, func(t *testing.T) {
			c := unsignedConfig(t)
			tc.change(&c)
			if _, err := readConfig(writeConfig(t, c)); err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("configuration refused for the wrong reason or accepted: %v (want %q)", err, tc.reason)
			}
		})
	}
}

// Every way an unsigned profile can be wrong stops the gateway at start, before it listens.
func TestUnsignedProfileRefusedAtStart(t *testing.T) {
	good := unsignedProfileJSON("TENANT")
	var many strings.Builder
	for i := 0; i < 31; i++ {
		many.WriteString(`{"id":"m` + strings.Repeat("x", i) + `","name":"m"},`)
	}
	for name, raw := range map[string]string{
		"other tenant":       strings.Replace(good, `"tenantId":"TENANT"`, `"tenantId":"someone-else"`, 1),
		"expired":            unsignedProfileWindow("TENANT", time.Now().Add(-time.Hour), time.Now().Add(-time.Minute)),
		"not yet valid":      unsignedProfileWindow("TENANT", time.Now().Add(time.Minute), time.Now().Add(time.Hour)),
		"window reversed":    unsignedProfileWindow("TENANT", time.Now().Add(time.Hour), time.Now().Add(-time.Hour)),
		"other schema":       strings.Replace(good, "profile.unsigned/v1", "profile.unsigned/v2", 1),
		"no default model":   strings.Replace(good, `{"id":"gpt-5.6-sol","name":"GPT-5.6 Sol"},`, "", 1),
		"no models":          strings.Replace(good, `"models":[`, `"models":[],"x":[`, 1),
		"null models":        strings.Replace(good, `"models":[`, `"models":null,"x":[`, 1),
		"duplicate model":    strings.Replace(good, `"gpt-5.6-luna"`, `"gpt-5.6-sol"`, 1),
		"model id slash":     strings.Replace(good, `"gpt-5.6-luna"`, `"openai/gpt-5.6-luna"`, 1),
		"model id newline":   strings.Replace(good, `"gpt-5.6-luna"`, `"gpt-5.6-luna\n"`, 1),
		"model id too long":  strings.Replace(good, `"gpt-5.6-luna"`, `"`+strings.Repeat("a", 129)+`"`, 1),
		"name control":       strings.Replace(good, `"GPT-5.6 Luna"`, `"GPT\u0007Luna"`, 1),
		"name empty":         strings.Replace(good, `"GPT-5.6 Luna"`, `""`, 1),
		"name too long":      strings.Replace(good, `"GPT-5.6 Luna"`, `"`+strings.Repeat("a", 65)+`"`, 1),
		"context zero":       strings.Replace(good, `"context":65536`, `"context":0`, 1),
		"context null":       strings.Replace(good, `"context":65536`, `"context":null`, 1),
		"context fraction":   strings.Replace(good, `"context":65536`, `"context":1.5`, 1),
		"output huge":        strings.Replace(good, `"output":8192`, `"output":99999999999`, 1),
		"unknown model key":  strings.Replace(good, `"output":8192`, `"output":8192,"baseURL":"https://elsewhere.invalid"`, 1),
		"unknown key":        strings.TrimSuffix(good, "}") + `,"authority":true}`,
		"duplicate key":      strings.Replace(good, `"tenantId":"TENANT"`, `"tenantId":"TENANT","tenantId":"TENANT"`, 1),
		"bad classification": strings.Replace(good, `"CONFIDENTIAL"`, `"CONFIDENTIALISH"`, 1),
		// 33: the two below and 31 more.
		"too many models":       strings.Replace(good, `"models":[`, `"models":[`+many.String(), 1),
		"connector extra field": strings.Replace(good, `"connectors":[]`, `"connectors":[{"name":"jira","classification":"SECRET","baseUrl":"https://jira.invalid"}]`, 1),
		"connector bad name":    strings.Replace(good, `"connectors":[]`, `"connectors":[{"name":"Jira_1","classification":"SECRET"}]`, 1),
		"connector duplicate":   strings.Replace(good, `"connectors":[]`, `"connectors":[{"name":"jira","classification":"SECRET"},{"name":"jira","classification":"SECRET"}]`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			c := unsignedConfig(t)
			writeUnsignedProfile(t, &c, strings.ReplaceAll(raw, "TENANT", c.Tenant))
			if _, err := newGateway(c); err == nil {
				t.Fatal("gateway started with an invalid unsigned profile")
			}
		})
	}
	t.Run("digest mismatch", func(t *testing.T) {
		c := unsignedConfig(t)
		c.ProfileDigest = strings.Repeat("a", 64)
		if _, err := newGateway(c); err == nil || !strings.Contains(err.Error(), "digest") {
			t.Fatal("gateway started with a profile its digest does not pin:", err)
		}
	})
	t.Run("readable by others", func(t *testing.T) {
		c := unsignedConfig(t)
		if err := os.Chmod(c.ProfileFile, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := newGateway(c); err == nil {
			t.Fatal("gateway started with a profile file others can write or read")
		}
	})
}

// Each allowlisted model is forwarded as asked; anything else, however close, is refused before
// the provider. The audit names the model the request asked for, durably before the provider call.
func TestGatewayAdmitsEveryAllowlistedModel(t *testing.T) {
	g, sent := unsignedGateway(t)
	var startedWith []string
	inner := g.client.Transport
	g.client.Transport = transport(func(r *http.Request) (*http.Response, error) {
		for _, record := range spooled(t, g) {
			if record.Outcome == "started" {
				startedWith = append(startedWith, record.Model)
			}
		}
		return inner.RoundTrip(r)
	})
	for _, model := range []string{"gpt-5.6-sol", "gpt-5.6-luna"} {
		w := httptest.NewRecorder()
		g.ServeHTTP(w, httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(modelBody(model))))
		if w.Code != 200 {
			t.Fatalf("%s refused: %d %s", model, w.Code, w.Body)
		}
	}
	if len(*sent) != 2 || !strings.Contains((*sent)[0], `"model":"gpt-5.6-sol"`) || !strings.Contains((*sent)[1], `"model":"gpt-5.6-luna"`) {
		t.Fatalf("provider did not receive the requested models: %q", *sent)
	}
	if strings.Join(startedWith, ",") != "gpt-5.6-sol,gpt-5.6-luna" {
		t.Fatalf("durable start records named %q", startedWith)
	}
	for _, model := range []string{"approved", "GPT-5.6-SOL", "gpt-5.6-sol ", "gpt-5.6", "gpt-5.6-sol-pro", ""} {
		w := httptest.NewRecorder()
		g.ServeHTTP(w, httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(modelBody(model))))
		if w.Code != 403 {
			t.Fatalf("%q admitted: %d", model, w.Code)
		}
	}
	if len(*sent) != 2 {
		t.Fatal("a refused model reached the provider")
	}
	models := map[string]int{}
	for _, record := range spooled(t, g) {
		models[record.Model]++
	}
	// The refused well-formed ID is recorded as asked; a malformed one is recorded as the default.
	if models["gpt-5.6-luna"] != 1 || models["approved"] != 1 || models["gpt-5.6-sol-pro"] != 1 || models["gpt-5.6-sol"] < 2 {
		t.Fatalf("audit models %v", models)
	}
	for _, record := range spooled(t, g) {
		if record.Model == "gpt-5.6-luna" && !strings.Contains(string(otlp(record, profileSignature(g.config))), `"key":"gen_ai.request.model","value":{"stringValue":"gpt-5.6-luna"}`) {
			t.Fatal("exported audit does not name the requested model")
		}
	}
}

// A gateway with no profile allowlist keeps exactly today's single model.
func TestGatewayWithoutAllowlistAdmitsOnlyItsModel(t *testing.T) {
	g, sent := gatewayV3Fixture(t, []admittedConnector{})
	for model, code := range map[string]int{"approved": 200, "gpt-5.6-sol": 403} {
		w := httptest.NewRecorder()
		g.ServeHTTP(w, httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(modelBody(model))))
		if w.Code != code {
			t.Fatalf("%s: %d, want %d", model, w.Code, code)
		}
	}
	if *sent != 1 {
		t.Fatalf("%d provider calls", *sent)
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, httptest.NewRequest("GET", "/v1/models", nil))
	if w.Code != 404 {
		t.Fatalf("a gateway with no profile allowlist served one: %d %s", w.Code, w.Body)
	}
}

// GET /v1/models is the profile's allowlist, written by the gateway itself: nothing is asked of
// the provider, nothing from the request is used, and the model's one slot is not taken.
func TestModelsRouteServesTheProfileAllowlist(t *testing.T) {
	g, sent := unsignedGateway(t)
	get := func(method, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		g.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		return w
	}
	g.active <- struct{}{}
	w := get("GET", "/v1/models")
	<-g.active
	want := `{"default":"gpt-5.6-sol","models":[{"id":"gpt-5.6-sol","name":"GPT-5.6 Sol"},{"id":"gpt-5.6-luna","name":"GPT-5.6 Luna","context":65536,"output":8192}]}`
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != want || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("served %d %q", w.Code, w.Body)
	}
	for _, c := range [][2]string{{"POST", "/v1/models"}, {"GET", "/v1/models?all=true"}, {"GET", "/v1/models/gpt-5.6-sol"}} {
		if w := get(c[0], c[1]); w.Code != 400 {
			t.Errorf("%s %s: %d", c[0], c[1], w.Code)
		}
	}
	if len(*sent) != 0 {
		t.Fatal("the models route reached the provider")
	}
	outcomes := map[string]int{}
	for _, record := range spooled(t, g) {
		outcomes[record.Outcome]++
	}
	if outcomes["models-served"] != 1 || outcomes["request-denied"] != 3 {
		t.Fatalf("audit outcomes %v", outcomes)
	}
}

// The profile is checked again for every model request: replaced, expired or above the gateway's
// accreditation, nothing is sent.
func TestUnsignedProfileCheckedForEveryRequest(t *testing.T) {
	send := func(g *Gateway) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		g.ServeHTTP(w, httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(modelBody("gpt-5.6-sol"))))
		return w
	}
	g, sent := unsignedGateway(t)
	if w := send(g); w.Code != 200 {
		t.Fatalf("valid profile refused: %d %s", w.Code, w.Body)
	}
	if err := os.WriteFile(g.config.ProfileFile, []byte(strings.Replace(unsignedProfileJSON(g.config.Tenant), "GPT-5.6 Luna", "GPT-5.6 Lune", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if w := send(g); w.Code != 403 || len(*sent) != 1 {
		t.Fatalf("replaced profile admitted: %d", w.Code)
	}
	if err := os.Remove(g.config.ProfileFile); err != nil {
		t.Fatal(err)
	}
	if w := send(g); w.Code != 403 || len(*sent) != 1 {
		t.Fatalf("removed profile admitted: %d", w.Code)
	}

	// A connector above the accreditation (CONFIDENTIAL) refuses every request, as under v3 signed.
	c := unsignedConfig(t)
	writeUnsignedProfile(t, &c, strings.Replace(unsignedProfileJSON(c.Tenant), `"connectors":[]`, `"connectors":[{"name":"confluence","classification":"SECRET"}]`, 1))
	above, err := newGateway(c)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	above.client = &http.Client{Transport: transport(func(*http.Request) (*http.Response, error) { called = true; return nil, io.EOF })}
	if w := send(above); w.Code != 403 || called || !strings.Contains(w.Body.String(), "admits a connector marked SECRET") {
		t.Fatalf("sent with a connector above the accreditation: %d %s", w.Code, w.Body)
	}
}

// The audit says the profile was unsigned, and the start log says so too.
func TestUnsignedProfileIsAudited(t *testing.T) {
	g, _ := unsignedGateway(t)
	w := httptest.NewRecorder()
	g.ServeHTTP(w, httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(modelBody("gpt-5.6-sol"))))
	records := spooled(t, g)
	if len(records) != 1 {
		t.Fatalf("%d records", len(records))
	}
	if !strings.Contains(string(otlp(records[0], profileSignature(g.config))), `"key":"profile.signature","value":{"stringValue":"unsigned"}`) {
		t.Fatal("audit does not say the profile is unsigned")
	}
	signed, _ := gatewayV3Fixture(t, nil)
	if profileSignature(signed.config) != "signed" || profileSignature(Config{}) != "none" {
		t.Fatal("profile signature misreported")
	}
	if line := startLine(g); line != "profile=unsigned sha256="+g.config.ProfileDigest+" default=gpt-5.6-sol models=gpt-5.6-sol,gpt-5.6-luna" {
		t.Fatalf("start line %q", line)
	}
}

// A record written for a model the allowlist later dropped still reloads: the spool binds the
// session, not today's allowlist. A malformed model still does not.
func TestSpoolReloadsRecordsForAnyWellFormedModel(t *testing.T) {
	g, _ := unsignedGateway(t)
	w := httptest.NewRecorder()
	g.ServeHTTP(w, httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(modelBody("gpt-5.6-luna"))))
	reopen := g.config
	reopen.Model = "approved"
	if _, err := openSpool(reopen); err != nil {
		t.Fatal("spool with a non-default model refused:", err)
	}
	record := spooled(t, g)[0]
	record.Model = "gpt-5.6-luna\nforged"
	raw, _ := json.Marshal(record)
	if err := os.WriteFile(filepath.Join(g.config.Spool, record.ID+".json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openSpool(reopen); err == nil {
		t.Fatal("spool with a malformed model accepted")
	}
}

// Responses validates the provider's echoed model against the model the request asked for.
func TestResponsesChecksTheRequestedModel(t *testing.T) {
	reply := strings.ReplaceAll(fixtureResponse("completed"), `"model":"approved"`, `"model":"gpt-5.6-luna"`)
	w := httptest.NewRecorder()
	var count int64
	if outcome, abort := forwardResponses(w, strings.NewReader(reply), false, "gpt-5.6-luna", &count); abort || outcome != "provider-response-completed" {
		t.Fatalf("requested model's response refused: %s %v", outcome, abort)
	}
	c := Config{Protocol: "responses", Model: "gpt-5.6-sol", Spool: privateTemp(t), MaxRecords: 16, MaxOfflineSeconds: 60, DevelopmentLoopback: true, ProviderURL: "https://provider.test/v1/responses", TimeoutSeconds: 5}
	_ = os.Chmod(c.Spool, 0700)
	s, err := openSpool(c)
	if err != nil {
		t.Fatal(err)
	}
	g := &Gateway{config: c, spool: s, active: make(chan struct{}, 1), models: []ModelEntry{{ID: "gpt-5.6-sol", Name: "Sol"}, {ID: "gpt-5.6-luna", Name: "Luna"}},
		client: &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(reply))}, nil
		})}}
	w = httptest.NewRecorder()
	g.ServeHTTP(w, httptest.NewRequest("POST", "/v1/responses", strings.NewReader(`{"model":"gpt-5.6-luna","store":false,"input":"hello"}`)))
	if w.Code != 200 || w.Body.String() != reply {
		t.Fatalf("responses with an allowlisted model: %d %s", w.Code, w.Body)
	}
}
