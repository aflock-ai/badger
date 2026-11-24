package broker

import (
	"bufio"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb/pgtest"
)

const (
	testIssuer   = "https://gitlab.example.com"
	testAudience = "badger-broker"
	// A second GitLab, its own provider and header at the edge.
	testIssuer2 = "https://gitlab-2.example.com"
	testHeader2 = "x-broker-ci-claims-gitlab-2"
)

var testNow = time.Unix(1_800_000_000, 0)

type fixture struct {
	t         *testing.T
	b         *Broker
	cfg       *FileConfig
	dir       string
	upstream  *httptest.Server
	calls     atomic.Int64
	delayMs   atomic.Int64 // upstream answers after this long, to hold calls in flight
	lastBody  atomic.Value
	internal  http.Handler
	edge      http.Handler
	provision http.Handler
	admin     http.Handler
	pg        *pgtest.DB
	db        *sql.DB
}

// issue asks the provisioning listener for a workspace token.
func (f *fixture) issue(workspace, principal string) string {
	f.t.Helper()
	w := do(f.provision, "POST", "/provision/v1/tokens", map[string]string{"Authorization": "Bearer prov-key"},
		`{"workspace":"`+workspace+`","principal":"`+principal+`"}`)
	if w.Code != 201 {
		f.t.Fatalf("issue %s: %d %s", workspace, w.Code, w.Body)
	}
	var out struct {
		Token string `json:"token"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	return out.Token
}

// newFixture: a broker with two routes to a fake upstream, people alice@ and bob@, and the
// corpus policy seeded as version 1.
func newFixture(t *testing.T, twoPerson bool) *fixture {
	t.Helper()
	f := &fixture{t: t, dir: t.TempDir()}
	f.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		time.Sleep(time.Duration(f.delayMs.Load()) * time.Millisecond)
		b, _ := io.ReadAll(r.Body)
		f.lastBody.Store(string(b))
		if r.Header.Get("api-key") != "test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if strings.Contains(string(b), `"stream":true`) {
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "data: {\"choices\":[]}\n\ndata: {\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":4}}\n\ndata: [DONE]\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":3,"completion_tokens":2}}`)
	}))
	t.Cleanup(f.upstream.Close)
	key := filepath.Join(f.dir, "key")
	os.WriteFile(key, []byte("test-key\n"), 0o600)
	os.WriteFile(filepath.Join(f.dir, "provisioner-key"), []byte("prov-key\n"), 0o600)
	raw := `{
	 "listen": {"internal": ":8080", "edge": ":8081", "provision": ":8082", "admin": ":8083"},
	 "provisioner_key_file": "` + filepath.Join(f.dir, "provisioner-key") + `", "workspace_token_ttl_hours": 24,
	 "issuers": [
	  {"id": "gitlab-1", "type": "gitlab", "primary": true, "issuer": "` + testIssuer + `", "audience": "` + testAudience + `",
	   "claims_header": "x-broker-ci-claims", "max_token_lifetime_seconds": 0,
	   "config_ref_template": "gitlab.example.com/{project_path}//.gitlab-ci.yml@refs/heads/{ref}"},
	  {"id": "gitlab-2", "type": "gitlab", "issuer": "` + testIssuer2 + `", "audience": "` + testAudience + `",
	   "claims_header": "` + testHeader2 + `", "max_token_lifetime_seconds": 3600,
	   "config_ref_template": "gitlab-2.example.com/{project_path}//.gitlab-ci.yml@refs/heads/{ref}"}],
	 "clock_skew_seconds": 0,
	 "sources": ["web", "push", "schedule"],
	 "headers": {"principal": "x-broker-principal", "admin_id": "x-broker-user-id",
	             "admin_name": "x-broker-user", "admin_role": "x-broker-role"},
	 "human_principals": ["alice@example.com", "bob@example.com"],
	 "admin_roles": ["superAdmin"], "two_person_rule": ` + map[bool]string{true: "true", false: "false"}[twoPerson] + `,
	 "max_named_branch_ttl_hours": 336, "allowed_origins": ["https://broker.example.com"],
	 "database": {"dsn_file": "` + filepath.Join(f.dir, "dsn") + `", "service_role": "` + pgtest.Service + `"},
	 "ceiling_marking": "SECRET", "seed_policy_file": "` + filepath.Join(f.dir, "seed.json") + `",
	 "routes": [
	  {"model": "model-a", "upstream_url": "` + f.upstream.URL + `/a", "auth_header": "api-key", "key_file": "` + key + `",
	   "api_version": "2025-04-01-preview", "reasoning_map": {"minimal": "low"}, "no_reasoning_with_tools": true},
	  {"model": "model-b", "upstream_url": "` + f.upstream.URL + `/b", "auth_header": "api-key", "key_file": "` + key + `"}]
	}`
	path := filepath.Join(f.dir, "config.json")
	os.WriteFile(path, []byte(raw), 0o600)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := loadCorpus(t)
	seed, _ := json.Marshal(Policy{Entries: c.Entries})
	os.WriteFile(cfg.SeedPolicyFile, seed, 0o600)
	// Every seeded pipeline entry has a human owner, as production requires; owner tests remove it.
	owners := map[string]string{}
	for _, e := range c.Entries {
		owners[e.ID] = "alice@example.com"
	}
	f.pg, f.db = pgtest.Migrated(t, pgdb.Core, Schema)
	f.cfg = cfg
	if err := (documents{db: f.db, label: cfg.Ceiling()}).put("owners", 0, OwnerSet{Version: 1, Owners: owners}); err != nil {
		t.Fatal(err)
	}
	f.open()
	return f
}

func (f *fixture) open() {
	op := f.cfg.Operator()
	store := OpenStore(f.db, f.cfg.Ceiling(), op)
	if store.broken != nil {
		f.t.Fatal(store.broken)
	}
	if err := store.Seed(op, f.cfg.SeedPolicyFile, testNow); err != nil {
		f.t.Fatal(err)
	}
	f.b = newBroker(f.cfg, f.db, store, f.upstream.Client())
	f.b.now = func() time.Time { return testNow }
	f.internal, f.edge, f.provision, f.admin = f.b.Internal(), f.b.Edge(), f.b.Provision(), f.b.Admin()
}

func payload(over map[string]any) string {
	c := map[string]any{"iss": testIssuer, "aud": testAudience, "exp": testNow.Unix() + 3000, "iat": testNow.Unix() - 600,
		"project_path": "group/alpha", "ref": "main", "ref_type": "branch", "ref_protected": "true",
		"pipeline_source": "web", "ci_config_ref_uri": "gitlab.example.com/group/alpha//.gitlab-ci.yml@refs/heads/main",
		"user_login": "alice"}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

func do(h http.Handler, method, path string, headers map[string]string, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	if body != "" && r.Header.Get("Content-Type") == "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

const chatA = `{"model":"model-a","messages":[{"role":"user","content":"hi"}]}`

func TestPipelineAllowedAndAccounted(t *testing.T) {
	f := newFixture(t, true)
	w := do(f.edge, "POST", "/v1/chat/completions", map[string]string{"x-broker-ci-claims": payload(nil)}, chatA)
	if w.Code != 200 || w.Header().Get("X-Broker-Usage-Principal") != "ci:group/alpha" {
		t.Fatalf("%d %s %v", w.Code, w.Body, w.Header())
	}
	var usage struct {
		Principals map[string]map[string]usageCount `json:"principals"`
	}
	raw, err := f.b.up.usage.reportAll(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(raw, &usage)
	if usage.Principals["ci:group/alpha"]["model-a"].Requests != 1 {
		t.Fatalf("usage %+v", usage)
	}
	recs, _ := f.b.store.AuditAfter(0, 100)
	last := recs[len(recs)-1]
	if last.Kind != "decision" || last.Decision != "allow" || last.Principal != "ci:group/alpha" ||
		last.UserLogin != "alice" || last.Version != 1 || last.EntryID != "alpha" {
		t.Fatalf("audit %+v", last)
	}
}

// TestPipelineDenials: fail closed on the edge listener, each without reaching the upstream.
func TestPipelineDenials(t *testing.T) {
	f := newFixture(t, true)
	for name, tc := range map[string]struct {
		headers map[string]string
		path    string
		body    string
		want    int
	}{
		"no payload":         {map[string]string{}, "/v1/chat/completions", chatA, 401},
		"garbage payload":    {map[string]string{"x-broker-ci-claims": "%%%"}, "/v1/chat/completions", chatA, 401},
		"payload not json":   {map[string]string{"x-broker-ci-claims": base64.RawURLEncoding.EncodeToString([]byte("{"))}, "/v1/chat/completions", chatA, 401},
		"wrong issuer":       {map[string]string{"x-broker-ci-claims": payload(map[string]any{"iss": "https://x"})}, "/v1/chat/completions", chatA, 401},
		"list audience":      {map[string]string{"x-broker-ci-claims": payload(map[string]any{"aud": []string{testAudience}})}, "/v1/chat/completions", chatA, 401},
		"expired":            {map[string]string{"x-broker-ci-claims": payload(map[string]any{"exp": testNow.Unix()})}, "/v1/chat/completions", chatA, 401},
		"unprotected":        {map[string]string{"x-broker-ci-claims": payload(map[string]any{"ref_protected": "false"})}, "/v1/chat/completions", chatA, 403},
		"unlisted project":   {map[string]string{"x-broker-ci-claims": payload(map[string]any{"project_path": "group/other"})}, "/v1/chat/completions", chatA, 403},
		"model not on entry": {map[string]string{"x-broker-ci-claims": payload(nil)}, "/v1/chat/completions", `{"model":"model-b"}`, 403},
		"no model":           {map[string]string{"x-broker-ci-claims": payload(nil)}, "/v1/chat/completions", `{"messages":[]}`, 403},
		"usage":              {map[string]string{"x-broker-ci-claims": payload(nil)}, "/v1/usage", "", 404},
		"models":             {map[string]string{"x-broker-ci-claims": payload(nil)}, "/v1/models", "", 404},
		"origin":             {map[string]string{"x-broker-ci-claims": payload(nil), "Origin": "https://broker.example.com"}, "/v1/chat/completions", chatA, 403},
		"two payloads":       {map[string]string{"x-broker-ci-claims": payload(nil) + "," + payload(nil)}, "/v1/chat/completions", chatA, 401},
	} {
		method := "POST"
		if tc.body == "" {
			method = "GET"
		}
		if w := do(f.edge, method, tc.path, tc.headers, tc.body); w.Code != tc.want {
			t.Errorf("%s: %d, want %d", name, w.Code, tc.want)
		}
	}
	if f.calls.Load() != 0 {
		t.Fatalf("a denied request reached the upstream %d times", f.calls.Load())
	}
}

// TestEdgeIgnoresPrincipalHeader: edge_payload_ignores_principal_header. With a payload, a
// person's principal header changes nothing.
func TestEdgeIgnoresPrincipalHeader(t *testing.T) {
	f := newFixture(t, true)
	w := do(f.edge, "POST", "/v1/chat/completions", map[string]string{"x-broker-principal": "alice@example.com",
		"x-broker-ci-claims": payload(nil)}, chatA)
	if w.Code != 200 || w.Header().Get("X-Broker-Usage-Principal") != "ci:group/alpha" {
		t.Fatalf("%d %s", w.Code, w.Header().Get("X-Broker-Usage-Principal"))
	}
}

// TestInternalNeverPipeline: internal_never_pipeline, internal_ignores_principal_header. The
// listener workspaces reach serves only a valid workspace token's owner; a principal header, a
// ci: name or a pipeline payload gets nothing.
func TestInternalNeverPipeline(t *testing.T) {
	f := newFixture(t, true)
	tok := f.issue("ws-alice", "alice@example.com")
	for name, h := range map[string]map[string]string{
		"payload":              {"x-broker-ci-claims": payload(nil)},
		"payload and token":    {"x-broker-ci-claims": payload(nil), "Authorization": "Bearer " + tok},
		"principal header":     {"x-broker-principal": "alice@example.com"},
		"ci principal header":  {"x-broker-principal": "ci:group/alpha"},
		"junk token":           {"Authorization": "Bearer bbt_junk"},
		"no credential":        {},
		"edge identity copies": {"x-broker-user-id": "u1", "x-broker-role": "superAdmin"},
	} {
		// An admin identity is refused outright (403); every other credential is unauthenticated.
		if w := do(f.internal, "POST", "/v1/chat/completions", h, chatA); w.Code != 401 && !(w.Code == 403 && name == "edge identity copies") {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	if f.calls.Load() != 0 {
		t.Fatal("reached upstream")
	}
}

// TestWorkspaceServedAsOwner: workspace_served_as_owner. A header naming someone else changes
// nothing; the token decides.
func TestWorkspaceServedAsOwner(t *testing.T) {
	f := newFixture(t, true)
	tok := f.issue("ws-alice", "alice@example.com")
	w := do(f.internal, "POST", "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + tok,
		"x-broker-principal": "bob@example.com"}, chatA)
	if w.Code != 200 || w.Header().Get("X-Broker-Usage-Principal") != "alice@example.com" {
		t.Fatalf("%d %s", w.Code, w.Header().Get("X-Broker-Usage-Principal"))
	}
}

// TestTokenRotationAndRevocation: rotate_denies_old, revoke_denies, expired_token_refused,
// issue_refuses_ci, unauthorized_provision_noop; the registry survives a restart.
func TestTokenRotationAndRevocation(t *testing.T) {
	f := newFixture(t, true)
	h := func(tok string) map[string]string { return map[string]string{"Authorization": "Bearer " + tok} }
	old := f.issue("ws-alice", "alice@example.com")
	bob := f.issue("ws-bob", "bob@example.com")
	fresh := f.issue("ws-alice", "alice@example.com")
	if w := do(f.internal, "GET", "/v1/models", h(old), ""); w.Code != 401 {
		t.Fatalf("old token after rotation: %d", w.Code)
	}
	if w := do(f.internal, "GET", "/v1/models", h(fresh), ""); w.Code != 200 {
		t.Fatalf("new token: %d", w.Code)
	}
	f.open() // restart: tokens.json reloads
	if w := do(f.internal, "GET", "/v1/models", h(fresh), ""); w.Code != 200 {
		t.Fatalf("after restart: %d", w.Code)
	}
	if w := do(f.provision, "DELETE", "/provision/v1/tokens/ws-alice", map[string]string{"Authorization": "Bearer prov-key"}, ""); w.Code != 204 {
		t.Fatalf("revoke: %d", w.Code)
	}
	if w := do(f.internal, "GET", "/v1/models", h(fresh), ""); w.Code != 401 {
		t.Fatalf("revoked token: %d", w.Code)
	}
	if w := do(f.internal, "GET", "/v1/models", h(bob), ""); w.Code != 200 {
		t.Fatalf("another workspace's token must survive: %d", w.Code)
	}
	f.b.now = func() time.Time { return testNow.Add(25 * time.Hour) }
	if w := do(f.internal, "GET", "/v1/models", h(bob), ""); w.Code != 401 {
		t.Fatalf("expired token: %d", w.Code)
	}
	for name, body := range map[string]string{
		"ci principal":  `{"workspace":"ws-x","principal":"ci:group/alpha"}`,
		"unlisted":      `{"workspace":"ws-x","principal":"mallory@example.com"}`,
		"bad workspace": `{"workspace":"WS X","principal":"alice@example.com"}`,
	} {
		if w := do(f.provision, "POST", "/provision/v1/tokens", map[string]string{"Authorization": "Bearer prov-key"}, body); w.Code != 422 {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	for name, hh := range map[string]map[string]string{
		"no key":    {},
		"wrong key": {"Authorization": "Bearer nope"},
	} {
		if w := do(f.provision, "POST", "/provision/v1/tokens", hh, `{"workspace":"ws-x","principal":"alice@example.com"}`); w.Code != 401 {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	if strings.Contains(f.superText(`SELECT coalesce(string_agg(workspace || hash || principal, ' '), '') FROM broker.tokens`), "bbt_") {
		t.Fatal("tokens.json holds a token, not a hash")
	}
}

// TestEdgePeople: people the edge signed in are served on the edge listener by the principal
// header (edge_person_listed).
func TestEdgePeople(t *testing.T) {
	f := newFixture(t, true)
	alice := map[string]string{"x-broker-principal": "alice@example.com"}
	if w := do(f.edge, "POST", "/v1/chat/completions", alice, chatA); w.Code != 200 ||
		w.Header().Get("X-Broker-Usage-Principal") != "alice@example.com" {
		t.Fatalf("%d", w.Code)
	}
	for name, h := range map[string]map[string]string{
		"ci header": {"x-broker-principal": "ci:group/alpha"},
		"unlisted":  {"x-broker-principal": "mallory@example.com"},
		"no header": {},
	} {
		if w := do(f.edge, "POST", "/v1/chat/completions", h, chatA); w.Code != 401 {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
}

// TestHumanPathUnchanged: people keep what apim-broker gave them.
func TestHumanPathUnchanged(t *testing.T) {
	f := newFixture(t, true)
	tok := f.issue("ws-alice", "alice@example.com")
	alice := map[string]string{"Authorization": "Bearer " + tok}
	w := do(f.internal, "POST", "/v1/chat/completions", alice,
		`{"model":"model-a","reasoning_effort":"minimal","max_tokens":5,"tools":[],"messages":[]}`)
	if w.Code != 200 || w.Header().Get("X-Broker-Usage-Principal") != "alice@example.com" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var sent map[string]any
	json.Unmarshal([]byte(f.lastBody.Load().(string)), &sent)
	if _, ok := sent["reasoning_effort"]; ok || sent["max_completion_tokens"] != float64(5) || sent["max_tokens"] != nil {
		t.Fatalf("payload rewrite: %v", sent)
	}
	if w := do(f.internal, "POST", "/v1/chat/completions", alice, `{"messages":[]}`); w.Code != 200 {
		t.Fatalf("default route for people: %d", w.Code)
	}
	if w := do(f.internal, "GET", "/v1/usage", alice, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"principal":"alice@example.com"`) {
		t.Fatalf("usage %d %s", w.Code, w.Body)
	}
	if w := do(f.internal, "GET", "/v1/models", alice, ""); w.Code != 200 || !strings.Contains(w.Body.String(), "model-b") {
		t.Fatalf("models %d", w.Code)
	}
	if w := do(f.internal, "GET", "/", alice, ""); w.Code != 200 || !strings.Contains(w.Body.String(), "alice@example.com") {
		t.Fatalf("page %d", w.Code)
	}
	if w := do(f.internal, "POST", "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + tok,
		"Origin": "https://evil.example"}, chatA); w.Code != 403 {
		t.Fatalf("foreign origin: %d", w.Code)
	}
	// Admin is not on the internal listener at all.
	if w := do(f.internal, "GET", "/admin/v1/policy", map[string]string{"x-broker-user-id": "u1", "x-broker-role": "superAdmin"}, ""); w.Code/100 == 2 {
		t.Fatalf("admin on internal: %d", w.Code)
	}
}

func TestStreamingUsage(t *testing.T) {
	f := newFixture(t, true)
	w := do(f.edge, "POST", "/v1/chat/completions", map[string]string{"x-broker-ci-claims": payload(nil)},
		`{"model":"model-a","stream":true}`)
	sc := bufio.NewScanner(w.Body)
	lines := 0
	for sc.Scan() {
		lines++
	}
	if w.Code != 200 || lines == 0 {
		t.Fatalf("%d", w.Code)
	}
	if got := reportOf(t, f.b.up.usage, time.Now()).Principals["ci:group/alpha"]["model-a"]; got.PromptTokens != 7 {
		t.Fatalf("usage %+v", got)
	}
}

func TestReadyz(t *testing.T) {
	f := newFixture(t, true)
	if w := do(f.edge, "GET", "/readyz", nil, ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	os.WriteFile(f.cfg.Routes[0].KeyFile, nil, 0o600)
	if w := do(f.internal, "GET", "/readyz", nil, ""); w.Code != 503 {
		t.Fatal(w.Code)
	}
}

func TestConfigRefusesUnsafeSettings(t *testing.T) {
	f := newFixture(t, true)
	raw, _ := os.ReadFile(filepath.Join(f.dir, "config.json"))
	for name, edit := range map[string][2]string{
		"ci human":       {`"alice@example.com"`, `"ci:alice"`},
		"same listeners": {`":8081"`, `":8080"`},
		"admin shares":   {`":8083"`, `":8081"`},
		"no admin":       {`, "admin": ":8083"`, ``},
		"unknown field":  {`"seed_policy_file"`, `"seed_policy_fil"`},
		"header clash":   {`"x-broker-user"`, `"x-broker-role"`},
		"bad template":   {`{project_path}//`, `x//`},
		"http origin":    {`https://broker.example.com`, `http://broker.example.com`},
		"auth header":    {`"auth_header": "api-key", "key_file"`, `"auth_header": "x-other", "key_file"`},
	} {
		bad := strings.Replace(string(raw), edit[0], edit[1], 1)
		if bad == string(raw) {
			t.Fatalf("%s: edit did not apply", name)
		}
		p := filepath.Join(t.TempDir(), "c.json")
		os.WriteFile(p, []byte(bad), 0o600)
		if _, err := LoadConfig(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
