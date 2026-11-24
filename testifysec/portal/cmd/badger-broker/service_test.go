package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	broker "github.com/aflock-ai/badger/testifysec/model-broker"
	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb/pgtest"
)

type fixture struct {
	t     *testing.T
	svc   *service
	dir   string
	db    *sql.DB
	calls *atomic.Int64
}

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	_, db := pgtest.Migrated(t, components...)
	return db
}

const chat = `{"model":"model-a","messages":[{"role":"user","content":"hi"}]}`

func writeConfig(t *testing.T, dir, upstream, portal string) string {
	t.Helper()
	os.WriteFile(filepath.Join(dir, "model-key"), []byte("test-key\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "provisioner-key"), []byte("prov-key\n"), 0o600)
	raw := `{
	 "listen": {"internal": ":8080", "edge": ":8081", "provision": ":8082", "admin": ":8083"},
	 "provisioner_key_file": "` + filepath.Join(dir, "provisioner-key") + `", "workspace_token_ttl_hours": 24,
	 "issuers": [{"id": "issuer-a", "type": "gitlab", "primary": true, "issuer": "https://issuer-a.example.com",
	   "audience": "badger-broker", "claims_header": "x-broker-ci-claims",
	   "config_ref_template": "issuer-a.example.com/{project_path}//.gitlab-ci.yml@refs/heads/{ref}"}],
	 "sources": ["web"],
	 "headers": {"principal": "x-broker-principal", "admin_id": "x-broker-user-id",
	             "admin_name": "x-broker-user", "admin_role": "x-broker-role"},
	 "human_principals": ["alice@example.com"], "admin_roles": ["badger-admins"], "max_named_branch_ttl_hours": 24,
	 "allowed_origins": ["https://badger.example.com"],
	 "database": {"dsn_file": "` + filepath.Join(dir, "dsn") + `", "service_role": "` + pgtest.Service + `"},
	 "ceiling_marking": "SECRET",
	 "routes": [{"model": "model-a", "upstream_url": "` + upstream + `", "auth_header": "api-key",
	             "key_file": "` + filepath.Join(dir, "model-key") + `"}]`
	if portal != "" {
		raw += `, "portal": ` + portal
	}
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(raw+"}"), 0o600)
	return path
}

func signingKey(t *testing.T, path string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o400); err != nil {
		t.Fatal(err)
	}
}

func portalSection(dir string) string {
	return `{"signing_key_file": "` + filepath.Join(dir, "signing-key") + `",
	 "tenant_id": "tenant-example", "minimum_sequence": 1,
	 "bootstrap": {"idp-sub-admin": "admin", "idp-sub-approver": "approver"}}`
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, dir: t.TempDir(), calls: &atomic.Int64{}}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	t.Cleanup(up.Close)
	signingKey(t, filepath.Join(f.dir, "signing-key"))
	cfg, err := broker.LoadConfig(writeConfig(t, f.dir, up.URL, portalSection(f.dir)))
	if err != nil {
		t.Fatal(err)
	}
	f.db = testDB(t)
	if f.svc, err = build(cfg, f.db); err != nil {
		t.Fatal(err)
	}
	return f
}

func admin(sub string) map[string]string {
	return map[string]string{"x-broker-user-id": sub, "x-broker-user": sub, "x-broker-role": "badger-admins"}
}

func with(h map[string]string, kv ...string) map[string]string {
	out := map[string]string{}
	for k, v := range h {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i]] = kv[i+1]
	}
	return out
}

func do(h http.Handler, method, path string, headers map[string]string, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func (f *fixture) listeners() map[string]http.Handler {
	return map[string]http.Handler{"internal": f.svc.internal, "edge": f.svc.edge, "provision": f.svc.provision}
}

func (f *fixture) token() string {
	w := do(f.svc.provision, "POST", "/provision/v1/tokens", map[string]string{"Authorization": "Bearer prov-key"},
		`{"workspace":"ws-1","principal":"alice@example.com"}`)
	var out struct{ Token string }
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &out) != nil {
		f.t.Fatalf("token: %d %s", w.Code, w.Body)
	}
	return out.Token
}

func (f *fixture) profiles() int {
	var n int
	if err := pgdb.Tx(context.Background(), f.db, ceiling, func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT count(*) FROM portal.profile_versions`).Scan(&n)
	}); err != nil {
		f.t.Fatal(err)
	}
	return n
}

var ceiling, _ = pgdb.ParseLabel("SECRET")

const publish = `{"deploymentId":"deploy-a","notBefore":"2026-01-01T00:00:00Z","expiresAt":"2099-01-01T00:00:00Z"}`

// The portal is served on the admin listener, under /admin/portal, to an IdP admin.
func TestPortalMountedOnAdminListener(t *testing.T) {
	f := newFixture(t)
	if w := do(f.svc.admin, "GET", "/admin/portal/api/v1/users", admin("idp-sub-admin"), ""); w.Code != 200 {
		t.Fatalf("users: %d %s", w.Code, w.Body)
	}
	if w := do(f.svc.admin, "GET", "/admin/portal/", admin("idp-sub-admin"), ""); w.Code != 200 || !strings.Contains(w.Body.String(), "<html") {
		t.Fatalf("page: %d", w.Code)
	}
	w := do(f.svc.admin, "POST", "/admin/portal/api/v1/profiles/engineering/versions", admin("idp-sub-admin"), publish)
	if w.Code != 201 || f.profiles() == 0 {
		t.Fatalf("publish: %d %s", w.Code, w.Body)
	}
	// The broker's own admin API is on the same listener, behind the same check.
	if w := do(f.svc.admin, "GET", "/admin/v1/policy", admin("idp-sub-admin"), ""); w.Code != 200 {
		t.Fatalf("broker admin: %d", w.Code)
	}
	// Signed in with the admin group but unknown to the directory: no portal role.
	if w := do(f.svc.admin, "GET", "/admin/portal/api/v1/users", admin("idp-sub-stranger"), ""); w.Code != 401 {
		t.Fatalf("stranger: %d", w.Code)
	}
}

// A bootstrap subject outside the IdP admin group never reaches the portal.
func TestPortalNeedsAdminGroup(t *testing.T) {
	f := newFixture(t)
	for name, h := range map[string]map[string]string{
		"no group":    {"x-broker-user-id": "idp-sub-admin"},
		"wrong group": with(admin("idp-sub-admin"), "x-broker-role", "everyone"),
		"no identity": nil,
	} {
		if w := do(f.svc.admin, "POST", "/admin/portal/api/v1/profiles/engineering/versions", h, publish); w.Code != 401 && w.Code != 403 {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	if f.profiles() != 0 {
		t.Fatal("a profile was signed")
	}
}

// Signing is reachable only through the admin listener: no model listener has a portal route,
// whatever credential the request carries.
func TestSigningUnreachableFromModelTraffic(t *testing.T) {
	f := newFixture(t)
	tok := f.token()
	creds := []map[string]string{nil, {"Authorization": "Bearer " + tok}, {"Authorization": "Bearer prov-key"},
		{"x-broker-principal": "alice@example.com"}, admin("idp-sub-admin")}
	for name, h := range f.listeners() {
		for _, c := range creds {
			for _, p := range []string{"/admin/portal/api/v1/profiles/engineering/versions", "/api/v1/profiles/engineering/versions",
				"/admin/portal/api/v1/users", "/api/v1/users"} {
				if w := do(h, "POST", p, c, publish); w.Code/100 == 2 {
					t.Errorf("%s served %s: %d", name, p, w.Code)
				}
			}
		}
	}
	// Model credentials on the admin listener, alone or riding with an admin identity.
	for _, c := range creds[1:4] {
		for _, h := range []map[string]string{c, with(admin("idp-sub-admin"), flatten(c)...)} {
			if w := do(f.svc.admin, "POST", "/admin/portal/api/v1/profiles/engineering/versions", h, publish); w.Code != 403 {
				t.Errorf("model credential on the admin listener: %d", w.Code)
			}
		}
	}
	if f.profiles() != 0 {
		t.Fatal("a profile was signed from model traffic")
	}
}

// An admin session is never served as a model user, on any model listener.
func TestAdminSessionNeverServedAsModelUser(t *testing.T) {
	f := newFixture(t)
	tok := f.token()
	for name, c := range map[string]struct {
		h    http.Handler
		cred map[string]string
	}{
		"edge":     {f.svc.edge, with(admin("idp-sub-admin"), "x-broker-principal", "alice@example.com")},
		"internal": {f.svc.internal, with(admin("idp-sub-admin"), "Authorization", "Bearer "+tok)},
		"admin":    {f.svc.admin, admin("idp-sub-admin")},
	} {
		if w := do(c.h, "POST", "/v1/chat/completions", c.cred, chat); w.Code/100 == 2 {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	if n := f.calls.Load(); n != 0 {
		t.Fatalf("model called %d times", n)
	}
}

// The admin side never calls the model service: every admin route, the portal's included, runs
// with zero upstream calls, while a person's chat on the edge does reach it.
func TestAdminSideNeverCallsModel(t *testing.T) {
	f := newFixture(t)
	a := admin("idp-sub-admin")
	for _, rq := range [][3]string{
		{"GET", "/admin/v1/policy", ""}, {"GET", "/admin/v1/config", ""}, {"GET", "/admin/v1/usage", ""},
		{"GET", "/admin/v1/ui/", ""}, {"GET", "/admin/v1/audit", ""}, {"GET", "/admin/v1/quotas", ""},
		{"GET", "/admin/portal/", ""}, {"GET", "/admin/portal/users", ""}, {"GET", "/admin/portal/api/v1/profiles", ""},
		{"POST", "/admin/portal/api/v1/profiles/engineering/versions", publish},
		{"POST", "/admin/portal/api/v1/users", `{"kind":"oidc","subject":"idp-sub-dana"}`},
		{"GET", "/admin/portal/api/v1/role-requests", ""}, {"GET", "/admin/portal/.well-known/badger-portal", ""},
	} {
		if w := do(f.svc.admin, rq[0], rq[1], a, rq[2]); w.Code/100 != 2 {
			t.Errorf("%s %s: %d %s", rq[0], rq[1], w.Code, w.Body)
		}
	}
	if n := f.calls.Load(); n != 0 {
		t.Fatalf("admin routes called the model %d times", n)
	}
	if w := do(f.svc.edge, "POST", "/v1/chat/completions", map[string]string{"x-broker-principal": "alice@example.com"}, chat); w.Code != 200 || f.calls.Load() != 1 {
		t.Fatalf("model path: %d calls %d", w.Code, f.calls.Load())
	}
}

// Only the broker's model client dials out. No portal package and not this command builds an HTTP
// client or opens a connection.
func TestAdminCodeHasNoOutboundClient(t *testing.T) {
	forbidden := regexp.MustCompile(`http\.Client\b|http\.(Get|Post|PostForm|Head)\(|http\.Default(Client|Transport)|http\.Transport\b|net\.Dial|tls\.Dial|net\.Dialer`)
	checked := 0
	for _, root := range []string{"../../internal", "."} {
		filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			raw, _ := os.ReadFile(p)
			checked++
			if m := forbidden.Find(raw); m != nil {
				t.Errorf("%s: %s", p, m)
			}
			return nil
		})
	}
	if checked < 8 {
		t.Fatalf("checked only %d files", checked)
	}
}

func TestPortalConfig(t *testing.T) {
	dir := t.TempDir()
	signingKey(t, filepath.Join(dir, "signing-key"))
	good := portalSection(dir)
	for name, bad := range map[string]string{
		"unknown field":     strings.Replace(good, `"tenant_id"`, `"tenant":"x", "tenant_id"`, 1),
		"two admins":        strings.Replace(good, `"idp-sub-approver": "approver"`, `"idp-sub-approver": "admin"`, 1),
		"auditor bootstrap": strings.Replace(good, `"idp-sub-approver": "approver"`, `"idp-sub-approver": "auditor"`, 1),
		"no key":            strings.Replace(good, filepath.Join(dir, "signing-key"), filepath.Join(dir, "missing-key"), 1),
		"bad tenant":        strings.Replace(good, `"tenant-example"`, `"bad tenant/"`, 1),
		"zero sequence":     strings.Replace(good, `"minimum_sequence": 1`, `"minimum_sequence": 0`, 1),
		"relative key":      strings.Replace(good, filepath.Join(dir, "signing-key"), "signing-key", 1),
	} {
		if bad == good {
			t.Fatalf("%s: edit did not apply", name)
		}
		cfg, err := broker.LoadConfig(writeConfig(t, t.TempDir(), "https://model.example.com/a", bad))
		if err != nil {
			t.Fatalf("%s: broker config: %v", name, err)
		}
		if _, err := build(cfg, testDB(t)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Without a portal section the service is the broker alone; the admin listener still works.
	cfg, err := broker.LoadConfig(writeConfig(t, t.TempDir(), "https://model.example.com/a", ""))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := build(cfg, testDB(t))
	if err != nil {
		t.Fatal(err)
	}
	if w := do(svc.admin, "GET", "/admin/portal/api/v1/users", admin("idp-sub-admin"), ""); w.Code != 404 {
		t.Fatalf("portal served without config: %d", w.Code)
	}
}

func flatten(m map[string]string) []string {
	var out []string
	for k, v := range m {
		out = append(out, k, v)
	}
	return out
}
