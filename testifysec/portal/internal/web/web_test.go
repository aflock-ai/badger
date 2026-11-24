package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb/pgtest"
	"github.com/aflock-ai/badger/testifysec/portal/contract"
	"github.com/aflock-ai/badger/testifysec/portal/internal/issue"
	"github.com/aflock-ai/badger/testifysec/portal/internal/sign"
	"github.com/aflock-ai/badger/testifysec/portal/internal/store"
	"github.com/aflock-ai/badger/testifysec/portal/internal/users"
)

// header authenticator for handler tests; production uses users.Service over mTLS.
type header struct{}

func (header) Authenticate(r *http.Request) (Principal, error) {
	role := r.Header.Get("X-Test-Role")
	if role == "" {
		return Principal{}, errors.New("no credential")
	}
	return Principal{Name: "CN=" + role + " <one>", Role: Role(role)}, nil
}

func NewTestServer(t *testing.T) *Server {
	t.Helper()
	files := store.NewPG(testDB(t), testLabel)
	audit := files
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key, err := sign.NewKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	return &Server{Auth: header{}, Profiles: files, Issuer: &issue.Issuer{TenantID: "tenant-example", MinimumSequence: 3,
		Signers: []sign.Signer{key}, Profiles: files, Assignments: files, Audit: audit, Now: time.Now}}
}

func do(h http.Handler, method, path, role, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if role != "" {
		r.Header.Set("X-Test-Role", role)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestProfileSlice(t *testing.T) {
	h := NewTestServer(t).Handler()
	body := `{"deploymentId":"deploy-a","notBefore":"2026-01-01T00:00:00Z","expiresAt":"2099-01-01T00:00:00Z"}`
	if w := do(h, "POST", "/api/v1/profiles/engineering/versions", "", body); w.Code != 401 || !strings.Contains(w.Body.String(), `"error":"unauthenticated"`) {
		t.Fatalf("unauthenticated: %d %s", w.Code, w.Body)
	}
	if w := do(h, "POST", "/api/v1/profiles/engineering/versions", "auditor", body); w.Code != 403 {
		t.Fatalf("auditor create: %d", w.Code)
	}
	if w := do(h, "POST", "/api/v1/profiles/engineering/versions", "admin", `{"deploymentId":"deploy-a","notBefore":"2026-01-01T00:00:00Z","expiresAt":"2099-01-01T00:00:00Z","sequence":1}`); w.Code != 400 || !strings.Contains(w.Body.String(), `"error":"invalid-request"`) {
		t.Fatalf("unknown field: %d", w.Code)
	}
	w := do(h, "POST", "/api/v1/profiles/engineering/versions", "admin", body)
	var v store.Version
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &v) != nil || v.Sequence != 3 || v.Envelope != nil || v.CreatedBy != "CN=admin <one>" {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	w = do(h, "GET", "/api/v1/profiles", "auditor", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), v.PayloadSHA256) || strings.Contains(w.Body.String(), `"payloadType"`) {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	var tr struct {
		PublicKeys      []string `json:"publicKeys"`
		MinimumSequence uint64   `json:"minimumSequence"`
		Threshold       int      `json:"threshold"`
	}
	w = do(h, "GET", "/api/v1/profiles/engineering/trust", "admin", "")
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &tr) != nil || len(tr.PublicKeys) != 1 || tr.MinimumSequence != 3 || tr.Threshold != 1 {
		t.Fatalf("trust: %d %s", w.Code, w.Body)
	}
	w = do(h, "GET", "/", "approver", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), v.PayloadSHA256) || !strings.Contains(w.Body.String(), "CN=approver &lt;one&gt;") {
		t.Fatalf("page: %d %s", w.Code, w.Body)
	}
}

type as string

func (r as) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("X-Test-Role", string(r))
	return http.DefaultTransport.RoundTrip(req)
}

// The conformance suite, run against this portal in-process.
func TestContractInProcess(t *testing.T) {
	srv := httptest.NewServer(NewTestServer(t).Handler())
	defer srv.Close()
	contract.Run(t, contract.Target{Base: srv.URL, Admin: &http.Client{Transport: as("admin")},
		Auditor: &http.Client{Transport: as("auditor")}, Anonymous: http.DefaultClient})
}

func TestCrossSiteSigningRefused(t *testing.T) {
	h := NewTestServer(t).Handler()
	body := `{"deploymentId":"deploy-a","notBefore":"2026-01-01T00:00:00Z","expiresAt":"2099-01-01T00:00:00Z"}`
	attempts := []func(*http.Request){
		func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
		func(r *http.Request) { r.Header.Set("Origin", "https://attacker.example.invalid") },
		func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") },                        // CORS-simple
		func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") }, // a form
		func(r *http.Request) { r.Header.Del("Content-Type") },
	}
	for i, tamper := range attempts {
		r := httptest.NewRequest("POST", "https://portal.example.invalid/api/v1/profiles/engineering/versions", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Test-Role", "admin")
		tamper(r)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 && w.Code != 415 {
			t.Errorf("attempt %d: %d %s", i, w.Code, w.Body)
		}
	}
	if w := do(h, "GET", "/api/v1/profiles", "auditor", ""); strings.Contains(w.Body.String(), "engineering") {
		t.Fatal("a refused cross-site request signed a profile")
	}
	same := httptest.NewRequest("POST", "https://portal.example.invalid/api/v1/profiles/engineering/versions", strings.NewReader(body))
	same.Header.Set("Content-Type", "application/json")
	same.Header.Set("X-Test-Role", "admin")
	same.Header.Set("Sec-Fetch-Site", "same-origin")
	same.Header.Set("Origin", "https://portal.example.invalid")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, same)
	if w.Code != 201 {
		t.Fatalf("same-origin create: %d %s", w.Code, w.Body)
	}
}

func TestTraversalInProfileID(t *testing.T) {
	h := NewTestServer(t).Handler()
	for _, path := range []string{"/api/v1/profiles/..%2F..%2Fetc/trust", "/api/v1/profiles/..%2Faudit/trust", "/api/v1/profiles/%2A/trust", "/api/v1/profiles/..%2Fx/versions"} {
		method, body := "GET", ""
		if strings.HasSuffix(path, "versions") {
			method, body = "POST", `{"deploymentId":"deploy-a","notBefore":"2026-01-01T00:00:00Z","expiresAt":"2099-01-01T00:00:00Z"}`
		}
		if w := do(h, method, path, "admin", body); w.Code != 400 && w.Code != 404 {
			t.Errorf("%s %s: %d %s", method, path, w.Code, w.Body)
		}
	}
}

func create(t *testing.T, h http.Handler, profileID, deployment string) store.Version {
	t.Helper()
	w := do(h, "POST", "/api/v1/profiles/"+profileID+"/versions", "admin",
		`{"deploymentId":"`+deployment+`","notBefore":"2026-01-01T00:00:00Z","expiresAt":"2099-01-01T00:00:00Z"}`)
	var v store.Version
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &v) != nil {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	return v
}

func TestHistoryAndEnvelope(t *testing.T) {
	h := NewTestServer(t).Handler()
	first, second := create(t, h, "engineering", "deploy-a"), create(t, h, "engineering", "deploy-a")
	var hist struct{ Items []store.Version }
	w := do(h, "GET", "/api/v1/profiles/engineering/versions", "auditor", "")
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &hist) != nil || len(hist.Items) != 2 ||
		hist.Items[0].Sequence != second.Sequence || hist.Items[1].Sequence != first.Sequence || hist.Items[0].Envelope != nil {
		t.Fatalf("history: %d %s", w.Code, w.Body)
	}
	w = do(h, "GET", fmt.Sprintf("/api/v1/profiles/engineering/versions/%d/envelope", first.Sequence), "auditor", "")
	sum := sha256.Sum256(w.Body.Bytes())
	if w.Code != 200 || hex.EncodeToString(sum[:]) != first.EnvelopeSHA256 || w.Header().Get("ETag") != `"sha256:`+first.EnvelopeSHA256+`"` {
		t.Fatalf("envelope bytes differ from what was signed: %d", w.Code)
	}
	for _, path := range []string{"/api/v1/profiles/engineering/versions/99", "/api/v1/profiles/engineering/versions/x/envelope",
		"/api/v1/profiles/..%2Fx/versions", "/api/v1/profiles/engineering/versions/00003"} {
		if w := do(h, "GET", path, "auditor", ""); w.Code != 404 && w.Code != 400 {
			t.Errorf("%s: %d", path, w.Code)
		}
	}
}

func TestAssignmentRules(t *testing.T) {
	h := NewTestServer(t).Handler()
	first, second := create(t, h, "engineering", "deploy-a"), create(t, h, "engineering", "deploy-a")
	create(t, h, "other", "deploy-b")
	put := func(role, deployment, body string) *httptest.ResponseRecorder {
		return do(h, "PUT", "/api/v1/deployments/"+deployment+"/assignment", role, body)
	}
	body := func(id string, seq uint64) string { return fmt.Sprintf(`{"profileId":%q,"sequence":%d}`, id, seq) }
	if w := put("auditor", "deploy-a", body("engineering", second.Sequence)); w.Code != 403 {
		t.Fatalf("auditor assign: %d", w.Code)
	}
	if w := put("admin", "deploy-a", body("other", 3)); w.Code != 400 {
		t.Fatalf("profile of another deployment: %d %s", w.Code, w.Body)
	}
	if w := put("admin", "deploy-a", body("engineering", 99)); w.Code != 404 {
		t.Fatalf("missing version: %d", w.Code)
	}
	var a store.Assignment
	w := put("admin", "deploy-a", body("engineering", second.Sequence))
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &a) != nil || a.PayloadSHA256 != second.PayloadSHA256 || a.AssignedBy != "CN=admin <one>" {
		t.Fatalf("assign: %d %s", w.Code, w.Body)
	}
	// Rolling back re-pins nothing: it is a new, higher version.
	if w := put("admin", "deploy-a", body("engineering", first.Sequence)); w.Code != 409 || !strings.Contains(w.Body.String(), `"error":"rollback"`) {
		t.Fatalf("re-pin older: %d %s", w.Code, w.Body)
	}
	if w := do(h, "GET", "/api/v1/deployments/deploy-a/assignment", "auditor", ""); w.Code != 200 || !strings.Contains(w.Body.String(), second.PayloadSHA256) {
		t.Fatalf("read assignment: %d %s", w.Code, w.Body)
	}
	if w := do(h, "GET", "/api/v1/deployments/deploy-c/assignment", "auditor", ""); w.Code != 404 {
		t.Fatalf("unassigned: %d", w.Code)
	}
}

func TestDiscoveryIsPublic(t *testing.T) {
	h := NewTestServer(t).Handler()
	var d map[string]any
	w := do(h, "GET", "/.well-known/badger-portal", "", "")
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &d) != nil || d["apiBase"] != "/api/v1" || d["profilePayloadType"] == nil {
		t.Fatalf("discovery: %d %s", w.Code, w.Body)
	}
}

func TestTrailingJSONRefused(t *testing.T) {
	h := NewTestServer(t).Handler()
	valid := `{"deploymentId":"deploy-a","notBefore":"2026-01-01T00:00:00Z","expiresAt":"2099-01-01T00:00:00Z"}`
	for _, tail := range []string{` {}`, ` x`, valid} {
		if w := do(h, "POST", "/api/v1/profiles/engineering/versions", "admin", valid+tail); w.Code != 400 {
			t.Errorf("trailing %q: %d", tail, w.Code)
		}
	}
	if w := do(h, "GET", "/api/v1/profiles/engineering/versions", "auditor", ""); strings.Contains(w.Body.String(), "sequence") {
		t.Fatal("a request with trailing content signed a version")
	}
	v := create(t, h, "engineering", "deploy-a")
	body := fmt.Sprintf(`{"profileId":"engineering","sequence":%d}`, v.Sequence)
	if w := do(h, "PUT", "/api/v1/deployments/deploy-a/assignment", "admin", body+` {}`); w.Code != 400 {
		t.Fatalf("assignment with trailing content: %d", w.Code)
	}
}

func TestUserRoutes(t *testing.T) {
	srv := NewTestServer(t)
	db := testDB(t)
	files, audit := users.NewPG(db, testLabel), store.NewPG(db, testLabel)
	srv.Users = &users.Service{Store: files, Audit: audit, Now: time.Now,
		Bootstrap: map[string]Role{"CN=Boot Admin": Admin, "CN=Boot Approver": Approver},
		Identify: func(r *http.Request) (users.Identity, error) {
			return users.Identity{Kind: "oidc", Subject: r.Header.Get("X-Test-Subject")}, nil
		}}
	srv.Auth = srv.Users
	h := srv.Handler()
	call := func(subject, method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("X-Test-Subject", subject)
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	var invited struct {
		User       users.User
		Activation users.Request
	}
	w := call("CN=Boot Admin", "POST", "/api/v1/users", `{"kind":"oidc","subject":"CN=Dana"}`)
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &invited) != nil || invited.User.Role != "" || invited.Activation.Kind != "activate" {
		t.Fatalf("provision: %d %s", w.Code, w.Body)
	}
	u := invited.User
	if w := call("CN=Dana", "GET", "/api/v1/users", ""); w.Code != 401 {
		t.Fatalf("a pending user without a role read the directory: %d", w.Code)
	}
	if w := call("CN=Boot Admin", "POST", "/api/v1/users", `{"kind":"oidc","subject":"CN=Dana"}`); w.Code != 409 {
		t.Fatalf("provisioned twice: %d", w.Code)
	}
	if w := call("CN=Boot Approver", "POST", "/api/v1/users", `{"kind":"oidc","subject":"CN=Eve"}`); w.Code != 403 {
		t.Fatalf("approver provisioned: %d", w.Code)
	}
	if w := call("CN=Boot Approver", "GET", "/api/v1/users", ""); w.Code != 200 || !strings.Contains(w.Body.String(), "CN=Dana") {
		t.Fatalf("directory: %d %s", w.Code, w.Body)
	}
	if w := call("CN=Boot Admin", "POST", "/api/v1/users/"+u.ID+"/role-requests", `{"role":"auditor"}`); w.Code != 409 {
		t.Fatalf("grant to a pending user: %d %s", w.Code, w.Body)
	}
	if w := call("CN=Boot Approver", "POST", "/api/v1/role-requests/"+invited.Activation.ID+"/approve", `{}`); w.Code != 200 {
		t.Fatalf("activate: %d %s", w.Code, w.Body)
	}
	var req users.Request
	w = call("CN=Boot Admin", "POST", "/api/v1/users/"+u.ID+"/role-requests", `{"role":"auditor"}`)
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &req) != nil {
		t.Fatalf("request: %d %s", w.Code, w.Body)
	}
	if w := call("CN=Boot Admin", "POST", "/api/v1/role-requests/"+req.ID+"/approve", `{}`); w.Code != 403 {
		t.Fatalf("admin approved: %d", w.Code)
	}
	if w := call("CN=Boot Approver", "POST", "/api/v1/role-requests/"+req.ID+"/approve", `{}`); w.Code != 200 {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	if w := call("CN=Dana", "GET", "/api/v1/users", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"role":"auditor"`) {
		t.Fatalf("auditor reads the directory: %d %s", w.Code, w.Body)
	}
	if w := call("CN=Boot Approver", "POST", "/api/v1/role-requests/"+req.ID+"/reject", `{}`); w.Code != 409 {
		t.Fatalf("decided twice: %d", w.Code)
	}
	if w := call("CN=Boot Admin", "POST", "/api/v1/users/"+u.ID+"/drop-role", `{}`); w.Code != 200 {
		t.Fatalf("drop-role: %d %s", w.Code, w.Body)
	}
	if w := call("CN=Dana", "GET", "/api/v1/users", ""); w.Code != 401 {
		t.Fatalf("dropped role still reads: %d", w.Code)
	}
	if w := call("CN=Boot Admin", "POST", "/api/v1/users/..%2Fx/role-requests", `{"role":"admin"}`); w.Code != 400 && w.Code != 404 {
		t.Fatalf("traversal: %d", w.Code)
	}
}

func TestUserLifecycleRoutes(t *testing.T) {
	srv := NewTestServer(t)
	db := testDB(t)
	files, audit := users.NewPG(db, testLabel), store.NewPG(db, testLabel)
	srv.Users = &users.Service{Store: files, Audit: audit, Now: time.Now,
		Bootstrap: map[string]Role{"CN=Boot Admin": Admin, "CN=Boot Approver": Approver},
		Identify: func(r *http.Request) (users.Identity, error) {
			return users.Identity{Kind: "oidc", Subject: r.Header.Get("X-Test-Subject")}, nil
		}}
	srv.Auth = srv.Users
	h := srv.Handler()
	call := func(subject, method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("X-Test-Subject", subject)
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	var invited struct {
		User       users.User
		Activation users.Request
	}
	w := call("CN=Boot Admin", "POST", "/api/v1/users", `{"kind":"oidc","subject":"CN=Dana"}`)
	json.Unmarshal(w.Body.Bytes(), &invited)
	call("CN=Boot Approver", "POST", "/api/v1/role-requests/"+invited.Activation.ID+"/approve", `{}`)
	if w := call("CN=Boot Approver", "GET", "/api/v1/role-requests", ""); w.Code != 200 || strings.Contains(w.Body.String(), invited.Activation.ID) {
		t.Fatalf("decided activation still queued: %d %s", w.Code, w.Body)
	}
	dep := "/api/v1/users/" + invited.User.ID + "/deployments/deploy-a"
	if w := call("CN=Boot Admin", "PUT", dep, `{}`); w.Code != 200 || !strings.Contains(w.Body.String(), "deploy-a") {
		t.Fatalf("assign: %d %s", w.Code, w.Body)
	}
	if w := call("CN=Boot Approver", "PUT", dep, `{}`); w.Code != 403 {
		t.Fatalf("approver assigned: %d", w.Code)
	}
	if w := call("CN=Boot Admin", "DELETE", dep, `{}`); w.Code != 200 || strings.Contains(w.Body.String(), "deploy-a") {
		t.Fatalf("unassign: %d %s", w.Code, w.Body)
	}
	call("CN=Boot Admin", "PUT", dep, `{}`)
	if w := call("CN=Boot Admin", "GET", "/users", ""); w.Code != 200 || !strings.Contains(w.Body.String(), "CN=Dana") || !strings.Contains(w.Body.String(), "deploy-a") {
		t.Fatalf("users page: %d %s", w.Code, w.Body)
	}
	if w := call("CN=Boot Admin", "POST", "/api/v1/users/"+invited.User.ID+"/offboard", `{}`); w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"offboarded"`) {
		t.Fatalf("offboard: %d %s", w.Code, w.Body)
	}
	if w := call("CN=Boot Admin", "DELETE", dep, `{}`); w.Code != 409 {
		t.Fatalf("membership change on an offboarded user: %d", w.Code)
	}
}

// testDB is a fresh migrated database; testLabel the ceiling the tests run at.
func testDB(t *testing.T) *sql.DB {
	t.Helper()
	_, db := pgtest.Migrated(t, pgdb.Core, store.Schema)
	return db
}

var testLabel = func() pgdb.Label {
	l, err := pgdb.ParseLabel("SECRET")
	if err != nil {
		panic(err)
	}
	return l
}()

// A v3 profile is authored through the same route; every nested object is as strict as the top.
func TestProfileV3Route(t *testing.T) {
	h := NewTestServer(t).Handler()
	connector := `{"name":"confluence","binarySha256":"` + strings.Repeat("a", 64) + `","baseUrl":"https://wiki.example.invalid",` +
		`"tokenPath":"/run/badger/tokens/confluence.token","caPath":null,"writes":false,"classification":"CONFIDENTIAL",` +
		`"flags":{"label-prefix":"m-"},"permissions":{"confluence_*":"allow"}%s}`
	body := `{"schemaVersion":3,"deploymentId":"deploy-a","notBefore":"2026-01-01T00:00:00Z","expiresAt":"2099-01-01T00:00:00Z",` +
		`"gateway":{"classification":"SECRET"%s},"connectors":[` + connector + `]}`
	for name, b := range map[string]string{
		"connector-field": fmt.Sprintf(body, "", `,"authority":true`),
		"gateway-field":   fmt.Sprintf(body, `,"override":true`, ""),
	} {
		if w := do(h, "POST", "/api/v1/profiles/engineering/versions", "admin", b); w.Code != 400 || !strings.Contains(w.Body.String(), `"error":"invalid-request"`) {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	above := strings.Replace(fmt.Sprintf(body, "", ""), `"classification":"CONFIDENTIAL"`, `"classification":"TOP SECRET"`, 1)
	if w := do(h, "POST", "/api/v1/profiles/engineering/versions", "admin", above); w.Code != 400 || !strings.Contains(w.Body.String(), `"error":"invalid-profile"`) {
		t.Fatalf("connector above the gateway: %d %s", w.Code, w.Body)
	}
	w := do(h, "POST", "/api/v1/profiles/engineering/versions", "admin", fmt.Sprintf(body, "", ""))
	var v store.Version
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &v) != nil || v.Sequence != 3 {
		t.Fatalf("create v3: %d %s", w.Code, w.Body)
	}
	w = do(h, "GET", "/api/v1/profiles/engineering/versions/3/envelope", "auditor", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"payloadType":"application/vnd.testifysec.hardened-opencode.profile.v3+json"`) {
		t.Fatalf("envelope: %d %s", w.Code, w.Body)
	}
	var tr struct {
		SchemaVersion int `json:"schemaVersion"`
	}
	if w = do(h, "GET", "/api/v1/profiles/engineering/trust", "admin", ""); w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &tr) != nil || tr.SchemaVersion != 3 {
		t.Fatalf("trust: %d %s", w.Code, w.Body)
	}
}
