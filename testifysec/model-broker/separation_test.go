package broker

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Admin and model traffic are separate surfaces: the admin API lives only on the admin listener,
// a model-traffic credential never reaches it, and an admin session never reaches a model route.

func TestAdminAPIOnlyOnAdminListener(t *testing.T) {
	f := newFixture(t, true)
	if w := do(f.admin, "GET", "/admin/v1/policy", admin("u1"), ""); w.Code != 200 {
		t.Fatalf("admin listener: %d %s", w.Code, w.Body)
	}
	for name, h := range map[string]http.Handler{"edge": f.edge, "internal": f.internal, "provision": f.provision} {
		for _, rq := range [][2]string{{"GET", "/admin/v1/policy"}, {"PUT", "/admin/v1/policy"}, {"GET", "/admin/v1/ui/usage"},
			{"GET", "/admin/v1/usage"}, {"POST", "/admin/v1/proposals/1/approve"}} {
			if w := do(h, rq[0], rq[1], nil, `{"entries":[]}`); w.Code/100 == 2 {
				t.Errorf("%s served %s %s without identity: %d", name, rq[0], rq[1], w.Code)
			}
			if w := do(h, rq[0], rq[1], with(admin("u1"), "If-Match", `"1"`), `{"entries":[]}`); w.Code/100 == 2 {
				t.Errorf("%s served %s %s to an admin: %d", name, rq[0], rq[1], w.Code)
			}
		}
	}
	if v := f.b.store.Active(); v == nil || v.N != 1 {
		t.Fatal("a model listener changed the policy")
	}
}

func TestModelCredentialNeverReachesAdmin(t *testing.T) {
	f := newFixture(t, true)
	tok := f.issue("ws-1", "alice@example.com")
	creds := map[string]map[string]string{
		"workspace token":     {"Authorization": "Bearer " + tok},
		"provisioner key":     {"Authorization": "Bearer prov-key"},
		"any authorization":   {"Authorization": "Basic dTE6cGFzcw=="},
		"pipeline payload":    {"x-broker-ci-claims": payload(nil)},
		"edge person":         {"x-broker-principal": "alice@example.com"},
		"two principal heads": {"x-broker-principal": "alice@example.com", "x-broker-ci-claims": payload(nil)},
	}
	for name, c := range creds {
		for _, rq := range [][2]string{{"GET", "/admin/v1/policy"}, {"PUT", "/admin/v1/policy"}, {"GET", "/admin/v1/ui/usage"},
			{"GET", "/admin/v1/audit"}, {"PUT", "/admin/v1/quotas"}, {"GET", "/admin/portal/api/v1/users"}, {"GET", "/nowhere"}} {
			// Alone, and riding along with a valid admin identity: both refused.
			for _, h := range []map[string]string{c, merge(admin("u1"), c)} {
				w := do(f.admin, rq[0], rq[1], with(h, "If-Match", `"1"`), `{"entries":[]}`)
				if w.Code != 403 {
					t.Errorf("%s on %s %s: %d %s", name, rq[0], rq[1], w.Code, w.Body)
				}
			}
		}
	}
	if v := f.b.store.Active(); v == nil || v.N != 1 {
		t.Fatal("a model credential changed the policy")
	}
}

func TestAdminSessionNeverCallsModel(t *testing.T) {
	f := newFixture(t, true)
	tok := f.issue("ws-1", "alice@example.com")
	for _, hdr := range []string{"x-broker-user-id", "x-broker-role", "x-broker-user"} {
		cases := []struct {
			name string
			h    http.Handler
			cred map[string]string
		}{
			{"edge person", f.edge, map[string]string{"x-broker-principal": "alice@example.com"}},
			{"edge pipeline", f.edge, map[string]string{"x-broker-ci-claims": payload(nil)}},
			{"internal token", f.internal, map[string]string{"Authorization": "Bearer " + tok}},
		}
		for _, c := range cases {
			for _, rq := range [][2]string{{"POST", "/v1/chat/completions"}, {"GET", "/v1/models"}, {"GET", "/v1/usage"}, {"GET", "/"}} {
				w := do(c.h, rq[0], rq[1], with(c.cred, hdr, "u1"), chatA)
				if w.Code != 403 {
					t.Errorf("%s with %s on %s %s: %d", c.name, hdr, rq[0], rq[1], w.Code)
				}
			}
		}
	}
	// A full admin session on the admin listener has no model route.
	for _, rq := range [][2]string{{"POST", "/v1/chat/completions"}, {"GET", "/v1/models"}, {"GET", "/v1/usage"}, {"POST", "/device/token"}} {
		if w := do(f.admin, rq[0], rq[1], admin("u1"), chatA); w.Code != 404 {
			t.Errorf("admin listener %s %s: %d", rq[0], rq[1], w.Code)
		}
	}
	if n := f.calls.Load(); n != 0 {
		t.Fatalf("an admin session reached the model %d times", n)
	}
	// The same credentials without the admin header still work: the refusal is the header's.
	if w := do(f.edge, "POST", "/v1/chat/completions", map[string]string{"x-broker-principal": "alice@example.com"}, chatA); w.Code != 200 {
		t.Fatalf("edge person: %d", w.Code)
	}
}

func TestAdminListenerNeedsAdminGroup(t *testing.T) {
	f := newFixture(t, true)
	if w := do(f.admin, "GET", "/healthz", nil, ""); w.Code != 200 {
		t.Fatalf("healthz: %d", w.Code)
	}
	twoIDs := httpReq("GET", "/admin/portal/", map[string]string{"x-broker-role": "superAdmin"})
	twoIDs.Header.Add("x-broker-user-id", "u1")
	twoIDs.Header.Add("x-broker-user-id", "u2")
	for name, r := range map[string]*http.Request{
		"nobody":     httpReq("GET", "/admin/portal/", nil),
		"not admin":  httpReq("GET", "/admin/portal/", with(admin("u1"), "x-broker-role", "user")),
		"no id":      httpReq("GET", "/admin/portal/", map[string]string{"x-broker-role": "superAdmin"}),
		"bad origin": httpReq("GET", "/admin/portal/", with(admin("u1"), "Origin", "https://evil.example.com")),
		"two ids":    twoIDs,
	} {
		w := httptest.NewRecorder()
		f.admin.ServeHTTP(w, r)
		if w.Code != 401 && w.Code != 403 {
			t.Errorf("%s reached the admin listener: %d", name, w.Code)
		}
	}
	id, name, ok := f.b.AdminIdentity(httpReq("GET", "/admin/portal/", merge(admin("u1"), map[string]string{"x-broker-user": "Una"})))
	if !ok || id != "u1" || name != "Una" {
		t.Fatalf("AdminIdentity: %q %q %v", id, name, ok)
	}
	if _, _, ok := f.b.AdminIdentity(httpReq("GET", "/", merge(admin("u1"), map[string]string{"Authorization": "Bearer x"}))); ok {
		t.Fatal("AdminIdentity accepted a request carrying a model credential")
	}
}

func TestAdminMountsShareTheGate(t *testing.T) {
	f := newFixture(t, true)
	hit := 0
	h := f.b.Admin(Mount{Prefix: "/admin/portal", Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit++
		if r.URL.Path != "/users" {
			t.Errorf("mount saw %q", r.URL.Path)
		}
	})})
	if w := do(h, "GET", "/admin/portal/users", nil, ""); w.Code != 401 || hit != 0 {
		t.Fatalf("mount reached without identity: %d", w.Code)
	}
	if w := do(h, "GET", "/admin/portal/users", admin("u1"), ""); w.Code != 200 || hit != 1 {
		t.Fatalf("mount with admin: %d", w.Code)
	}
	if w := do(h, "GET", "/admin/portalx/users", admin("u1"), ""); w.Code != 404 || hit != 1 {
		t.Fatalf("prefix matched a longer name: %d", w.Code)
	}
}

func merge(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func httpReq(method, path string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}
