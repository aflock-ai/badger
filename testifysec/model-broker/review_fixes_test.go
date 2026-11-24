package broker

import (
	"strings"
	"testing"
	"time"
)

func TestAuditFailureRefusesAndDeactivates(t *testing.T) {
	f := newFixture(t, true)
	f.denyAudit()
	calls := f.calls.Load()
	for i := 0; i < 2; i++ {
		w := do(f.edge, "POST", "/v1/chat/completions", map[string]string{"x-broker-ci-claims": payload(nil)}, chatA)
		if w.Code != 503 {
			t.Fatalf("call %d with an unwritable audit log: %d", i, w.Code)
		}
	}
	if f.calls.Load() != calls {
		t.Fatal("a pipeline call reached the model without its audit record")
	}
	// The decision and its record are one: once the log accepts records again, calls are served.
	f.allowAudit()
	if w := do(f.edge, "POST", "/v1/chat/completions", map[string]string{"x-broker-ci-claims": payload(nil)}, chatA); w.Code != 200 {
		t.Fatalf("after the log recovered: %d", w.Code)
	}
}

func TestHeadNeedsAdmin(t *testing.T) {
	f := newFixture(t, true)
	for _, p := range []string{"/admin/v1/policy", "/admin/v1/usage", "/admin/v1/quotas", "/admin/v1/owners"} {
		if w := do(f.admin, "HEAD", p, nil, ""); w.Code != 401 || w.Header().Get("ETag") != "" {
			t.Errorf("HEAD %s without identity: %d etag %q", p, w.Code, w.Header().Get("ETag"))
		}
	}
}

func TestNullStreamOptions(t *testing.T) {
	f := newFixture(t, true)
	body := `{"model":"model-a","stream":true,"stream_options":null,"messages":[{"role":"user","content":"hi"}]}`
	w := do(f.edge, "POST", "/v1/chat/completions", map[string]string{"x-broker-ci-claims": payload(nil)}, body)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if got, _ := f.lastBody.Load().(string); !strings.Contains(got, `"include_usage":true`) {
		t.Fatalf("upstream body %s", got)
	}
}

func TestTokenIssueNeedsItsAuditRecord(t *testing.T) {
	f := newFixture(t, true)
	f.denyAudit()
	w := do(f.provision, "POST", "/provision/v1/tokens", map[string]string{"Authorization": "Bearer prov-key"},
		`{"workspace":"ws-2","principal":"alice@example.com"}`)
	if w.Code != 503 || strings.Contains(w.Body.String(), "bbt_") {
		t.Fatalf("issue without an audit record: %d %s", w.Code, w.Body)
	}
	if strings.Contains(f.superText(`SELECT coalesce(string_agg(workspace, ' '), '') FROM broker.tokens`), "ws-2") {
		t.Fatal("a token was stored although its issue could not be audited")
	}
}

func TestPolicyWriteAuditFailureBreaksTheStore(t *testing.T) {
	f := newFixture(t, true)
	f.denyAudit()
	w := do(f.admin, "PUT", "/admin/v1/policy", with(admin("u1"), "If-Match", `"1"`), `{"entries":[],"comment":"x"}`)
	if w.Code/100 == 2 {
		t.Fatalf("policy write without its audit record: %d", w.Code)
	}
	// The version and its record are one transaction: nothing was written.
	if v := f.b.store.Active(); v == nil || v.N != 1 {
		t.Fatal("a policy version was written without its audit record")
	}
}

func TestRevokeWithoutAuditStillRevokesAndSaysSo(t *testing.T) {
	f := newFixture(t, true)
	tok := f.issue("ws-3", "alice@example.com")
	f.denyAudit()
	w := do(f.provision, "DELETE", "/provision/v1/tokens/ws-3", map[string]string{"Authorization": "Bearer prov-key"}, "")
	if w.Code != 503 || !strings.Contains(w.Body.String(), "audit_unavailable") {
		t.Fatalf("revoke with an unwritable audit log: %d %s", w.Code, w.Body)
	}
	if _, ok := f.b.tokens.Auth(tok, f.cfg.HumanPrincipals, f.b.now()); ok {
		t.Fatal("the token still works after a revoke whose record failed")
	}
}

func TestFailedApprovalCanBeRetried(t *testing.T) {
	f := newFixture(t, true)
	exp := testNow.Add(48 * time.Hour)
	body := policyBody(t, f, func(es []Entry) []Entry {
		return append(es, Entry{ID: "alpha-feature", Kind: KindNamed, ProjectPath: "group/alpha", Ref: "feat/y",
			Sources: []string{"web"}, Models: []string{"model-a"}, TriggerUsers: []string{"alice"}, ExpiresAt: &exp, Enabled: true})
	})
	if w := do(f.admin, "PUT", "/admin/v1/policy", with(admin("u1"), "If-Match", `"1"`), body); w.Code != 202 {
		t.Fatalf("propose: %d %s", w.Code, w.Body)
	}
	f.denyAudit()
	if w := do(f.admin, "POST", "/admin/v1/proposals/1/approve", admin("u2"), ""); w.Code/100 == 2 {
		t.Fatalf("approval with no audit log: %d", w.Code)
	}
	f.allowAudit()
	f.open() // and across a restart
	if w := do(f.admin, "POST", "/admin/v1/proposals/1/approve", admin("u2"), ""); w.Code/100 != 2 {
		t.Fatalf("retry after the volume recovered: %d %s", w.Code, w.Body)
	}
	if len(f.b.store.Versions()) != 2 {
		t.Fatal("approved proposal not committed")
	}
}

func TestRemoteUpstreamMustBeHTTPS(t *testing.T) {
	base := RouteConfig{Model: "m", AuthHeader: "api-key", KeyFile: "/k"}
	for url, ok := range map[string]bool{
		"https://models.example.com/v1": true,
		"http://models.example.com/v1":  false,
		"http://10.0.0.5:8080/v1":       false,
		"http://127.0.0.1:8080/v1":      true,
		"http://[::1]:8080/v1":          true,
		"http://localhost:8080/v1":      true,
	} {
		r := base
		r.UpstreamURL = url
		if err := r.check(); (err == nil) != ok {
			t.Errorf("%s: accepted=%v, want %v", url, err == nil, ok)
		}
	}
}
