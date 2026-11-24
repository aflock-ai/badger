package broker

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Device tokens share the registry with workspace tokens; a record's Device flag says which issuer
// owns it (formal/BadgerBroker/DeviceTokens.lean).

func TestProvisionerCannotTouchDeviceRecords(t *testing.T) {
	f := newFixture(t, true)
	key := map[string]string{"Authorization": "Bearer prov-key"}
	tok, _, err := f.b.tokens.IssueDevice("dev-abc", "alice@example.com", f.cfg.HumanPrincipals, time.Hour, 5, testNow, func(*sql.Tx) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if w := do(f.provision, "POST", "/provision/v1/tokens", key, `{"workspace":"dev-abc","principal":"alice@example.com"}`); w.Code != 422 {
		t.Fatalf("provisioner issued over a device record: %d", w.Code)
	}
	if w := do(f.provision, "DELETE", "/provision/v1/tokens/dev-abc", key, ""); w.Code != 422 {
		t.Fatalf("provisioner revoked a device record: %d", w.Code)
	}
	if w := do(f.internal, "GET", "/v1/models", map[string]string{"Authorization": "Bearer " + tok}, ""); w.Code != 200 {
		t.Fatalf("device token after the provisioner's attempts: %d", w.Code)
	}
}

// A provisioned workspace that happens to be named like a device keeps its life cycle.
func TestProvisionedDeviceLikeNamesStillRotateAndRevoke(t *testing.T) {
	f := newFixture(t, true)
	key := map[string]string{"Authorization": "Bearer prov-key"}
	old := f.issue("dev-team", "alice@example.com")
	fresh := f.issue("dev-team", "alice@example.com")
	if _, ok := f.b.tokens.Auth(old, f.cfg.HumanPrincipals, testNow); ok {
		t.Fatal("rotation kept the old token")
	}
	if _, _, err := f.b.tokens.IssueDevice("dev-team", "alice@example.com", f.cfg.HumanPrincipals, time.Hour, 5, testNow, func(*sql.Tx) error { return nil }); err == nil {
		t.Fatal("device sign-in replaced a provisioned workspace")
	}
	if _, ok := f.b.tokens.Auth(fresh, f.cfg.HumanPrincipals, testNow); !ok {
		t.Fatal("the workspace token was lost")
	}
	if w := do(f.provision, "DELETE", "/provision/v1/tokens/dev-team", key, ""); w.Code != 204 {
		t.Fatalf("revoke: %d", w.Code)
	}
	if _, ok := f.b.tokens.Auth(fresh, f.cfg.HumanPrincipals, testNow); ok {
		t.Fatal("revoked workspace token still accepted")
	}
}

func TestIssueDeviceRefusesAnotherPersonsDevice(t *testing.T) {
	f := newFixture(t, true)
	none := func(*sql.Tx) error { return nil }
	bob, _, err := f.b.tokens.IssueDevice("dev-x", "bob@example.com", f.cfg.HumanPrincipals, time.Hour, 5, testNow, none)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.b.tokens.IssueDevice("dev-x", "alice@example.com", f.cfg.HumanPrincipals, time.Hour, 5, testNow, none); err == nil {
		t.Fatal("alice's sign-in took bob's device name")
	}
	if p, ok := f.b.tokens.Auth(bob, f.cfg.HumanPrincipals, testNow); !ok || p != "bob@example.com" {
		t.Fatalf("bob's token after alice's attempt: %q %v", p, ok)
	}
}

func TestIssueDeviceStaysInItsNameSpace(t *testing.T) {
	f := newFixture(t, true)
	ws := f.issue("ws-alice", "alice@example.com")
	none := func(*sql.Tx) error { return nil }
	for _, name := range []string{"ws-alice", "devx", "", "dev-UPPER", "ws-new"} {
		if _, _, err := f.b.tokens.IssueDevice(name, "alice@example.com", f.cfg.HumanPrincipals, time.Hour, 5, testNow, none); err == nil {
			t.Errorf("device issue for %q accepted", name)
		}
	}
	for _, p := range []string{"ci:group/alpha", "mallory@example.com"} {
		if _, _, err := f.b.tokens.IssueDevice("dev-a", p, f.cfg.HumanPrincipals, time.Hour, 5, testNow, none); err == nil {
			t.Errorf("device issue for %q accepted", p)
		}
	}
	if w := do(f.internal, "GET", "/v1/models", map[string]string{"Authorization": "Bearer " + ws}, ""); w.Code != 200 {
		t.Fatalf("workspace token after device issues: %d", w.Code)
	}
}

func TestIssueDeviceRotatesAndCaps(t *testing.T) {
	f := newFixture(t, true)
	none := func(*sql.Tx) error { return nil }
	issue := func(name, p string, at time.Time) string {
		t.Helper()
		tok, _, err := f.b.tokens.IssueDevice(name, p, f.cfg.HumanPrincipals, time.Hour, 3, at, none)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	auth := func(tok string) bool {
		_, ok := f.b.tokens.Auth(tok, f.cfg.HumanPrincipals, testNow.Add(5*time.Minute))
		return ok
	}
	ws := f.issue("ws-alice", "alice@example.com")
	bob := issue("dev-b1", "bob@example.com", testNow)
	a1 := issue("dev-a1", "alice@example.com", testNow)
	a1again := issue("dev-a1", "alice@example.com", testNow.Add(time.Second))
	if auth(a1) || !auth(a1again) {
		t.Fatal("re-login on the same device must replace its token")
	}
	a2 := issue("dev-a2", "alice@example.com", testNow.Add(2*time.Second))
	a3 := issue("dev-a3", "alice@example.com", testNow.Add(3*time.Second))
	a4 := issue("dev-a4", "alice@example.com", testNow.Add(4*time.Second))
	if auth(a1again) {
		t.Fatal("the cap of 3 devices kept the oldest token")
	}
	for name, tok := range map[string]string{"a2": a2, "a3": a3, "a4": a4, "bob": bob} {
		if !auth(tok) {
			t.Errorf("%s refused", name)
		}
	}
	if _, ok := f.b.tokens.Auth(ws, f.cfg.HumanPrincipals, testNow); !ok {
		t.Fatal("the device cap evicted a workspace token")
	}
}

func TestRevokeTokenRevokesOnlyThePresentedToken(t *testing.T) {
	f := newFixture(t, true)
	none := func(*sql.Tx) error { return nil }
	a, _, _ := f.b.tokens.IssueDevice("dev-a", "alice@example.com", f.cfg.HumanPrincipals, time.Hour, 5, testNow, none)
	b, _, _ := f.b.tokens.IssueDevice("dev-b", "alice@example.com", f.cfg.HumanPrincipals, time.Hour, 5, testNow, none)
	ws := f.issue("ws-alice", "alice@example.com")
	rec, found, err := f.b.tokens.RevokeToken(a)
	if err != nil || !found || rec.Workspace != "dev-a" || rec.Principal != "alice@example.com" {
		t.Fatalf("revoke: %+v %v %v", rec, found, err)
	}
	if _, ok := f.b.tokens.Auth(a, f.cfg.HumanPrincipals, testNow); ok {
		t.Fatal("revoked token still accepted")
	}
	for name, tok := range map[string]string{"other device": b, "workspace": ws} {
		if _, ok := f.b.tokens.Auth(tok, f.cfg.HumanPrincipals, testNow); !ok {
			t.Errorf("%s refused after revoking another token", name)
		}
	}
	if _, found, err := f.b.tokens.RevokeToken("bbt_unknown"); found || err != nil {
		t.Fatalf("unknown token: %v %v", found, err)
	}
	f.open()
	if _, ok := f.b.tokens.Auth(a, f.cfg.HumanPrincipals, testNow); ok {
		t.Fatal("revocation did not survive a restart")
	}
	if strings.Contains(f.superText(`SELECT coalesce(string_agg(workspace || hash || principal, ' '), '') FROM broker.tokens`), "bbt_") {
		t.Fatal("tokens.json holds a token")
	}
}

func TestDeviceLoginConfig(t *testing.T) {
	f := newFixture(t, true)
	if f.cfg.DeviceLogin || f.cfg.DeviceTokenTTLHours != 0 {
		t.Fatalf("device login must be off unless configured: %+v", f.cfg.DeviceLogin)
	}
	base, _ := os.ReadFile(filepath.Join(f.dir, "config.json"))
	load := func(extra string) (*FileConfig, error) {
		p := filepath.Join(t.TempDir(), "config.json")
		os.WriteFile(p, []byte(strings.Replace(string(base), `"listen":`, extra+` "listen":`, 1)), 0o600)
		return LoadConfig(p)
	}
	c, err := load(`"device_login": true,`)
	if err != nil || c.DeviceTokenTTLHours != 8 || c.MaxDeviceTokens != 5 {
		t.Fatalf("defaults: %v %+v", err, c)
	}
	for _, bad := range []string{
		`"device_login": true, "device_token_ttl_hours": 25,`,
		`"device_login": true, "device_token_ttl_hours": -1,`,
		`"device_login": true, "max_device_tokens": 51,`,
		`"device_login": true, "max_device_tokens": -1,`,
	} {
		if _, err := load(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
