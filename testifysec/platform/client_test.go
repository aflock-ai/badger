// jade:ring local
package platformsession

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const fixtureTenant = "11111111-1111-4111-8111-111111111111"
const fixtureAgent = "22222222-2222-4222-8222-222222222222"
const fixtureRepository = "33333333-3333-4333-8333-333333333333"

func fixtureReply(nonce string) Identity {
	return Identity{Schema: "testifysec.agent-session-check.response/v1", Purpose: Purpose, Authenticated: true,
		Authorization: "none", TenantID: fixtureTenant, AgentID: fixtureAgent, RepositoryID: fixtureRepository,
		RepositoryScope: "enrollment-repository", SPIFFEID: "spiffe://fixture.test/tenant/" + fixtureTenant + "/agent/" + fixtureAgent,
		Nonce: nonce, CheckedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour),
		Delegation: Delegation{Source: "agent-enrollment", UserID: fixtureTenant, IdentityID: fixtureAgent,
			EnrollmentAAL: "aal2", EnrollmentGitoid: "sha256:synthetic-evidence-handle", HumanPresence: "not-asserted"}}
}

func clientFixture(t *testing.T, handler http.Handler) (*Client, Config) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	secret := filepath.Join(dir, "credential")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte(strings.Repeat("a", 43)), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Endpoint: server.URL + EndpointPath, CAFile: ca, CredentialFile: secret, TenantID: fixtureTenant, AgentID: fixtureAgent, RepositoryID: fixtureRepository, TrustDomain: "fixture.test", MinimumEnrollmentAAL: "aal2"}
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client, cfg
}

// Success authority is exercised against the actual platform handler in the
// judge-api UAT. These servers deliberately generate malicious responses to
// exercise the native consumer, rather than pretending to authenticate a user.
func TestClientRejectsMisboundOrStaleResponses(t *testing.T) {
	for _, kind := range []string{"tenant", "agent", "repository", "spiffe", "nonce", "stale", "future", "expired", "grant", "scope", "aal", "human", "delegation", "duplicate", "alias", "missing", "null", "extra", "redirect"} {
		t.Run(kind, func(t *testing.T) {
			client, _ := clientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request map[string]string
				_ = json.NewDecoder(r.Body).Decode(&request)
				answer := fixtureReply(request["nonce"])
				switch kind {
				case "tenant":
					answer.TenantID = fixtureAgent
				case "agent":
					answer.AgentID = fixtureTenant
				case "repository":
					answer.RepositoryID = fixtureAgent
				case "spiffe":
					answer.SPIFFEID = strings.Replace(answer.SPIFFEID, "fixture.test", "evil.test", 1)
				case "nonce":
					answer.Nonce = strings.Repeat("0", 64)
				case "stale":
					answer.CheckedAt = time.Now().UTC().Add(-time.Minute)
				case "future":
					answer.CheckedAt = time.Now().UTC().Add(time.Minute)
				case "expired":
					answer.ExpiresAt = time.Now().UTC().Add(-time.Minute)
				case "grant":
					answer.Authorization = "model:invoke"
				case "scope":
					answer.RepositoryScope = "all"
				case "aal":
					answer.Delegation.EnrollmentAAL = "aal1"
				case "human":
					answer.Delegation.HumanPresence = "verified"
				case "delegation":
					answer.Delegation.UserID = ""
				case "redirect":
					w.Header().Set("Location", "http://127.0.0.1:1/steal")
					w.WriteHeader(302)
					return
				}
				data, _ := json.Marshal(answer)
				switch kind {
				case "duplicate":
					data = []byte(strings.TrimSuffix(string(data), "}") + `,"authenticated":true}`)
				case "alias":
					data = []byte(strings.Replace(string(data), `"authenticated":`, `"Authenticated":`, 1))
				case "missing":
					data = []byte(strings.Replace(string(data), `"authorization":"none",`, "", 1))
				case "null":
					data = []byte(strings.Replace(string(data), `"human_presence":"not-asserted"`, `"human_presence":null`, 1))
				case "extra":
					data = []byte(strings.TrimSuffix(string(data), "}") + `,"token":"forged"}`)
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				_, _ = w.Write(data)
			}))
			answer, err := client.Check(context.Background())
			if err == nil || answer.Authenticated {
				t.Fatalf("admitted %s: %+v %v", kind, answer, err)
			}
		})
	}
}

func TestPrivateFilesAndConfigurationFailClosed(t *testing.T) {
	client, cfg := clientFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unexpected network access") }))
	client.Close()
	for _, kind := range []string{"http", "query", "userinfo", "path", "current-aal2", "current-aal3", "unknown-enrollment-aal", "symlink", "permissions", "untrusted-ca"} {
		t.Run(kind, func(t *testing.T) {
			c := cfg
			switch kind {
			case "http":
				c.Endpoint = strings.Replace(c.Endpoint, "https:", "http:", 1)
			case "query":
				c.Endpoint += "?target=other"
			case "userinfo":
				c.Endpoint = strings.Replace(c.Endpoint, "https://", "https://user@", 1)
			case "path":
				c.Endpoint += "/extra"
			case "current-aal2":
				c.RequireCurrentHumanAAL = "aal2"
			case "current-aal3":
				c.RequireCurrentHumanAAL = "aal3"
			case "unknown-enrollment-aal":
				c.MinimumEnrollmentAAL = "aal9"
			case "symlink":
				p := filepath.Join(t.TempDir(), "link")
				if err := os.Symlink(c.CredentialFile, p); err != nil {
					t.Fatal(err)
				}
				c.CredentialFile = p
			case "permissions":
				p := filepath.Join(t.TempDir(), "public")
				os.WriteFile(p, []byte(strings.Repeat("a", 43)), 0644)
				c.CredentialFile = p
			case "untrusted-ca":
				p := filepath.Join(t.TempDir(), "bad-ca")
				os.WriteFile(p, []byte("not a certificate"), 0600)
				c.CAFile = p
			}
			if value, err := New(c); err == nil {
				value.Close()
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}

func TestTLSTrustCannotBeSuppliedByServer(t *testing.T) {
	client, _ := clientFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("TLS did not reject wrong trust") }))
	client.http.Transport.(*http.Transport).TLSClientConfig.RootCAs = x509.NewCertPool()
	if _, err := client.Check(context.Background()); err == nil {
		t.Fatal("untrusted platform admitted")
	}
}

func TestCheckDoesNotUseCachedCredentialsOrIdentity(t *testing.T) {
	var calls atomic.Int64
	client, cfg := clientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); http.Error(w, "refused", 401) }))
	for i := 0; i < 2; i++ {
		if _, err := client.Check(context.Background()); err != ErrRefused {
			t.Fatal(err)
		}
	}
	if calls.Load() != 2 {
		t.Fatal("check was cached")
	}
	if err := os.Remove(cfg.CredentialFile); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Check(context.Background()); err != ErrUnavailable || calls.Load() != 2 {
		t.Fatal("credential read was cached")
	}
}
