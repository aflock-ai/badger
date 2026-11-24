// jade:ring local
// Synthetic platform for vm/uat-session.py. It answers POST /api/agent/session-check for one
// generated agent with the response platformsession.Client validates, and gives the harness a
// private Unix control socket for its revoke, scope and outage cases. It is a stand-in: the
// production handler this endpoint describes is not available to this repository, so no real
// enrollment state, tenant filter or revocation store is exercised.
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	platformsession "github.com/aflock-ai/badger/testifysec/platform"
)

const requestSchema = "testifysec.agent-session-check.request/v1"
const trustDomain = "platform.example"

var noncePattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type sessionRequest struct {
	Schema            string `json:"schema"`
	Purpose           string `json:"purpose"`
	TenantID          string `json:"tenant_id"`
	AgentID           string `json:"agent_id"`
	RepositoryID      string `json:"repository_id"`
	Nonce             string `json:"nonce"`
	RefreshCredential string `json:"refresh_credential"`
}

type fixture struct {
	mu                                                    sync.Mutex
	tenant, agent, repository, user, identity, credential string
	scoped, revoked, outage                               bool
	calls                                                 []map[string]any
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: session-platform-fixture DIRECTORY")
		os.Exit(2)
	}
	if err := run(os.Args[1], 30*time.Minute); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run serves until the harness posts /stop, or fails when lifetime passes first.
func run(base string, lifetime time.Duration) error {
	info, err := os.Lstat(base)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("fixture directory must be an existing private directory")
	}
	f := &fixture{tenant: uuid(), agent: uuid(), repository: uuid(), user: uuid(), identity: uuid(), credential: secret(), scoped: true}
	platform := httptest.NewUnstartedServer(http.HandlerFunc(f.check))
	platform.StartTLS()
	defer platform.Close()
	ca := filepath.Join(base, "platform-ca.pem")
	credential := filepath.Join(base, "refresh")
	if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: platform.Certificate().Raw}), 0600); err != nil {
		return err
	}
	if err = os.WriteFile(credential, []byte(f.credential), 0600); err != nil {
		return err
	}
	if err = write(base, "platform.json", platformsession.Config{Endpoint: platform.URL + platformsession.EndpointPath, CAFile: ca,
		CredentialFile: credential, TenantID: f.tenant, AgentID: f.agent, RepositoryID: f.repository, TrustDomain: trustDomain,
		MinimumEnrollmentAAL: "aal2"}); err != nil {
		return err
	}
	socket := filepath.Join(base, "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	if err = os.Chmod(socket, 0600); err != nil {
		listener.Close()
		return err
	}
	stopped := make(chan struct{})
	control := &http.Server{ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second,
		Handler: f.control(stopped)}
	done := make(chan error, 1)
	go func() { done <- control.Serve(listener) }()
	if err = write(base, "ready.json", map[string]any{"schema": "testifysec.aflock.vz-session-platform-fixture/v1", "controlSocket": socket,
		"platformConfigFile": filepath.Join(base, "platform.json"), "tenantId": f.tenant, "agentId": f.agent,
		"repositoryId": f.repository, "spiffeId": f.spiffe(), "delegatingUserId": f.user, "enrollmentAal": "aal2",
		"humanPresence": "not-asserted", "synthetic": true}); err != nil {
		control.Close()
		return err
	}
	var lifetimeErr error
	select {
	case <-stopped:
	case <-time.After(lifetime):
		lifetimeErr = errors.New("fixture lifetime exceeded")
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err = control.Shutdown(shutdown); err != nil {
		return err
	}
	if err = <-done; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return lifetimeErr
}

func (f *fixture) spiffe() string {
	return "spiffe://" + trustDomain + "/tenant/" + f.tenant + "/agent/" + f.agent
}

// check records each request without its credential and answers the way the native client expects.
func (f *fixture) check(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Method != http.MethodPost || r.URL.Path != platformsession.EndpointPath {
		http.Error(w, "fixture route refused", http.StatusNotFound)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4097))
	if err != nil || len(raw) > 4096 {
		http.Error(w, "fixture request bound", http.StatusBadRequest)
		return
	}
	var request sessionRequest
	_ = json.Unmarshal(raw, &request)
	record := map[string]any{"at": time.Now().UTC().Format(time.RFC3339Nano), "nonce": request.Nonce,
		"tenantId": request.TenantID, "agentId": request.AgentID, "repositoryId": request.RepositoryID,
		"credentialMatched": f.matches(request.RefreshCredential), "tls": r.TLS != nil, "outage": f.outage}
	if f.outage {
		f.calls = append(f.calls, record)
		if connection, _, err := w.(http.Hijacker).Hijack(); err == nil {
			_ = connection.Close()
		}
		return
	}
	status, identity := f.decide(request)
	record["status"] = status
	body := []byte(`{"error":"refused"}`)
	if identity != nil {
		body, _ = json.Marshal(identity)
		var response map[string]any
		_ = json.Unmarshal(body, &response)
		record["response"] = response
	}
	f.calls = append(f.calls, record)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (f *fixture) matches(credential string) bool {
	return subtle.ConstantTimeCompare([]byte(credential), []byte(f.credential)) == 1
}

// decide is the synthetic policy: the credential authenticates exactly one agent, revocation is
// terminal, and the agent is scoped to exactly one repository until the harness removes it.
func (f *fixture) decide(request sessionRequest) (int, *platformsession.Identity) {
	if request.Schema != requestSchema || request.Purpose != platformsession.Purpose || !noncePattern.MatchString(request.Nonce) {
		return http.StatusBadRequest, nil
	}
	if !f.matches(request.RefreshCredential) || f.revoked || request.TenantID != f.tenant || request.AgentID != f.agent {
		return http.StatusUnauthorized, nil
	}
	if !f.scoped || request.RepositoryID != f.repository {
		return http.StatusForbidden, nil
	}
	checked := time.Now().UTC()
	return http.StatusOK, &platformsession.Identity{Schema: "testifysec.agent-session-check.response/v1", Purpose: platformsession.Purpose,
		Authenticated: true, Authorization: "none", TenantID: f.tenant, AgentID: f.agent, RepositoryID: f.repository,
		RepositoryScope: "enrollment-repository", SPIFFEID: f.spiffe(), Nonce: request.Nonce, CheckedAt: checked,
		ExpiresAt: checked.Add(5 * time.Minute), Delegation: platformsession.Delegation{Source: "agent-enrollment", UserID: f.user,
			IdentityID: f.identity, EnrollmentAAL: "aal2", EnrollmentGitoid: "gitoid:blob:sha256:" + hex.EncodeToString(make([]byte, 32)),
			HumanPresence: "not-asserted"}}
}

func (f *fixture) control(stopped chan struct{}) http.Handler {
	var stopOnce sync.Once
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "fixture method", http.StatusMethodNotAllowed)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 257))
		if err != nil || string(raw) != "{}" {
			http.Error(w, "fixture body", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.URL.Path {
		case "/observations":
		case "/reset":
			// Revocation is terminal, as on a real platform; reset never clears it.
			f.outage, f.scoped, f.calls = false, true, nil
		case "/clear-observations":
			f.calls = nil
		case "/revoke":
			f.revoked = true
		case "/remove-scope":
			f.scoped = false
		case "/outage":
			f.outage = true
		case "/stop":
			stopOnce.Do(func() { close(stopped) })
		default:
			http.Error(w, "fixture control", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"calls": f.calls, "fixture": true})
	})
}

func write(base, name string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(base, name), raw, 0600)
}

func uuid() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func secret() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
