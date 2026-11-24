// jade:ring local
package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	platformsession "github.com/aflock-ai/badger/testifysec/platform"
)

type running struct {
	t      *testing.T
	dir    string
	ready  map[string]any
	client *platformsession.Client
	done   chan error
}

func start(t *testing.T) *running {
	t.Helper()
	// Unix socket paths are bounded; keep the fixture directory short.
	dir, err := os.MkdirTemp("/tmp", "spf-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	r := &running{t: t, dir: dir, done: make(chan error, 1)}
	go func() { r.done <- run(dir, time.Minute) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		raw, err := os.ReadFile(filepath.Join(dir, "ready.json"))
		if err == nil && json.Unmarshal(raw, &r.ready) == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fixture never became ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	config, err := platformsession.LoadConfig(r.ready["platformConfigFile"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if r.client, err = platformsession.New(config); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		r.client.Close()
		r.control("stop")
		if err := <-r.done; err != nil {
			t.Errorf("fixture exit: %v", err)
		}
	})
	return r
}

func (r *running) control(operation string) []map[string]any {
	r.t.Helper()
	socket := r.ready["controlSocket"].(string)
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
	defer client.CloseIdleConnections()
	res, err := client.Post("http://fixture/"+operation, "application/json", strings.NewReader("{}"))
	if err != nil {
		r.t.Fatal(err)
	}
	defer res.Body.Close()
	var body struct {
		Calls   []map[string]any `json:"calls"`
		Fixture bool             `json:"fixture"`
	}
	if res.StatusCode != http.StatusOK || json.NewDecoder(res.Body).Decode(&body) != nil || !body.Fixture {
		r.t.Fatalf("control %s: status %d", operation, res.StatusCode)
	}
	return body.Calls
}

func TestFixtureAnswersTheNativeClientContract(t *testing.T) {
	r := start(t)
	identity, err := r.client.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if identity.TenantID != r.ready["tenantId"] || identity.AgentID != r.ready["agentId"] || identity.RepositoryID != r.ready["repositoryId"] ||
		identity.SPIFFEID != r.ready["spiffeId"] || identity.Delegation.UserID != r.ready["delegatingUserId"] || identity.Authorization != "none" {
		t.Fatalf("identity does not match ready.json: %+v", identity)
	}
	second, err := r.client.Check(context.Background())
	if err != nil || second.Nonce == identity.Nonce || second.CheckedAt.Equal(identity.CheckedAt) {
		t.Fatalf("checks must be fresh: %v", err)
	}
	calls := r.control("observations")
	if len(calls) != 2 || calls[0]["status"] != float64(200) || calls[0]["credentialMatched"] != true || calls[0]["tls"] != true ||
		calls[0]["nonce"] == calls[1]["nonce"] || calls[1]["response"].(map[string]any)["nonce"] != second.Nonce {
		t.Fatalf("observations: %v", calls)
	}
	credential, err := os.ReadFile(filepath.Join(r.dir, "refresh"))
	if err != nil || strings.Contains(string(mustJSON(t, calls)), strings.TrimSpace(string(credential))) {
		t.Fatal("observations must never carry the refresh credential")
	}
}

func TestRevocationIsTerminalAcrossReset(t *testing.T) {
	r := start(t)
	r.control("revoke")
	if _, err := r.client.Check(context.Background()); !errors.Is(err, platformsession.ErrRefused) {
		t.Fatalf("revoked agent: %v", err)
	}
	r.control("reset")
	if _, err := r.client.Check(context.Background()); !errors.Is(err, platformsession.ErrRefused) {
		t.Fatalf("revocation must survive reset: %v", err)
	}
}

func TestScopeRemovalAndOutageRefuseUntilReset(t *testing.T) {
	r := start(t)
	r.control("remove-scope")
	if _, err := r.client.Check(context.Background()); !errors.Is(err, platformsession.ErrRefused) {
		t.Fatalf("unscoped repository: %v", err)
	}
	r.control("reset")
	if _, err := r.client.Check(context.Background()); err != nil {
		t.Fatalf("reset restores scope: %v", err)
	}
	r.control("outage")
	if _, err := r.client.Check(context.Background()); !errors.Is(err, platformsession.ErrUnavailable) {
		t.Fatalf("outage: %v", err)
	}
	// Reset dropped the refused call; the restored check and the outage remain.
	if calls := r.control("observations"); len(calls) != 2 || calls[0]["status"] != float64(200) || calls[1]["outage"] != true {
		t.Fatalf("reset clears observations; outage is recorded: %v", calls)
	}
	r.control("clear-observations")
	if calls := r.control("observations"); len(calls) != 0 {
		t.Fatalf("clear-observations: %v", calls)
	}
}

func TestRequestsForAnotherPrincipalAreRefused(t *testing.T) {
	f := &fixture{tenant: "a", agent: "b", repository: "c", credential: strings.Repeat("x", 43), scoped: true}
	for name, request := range map[string]sessionRequest{
		"wrong credential": {Schema: requestSchema, Purpose: platformsession.Purpose, TenantID: "a", AgentID: "b", RepositoryID: "c", Nonce: strings.Repeat("0", 64), RefreshCredential: strings.Repeat("y", 43)},
		"wrong repository": {Schema: requestSchema, Purpose: platformsession.Purpose, TenantID: "a", AgentID: "b", RepositoryID: "d", Nonce: strings.Repeat("0", 64), RefreshCredential: strings.Repeat("x", 43)},
		"wrong agent":      {Schema: requestSchema, Purpose: platformsession.Purpose, TenantID: "a", AgentID: "e", RepositoryID: "c", Nonce: strings.Repeat("0", 64), RefreshCredential: strings.Repeat("x", 43)},
		"bad nonce":        {Schema: requestSchema, Purpose: platformsession.Purpose, TenantID: "a", AgentID: "b", RepositoryID: "c", Nonce: "short", RefreshCredential: strings.Repeat("x", 43)},
	} {
		if status, _ := f.decide(request); status == http.StatusOK {
			t.Errorf("%s: accepted", name)
		}
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
