// jade:ring local
package main

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	platformsession "github.com/aflock-ai/badger/testifysec/platform"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fixtureResponse(status string) string {
	details := `"error":null,"incomplete_details":null`
	if status == "failed" {
		details = `"error":{"code":"server_error","message":"fixture"},"incomplete_details":null`
	}
	if status == "incomplete" {
		details = `"error":null,"incomplete_details":{"reason":"max_output_tokens"}`
	}
	return `{"id":"resp_fixture","object":"response","model":"approved","status":"` + status + `","output":[],` + details + `}`
}
func fixtureEvent(kind string, seq int, extra string) string {
	return fmt.Sprintf("event: %s\ndata: {\"type\":%q,\"sequence_number\":%d,%s}\n\n", kind, kind, seq, extra)
}
func fixtureStream(status string) string {
	return fixtureEvent("response.created", 0, `"response":`+fixtureResponse("in_progress")) + fixtureEvent("response."+status, 1, `"response":`+fixtureResponse(status))
}

func TestResponsesRequestSubset(t *testing.T) {
	valid := []string{
		`{"model":"approved","store":false,"input":"hello"}`,
		`{"model":"approved","store":false,"input":[{"role":"user","content":[{"type":"input_text","text":"hello"}]}],"stream":true}`,
		`{"model":"approved","store":false,"input":[{"type":"reasoning","id":"rs_1","summary":[],"encrypted_content":"opaque"},{"type":"function_call","call_id":"call_1","name":"read","arguments":"{}"},{"type":"function_call_output","call_id":"call_1","output":"result"}],"tools":[{"type":"function","name":"read","parameters":{"type":"object"},"strict":false}],"tool_choice":"auto","include":["reasoning.encrypted_content"],"reasoning":{"effort":"low","summary":"auto"}}`,
	}
	invalid := []string{
		`{"model":"approved","input":"hello"}`, `{"model":"approved","store":true,"input":"hello"}`,
		`{"model":"approved","store":false,"store":true,"input":"hello"}`,
		`{"model":"approved","store":false,"input":[{"role":"user","content":[{"type":"input_text","text":"first","\u0074ext":"second"}]}]}`,
		`{"model":"approved","store":false,"input":"hello","background":true}`,
		`{"model":"approved","store":false,"input":"hello","previous_response_id":"stored"}`,
		`{"model":"approved","store":false,"input":[{"type":"item_reference","id":"stored"}]}`,
		`{"model":"approved","store":false,"input":[{"role":"user","content":[{"type":"input_image","image_url":"https://example.invalid/image"}]}]}`,
		`{"model":"approved","store":false,"input":"hello","tools":[{"type":"web_search"}]}`,
		`{"model":"approved","store":false,"input":"hello","tools":[{"type":"function","name":"x","parameters":null}]}`,
		`{"model":"approved","store":false,"input":"hello","include":["web_search_call.action.sources"]}`,
		`{"model":"approved","store":false,"input":"hello","reasoning":{"effort":"high","context":"stored"}}`,
		`{"model":"approved","store":false,"input":"hello","temperature":null}`,
		`{"model":"approved","store":false,"input":"hello","stream":null}`,
		`{"model":"approved","store":false,"input":"hello","max_output_tokens":1.5}`,
	}
	for _, set := range []struct {
		bodies   []string
		accepted bool
	}{{valid, true}, {invalid, false}} {
		for _, raw := range set.bodies {
			var body jsonObject
			err := strictJSON([]byte(raw), &body)
			if err == nil {
				err = validateResponsesRequest(body)
			}
			if (err == nil) != set.accepted {
				t.Fatalf("accepted=%v: %s (%v)", err == nil, raw, err)
			}
		}
	}
}

func TestResponsesTerminalsAllChunkBoundaries(t *testing.T) {
	for _, status := range []string{"completed", "failed", "incomplete"} {
		raw := []byte(fixtureStream(status))
		for split := 0; split <= len(raw); split++ {
			s := responsesSSE{model: "approved"}
			a, e := s.observe(raw[:split])
			if e != nil {
				t.Fatal(e)
			}
			b, e := s.observe(raw[split:])
			if e != nil {
				t.Fatal(e)
			}
			if s.outcome != "provider-response-"+status || len(s.frame) != 0 || !bytes.Equal(append(append(a, b...), s.terminal...), raw) {
				t.Fatalf("invalid boundary %s/%d", status, split)
			}
			if bytes.Contains(append(a, b...), []byte(`"type":"response.`+status+`"`)) {
				t.Fatal("terminal leaked before EOF")
			}
		}
	}
}

func TestResponsesNeverTreatsInvalidOrTruncatedStreamAsCompleted(t *testing.T) {
	created := fixtureEvent("response.created", 0, `"response":`+fixtureResponse("in_progress"))
	terminal := fixtureEvent("response.completed", 1, `"response":`+fixtureResponse("completed"))
	cases := []string{
		"", "data: [DONE]\n\n", created, created + strings.TrimSuffix(terminal, "\n"), created + terminal + terminal,
		created + terminal + "data: [DONE]\n\n", strings.Replace(created+terminal, `"sequence_number":1`, `"sequence_number":0`, 1),
		created + strings.Replace(terminal, `resp_fixture`, `resp_wrong`, 1), created + strings.Replace(terminal, `"model":"approved"`, `"model":"other"`, 1),
		created + strings.Replace(terminal, `"status":"completed"`, `"status":"incomplete"`, 1),
		strings.Replace(created+terminal, `"type":"response.completed"`, `"type":"response.completed","type":"response.failed"`, 1),
		strings.Replace(created+terminal, `"sequence_number":0`, `"sequence_number":null`, 1),
		terminal, created + terminal + "data: incomplete", created + "data: " + strings.Repeat("x", 65536) + "\n\n",
		created + fixtureEvent("response.unknown", 1, `"delta":"unknown"`),
	}
	for index, raw := range cases {
		w := httptest.NewRecorder()
		var count int64
		outcome, abort := forwardResponses(w, strings.NewReader(raw), true, "approved", &count)
		if !abort || outcome != "response-interrupted" || strings.Contains(w.Body.String(), `"type":"response.completed"`) {
			t.Fatalf("case%d exposed success: %s %v %s", index, outcome, abort, w.Body.String())
		}
	}
}

func TestResponsesRefusalIsDistinctValidModelOutcome(t *testing.T) {
	reply := strings.Replace(fixtureResponse("completed"), `"output":[]`, `"output":[{"type":"message","role":"assistant","status":"completed","content":[{"type":"refusal","refusal":"fixture refusal"}]}]`, 1)
	for _, streaming := range []bool{false, true} {
		raw := reply
		if streaming {
			raw = fixtureEvent("response.created", 0, `"response":`+fixtureResponse("in_progress")) + fixtureEvent("response.completed", 1, `"response":`+reply)
		}
		w := httptest.NewRecorder()
		var count int64
		outcome, abort := forwardResponses(w, strings.NewReader(raw), streaming, "approved", &count)
		if abort || outcome != "provider-response-refused" || w.Body.String() != raw || count != int64(len(raw)) {
			t.Fatalf("refusal incorrectly classified %s/%v", outcome, abort)
		}
	}
}

func TestResponsesAuditBeforeEffectAndAbortOutcome(t *testing.T) {
	c := Config{Protocol: "responses", Model: "approved", Spool: privateTemp(t), MaxRecords: 16, MaxOfflineSeconds: 60, DevelopmentLoopback: true, ProviderURL: "https://provider.test/v1/responses", TimeoutSeconds: 5}
	_ = os.Chmod(c.Spool, 0700)
	s, err := openSpool(c)
	if err != nil {
		t.Fatal(err)
	}
	effects := 0
	g := &Gateway{config: c, spool: s, active: make(chan struct{}, 1), client: &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		effects++
		entries, err := os.ReadDir(c.Spool)
		if err != nil {
			t.Fatal(err)
		}
		started := false
		for _, entry := range entries {
			raw, _ := os.ReadFile(filepath.Join(c.Spool, entry.Name()))
			var record Record
			_ = json.Unmarshal(raw, &record)
			if record.Outcome == "started" {
				started = true
			}
		}
		if !started {
			t.Fatal("provider effect without durable start")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(fixtureEvent("response.created", 0, `"response":`+fixtureResponse("in_progress"))))}, nil
	})}}
	run := func(path, body string) (w *httptest.ResponseRecorder, panicked any) {
		w = httptest.NewRecorder()
		defer func() { panicked = recover() }()
		g.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(body)))
		return
	}
	for _, bad := range []struct{ path, body string }{{"/v1/chat/completions", `{"model":"approved","store":false,"input":"hello"}`}, {"/v1/responses", `{"model":"other","store":false,"input":"hello"}`}, {"/v1/responses", `{"model":"approved","store":false,"input":"hello","tools":[{"type":"web_search"}]}`}} {
		w, p := run(bad.path, bad.body)
		if p != nil || w.Code < 400 || effects != 0 {
			t.Fatal("denial caused provider effect")
		}
	}
	_, p := run("/v1/responses", `{"model":"approved","store":false,"input":"hello","stream":true}`)
	if p != http.ErrAbortHandler || effects != 1 {
		t.Fatal("truncation did not abort")
	}
	entries, _ := os.ReadDir(c.Spool)
	found := false
	for _, entry := range entries {
		raw, _ := os.ReadFile(filepath.Join(c.Spool, entry.Name()))
		var record Record
		_ = json.Unmarshal(raw, &record)
		if record.Outcome == "response-interrupted" {
			found = true
		}
	}
	if !found {
		t.Fatal("abort outcome not durably recorded")
	}
	s.fault = fmt.Errorf("fixture audit fault")
	w, p := run("/v1/responses", `{"model":"approved","store":false,"input":"hello"}`)
	if p != nil || w.Code != 503 || effects != 1 {
		t.Fatal("audit failure admitted effect")
	}
}

// Synthetic TLS identity replies exercise the real native client's per-effect
// checks here; actual platform authentication is the separate platform UAT.
func TestResponsesLiveIdentityRequiredForEveryEffect(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	const agent = "22222222-2222-4222-8222-222222222222"
	const repository = "33333333-3333-4333-8333-333333333333"
	var mode atomic.Value
	mode.Store("valid")
	var checked, effects atomic.Int32
	identityServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checked.Add(1)
		var request map[string]string
		if json.NewDecoder(r.Body).Decode(&request) != nil || r.URL.Path != platformsession.EndpointPath || request["refresh_credential"] != strings.Repeat("a", 43) {
			t.Error("invalid identity request")
			http.Error(w, "invalid", 400)
			return
		}
		kind := mode.Load().(string)
		if kind == "revoked" {
			http.Error(w, "revoked", 403)
			return
		}
		if kind == "outage" {
			http.Error(w, "outage", 503)
			return
		}
		reply := platformsession.Identity{Schema: "testifysec.agent-session-check.response/v1", Purpose: platformsession.Purpose, Authenticated: true, Authorization: "none", TenantID: tenant, AgentID: agent, RepositoryID: repository, RepositoryScope: "enrollment-repository", SPIFFEID: "spiffe://fixture.test/tenant/" + tenant + "/agent/" + agent, Nonce: request["nonce"], CheckedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute), Delegation: platformsession.Delegation{Source: "agent-enrollment", UserID: tenant, IdentityID: agent, EnrollmentAAL: "aal2", EnrollmentGitoid: "sha256:fixture", HumanPresence: "not-asserted"}}
		switch kind {
		case "wrong-nonce":
			reply.Nonce = "wrong"
		case "wrong-repository":
			reply.RepositoryID = agent
		case "expired":
			reply.ExpiresAt = time.Now().UTC().Add(-time.Minute)
		case "weak-aal":
			reply.Delegation.EnrollmentAAL = "aal1"
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(reply)
	}))
	defer identityServer.Close()
	dir := privateTemp(t)
	_ = os.Chmod(dir, 0700)
	ca, credential := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "credential")
	for path, raw := range map[string][]byte{ca: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: identityServer.Certificate().Raw}), credential: []byte(strings.Repeat("a", 43))} {
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	identity, err := platformsession.New(platformsession.Config{Endpoint: identityServer.URL + platformsession.EndpointPath, CAFile: ca, CredentialFile: credential, TenantID: tenant, AgentID: agent, RepositoryID: repository, TrustDomain: "fixture.test", MinimumEnrollmentAAL: "aal2"})
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Close()
	c := Config{Protocol: "responses", Model: "approved", Spool: privateTemp(t), MaxRecords: 32, MaxOfflineSeconds: 60, DevelopmentLoopback: true, ProviderURL: "https://provider.test/v1/responses", TimeoutSeconds: 5, Tenant: tenant, Agent: "spiffe://fixture.test/tenant/" + tenant + "/agent/" + agent}
	_ = os.Chmod(c.Spool, 0700)
	spool, err := openSpool(c)
	if err != nil {
		t.Fatal(err)
	}
	g := &Gateway{config: c, spool: spool, identity: identity, active: make(chan struct{}, 1), client: &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		effects.Add(1)
		entries, _ := os.ReadDir(c.Spool)
		bound := false
		for _, entry := range entries {
			raw, _ := os.ReadFile(filepath.Join(c.Spool, entry.Name()))
			var record Record
			_ = json.Unmarshal(raw, &record)
			if record.Outcome == "started" && record.IdentitySource == "platform-online-check" && record.RepositoryID == repository && record.EnrollmentAAL == "aal2" && !record.IdentityCheckedAt.IsZero() {
				bound = true
			}
		}
		if !bound {
			t.Error("provider without durable live identity attribution")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(fixtureResponse("completed")))}, nil
	})}}
	for _, kind := range []string{"valid", "revoked", "outage", "wrong-nonce", "wrong-repository", "expired", "weak-aal", "valid"} {
		mode.Store(kind)
		before, checks := effects.Load(), checked.Load()
		w := httptest.NewRecorder()
		g.ServeHTTP(w, httptest.NewRequest("POST", "/v1/responses", strings.NewReader(`{"model":"approved","store":false,"input":"fixture"}`)))
		if checked.Load() != checks+1 {
			t.Fatal("live identity check was cached")
		}
		if kind == "valid" {
			if w.Code != 200 || effects.Load() != before+1 {
				t.Fatal("valid fixture refused", w.Code)
			}
		} else if w.Code < 400 || effects.Load() != before {
			t.Fatal("identity denial reached provider", kind)
		}
	}
}

func TestResponsesOutputSchemaDoesNotInventCompletion(t *testing.T) {
	for _, output := range []string{`[null]`, `[{"type":"web_search_call","id":"call"}]`, `[{"type":"message","role":"assistant","status":"completed","content":[{"type":"refusal","refusal":null}]}]`} {
		raw := strings.Replace(fixtureResponse("completed"), `"output":[]`, `"output":`+output, 1)
		w := httptest.NewRecorder()
		var count int64
		outcome, abort := forwardResponses(w, strings.NewReader(raw), false, "approved", &count)
		if abort || outcome != "response-interrupted" || w.Code != 502 {
			t.Fatal("invalid output advertised completion")
		}
	}
	created := fixtureEvent("response.created", 0, `"response":`+fixtureResponse("in_progress"))
	for _, extra := range []string{`"output_index":-1,"item":{"type":"reasoning","id":"rs_1"}`, `"output_index":0,"item":null`, `"output_index":0,"item":{"type":"web_search_call","id":"x"}`} {
		stream := responsesSSE{model: "approved"}
		if _, err := stream.observe([]byte(created + fixtureEvent("response.output_item.added", 1, extra))); err == nil {
			t.Fatal("invalid intermediate item accepted", extra)
		}
	}
}
