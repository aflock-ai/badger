// jade:ring local
package vzsession

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aflock-ai/badger/testifysec/platform"
)

// fakeEdge is the broker behind its edge, as far as device sign-in sees it: the approval page
// redirects straight to the loopback callback (as if the person approved), the exchange checks
// the PKCE verifier and port, and DELETE signs a token out.
type fakeEdge struct {
	*httptest.Server
	mu        sync.Mutex
	devices   []string
	codes     map[string]url.Values
	issued    string
	signedOut []string
	exchanges int
	// signOutStatus, when set, is the edge's answer to a sign-out.
	signOutStatus int
}

var edgeToken = "bbt_" + base64.RawURLEncoding.EncodeToString([]byte("edge-token-edge-token-edge-token"))

func newFakeEdge(t *testing.T) *fakeEdge {
	t.Helper()
	e := &fakeEdge{codes: map[string]url.Values{}, issued: edgeToken}
	e.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		defer e.mu.Unlock()
		switch {
		case r.Method == "GET" && r.URL.Path == "/broker/device/authorize":
			q := r.URL.Query()
			e.devices = append(e.devices, q.Get("device"))
			code := "code-" + q.Get("state")
			e.codes[code] = q
			http.Redirect(w, r, "http://127.0.0.1:"+q.Get("port")+"/callback?code="+code+"&state="+q.Get("state"), http.StatusSeeOther)
		case r.Method == "POST" && r.URL.Path == "/broker/device/token":
			e.exchanges++
			var body struct {
				Code     string `json:"code"`
				Verifier string `json:"verifier"`
				Port     int    `json:"port"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			q, ok := e.codes[body.Code]
			delete(e.codes, body.Code)
			sum := sha256.Sum256([]byte(body.Verifier))
			if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != q.Get("challenge") || q.Get("port") != itoa(body.Port) {
				w.WriteHeader(400)
				return
			}
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(map[string]string{"token": e.issued})
		case r.Method == "DELETE" && r.URL.Path == "/broker/device/token":
			e.signedOut = append(e.signedOut, r.Header.Get("Authorization"))
			if e.signOutStatus != 0 {
				w.WriteHeader(e.signOutStatus)
				return
			}
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(e.Close)
	return e
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func (e *fakeEdge) pin() string {
	sum := sha256.Sum256(e.Certificate().RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// browser follows the approval page to the loopback callback, as a person's browser would.
func browser(e *fakeEdge) func(context.Context, string) error {
	return func(_ context.Context, u string) error {
		go func() {
			res, err := e.Client().Get(u)
			if err == nil {
				io.Copy(io.Discard, res.Body)
				res.Body.Close()
			}
		}()
		return nil
	}
}

func signInFixture(t *testing.T, e *fakeEdge) *brokerSignIn {
	t.Helper()
	b := &brokerSignIn{EdgeURL: e.URL + "/broker", EdgeCertSHA256: e.pin(), DeviceIDFile: filepath.Join(privateTestDir(t), "config", "device-id")}
	if err := b.validate(); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDeviceSignInAndSignOut(t *testing.T) {
	e := newFakeEdge(t)
	b := signInFixture(t, e)
	tok, err := b.signIn(context.Background(), browser(e))
	if err != nil {
		t.Fatal(err)
	}
	if tok.token != edgeToken {
		t.Fatalf("token %q", tok.token)
	}
	// The device id is stable across sign-ins and private to the user.
	if _, err = b.signIn(context.Background(), browser(e)); err != nil {
		t.Fatal(err)
	}
	// Each session is its own device record, under the computer's stable id: a second session on
	// the same computer never replaces the first one's token.
	stable, _ := b.deviceID()
	if len(e.devices) != 2 || e.devices[0] == e.devices[1] ||
		!strings.HasPrefix(e.devices[0], stable+"-") || !strings.HasPrefix(e.devices[1], stable+"-") {
		t.Fatalf("device ids %v (stable %s)", e.devices, stable)
	}
	info, err := os.Stat(b.DeviceIDFile)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("device id file: %v %v", info, err)
	}
	if err = tok.signOut(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(e.signedOut) != 1 || e.signedOut[0] != "Bearer "+edgeToken {
		t.Fatalf("sign-out sent %v", e.signedOut)
	}
}

func TestDeviceSignInRefusesAWrongEdgeKey(t *testing.T) {
	e := newFakeEdge(t)
	b := signInFixture(t, e)
	b.EdgeCertSHA256 = strings.Repeat("0", 64)
	if _, err := b.signIn(context.Background(), browser(e)); err == nil || Code(err) != "broker_signin_exchange" {
		t.Fatalf("wrong pin: %v", err)
	}
	// The code was never redeemed: the exchange never reached the edge.
	if e.exchanges != 0 {
		t.Fatal("exchange sent to an edge with the wrong key")
	}
}

func TestDeviceSignInChecksTheCallback(t *testing.T) {
	e := newFakeEdge(t)
	b := signInFixture(t, e)
	// A page that hits the loopback listener with the wrong state gets nothing, and the sign-in
	// waits for the real callback until its deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	forged := func(_ context.Context, u string) error {
		q, _ := url.Parse(u)
		go func() {
			res, err := http.Get("http://127.0.0.1:" + q.Query().Get("port") + "/callback?code=x&state=forged")
			if err == nil {
				if res.StatusCode != 400 {
					t.Errorf("forged callback answered %d", res.StatusCode)
				}
				res.Body.Close()
			}
		}()
		return nil
	}
	if _, err := b.signIn(ctx, forged); err == nil || Code(err) != "broker_signin_timeout" {
		t.Fatalf("forged callback: %v", err)
	}
	if e.exchanges != 0 {
		t.Fatal("a forged code was exchanged")
	}
}

func TestDeviceSignInRefusesAMalformedToken(t *testing.T) {
	e := newFakeEdge(t)
	e.issued = "not-a-broker-token"
	if _, err := signInFixture(t, e).signIn(context.Background(), browser(e)); err == nil {
		t.Fatal("malformed token accepted")
	}
}

func TestBrokerSignInAssignment(t *testing.T) {
	for edge, ok := range map[string]bool{
		"https://edge.example.test":         true,
		"https://edge.example.test/broker":  true,
		"http://edge.example.test/broker":   false,
		"https://edge.example.test/broker/": false,
		"https://edge.example.test/../x":    false,
		"https://u@edge.example.test":       false,
		"https://edge.example.test?x=1":     false,
	} {
		b := brokerSignIn{EdgeURL: edge}
		if err := b.validate(); (err == nil) != ok {
			t.Errorf("%s: %v", edge, err)
		}
	}
	for pin, ok := range map[string]bool{"": true, strings.Repeat("a", 64): true, strings.Repeat("A", 64): false, "x": false} {
		b := brokerSignIn{EdgeURL: "https://edge.example.test", EdgeCertSHA256: pin}
		if err := b.validate(); (err == nil) != ok {
			t.Errorf("pin %q: %v", pin, err)
		}
	}
	if err := (&brokerSignIn{EdgeURL: "https://edge.example.test", DeviceIDFile: "relative"}).validate(); err == nil {
		t.Error("relative device id file accepted")
	}
}

// The gateway's configuration carries a descriptor number and the edge pin, never a token or a
// token file; a template that names a token file is refused.
func TestGatewayTemplateHasNoTokenFile(t *testing.T) {
	template := gatewayTemplate{Schema: "testifysec.aflock.vz-gateway-template/v1", Protocol: "chat-completions",
		ProviderURL: "https://edge.example.test/broker/v1/chat/completions", CollectorURL: "https://collector.example/v1/logs",
		Model: "approved", MaxRecords: 10, MaxOfflineSeconds: 60, TimeoutSeconds: 30,
		BrokerSignIn: &brokerSignIn{EdgeURL: "https://edge.example.test/broker", EdgeCertSHA256: strings.Repeat("a", 64)}}
	if err := template.validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*gatewayTemplate){
		"no sign-in":     func(g *gatewayTemplate) { g.BrokerSignIn = nil },
		"other provider": func(g *gatewayTemplate) { g.ProviderURL = "https://other.example.test/v1/chat/completions" },
	} {
		candidate := template
		mutate(&candidate)
		if err := candidate.validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	raw, _ := json.Marshal(template)
	var withFile map[string]any
	json.Unmarshal(raw, &withFile)
	withFile["providerTokenFile"] = "/private/token"
	raw, _ = json.Marshal(withFile)
	var target gatewayTemplate
	if err := strict(raw, &target); err == nil {
		t.Fatal("a template naming a token file was accepted")
	}
	c := configuration{template: template}
	out, err := c.gatewayConfig("af-session", "/private/state", "/private/audit", platformsession.Identity{TenantID: "tenant", SPIFFEID: "spiffe://platform.example.test/tenant/tenant/agent/agent"})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	json.Unmarshal(out, &cfg)
	if cfg["providerTokenFd"] != float64(gatewayTokenFD) || cfg["providerCertSha256"] != strings.Repeat("a", 64) {
		t.Fatalf("gateway config %v", cfg)
	}
	if _, ok := cfg["providerTokenFile"]; ok || strings.Contains(string(out), "bbt_") {
		t.Fatalf("gateway config names a token: %s", out)
	}
}

// Two sessions starting at once on a new device agree on one device id, and a reader never sees a
// partly written one.
func TestDeviceIDIsCreatedOnceUnderConcurrency(t *testing.T) {
	b := &brokerSignIn{EdgeURL: "https://edge.example.test", DeviceIDFile: filepath.Join(privateTestDir(t), "cfg", "device-id")}
	ids := make(chan string, 16)
	errs := make(chan error, 16)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := b.deviceID()
			ids <- id
			errs <- err
		}()
	}
	wg.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	first := ""
	for id := range ids {
		if first == "" {
			first = id
		}
		if id != first || !reDeviceID.MatchString(id) {
			t.Fatalf("device ids differ: %q %q", first, id)
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(b.DeviceIDFile))
	if len(entries) != 1 {
		t.Fatalf("temporary files left: %v", entries)
	}
}

// When the browser cannot be opened, the printed URL still works: sign-in keeps waiting.
func TestDeviceSignInWaitsWhenTheBrowserDoesNotOpen(t *testing.T) {
	e := newFakeEdge(t)
	b := signInFixture(t, e)
	follow := browser(e)
	failing := func(ctx context.Context, u string) error {
		follow(ctx, u) // the person opens the printed URL themselves
		return errors.New("no browser")
	}
	setForTest(t, &openerRequired, false)
	if _, err := b.signIn(context.Background(), failing); err != nil {
		t.Fatal(err)
	}
}

// Anything but a regular file at the device id path is refused, once: no retry loop.
func TestDeviceIDRefusesASymlinkOrDirectory(t *testing.T) {
	dir := privateTestDir(t)
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "missing"), dangling); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(dir, "directory")
	os.Mkdir(directory, 0o700)
	garbage := filepath.Join(dir, "garbage")
	os.WriteFile(garbage, []byte("not an id"), 0o600)
	for _, path := range []string{dangling, directory, garbage} {
		if _, err := (&brokerSignIn{DeviceIDFile: path}).deviceID(); err == nil || Code(err) != "broker_signin_device" {
			t.Errorf("%s: %v", filepath.Base(path), err)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 3 {
		t.Fatalf("temporary files left: %v", entries)
	}
}

// A browser launch that never returns does not hold the session past its deadline.
func TestDeviceSignInDeadlineHoldsWhileTheBrowserStalls(t *testing.T) {
	e := newFakeEdge(t)
	b := signInFixture(t, e)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stalled := make(chan struct{})
	stall := func(ctx context.Context, _ string) error { <-ctx.Done(); close(stalled); return ctx.Err() }
	started := time.Now()
	if _, err := b.signIn(ctx, stall); err == nil || Code(err) != "broker_signin_timeout" {
		t.Fatalf("stalled browser: %v", err)
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("sign-in outlived its deadline")
	}
	select {
	case <-stalled:
	case <-time.After(5 * time.Second):
		t.Fatal("the browser launch was not cancelled")
	}
}

// The session limit starts when sign-in ends: a slow approval does not use up the session.
func TestSessionLimitStartsAfterSignIn(t *testing.T) {
	e := newFakeEdge(t)
	b := signInFixture(t, e)
	follow := browser(e)
	slow := func(ctx context.Context, u string) error {
		time.Sleep(1500 * time.Millisecond) // the person takes longer than the whole session limit
		return follow(ctx, u)
	}
	_, ctx, cancel, err := signInThenLimit(context.Background(), b, slow, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	if ctx.Err() != nil {
		t.Fatal("the session limit ran during sign-in")
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) < 500*time.Millisecond {
		t.Fatalf("session deadline %v, %v left", ok, time.Until(deadline))
	}
}

// Only the session UAT build replaces the browser; this (ordinary) build opens the person's.
func TestReleaseBuildOpensThePersonsBrowser(t *testing.T) {
	if headlessSignIn {
		t.Skip("UAT build")
	}
	if reflect.ValueOf(browserOpener).Pointer() != reflect.ValueOf(openBrowser).Pointer() {
		t.Fatal("the release build does not open the person's browser")
	}
}

// A sign-out the broker could not record is reported as such, never as signed out.
func TestSignOutFailureIsReported(t *testing.T) {
	e := newFakeEdge(t)
	tok, err := signInFixture(t, e).signIn(context.Background(), browser(e))
	if err != nil {
		t.Fatal(err)
	}
	e.signOutStatus = 503
	if err := tok.signOut(context.Background()); err == nil {
		t.Fatal("a 503 sign-out counted as signed out")
	}
}

func setForTest[T any](t *testing.T, v *T, to T) {
	was := *v
	*v = to
	t.Cleanup(func() { *v = was })
}

// Where the opener is the only approver (the UAT build), its failure ends sign-in at once and is
// logged: a refused edge certificate once held a session silent for the whole deadline.
func TestHeadlessSignInFailsFastWhenTheOpenerFails(t *testing.T) {
	e := newFakeEdge(t)
	b := signInFixture(t, e)
	var log bytes.Buffer
	setForTest(t, &openerRequired, true)
	setForTest[io.Writer](t, &signInLog, &log)
	refusedCert := func(context.Context, string) error {
		return errors.New("tls: failed to parse certificate from server: x509: invalid ECDSA parameters")
	}
	started := time.Now()
	if _, err := b.signIn(context.Background(), refusedCert); err == nil || Code(err) != "broker_signin_open" {
		t.Fatalf("failed opener: %v", err)
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("sign-in waited after its only approver failed")
	}
	if !strings.Contains(log.String(), "invalid ECDSA parameters") {
		t.Fatalf("the opener failure was not logged: %q", log.String())
	}
}

// Every sign-in step reaches the log; the token, verifier and code never do.
func TestSignInLogsEachStepWithoutSecrets(t *testing.T) {
	e := newFakeEdge(t)
	b := signInFixture(t, e)
	var log bytes.Buffer
	setForTest[io.Writer](t, &signInLog, &log)
	tok, err := b.signIn(context.Background(), browser(e))
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []string{"waiting up to", "approved, exchanging", "signed in"} {
		if !strings.Contains(log.String(), "broker sign-in: "+step) {
			t.Errorf("missing step %q in %q", step, log.String())
		}
	}
	if strings.Contains(log.String(), tok.token) || strings.Contains(log.String(), "bbt_") ||
		strings.Contains(log.String(), "challenge=") || strings.Contains(log.String(), "code=") {
		t.Fatalf("sign-in log carries a secret: %q", log.String())
	}
}
