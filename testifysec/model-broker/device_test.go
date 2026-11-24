package broker

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb/pgtest"
)

// Device sign-in (device.go, formal/BadgerBroker/DeviceTokens.lean): a person the edge signed in
// approves a device on the edge listener; the device redeems the code on the internal listener.

const (
	testVerifier = "dGhpcy1pcy1hLXRlc3QtdmVyaWZpZXItd2l0aC00My1jaGFycw"
	testDevice   = "ZGV2aWNlLWlkLTE2Yg"
	testState    = "c3RhdGUtc3RhdGUtc3RhdGU"
)

func s256(v string) string {
	h := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func deviceFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t, true)
	f.cfg.DeviceLogin, f.cfg.DeviceTokenTTLHours, f.cfg.MaxDeviceTokens = true, 8, 5
	f.open()
	return f
}

func authorizeQuery(over map[string]string) string {
	q := url.Values{"challenge": {s256(testVerifier)}, "port": {"49152"}, "state": {testState}, "device": {testDevice}}
	for k, v := range over {
		if v == "" {
			q.Del(k)
		} else {
			q.Set(k, v)
		}
	}
	return q.Encode()
}

func edgeReq(h http.Handler, method, target, principal string, extra map[string]string, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	if principal != "" {
		r.Header.Set("x-broker-principal", principal)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	for k, v := range extra {
		if v == "" {
			r.Header.Del(k)
		} else {
			r.Header.Set(k, v)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

var reNonce = regexp.MustCompile(`name="nonce" value="([A-Za-z0-9_-]+)"`)

// consent walks the consent page as principal and returns the loopback redirect.
func consent(t *testing.T, f *fixture, principal, query string) *url.URL {
	t.Helper()
	w := edgeReq(f.edge, "GET", "/device/authorize?"+query, principal, nil, "")
	if w.Code != 200 {
		t.Fatalf("consent page: %d %s", w.Code, w.Body)
	}
	m := reNonce.FindStringSubmatch(w.Body.String())
	if m == nil {
		t.Fatal("no nonce on the consent page")
	}
	w = edgeReq(f.edge, "POST", "/device/authorize?"+query, principal, nil, "nonce="+m[1])
	if w.Code != 303 {
		t.Fatalf("consent: %d %s", w.Code, w.Body)
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func exchange(f *fixture, code, verifier string, port int) *httptest.ResponseRecorder {
	b, _ := json.Marshal(map[string]any{"code": code, "verifier": verifier, "port": port})
	return do(f.internal, "POST", "/device/token", nil, string(b))
}

func TestDeviceSignIn(t *testing.T) {
	f := deviceFixture(t)
	u := consent(t, f, "alice@example.com", authorizeQuery(nil))
	if u.Scheme != "http" || u.Host != "127.0.0.1:49152" || u.Path != "/callback" || u.Query().Get("state") != testState {
		t.Fatalf("redirect %s", u)
	}
	w := exchange(f, u.Query().Get("code"), testVerifier, 49152)
	if w.Code != 201 {
		t.Fatalf("exchange: %d %s", w.Code, w.Body)
	}
	var out struct {
		Token     string    `json:"token"`
		Principal string    `json:"principal"`
		Expires   time.Time `json:"expires_at"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	if !strings.HasPrefix(out.Token, "bbt_") || out.Principal != "alice@example.com" || !out.Expires.Equal(testNow.Add(8*time.Hour)) {
		t.Fatalf("token response %+v", out)
	}
	bearer := map[string]string{"Authorization": "Bearer " + out.Token}
	if w := do(f.internal, "GET", "/v1/models", bearer, ""); w.Code != 200 {
		t.Fatalf("device token on the internal listener: %d", w.Code)
	}
	if w := do(f.internal, "POST", "/v1/chat/completions", bearer, chatA); w.Code != 200 || w.Header().Get("X-Broker-Usage-Principal") != "alice@example.com" {
		t.Fatalf("served as %q (%d)", w.Header().Get("X-Broker-Usage-Principal"), w.Code)
	}
	// The same device signing in again replaces its token.
	u2 := consent(t, f, "alice@example.com", authorizeQuery(map[string]string{"state": "b3RoZXItc3RhdGUtdmFsdWU"}))
	if w := exchange(f, u2.Query().Get("code"), testVerifier, 49152); w.Code != 201 {
		t.Fatalf("second sign-in: %d", w.Code)
	}
	if w := do(f.internal, "GET", "/v1/models", bearer, ""); w.Code != 401 {
		t.Fatalf("old device token after re-login: %d", w.Code)
	}
	audit := f.superText(`SELECT string_agg(record, E'\n') FROM broker.audit`)
	if !strings.Contains(audit, `"actor":"device-login"`) {
		t.Fatal("no device-login audit record")
	}
	if strings.Contains(audit, "bbt_") || strings.Contains(audit, u.Query().Get("code")) {
		t.Fatal("token or code in the audit log")
	}
}

func TestDeviceCodeIsSingleUseAndBound(t *testing.T) {
	f := deviceFixture(t)
	for name, try := range map[string]func(code string) *httptest.ResponseRecorder{
		"wrong verifier":     func(c string) *httptest.ResponseRecorder { return exchange(f, c, testVerifier+"x", 49152) },
		"wrong port":         func(c string) *httptest.ResponseRecorder { return exchange(f, c, testVerifier, 49153) },
		"malformed verifier": func(c string) *httptest.ResponseRecorder { return exchange(f, c, "x", 49152) },
		"expired": func(c string) *httptest.ResponseRecorder {
			f.b.now = func() time.Time { return testNow.Add(121 * time.Second) }
			defer func() { f.b.now = func() time.Time { return testNow } }()
			return exchange(f, c, testVerifier, 49152)
		},
	} {
		code := consent(t, f, "alice@example.com", authorizeQuery(nil)).Query().Get("code")
		if w := try(code); w.Code != 400 {
			t.Errorf("%s: %d", name, w.Code)
		}
		// Any attempt consumes the code, so the right verifier fails afterwards too.
		if w := exchange(f, code, testVerifier, 49152); w.Code != 400 {
			t.Errorf("%s: code still redeemable after a failed attempt: %d", name, w.Code)
		}
	}
	code := consent(t, f, "alice@example.com", authorizeQuery(nil)).Query().Get("code")
	if w := exchange(f, code, testVerifier, 49152); w.Code != 201 {
		t.Fatalf("first redeem: %d", w.Code)
	}
	if w := exchange(f, code, testVerifier, 49152); w.Code != 400 {
		t.Fatalf("second redeem: %d", w.Code)
	}
	if w := exchange(f, "bm90LWEtY29kZQ", testVerifier, 49152); w.Code != 400 {
		t.Fatalf("unknown code: %d", w.Code)
	}
}

func TestDeviceAuthorizeTakesThePrincipalFromTheEdgeOnly(t *testing.T) {
	f := deviceFixture(t)
	q := "/device/authorize?" + authorizeQuery(nil)
	for name, w := range map[string]*httptest.ResponseRecorder{
		"no principal":       edgeReq(f.edge, "GET", q, "", nil, ""),
		"unlisted principal": edgeReq(f.edge, "GET", q, "mallory@example.com", nil, ""),
		"ci principal":       edgeReq(f.edge, "GET", q, "ci:group/alpha", nil, ""),
		"pipeline payload":   edgeReq(f.edge, "GET", q, "alice@example.com", map[string]string{"x-broker-ci-claims": payload(nil)}, ""),
	} {
		if w.Code != 401 {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	// Two principal headers are refused.
	r := httptest.NewRequest("GET", q, nil)
	r.Header.Add("x-broker-principal", "alice@example.com")
	r.Header.Add("x-broker-principal", "bob@example.com")
	w := httptest.NewRecorder()
	f.edge.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Errorf("two principals: %d", w.Code)
	}
	// The internal listener never serves the consent page, whatever headers it is sent.
	if w := edgeReq(f.internal, "GET", q, "alice@example.com", nil, ""); w.Code == 200 || w.Code == 303 {
		t.Errorf("internal listener served consent: %d", w.Code)
	}
	// A nonce minted for one person cannot be used by another.
	page := edgeReq(f.edge, "GET", q, "alice@example.com", nil, "")
	nonce := reNonce.FindStringSubmatch(page.Body.String())[1]
	if w := edgeReq(f.edge, "POST", q, "bob@example.com", nil, "nonce="+nonce); w.Code != 403 {
		t.Errorf("bob used alice's consent nonce: %d", w.Code)
	}
}

func TestDeviceAuthorizeParsesStrictly(t *testing.T) {
	f := deviceFixture(t)
	for name, q := range map[string]string{
		"no challenge":   authorizeQuery(map[string]string{"challenge": ""}),
		"short":          authorizeQuery(map[string]string{"challenge": "abc"}),
		"port 0":         authorizeQuery(map[string]string{"port": "0"}),
		"port 80":        authorizeQuery(map[string]string{"port": "80"}),
		"port 70000":     authorizeQuery(map[string]string{"port": "70000"}),
		"port +5000":     authorizeQuery(map[string]string{"port": "+5000"}),
		"port 05000":     authorizeQuery(map[string]string{"port": "05000"}),
		"no state":       authorizeQuery(map[string]string{"state": ""}),
		"state chars":    authorizeQuery(map[string]string{"state": "a b<script>c-d-e-f-g"}),
		"no device":      authorizeQuery(map[string]string{"device": ""}),
		"extra param":    authorizeQuery(map[string]string{"redirect_uri": "https://evil.example"}),
		"repeated param": authorizeQuery(nil) + "&port=49153",
	} {
		if w := edgeReq(f.edge, "GET", "/device/authorize?"+q, "alice@example.com", nil, ""); w.Code != 400 {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
}

func TestDeviceConsentPageDefences(t *testing.T) {
	f := deviceFixture(t)
	q := "/device/authorize?" + authorizeQuery(nil)
	w := edgeReq(f.edge, "GET", q, "alice@example.com", nil, "")
	for k, want := range map[string]string{"X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"} {
		if w.Header().Get(k) != want {
			t.Errorf("%s = %q", k, w.Header().Get(k))
		}
	}
	csp := w.Header().Get("Content-Security-Policy")
	for _, part := range []string{"frame-ancestors 'none'", "default-src 'none'", "form-action 'self' http://127.0.0.1:49152"} {
		if !strings.Contains(csp, part) {
			t.Errorf("CSP %q lacks %q", csp, part)
		}
	}
	if !strings.Contains(w.Body.String(), "alice@example.com") {
		t.Error("the consent page does not name the person approving")
	}
	nonce := reNonce.FindStringSubmatch(w.Body.String())[1]
	for name, extra := range map[string]map[string]string{
		"cross-site":        {"Sec-Fetch-Site": "cross-site"},
		"no fetch metadata": {"Sec-Fetch-Site": ""},
	} {
		if w := edgeReq(f.edge, "POST", q, "alice@example.com", extra, "nonce="+nonce); w.Code != 403 {
			t.Errorf("%s consent: %d", name, w.Code)
		}
	}
	if w := edgeReq(f.edge, "POST", q, "alice@example.com", nil, "nonce=bm90LWEtbm9uY2U"); w.Code != 403 {
		t.Errorf("unknown nonce: %d", w.Code)
	}
	// A nonce is bound to the parameters it was shown with.
	other := "/device/authorize?" + authorizeQuery(map[string]string{"port": "50000"})
	if w := edgeReq(f.edge, "POST", other, "alice@example.com", nil, "nonce="+nonce); w.Code != 403 {
		t.Errorf("nonce reused with another port: %d", w.Code)
	}
}

func TestDeviceLogout(t *testing.T) {
	f := deviceFixture(t)
	code := consent(t, f, "alice@example.com", authorizeQuery(nil)).Query().Get("code")
	var out struct {
		Token string `json:"token"`
	}
	json.Unmarshal(exchange(f, code, testVerifier, 49152).Body.Bytes(), &out)
	ws := f.issue("ws-alice", "alice@example.com")
	if w := do(f.internal, "DELETE", "/device/token", nil, ""); w.Code != 401 {
		t.Fatalf("logout without a token: %d", w.Code)
	}
	if w := do(f.internal, "DELETE", "/device/token", map[string]string{"Authorization": "Bearer " + ws}, ""); w.Code != 403 {
		t.Fatalf("a workspace token logged out: %d", w.Code)
	}
	if w := do(f.internal, "GET", "/v1/models", map[string]string{"Authorization": "Bearer " + ws}, ""); w.Code != 200 {
		t.Fatalf("workspace token after a refused logout: %d", w.Code)
	}
	bearer := map[string]string{"Authorization": "Bearer " + out.Token}
	if w := do(f.internal, "DELETE", "/device/token", bearer, ""); w.Code != 204 {
		t.Fatalf("logout: %d", w.Code)
	}
	if w := do(f.internal, "GET", "/v1/models", bearer, ""); w.Code != 401 {
		t.Fatalf("token after logout: %d", w.Code)
	}
	if w := do(f.internal, "DELETE", "/device/token", bearer, ""); w.Code != 401 {
		t.Fatalf("second logout: %d", w.Code)
	}
}

func TestDeviceLoginOffByDefault(t *testing.T) {
	f := newFixture(t, true)
	if w := edgeReq(f.edge, "GET", "/device/authorize?"+authorizeQuery(nil), "alice@example.com", nil, ""); w.Code != 404 {
		t.Fatalf("authorize with device login off: %d", w.Code)
	}
	if w := exchange(f, "Y29kZQ", testVerifier, 49152); w.Code == 201 {
		t.Fatal("exchange with device login off")
	}
}

func TestDeviceCodesAreCapped(t *testing.T) {
	f := deviceFixture(t)
	q := "/device/authorize?" + authorizeQuery(nil)
	refused := false
	for i := 0; i < maxPendingDevice+5; i++ {
		w := edgeReq(f.edge, "GET", q, "alice@example.com", nil, "")
		if w.Code == 503 {
			refused = true
			break
		}
	}
	if !refused {
		t.Fatal("outstanding consents are not capped")
	}
	f.b.now = func() time.Time { return testNow.Add(10 * time.Minute) }
	if w := edgeReq(f.edge, "GET", q, "alice@example.com", nil, ""); w.Code != 200 {
		t.Fatalf("expired consents still count against the cap: %d", w.Code)
	}
}

// Two sessions on one computer sign in as different devices (badger's session suffix): both
// tokens stay valid together, and signing one out leaves the other.
func TestOverlappingSessionsKeepTheirOwnTokens(t *testing.T) {
	f := deviceFixture(t)
	tokens := []string{}
	for i, device := range []string{"ZGV2aWNlLWlkLTE2Yg-c2Vzc2lvbi1h", "ZGV2aWNlLWlkLTE2Yg-c2Vzc2lvbi1i"} {
		port := 49152 + i
		u := consent(t, f, "alice@example.com", authorizeQuery(map[string]string{"device": device, "port": itoaPort(port)}))
		w := exchange(f, u.Query().Get("code"), testVerifier, port)
		if w.Code != 201 {
			t.Fatalf("session %d: %d", i, w.Code)
		}
		var out struct {
			Token string `json:"token"`
		}
		json.Unmarshal(w.Body.Bytes(), &out)
		tokens = append(tokens, out.Token)
	}
	for i, tok := range tokens {
		if w := do(f.internal, "GET", "/v1/models", map[string]string{"Authorization": "Bearer " + tok}, ""); w.Code != 200 {
			t.Fatalf("session %d's token after the other signed in: %d", i, w.Code)
		}
	}
	if w := do(f.internal, "DELETE", "/device/token", map[string]string{"Authorization": "Bearer " + tokens[0]}, ""); w.Code != 204 {
		t.Fatal(w.Code)
	}
	if w := do(f.internal, "GET", "/v1/models", map[string]string{"Authorization": "Bearer " + tokens[1]}, ""); w.Code != 200 {
		t.Fatalf("the other session's token after one signed out: %d", w.Code)
	}
}

func itoaPort(p int) string { return strconv.Itoa(p) }

// A sign-out the registry cannot record is a 503, never "already gone": after the registry is
// repaired the token is still live, and signing out again revokes it.
func TestLogoutWithAnUnreadableRegistryIsAnError(t *testing.T) {
	f := deviceFixture(t)
	code := consent(t, f, "alice@example.com", authorizeQuery(nil)).Query().Get("code")
	var out struct {
		Token string `json:"token"`
	}
	json.Unmarshal(exchange(f, code, testVerifier, 49152).Body.Bytes(), &out)
	bearer := map[string]string{"Authorization": "Bearer " + out.Token}
	f.pg.Super(t, `REVOKE DELETE ON broker.tokens FROM `+pgtest.Service)
	if w := do(f.internal, "DELETE", "/device/token", bearer, ""); w.Code != 503 {
		t.Fatalf("sign-out with an unreadable registry: %d", w.Code)
	}
	f.pg.Super(t, `GRANT DELETE ON broker.tokens TO `+pgtest.Service)
	if w := do(f.internal, "GET", "/v1/models", bearer, ""); w.Code != 200 {
		t.Fatalf("token after repair: %d", w.Code)
	}
	if w := do(f.internal, "DELETE", "/device/token", bearer, ""); w.Code != 204 {
		t.Fatalf("sign-out after repair: %d", w.Code)
	}
}
