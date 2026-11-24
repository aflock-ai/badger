package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// pod is a stand-in connector pod: it records the upgrade request and, if accepted, echoes each
// line back with a prefix until the bridge closes its side.
func pod(t *testing.T, status int) (*httptest.Server, func() *http.Request, string) {
	t.Helper()
	var mu sync.Mutex
	var got *http.Request
	seen := func() *http.Request {
		mu.Lock()
		defer mu.Unlock()
		return got
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Clone(r.Context())
		mu.Unlock()
		if status != http.StatusSwitchingProtocols {
			http.Error(w, "the workspace profile and the connector pod disagree about this connector", status)
			return
		}
		conn, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: badger-mcp\r\nConnection: Upgrade\r\n\r\n")
		sc := bufio.NewScanner(buf)
		for sc.Scan() {
			_, _ = io.WriteString(conn, "pod:"+sc.Text()+"\n")
		}
	}))
	srv.EnableHTTP2 = false
	srv.StartTLS()
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return srv, seen, ca
}

func token(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte("projected-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBridgeCarriesTheStreamWithIdentityAndDeclaration(t *testing.T) {
	srv, seen, ca := pod(t, http.StatusSwitchingProtocols)
	args := []string{"--base-url=" + srv.URL + "/connectors/jira", "--token-file=" + token(t), "--classification=LEVEL",
		"--ca-file=" + ca, "--enable-writes", "--label-prefix=x"}
	var out, errs strings.Builder
	if code := run(args, strings.NewReader("one\ntwo\n"), &out, &errs); code != 0 {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	if out.String() != "pod:one\npod:two\n" {
		t.Fatalf("stream: %q", out.String())
	}
	req := seen()
	if req == nil || req.URL.Path != "/connectors/jira" || req.Header.Get("Authorization") != "Bearer projected-token" ||
		!strings.EqualFold(req.Header.Get("Upgrade"), "badger-mcp") {
		t.Fatalf("upgrade request: %+v", req)
	}
	var d struct {
		Classification string
		Writes         bool
		Flags          map[string]string
	}
	if err := json.Unmarshal([]byte(req.Header.Get("Badger-Connector")), &d); err != nil || d.Classification != "LEVEL" || !d.Writes ||
		len(d.Flags) != 1 || d.Flags["label-prefix"] != "x" {
		t.Fatalf("declaration %q", req.Header.Get("Badger-Connector"))
	}
}

func TestBridgeReportsARefusalAndCarriesNothing(t *testing.T) {
	srv, _, ca := pod(t, http.StatusConflict)
	var out, errs strings.Builder
	code := run([]string{"--base-url=" + srv.URL + "/connectors/jira", "--token-file=" + token(t), "--classification=LEVEL", "--ca-file=" + ca},
		strings.NewReader("one\n"), &out, &errs)
	if code != 1 || out.Len() != 0 || !strings.Contains(errs.String(), "409") || !strings.Contains(errs.String(), "disagree") {
		t.Fatalf("exit %d out %q err %q", code, out.String(), errs.String())
	}
}

// The bridge trusts only the CA it is given: a pod with another certificate gets no token.
func TestBridgeRefusesAnUntrustedPod(t *testing.T) {
	srv, seen, _ := pod(t, http.StatusSwitchingProtocols)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "other"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	otherCA := filepath.Join(t.TempDir(), "other.pem")
	if err := os.WriteFile(otherCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errs strings.Builder
	code := run([]string{"--base-url=" + srv.URL + "/connectors/jira", "--token-file=" + token(t), "--classification=LEVEL", "--ca-file=" + otherCA},
		strings.NewReader(""), &out, &errs)
	if code != 1 || seen() != nil {
		t.Fatalf("exit %d, pod saw %+v", code, seen())
	}
}

func TestBridgeRefusesBadSettings(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca.pem")
	tok := token(t)
	for name, args := range map[string][]string{
		"http":          {"--base-url=http://pod.example.invalid/connectors/jira", "--token-file=" + tok, "--classification=L", "--ca-file=" + ca},
		"no path":       {"--base-url=https://pod.example.invalid", "--token-file=" + tok, "--classification=L", "--ca-file=" + ca},
		"query":         {"--base-url=https://pod.example.invalid/connectors/jira?x=1", "--token-file=" + tok, "--classification=L", "--ca-file=" + ca},
		"no ca":         {"--base-url=https://pod.example.invalid/connectors/jira", "--token-file=" + tok, "--classification=L"},
		"no token":      {"--base-url=https://pod.example.invalid/connectors/jira", "--classification=L", "--ca-file=" + ca},
		"positional":    {"--base-url=https://pod.example.invalid/connectors/jira", "--token-file=" + tok, "--classification=L", "--ca-file=" + ca, "extra"},
		"flag twice":    {"--base-url=https://pod.example.invalid/connectors/jira", "--token-file=" + tok, "--classification=L", "--ca-file=" + ca, "--a=1", "--a=2"},
		"flag no value": {"--base-url=https://pod.example.invalid/connectors/jira", "--token-file=" + tok, "--classification=L", "--ca-file=" + ca, "--label-prefix"},
	} {
		var out, errs strings.Builder
		if code := run(args, strings.NewReader(""), &out, &errs); code != 2 {
			t.Errorf("%s: exit %d (%s)", name, code, errs.String())
		}
	}
	// Settings that parse but cannot be used fail before anything is sent.
	var out, errs strings.Builder
	if code := run([]string{"--base-url=https://pod.example.invalid/connectors/jira", "--token-file=" + tok, "--classification=L", "--ca-file=" + ca},
		strings.NewReader(""), &out, &errs); code != 1 || !strings.Contains(errs.String(), "CA") {
		t.Fatalf("missing CA file: exit %d %s", code, errs.String())
	}
}

// The workspace's scheme travels in the declaration; none means us-gov and adds nothing.
func TestBridgeDeclaresTheScheme(t *testing.T) {
	digest := "sha256:" + strings.Repeat("ab", 32)
	for _, c := range []struct {
		args []string
		want string
	}{{nil, ""}, {[]string{"--marking-scheme=" + digest}, digest}} {
		srv, seen, ca := pod(t, http.StatusSwitchingProtocols)
		args := append([]string{"--base-url=" + srv.URL + "/connectors/jira", "--token-file=" + token(t), "--classification=LEVEL", "--ca-file=" + ca}, c.args...)
		var out, errs strings.Builder
		if code := run(args, strings.NewReader(""), &out, &errs); code != 0 {
			t.Fatalf("exit %d: %s", code, errs.String())
		}
		var d map[string]any
		if err := json.Unmarshal([]byte(seen().Header.Get("Badger-Connector")), &d); err != nil {
			t.Fatal(err)
		}
		if got, _ := d["scheme"].(string); got != c.want {
			t.Errorf("scheme %q, want %q", got, c.want)
		}
	}
	if _, err := parse([]string{"--base-url=https://p.example.invalid/connectors/j", "--token-file=/t", "--classification=L", "--ca-file=/c", "--marking-scheme=corporate"}); err == nil {
		t.Error("a scheme name in place of a digest was accepted")
	}
}
