//go:build linux

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/aflock-ai/badger/testifysec/connectors/internal/bundle"
	"github.com/aflock-ai/badger/testifysec/connectors/internal/launch"
	"github.com/aflock-ai/badger/testifysec/connectors/marking"
)

// The test binary is also the plugin host's sandbox shim (launch.Serve starts its own executable).
func TestMain(m *testing.M) {
	launch.Shim()
	// A child running one test under the corporate scheme (underCorporate): set once, before any
	// test, as conngw's main sets the profile's.
	if os.Getenv("CONNGW_TEST_SCHEME") == "corporate" {
		s, err := marking.Preset("corporate")
		if err == nil {
			err = marking.Configure(s)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "the conngw tests:", err)
			os.Exit(1)
		}
	}
	// The plugin host stages into a memory-backed TMPDIR (an emptyDir with medium: Memory in the
	// pod); builds keep the disk one.
	if os.Getenv("CONNGW_TEST_TMP") != "" { // a child of the test binary: its parent's directory
		os.Exit(m.Run())
	}
	base, err := execTmpfsDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "the conngw tests:", err)
		os.Exit(1)
	}
	d, err := os.MkdirTemp(base, "conngw-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "the conngw tests:", err)
		os.Exit(1)
	}
	os.Setenv("TMPDIR", d)
	os.Setenv("CONNGW_TEST_TMP", d)
	code := m.Run()
	os.RemoveAll(d)
	os.Exit(code)
}

// diskTmp is the temporary directory before TestMain points TMPDIR at memory.
var diskTmp = os.TempDir()

// A plugin built in its own module (testdata/acme, which imports only sdk), packed and signed, is
// admitted and served through the real path: the plugin host (internal/launch, as cmd/plughost runs
// it) on a unix socket, the gateway's dial with the pinned image and the socket owner checked, and
// the plugin process: tools/list is the grant, a read call answers under the profile's marking, and
// its write tool is refused for a read-only grant. Another plugin can be given instead:
// CONNGW_E2E_PLUGIN (executable), CONNGW_E2E_BUNDLE (bundle directory), CONNGW_E2E_SIGNER (signer
// public key file), CONNGW_E2E_READ and CONNGW_E2E_WRITE (tool names) and CONNGW_E2E_ARGS (the read
// call's arguments).
func TestAnOutOfTreePluginRunsEndToEnd(t *testing.T) {
	acme := os.Getenv("CONNGW_E2E_BUNDLE") == ""
	if acme {
		buildAcme(t)
	}
	// The in-repo acme reads a real service behind TLS, which it can reach only through the plugin
	// host's egress socket: its filter kills any network socket of its own.
	baseURL, caPath := "https://acme.example.invalid", ""
	if acme {
		svc := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "ticket at "+r.URL.Path+": open")
		}))
		defer svc.Close()
		baseURL = svc.URL
		caPath = writeFile(t, "ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: svc.Certificate().Raw})))
	}
	dir := os.Getenv("CONNGW_E2E_BUNDLE")
	lv := levels(t)
	pubB, err := os.ReadFile(os.Getenv("CONNGW_E2E_SIGNER"))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := bundle.ParseKey(strings.TrimSpace(string(pubB)))
	if err != nil {
		t.Fatal(err)
	}
	m, err := bundle.Load(dir, pub)
	if err != nil {
		t.Fatal(err)
	}
	token := writeFile(t, "token", "not-a-real-token\n")
	sock := filepath.Join(t.TempDir(), "plugin.sock")
	l, err := launch.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() { _ = launch.Serve(l, os.Getenv("CONNGW_E2E_PLUGIN"), 4, os.Getuid()) }()
	body := `{"listen":":8443","certFile":"/c","keyFile":"/k","audience":"a","namespaces":["team-a"],"labelsFile":"/var/lib/conngw/labels",` +
		`"hostDigest":"` + hostDigest + `","signers":{"vendor":"` + strings.TrimSpace(string(pubB)) + `"},"connectors":[{"name":"acme","bundle":"` + dir + `","digest":"` + m.Digest +
		`","signer":"vendor","baseUrl":"` + baseURL + `","caPath":"` + caPath + `","tokenPath":"` + token + `","socket":"` + sock + `","uid":61000,"gid":61000,"classification":"` + lv[1] +
		`","writes":true,"grants":[{"workspaces":["team-a/*"]}]}]}`
	c, err := load(writeFile(t, "p.json", body))
	if err != nil {
		t.Fatal(err)
	}
	if err := admit(&c); err != nil {
		t.Fatal(err)
	}
	src := c.Sources[0]
	perm, ok := src.permitFor("team-a/alice")
	if !ok || perm.writes {
		t.Fatalf("permit %+v", perm)
	}
	src.Writes = perm.writes
	// The test runs as one user: the socket's owner is the test's.
	src.UID, src.GID = os.Getuid(), os.Getgid()
	pins := func(_ context.Context, name, digest string) (container, error) {
		if name != "acme" || digest != hostDigest {
			t.Fatalf("pin check %s %s", name, digest)
		}
		return container{id: "containerd://" + strings.Repeat("ac", 32)}, nil
	}
	saved := procRoot
	procRoot = fakeProc(t, map[string]string{strconv.Itoa(os.Getpid()): "0::/../cri-containerd-" + strings.Repeat("ac", 32) + ".scope\n"})
	defer func() { procRoot = saved }()
	p, err := dial(context.Background(), src, pins)
	if err != nil {
		t.Fatal(err)
	}
	callerR, callerW := io.Pipe()
	replyR, replyW := io.Pipe()
	s := &stream{ws: "team-a/alice", conn: src, labels: newLabels(), log: slog.New(slog.DiscardHandler), pending: map[string]bool{}, perm: perm}
	go s.relay(callerR, replyW, p, 0, 1<<62)
	defer callerW.Close()
	r := bufio.NewReader(replyR)
	call := func(line string) map[string]any {
		t.Helper()
		if _, err := io.WriteString(callerW, line+"\n"); err != nil {
			t.Fatal(err)
		}
		got, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		var v map[string]any
		if err := json.Unmarshal([]byte(got), &v); err != nil {
			t.Fatalf("%q", got)
		}
		return v
	}
	read, write := os.Getenv("CONNGW_E2E_READ"), os.Getenv("CONNGW_E2E_WRITE")
	args := os.Getenv("CONNGW_E2E_ARGS")
	if args == "" {
		args = "{}"
	}
	hello := call(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	t.Logf("initialize: %s", mustJSON(hello))
	list := mustJSON(call(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	if !strings.Contains(list, `"`+read+`"`) || strings.Contains(list, `"`+write+`"`) {
		t.Fatalf("tools/list %s", list)
	}
	got := call(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"` + read + `","arguments":` + args + `}}`)
	t.Logf("read call: %s", mustJSON(got))
	if metaBanner(got) != lv[1] || strings.Contains(mustJSON(got), `"isError":true`) {
		t.Fatalf("read call: %s", mustJSON(got))
	}
	got = call(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"` + write + `","arguments":{}}}`)
	if !strings.Contains(mustJSON(got), "not permitted") {
		t.Fatalf("write call: %s", mustJSON(got))
	}
	t.Logf("write call: %s", mustJSON(got))
	if acme {
		got = call(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"acme_get_ticket","arguments":{"id":1}}}`)
		if !strings.Contains(mustJSON(got), "ticket at /tickets/1: open") {
			t.Fatalf("service read through the egress socket: %s", mustJSON(got))
		}
	}
}

// buildAcme builds testdata/acme as its own module, offline, and packs it the way plugintool pack
// does: --manifest, the image digest (here the executable's, standing for the image's), the signer's
// signature.
func buildAcme(t *testing.T) {
	t.Helper()
	gobin := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(gobin); err != nil {
		t.Skip("no go toolchain to build the test plugin")
	}
	out, err := os.MkdirTemp(diskTmp, "acme")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(out) })
	exe := filepath.Join(out, "acme")
	cmd := exec.Command(gobin, "build", "-o", exe, ".")
	cmd.Dir = "testdata/acme"
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOPROXY=off", "GOWORK=off", "GOFLAGS=-mod=mod", "TMPDIR="+diskTmp)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, b)
	}
	// The plugin's own imports: the public sdk package and nothing else from this module.
	cmd = exec.Command(gobin, "list", "-f", `{{join .Imports " "}}`, ".")
	cmd.Dir = "testdata/acme"
	cmd.Env = append(os.Environ(), "GOPROXY=off", "GOWORK=off", "GOFLAGS=-mod=mod", "TMPDIR="+diskTmp)
	imports, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range strings.Fields(string(imports)) {
		if strings.HasPrefix(imp, "github.com/testifysec/") && imp != "github.com/aflock-ai/badger/testifysec/connectors/sdk" {
			t.Fatalf("test plugin imports %s", imp)
		}
	}
	manifest, err := exec.Command(exe, "--manifest").Output()
	if err != nil {
		t.Fatal(err)
	}
	m, err := bundle.Parse(manifest)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	m.Digest = bundle.Digest(b)
	mb, _ := json.Marshal(m)
	pub, priv := newKey(t)
	dir := filepath.Join(out, "bundle")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{bundle.ManifestFile: mb, bundle.SigFile: bundle.Sign(priv, mb)} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CONNGW_E2E_PLUGIN", exe)
	t.Setenv("CONNGW_E2E_BUNDLE", dir)
	t.Setenv("CONNGW_E2E_SIGNER", writeFile(t, "vendor.pub", b64(pub)))
	t.Setenv("CONNGW_E2E_READ", "acme_echo")
	t.Setenv("CONNGW_E2E_WRITE", "acme_close_ticket")
	t.Setenv("CONNGW_E2E_ARGS", `{"text":"hello"}`)
}

// execTmpfsDir finds a tmpfs the tests can stage executables in and run them from: LAUNCH_TEST_TMPFS
// when set, else /dev/shm, else $XDG_RUNTIME_DIR, else os.TempDir() (a container run with
// --tmpfs /tmp:exec). Each candidate must be tmpfs and allow exec (a copy of /bin/true runs from
// it); Docker's default /dev/shm is noexec.
func execTmpfsDir() (string, error) {
	var tried []string
	for _, d := range []string{os.Getenv("LAUNCH_TEST_TMPFS"), "/dev/shm", os.Getenv("XDG_RUNTIME_DIR"), os.TempDir()} {
		if d == "" {
			continue
		}
		tried = append(tried, d)
		if execTmpfs(d) {
			return d, nil
		}
	}
	return "", errors.New("no executable tmpfs found (tried " + filepath.Join(tried...) + "); set LAUNCH_TEST_TMPFS to one, or in Docker run with --tmpfs /dev/shm:exec or --tmpfs /tmp:exec")
}

func execTmpfs(d string) bool {
	var fs syscall.Statfs_t
	if syscall.Statfs(d, &fs) != nil || int64(fs.Type) != 0x01021994 /* TMPFS_MAGIC */ {
		return false
	}
	b, err := os.ReadFile("/bin/true")
	if err != nil {
		return false
	}
	dir, err := os.MkdirTemp(d, "exec-check-")
	if err != nil {
		return false
	}
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, "true")
	if os.WriteFile(p, b, 0o755) != nil {
		return false
	}
	return exec.Command(p).Run() == nil
}
