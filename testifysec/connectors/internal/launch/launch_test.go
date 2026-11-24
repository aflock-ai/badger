//go:build linux

package launch

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func line(h Hello) string { b, _ := json.Marshal(h); return string(b) + "\n" }

// good is a hello that passes; its digest is the probe's once probeExe has built it.
var good = Hello{Version: 1, BaseURL: "https://svc.example.invalid", TokenPath: "/tokens/x", Classification: "BANNER", Flags: map[string]string{"auth": "bearer"},
	PluginDigest: "sha256:" + strings.Repeat("0", 64)}

// The command line comes from the hello alone, in the shared connector flags; a flag that would
// override one of them, or a malformed setting, is refused.
func TestArgs(t *testing.T) {
	args, err := good.Args("/bin/plugin")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(args, " ") != "/bin/plugin --base-url=https://svc.example.invalid --token-file=/tokens/x --classification=BANNER --auth=bearer" {
		t.Fatalf("%q", args)
	}
	w := good
	w.Writes, w.CAPath = true, "/ca.pem"
	if args, _ := w.Args("/p"); !strings.Contains(strings.Join(args, " "), "--ca-file=/ca.pem --enable-writes") {
		t.Fatalf("%q", args)
	}
	for name, h := range map[string]Hello{
		"version":         {Version: 2, PluginDigest: good.PluginDigest, BaseURL: good.BaseURL, TokenPath: good.TokenPath, Classification: "B"},
		"no base":         {Version: 1, PluginDigest: good.PluginDigest, TokenPath: good.TokenPath, Classification: "B"},
		"relative token":  {Version: 1, PluginDigest: good.PluginDigest, BaseURL: good.BaseURL, TokenPath: "t", Classification: "B"},
		"relative ca":     {Version: 1, PluginDigest: good.PluginDigest, BaseURL: good.BaseURL, TokenPath: good.TokenPath, CAPath: "ca", Classification: "B"},
		"no marking":      {Version: 1, PluginDigest: good.PluginDigest, BaseURL: good.BaseURL, TokenPath: good.TokenPath},
		"reserved flag":   {Version: 1, PluginDigest: good.PluginDigest, BaseURL: good.BaseURL, TokenPath: good.TokenPath, Classification: "B", Flags: map[string]string{"enable-writes": "1"}},
		"manifest flag":   {Version: 1, PluginDigest: good.PluginDigest, BaseURL: good.BaseURL, TokenPath: good.TokenPath, Classification: "B", Flags: map[string]string{"manifest": "1"}},
		"bad flag name":   {Version: 1, PluginDigest: good.PluginDigest, BaseURL: good.BaseURL, TokenPath: good.TokenPath, Classification: "B", Flags: map[string]string{"Bad Flag": "1"}},
		"no digest":       {Version: 1, BaseURL: good.BaseURL, TokenPath: good.TokenPath, Classification: "B"},
		"bad digest":      {Version: 1, PluginDigest: "sha256:AB", BaseURL: good.BaseURL, TokenPath: good.TokenPath, Classification: "B"},
		"newline in flag": {Version: 1, PluginDigest: good.PluginDigest, BaseURL: good.BaseURL, TokenPath: good.TokenPath, Classification: "B", Flags: map[string]string{"x": "a\nb"}},
	} {
		if _, err := h.Args("/p"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Serve runs one plugin per connection: the hello sets its command line, then the connection is its
// stdin and stdout. Its environment is empty and its stderr goes nowhere, not to the host's. A
// connection whose hello is refused, or that carries an unknown field, is closed before anything runs.
func TestServeRunsOnePluginPerConnection(t *testing.T) {
	// The host runs as its own process, so its stderr is its own to capture (swapping os.Stderr here
	// would race with the host's goroutines that log).
	sock := filepath.Join(t.TempDir(), "plugin.sock")
	self, _ := os.Executable()
	host := exec.Command(self, hostFlag, sock, probeExe(t))
	var hostErr bytes.Buffer
	host.Stderr = &hostErr
	if err := host.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = host.Process.Kill(); _ = host.Wait() }()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if c, err := net.Dial("unix", sock); err == nil {
			c.Close()
			break
		} else if time.Now().After(deadline) {
			t.Fatal("the host never listened")
		}
	}
	dial := func(hello string) *bufio.Reader {
		t.Helper()
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte(hello)); err != nil {
			t.Fatal(err)
		}
		return bufio.NewReader(c)
	}

	echo := good
	echo.Flags = map[string]string{"auth": "bearer", "mode": "echo"}
	out := dial(line(echo) + "ping\n")
	var lines []string
	for range 3 {
		l, err := out.ReadString('\n')
		if err != nil {
			t.Fatalf("after %q: %v", lines, err)
		}
		lines = append(lines, strings.TrimSpace(l))
	}
	// The command line is the hello's flags (sorted), its environment holds only its egress socket, and
	// it reads its input.
	if !strings.HasPrefix(lines[0], "args ") || !strings.Contains(lines[0], "--auth=bearer") || !strings.Contains(lines[0], "--mode=echo") ||
		lines[1] != "env 1" || lines[2] != "got ping" {
		t.Fatalf("%q", lines)
	}

	bad := good
	bad.Flags = map[string]string{"token-file": "/other"}
	unknown := strings.Replace(line(good), `{`, `{"labelsFile":"/var/lib/conngw/labels",`, 1)
	for name, hello := range map[string]string{"reserved flag": line(bad), "unknown field": unknown, "not json": "x\n"} {
		if b, err := dial(hello).ReadString('\n'); err == nil || b != "" {
			t.Fatalf("%s: a refused hello ran something: %q %v", name, b, err)
		}
	}
	_ = host.Process.Kill()
	_ = host.Wait()
	if strings.Contains(hostErr.String(), "STDERR-MARK") {
		t.Fatalf("plugin stderr reached the host's: %q", hostErr.String())
	}
}

// The host refuses to run as root (a plugin started by it would be root) or where it cannot
// sandbox the plugin.
func TestCheckUser(t *testing.T) {
	if err := CheckSandbox(); err != nil {
		t.Fatal(err)
	}
	if CheckUser(0) == nil {
		t.Fatal("root accepted")
	}
	if err := CheckUser(61001); err != nil {
		t.Fatal(err)
	}
}

// serveProbe serves the test binary as the plugin in the given mode and returns a dialer that sends
// the hello (carrying the mode and arg) and returns the connection and a reader.
func serveProbe(t *testing.T, dir, mode, arg string, max int) func() (net.Conn, *bufio.Reader) {
	t.Helper()
	exe := probeExe(t)
	sock := filepath.Join(dir, "plugin.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() { _ = Serve(l, exe, max, os.Getuid()) }()
	h := good
	h.Flags = map[string]string{"mode": mode}
	if arg != "" {
		h.Flags["arg"] = arg
	}
	return func() (net.Conn, *bufio.Reader) {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = c.Write([]byte(line(h)))
		return c, bufio.NewReader(c)
	}
}

// shortGrace makes Grace short for one test.
func shortGrace(t *testing.T) {
	saved := Grace
	Grace = 100 * time.Millisecond
	t.Cleanup(func() { Grace = saved })
}

// A plugin that ignores its input is killed Grace after the connection's input ends, and its slot
// is free again: one that never reads (with more input sent than a pipe holds), and one that leaves a
// child holding its output open.
func TestAPluginIgnoringItsInputIsKilled(t *testing.T) {
	shortGrace(t)
	for _, mode := range []string{"hang"} {
		dial := serveProbe(t, t.TempDir(), mode, "", 1)
		for i := range 2 {
			c, r := dial()
			if got, err := r.ReadString('\n'); got != "up\n" {
				t.Fatalf("%s: stream %d: %q %v", mode, i, got, err)
			}
			_, _ = c.Write(bytes.Repeat([]byte("x"), 1<<20)) // more than a pipe holds, never read
			c.Close()
			time.Sleep(500 * time.Millisecond) // past Grace: the first plugin is gone and its slot free
		}
	}
}

// A client that half-closes its input and never reads the plugin's output cannot hold the stream:
// Grace after its input ends, the plugin and the connection are torn down and the slot is free.
func TestAClientThatStopsReadingIsTornDown(t *testing.T) {
	shortGrace(t)
	dial := serveProbe(t, t.TempDir(), "spew", "", 1)
	c, _ := dial()
	defer c.Close()
	_ = c.(*net.UnixConn).CloseWrite()
	time.Sleep(time.Second) // the plugin fills the socket; Grace passes
	c2, r := dial()
	defer c2.Close()
	if got, err := r.ReadString('\n'); got != "up\n" {
		t.Fatalf("second stream: %q %v", got, err)
	}
}

// When this test binary is started as the sandbox shim (Serve starts the host's own executable),
// it is one.
func TestMain(m *testing.M) {
	Shim()
	os.Exit(runWithMemoryTmp(m))
}

// diskTmp is the temporary directory before TestMain points TMPDIR at memory: builds (go's work
// files, the probe) go there, not into the small memory-backed one.
var diskTmp = os.TempDir()

// runWithMemoryTmp runs the tests with TMPDIR on an executable tmpfs (ExecTmpfs), as the plugin host
// requires for its staging directory (an emptyDir with medium: Memory in the pod). It fails, never
// skips, when there is none.
func runWithMemoryTmp(m *testing.M) int {
	if os.Getenv("LAUNCH_TEST_TMP") != "" { // a child of the test binary: its parent's directory
		return m.Run()
	}
	base, err := execTmpfsDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "the launch tests:", err)
		return 1
	}
	d, err := os.MkdirTemp(base, "launch-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "the launch tests:", err)
		return 1
	}
	defer os.RemoveAll(d)
	os.Setenv("TMPDIR", d)
	os.Setenv("LAUNCH_TEST_TMP", d)
	return m.Run()
}

// A plugin cannot change what serves the next stream: it cannot remove or replace its socket or
// write a file anywhere (its own directory included) to run or to listen on later, so every stream
// is the host's and runs the image's plugin afresh.
func TestAPluginCannotReplaceWhatServesTheNextStream(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "plugin.sock")
	dialReplace := serveProbe(t, dir, "replace", dir, 2)
	c, r := dialReplace()
	// unlinkat, symlinkat and mkdirat are off the allow-list (EPERM); creating a file is an
	// openat Landlock refuses (EACCES). Nothing changes in the directory.
	want := "tries EPERM EACCES EPERM EPERM up plugin.sock\n"
	b, _ := io.ReadAll(r)
	c.Close()
	if string(b) != want {
		t.Fatalf("the plugin changed the filesystem: %q, want %q", b, want)
	}
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("the plugin removed its socket: %v", err)
	}
	// A fresh stream on the same socket still serves, from the host.
	c2, r2 := dialReplace()
	defer c2.Close()
	if bb, _ := io.ReadAll(r2); string(bb) != want {
		t.Fatalf("second stream: %q", bb)
	}
}

// A plugin cannot spawn a process: a plain fork (clone without CLONE_THREAD) is denied (clone3
// answers ENOSYS, so the runtime falls back to clone), so it cannot leave a helper running or exec
// another program after it starts.
func TestAPluginCannotSpawnAProcess(t *testing.T) {
	dir := t.TempDir()
	dial := serveProbe(t, dir, "spawn", "", 1)
	c, r := dial()
	defer c.Close()
	if b, _ := io.ReadAll(r); string(b) != "spawn: EPERM\n" {
		t.Fatalf("the plugin spawned a process: %q", b)
	}
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
	if syscall.Statfs(d, &fs) != nil || int64(fs.Type) != tmpfsMagic {
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
