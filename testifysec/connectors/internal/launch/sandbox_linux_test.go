package launch

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// The host's refusal names the cause an operator can act on.
func TestTheSandboxRefusalNamesTheCause(t *testing.T) {
	for errno, want := range map[syscall.Errno]string{syscall.EOPNOTSUPP: "lsm=", syscall.ENOSYS: "seccomp", syscall.EPERM: "seccomp", syscall.EINVAL: "invalid argument"} {
		if got := landlockReason(errno); !strings.Contains(got, want) {
			t.Errorf("%v: %q", errno, got)
		}
	}
}

// A plugin cannot truncate a file, even one it may write by its mode: truncate is off the seccomp
// allow-list, so the call kills the plugin before Landlock (which also refuses it) is reached; the
// file is untouched either way.
func TestAPluginCannotTruncate(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("intact"), 0o666); err != nil {
		t.Fatal(err)
	}
	dial := serveProbe(t, dir, "truncate", victim, 1)
	c, r := dial()
	defer c.Close()
	if b, _ := io.ReadAll(r); string(b) != "truncate: EPERM\n" {
		t.Fatalf("the truncate was not denied: %q", b)
	}
	if got, _ := os.ReadFile(victim); string(got) != "intact" {
		t.Fatalf("truncated: %q", got)
	}
}

// The sandbox floor is Landlock ABI 3: below it the host refuses, with the exact reason.
func TestTheSandboxNeedsLandlockABI3(t *testing.T) {
	saved := abi
	defer func() { abi = saved }()
	for v, want := range map[int]string{
		1: "landlock not available on this node: the kernel's Landlock is ABI 1; plugins need ABI 3 (Linux 6.2 or newer), the first that can refuse truncate",
		2: "landlock not available on this node: the kernel's Landlock is ABI 2; plugins need ABI 3 (Linux 6.2 or newer), the first that can refuse truncate",
		3: "",
		4: "",
	} {
		abi = func() (int, syscall.Errno) { return v, 0 }
		err := CheckSandbox()
		if got := fmt.Sprint(err); (want == "" && err != nil) || (want != "" && got != want) {
			t.Errorf("ABI %d: %v", v, err)
		}
	}
}

// The host serves only the gateway's uid: a connection from any other user (here the host's own,
// which is a plugin's) runs nothing, so a plugin cannot open the socket and start a plugin of its own.
func TestOnlyTheGatewaysUIDIsServed(t *testing.T) {
	dir := t.TempDir()
	exe := probeExe(t)
	sock := filepath.Join(dir, "plugin.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() { _ = Serve(l, exe, 1, os.Getuid()+1) }() // the gateway is some other uid
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	h := good
	h.Flags = map[string]string{"mode": "echo"}
	_, _ = c.Write([]byte(line(h)))
	if b, err := bufio.NewReader(c).ReadString('\n'); err == nil || b != "" {
		t.Fatalf("a connection from the host's own user ran something: %q %v", b, err)
	}
}

// A plugin that makes a syscall off the allow-list (here kill, to stop its host) is denied (EPERM)
// and the call never runs, so a separate host process is unharmed: it is not stopped (wait4
// WUNTRACED) and its /proc files stay root's (non-dumpable). Every other forbidden call is refused
// the same way, which TestTheAllowListFilterDecides checks per syscall. The host is a child here,
// so a regression harms only it.
func TestADeniedCallLeavesTheHostUnharmed(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "plugin.sock")
	self, _ := os.Executable()
	host := exec.Command(self, hostFlag, sock, probeExe(t))
	var stderr bytes.Buffer
	host.Stderr = &stderr
	if err := host.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Process.Signal(syscall.SIGCONT); _ = host.Process.Kill(); _ = host.Wait() })
	var c net.Conn
	for deadline := time.Now().Add(5 * time.Second); c == nil && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		c, _ = net.Dial("unix", sock)
	}
	if c == nil {
		t.Fatal("the host never listened")
	}
	h := good
	h.Flags = map[string]string{"mode": "signalhost"}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte(line(h)))
	b, _ := io.ReadAll(c)
	c.Close()
	if string(b) != "signal: EPERM\n" {
		t.Fatalf("the signal was not denied: %q", b)
	}
	time.Sleep(500 * time.Millisecond) // a stopped host would show it by now
	var ws syscall.WaitStatus
	if pid, _ := syscall.Wait4(host.Process.Pid, &ws, syscall.WUNTRACED|syscall.WNOHANG, nil); pid == host.Process.Pid && (ws.Stopped() || ws.Exited()) {
		t.Fatalf("the host was stopped or exited: %+v", ws)
	}
	if fi, err := os.Stat(fmt.Sprintf("/proc/%d/environ", host.Process.Pid)); err != nil || fi.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Error("the host is dumpable: its /proc files are its user's")
	}
	_ = host.Process.Kill()
	_ = host.Wait()
}

// hostFlag starts this test binary as a plugin host: <socket> <plugin>, at most 4 streams.
const hostFlag = "--conngw-test-host"

func init() {
	if len(os.Args) == 4 && os.Args[1] == hostFlag {
		l, err := Listen(os.Args[2])
		if err == nil {
			err = Serve(l, os.Args[3], 4, os.Getuid())
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

// The sandbox asks only for Landlock ABI 1-3 rights, so the twin (ABI 4) enforces exactly what an
// ABI 3 kernel does: no right at or above ABI 4's first (bit 15), and every write right handled.
func TestTheRulesetIsABI3(t *testing.T) {
	handled, allowed := ruleset()
	if handled>>15 != 0 || allowed&^handled != 0 || handled != 1<<15-1 || allowed&(fsReadFile|fsReadDir) != 0 {
		t.Fatalf("handled %b allowed %b", handled, allowed)
	}
}

// The plugin starts with RLIMIT_CORE 1, soft and hard, at which the kernel refuses its core dumps
// (file and pipe), and it cannot change it: lowering it to 0 (which would re-enable pipe dumps)
// gets it killed. The probe is not an SDK connector: it reads a canary token itself and never calls
// Main, so this holds for any plugin executable.
func TestAPluginCannotChangeItsCoreLimit(t *testing.T) {
	canary := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(canary, []byte("canary-token-0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	dial := serveProbe(t, t.TempDir(), "corelimit", canary, 1)
	c, r := dial()
	defer c.Close()
	if got, err := r.ReadString('\n'); got != "core 1 1\n" {
		t.Fatalf("%q %v", got, err)
	}
	if rest, _ := io.ReadAll(r); string(rest) != "lower: EPERM, core 1 1\n" {
		t.Fatalf("the plugin lowered its core limit: %q", rest)
	}
}

// The core_pattern gate is checked again before every plugin start: a node changed to a collector
// the gate refuses after the host started gets no plugin run.
func TestTheCorePatternIsRecheckedPerStream(t *testing.T) {
	savedP, savedR := readCorePattern, readRelease
	t.Cleanup(func() { readCorePattern, readRelease = savedP, savedR })
	readCorePattern = func() ([]byte, error) { return []byte("@/run/collector.sock\n"), nil }
	readRelease = func() ([]byte, error) { return []byte("6.16.0\n"), nil }
	dial := serveProbe(t, t.TempDir(), "echo", "", 1)
	c, r := dial()
	defer c.Close()
	if b, _ := io.ReadAll(r); len(b) != 0 {
		t.Fatalf("a plugin ran under a refused core_pattern: %q", b)
	}
}

// Loading the system roots, as a connector's first TLS handshake does, works under the filter on a
// certificate directory with symlinks (as a Debian-style /etc/ssl/certs has): Go resolves each one.
func TestAPluginLoadsSymlinkedSystemRoots(t *testing.T) {
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"}, IsCA: true,
		BasicConstraintsValid: true, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "root.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("root.pem", filepath.Join(dir, "0a1b2c3d.0")); err != nil {
		t.Fatal(err)
	}
	dial := serveProbe(t, t.TempDir(), "roots", dir, 1)
	c, r := dial()
	defer c.Close()
	if got, err := r.ReadString('\n'); got != "roots ok\n" {
		t.Fatalf("%q %v", got, err)
	}
}

// The host leaves no core dump: it is non-dumpable with a core limit of 1, soft and hard, or of 0
// when it inherited a hard 0 (which it cannot raise; it still starts). Each case runs in a child.
func TestTheHostTakesNoCoreDump(t *testing.T) {
	if os.Getenv("LAUNCH_TEST_HARDEN") != "" {
		if os.Getenv("LAUNCH_TEST_HARDEN") == "zero" {
			_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})
		}
		err := hardenHost()
		d, _, _ := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0)
		var l syscall.Rlimit
		_ = syscall.Getrlimit(syscall.RLIMIT_CORE, &l)
		fmt.Printf("HARDEN %v %d %d %d\n", err, d, l.Cur, l.Max)
		os.Exit(0)
	}
	cases := map[string]string{"inherited": "HARDEN <nil> 0 1 1", "zero": "HARDEN <nil> 0 0 0"}
	var own syscall.Rlimit
	if syscall.Getrlimit(syscall.RLIMIT_CORE, &own) == nil && own.Max == 0 {
		delete(cases, "inherited") // this test run itself has a hard 0
	}
	for start, want := range cases {
		cmd := exec.Command(os.Args[0], "-test.run=^TestTheHostTakesNoCoreDump$")
		cmd.Env = append(os.Environ(), "LAUNCH_TEST_HARDEN="+start)
		if out, err := cmd.Output(); err != nil || !strings.Contains(string(out), want+"\n") {
			t.Errorf("%s: %v %q, want %q", start, err, out, want)
		}
	}
}

// The plugin has no network of its own: a raw TCP connection or an abstract unix socket gets it
// killed. Its one way out is descriptor 3, answered with a connection to the base URL of the hello
// the gateway sent (built from the signed profile), whatever the plugin itself names: here it sends
// its own hello and a CONNECT for another server, which is never contacted.
func TestAPluginReachesOnlyItsServiceThroughTheHost(t *testing.T) {
	listen := func(reply string, hits *atomic.Int32) net.Listener {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				hits.Add(1)
				_, _ = bufio.NewReader(c).ReadString('\n')
				fmt.Fprintln(c, reply)
				c.Close()
			}
		}()
		return l
	}
	var profileHits, otherHits atomic.Int32
	l := listen("service got it", &profileHits)
	other := listen("other got it", &otherHits)
	dial := serveProbe(t, t.TempDir(), "tcp", l.Addr().String(), 1)
	c, r := dial()
	if b, _ := io.ReadAll(r); string(b) != "tcp: EPERM\n" {
		t.Fatalf("a plugin opened a TCP connection of its own: %q", b)
	}
	c.Close()
	// Nor an abstract unix socket, which lives in the pod's shared network namespace, outside any
	// filesystem rule: a listener outside the sandbox is never reached.
	var abstractHits atomic.Int32
	name := fmt.Sprintf("badger-test-%d", os.Getpid())
	al, err := net.Listen("unix", "@"+name)
	if err != nil {
		t.Fatal(err)
	}
	defer al.Close()
	go func() {
		for {
			c, err := al.Accept()
			if err != nil {
				return
			}
			abstractHits.Add(1)
			c.Close()
		}
	}()
	dial = serveProbe(t, t.TempDir(), "abstract", name, 1)
	c, r = dial()
	if b, _ := io.ReadAll(r); string(b) != "abstract: EPERM\n" || abstractHits.Load() != 0 {
		t.Fatalf("a plugin reached an abstract socket: %q, %d hits", b, abstractHits.Load())
	}
	c.Close()

	sock := filepath.Join(t.TempDir(), "plugin.sock")
	ln, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	exe := probeExe(t) // before any hello copies good (probeExe sets its digest)
	go func() { _ = Serve(ln, exe, 2, os.Getuid()) }()
	h := good
	h.BaseURL = "http://" + l.Addr().String()
	h.Flags = map[string]string{"mode": "egress", "arg": other.Addr().String()}
	c2, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	_ = c2.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c2.Write([]byte(line(h)))
	if got, err := bufio.NewReader(c2).ReadString('\n'); got != "egress service got it\n" || otherHits.Load() != 0 {
		t.Fatalf("%q %v; the other server was contacted %d times", got, err, otherHits.Load())
	}
	// What it is handed cannot be re-aimed either: shutdown, then sendto with MSG_FASTOPEN to the
	// other server, fails (a connected unix socket, never an inet one) and reaches nothing.
	h.Flags = map[string]string{"mode": "egress", "arg": other.Addr().String(), "reaim": "1"}
	c3, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c3.Close()
	_ = c3.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c3.Write([]byte(line(h)))
	got, _ := bufio.NewReader(c3).ReadString('\n')
	time.Sleep(100 * time.Millisecond)
	if !strings.HasPrefix(got, "reaim: ") || got == "reaim: <nil>\n" || otherHits.Load() != 0 {
		t.Fatalf("re-aim: %q; the other server was contacted %d times", got, otherHits.Load())
	}
}

// A plugin reads its own /proc (and its threads') but no other process's: not a sibling holding a
// canary in its argv (same uid, which Landlock refuses regardless), and not pid 1 of its pid
// namespace. So nothing one plugin writes into its argv or name reaches another.
func TestAPluginCannotReadAnotherProcesssProc(t *testing.T) {
	// A sibling that stays alive with the canary in its argv (sh keeps running past the sleep).
	sib := exec.Command("sh", "-c", "sleep 30; :", "canary-in-argv")
	if err := sib.Start(); err != nil {
		t.Skipf("no sh: %v", err)
	}
	defer func() { _ = sib.Process.Kill(); _ = sib.Wait() }()
	// The control: unsandboxed, the sibling's cmdline is there to read, so a refusal below is the
	// sandbox's and not a process that is gone.
	for end := time.Now().Add(2 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		b, _ := os.ReadFile("/proc/" + strconv.Itoa(sib.Process.Pid) + "/cmdline")
		if strings.Contains(string(b), "canary-in-argv") {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("control: the sibling's cmdline is %q", b)
		}
	}
	for target, want := range map[string]string{
		strconv.Itoa(sib.Process.Pid): "proc refused",
		"1":                           "proc refused",
		"self":                        "proc ok",
		"thread-self":                 "proc ok",
	} {
		dial := serveProbe(t, t.TempDir(), "readproc", target, 1)
		c, r := dial()
		got, err := r.ReadString('\n')
		c.Close()
		if got != want+"\n" {
			t.Errorf("/proc/%s: %q %v, want %q", target, got, err, want)
		}
	}
}

// The prctl calls a Go plugin makes pass under the filter: the runtime's PR_SET_VMA heap naming
// (it starts at all, and the log says whether this kernel shows the names) and the SDK's
// PR_GET_DUMPABLE (1: execve made it dumpable again) and PR_SET_DUMPABLE to 0.
func TestAPluginsRuntimePrctlsPass(t *testing.T) {
	dial := serveProbe(t, t.TempDir(), "prctl", "", 1)
	c, r := dial()
	defer c.Close()
	got, err := r.ReadString('\n')
	if !strings.HasPrefix(got, "prctl dumpable 1 set true vma ") {
		t.Fatalf("%q %v", got, err)
	}
	t.Logf("%s", got)
}

// A plugin that names itself with prctl(PR_SET_NAME) is denied (EPERM), so any record about the
// process (an audit or OOM line on the node) carries the executable's name, not the plugin's
// choice. The test reads the name the process holds when it exits, while it is still unreaped.
func TestAPluginCannotNameItself(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe := probeExe(t)
	var out bytes.Buffer
	cmd := exec.Command(self, shimFlagName, exe, "--mode=setname", "--arg=canary-token")
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var info [128]byte
	const pPID, wExited, wNoWait = 1, 4, 0x01000000
	if _, _, errno := syscall.Syscall6(syscall.SYS_WAITID, pPID, uintptr(cmd.Process.Pid), uintptr(unsafe.Pointer(&info[0])), wExited|wNoWait, 0, 0); errno != 0 {
		t.Fatal(errno)
	}
	comm, err := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/comm")
	_ = cmd.Wait()
	if err != nil || string(comm) != filepath.Base(exe)+"\n" {
		t.Errorf("comm at exit %q %v, want %q", comm, err, filepath.Base(exe))
	}
	if out.String() != "name: EPERM\n" {
		t.Errorf("the name was not denied: %v %q", cmd.ProcessState, out.String())
	}
}

// Nor can it rename itself through /proc/self/comm or a thread's comm: Landlock refuses opening
// them for writing. The same probe run unsandboxed opens both (the control), so the refusal is the
// sandbox's, not file permissions.
func TestAPluginCannotWriteItsComm(t *testing.T) {
	if out, err := exec.Command(probeExe(t), "--mode=writecomm").Output(); string(out) != "comm refused false false\n" {
		t.Fatalf("control: %q %v", out, err)
	}
	dial := serveProbe(t, t.TempDir(), "writecomm", "", 1)
	c, r := dial()
	defer c.Close()
	if got, err := r.ReadString('\n'); got != "comm refused true true\n" {
		t.Fatalf("%q %v", got, err)
	}
}

// A plugin can run its own executable again through one of its descriptors (/proc/self/fd/N), and
// the kernel then names it N: comm can carry the digits of a descriptor number. That bounds what a
// name can carry into records about the process. The re-run is the same process (same pid), still
// under the seccomp filter (an off-list call is denied) and Landlock, and the stream ends when it
// exits: no second process, nothing outlives the stream. The remaining surface (audit, closed by the
// node audit requirement; the OOM-kill line, once per stream) is in the connector deploy notes.
func TestAReexecStaysTheSameSandboxedProcess(t *testing.T) {
	dial := serveProbe(t, t.TempDir(), "reexec", "", 1)
	c, r := dial()
	defer c.Close()
	before, err := r.ReadString('\n')
	if err != nil || !strings.HasPrefix(before, "before pid=") {
		t.Fatalf("%q %v", before, err)
	}
	pid := strings.TrimSpace(strings.TrimPrefix(before, "before pid="))
	after, _ := r.ReadString('\n')
	if want := "after pid=" + pid + " comm=77 signal: EPERM\n"; after != want {
		t.Fatalf("after the re-run: %q, want %q", after, want)
	}
	if rest, err := io.ReadAll(r); len(rest) != 0 || err != nil {
		t.Fatalf("the stream did not end with the process: %q %v", rest, err)
	}
}

// A plugin can put SIGSEGV back to its default action (rt_sigaction is allowed: the Go runtime needs
// it) and fault at an address it picks. It dies of SIGSEGV, which ends its stream. Whether the kernel
// also writes the address and registers to its log is the node's debug.exception-trace setting, which
// no sandbox can change: the connector deploy notes require 0 on conngw nodes (x86-64 defaults to 1),
// and a twin case checks that the line appears at 1 and not at 0. The pid logged here is the one to
// look for in `journalctl -k`.
func TestAFaultingPluginDiesAndTheKernelLogIsANodeSetting(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	cmd := exec.Command(self, shimFlagName, probeExe(t), "--mode=fault")
	cmd.Dir = t.TempDir()
	cmd.Stdout = &out
	_ = cmd.Run()
	ws, _ := cmd.ProcessState.Sys().(syscall.WaitStatus)
	want := fmt.Sprintf("fault pid=%d at 0xdead0000 reset: ok\n", cmd.Process.Pid)
	if out.String() != want || !ws.Signaled() || ws.Signal() != syscall.SIGSEGV {
		t.Fatalf("got %q, %v; want %q and death by SIGSEGV", out.String(), cmd.ProcessState, want)
	}
	trace, err := os.ReadFile("/proc/sys/debug/exception-trace")
	t.Logf("pid %d faulted at 0xdead0000; this node's debug.exception-trace: %q %v", cmd.Process.Pid, strings.TrimSpace(string(trace)), err)
}

// The host runs only the executable whose sha256 the hello names (from the signed profile). A
// different build at the plugin path (here the probe with one byte appended, as a substituted vendor
// binary would be) is refused before it runs: the connection closes with no output and the host
// logs the digest it found. The same hello against the real probe runs it.
func TestOnlyThePinnedPluginRuns(t *testing.T) {
	exe := probeExe(t)
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(other, append(b, 0), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(path string, h Hello) string {
		t.Helper()
		sock := filepath.Join(t.TempDir(), "plugin.sock")
		l, err := Listen(sock)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		go func() { _ = Serve(l, path, 1, os.Getuid()) }()
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = c.Write([]byte(line(h)))
		out, _ := io.ReadAll(c)
		return string(out)
	}
	h := good
	h.Flags = map[string]string{"mode": "truncate", "arg": filepath.Join(t.TempDir(), "x")}
	if got := run(exe, h); !strings.HasPrefix(got, "truncate: ") {
		t.Fatalf("the pinned probe did not run: %q", got)
	}
	if got := run(other, h); got != "" {
		t.Fatalf("a binary off the pin ran: %q", got)
	}
	wrong := h
	wrong.PluginDigest = "sha256:" + strings.Repeat("ab", 32)
	if got := run(exe, wrong); got != "" {
		t.Fatalf("the probe ran under another digest: %q", got)
	}
	if _, err := Stage(t.TempDir(), other, h.PluginDigest); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("%x", sha256.Sum256(append(b, 0)))) {
		t.Fatalf("refusal: %v", err)
	}
}

// A plugin cannot become a socket server in place of its host: it cannot open a socket, unix or
// inet (the filter denies socket), so a vendor binary that is a rogue server serves nothing.
func TestAPluginCannotListen(t *testing.T) {
	dial := serveProbe(t, t.TempDir(), "listen", filepath.Join(t.TempDir(), "rogue.sock"), 1)
	c, r := dial()
	defer c.Close()
	if got, err := r.ReadString('\n'); got != "listen: EPERM EPERM\n" {
		t.Fatalf("%q %v", got, err)
	}
}

// The vendor chose the image's contents, so the plugin path is checked as a file before it is
// hashed: a link (to /dev/zero, which would never end), a pipe (which would block the open), a
// device or a file over MaxPlugin bytes is refused at once, without reading it.
func TestThePluginPathMustBeABoundedRegularFile(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "link")
	if err := os.Symlink("/dev/zero", link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxPlugin + 1); err != nil { // sparse: no disk used
		t.Fatal(err)
	}
	f.Close()
	digest := "sha256:" + strings.Repeat("0", 64)
	for _, p := range []string{link, fifo, big, "/dev/zero", filepath.Join(dir, "missing")} {
		done := make(chan error, 1)
		go func() { _, err := Stage(dir, p, digest); done <- err }()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("%s: accepted", p)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: the check did not end", p)
		}
	}
}

// What runs is plughost's verified copy, not the mounted file: the bytes executed are the bytes
// hashed whatever the mount allows (an image volume may be noexec), a source that changes after the
// first stream changes nothing, and the plugin cannot write the copy a later stream will run.
func TestTheVerifiedCopyIsWhatRuns(t *testing.T) {
	b, err := os.ReadFile(probeExe(t))
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(src, b, 0o644); err != nil { // not even executable at the source
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", t.TempDir())
	sock := filepath.Join(t.TempDir(), "plugin.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() { _ = Serve(l, src, 1, os.Getuid()) }()
	call := func(mode, arg string) string {
		t.Helper()
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		h := good
		h.Flags = map[string]string{"mode": mode, "arg": arg}
		_, _ = c.Write([]byte(line(h)))
		out, _ := io.ReadAll(c)
		return string(out)
	}
	scratch := filepath.Join(t.TempDir(), "x")
	if got := call("truncate", scratch); !strings.HasPrefix(got, "truncate: ") {
		t.Fatalf("first stream: %q", got)
	}
	staged, _ := filepath.Glob(filepath.Join(os.Getenv("TMPDIR"), "plughost-*", strings.TrimPrefix(good.PluginDigest, "sha256:"), "probe"))
	if len(staged) != 1 {
		t.Fatalf("staged copies: %v", staged)
	}
	if got := call("truncate", staged[0]); got != "truncate: EPERM\n" && got != "truncate: EACCES\n" {
		t.Fatalf("the plugin could change its next run: %q", got)
	}
	if err := os.WriteFile(src, []byte("#!/bin/sh\necho swapped\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := call("truncate", scratch); !strings.HasPrefix(got, "truncate: ") {
		t.Fatalf("after the source changed: %q", got)
	}
}

// Staging is bounded: the host keeps one copy, in a fixed directory it empties at start (an emptyDir
// outlives a container restart, so an earlier run's copies are reclaimed, not added to), and a hello
// naming another digest replaces the copy. A refused digest leaves nothing behind.
func TestStagingKeepsOneCopy(t *testing.T) {
	exe := probeExe(t)
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(other, append(b, 0), 0o644); err != nil {
		t.Fatal(err)
	}
	otherDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(append(b, 0)))
	dir := filepath.Join(t.TempDir(), "plughost")
	entries := func() []string {
		t.Helper()
		var names []string
		_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				names = append(names, strings.TrimPrefix(p, dir+"/"))
			}
			return nil
		})
		return names
	}
	for run := 0; run < 2; run++ { // two host starts on one emptyDir
		st, err := newStage(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got := entries(); len(got) != 0 {
			t.Fatalf("start %d left %v", run, got)
		}
		if _, err := st.plugin(exe, good.PluginDigest); err != nil {
			t.Fatal(err)
		}
		if _, err := st.plugin(exe, otherDigest); err == nil {
			t.Fatal("staged under a digest it does not have")
		}
		if got := entries(); len(got) != 1 {
			t.Fatalf("after a refusal: %v", got)
		}
		if _, err := st.plugin(other, otherDigest); err != nil {
			t.Fatal(err)
		}
		if got := entries(); len(got) != 1 || !strings.HasPrefix(got[0], strings.TrimPrefix(otherDigest, "sha256:")) {
			t.Fatalf("after a new digest: %v", got)
		}
	}
}

// A plugin that skips the SDK and writes its own service token back, in any of the refused forms
// and even split over two writes with a pause between, gets none of it past the host: the clean
// line before it passes, nothing of the line that carries it does, and the stream ends. Nothing
// written after passes.
func TestAPluginCannotHandBackItsToken(t *testing.T) {
	control := serveProbe(t, t.TempDir(), "leaktoken", "none", 1)
	cc, cr := control()
	all, _ := io.ReadAll(cr)
	cc.Close()
	if !strings.HasSuffix(string(all), "no token here\"}]}}\nafter\n") {
		t.Fatalf("control: %q", all)
	}
	for _, form := range []string{"raw", "split", "base64", "hex", "escaped"} {
		dial := serveProbe(t, t.TempDir(), "leaktoken", form, 1)
		c, r := dial()
		got, _ := io.ReadAll(r)
		c.Close()
		if string(got) != "{\"clean\":true}\n" {
			t.Errorf("%s: the caller got %q", form, got)
		}
	}
}

// buildProbeVariant builds testdata/probe with extra environment and go build arguments.
func buildProbeVariant(t *testing.T, env []string, args ...string) (string, error) {
	t.Helper()
	dir, err := os.MkdirTemp(diskTmp, "variant")
	if err != nil {
		return "", err
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	out := filepath.Join(dir, "probe")
	cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), append(append([]string{"build"}, args...), "-o", out, ".")...)
	cmd.Dir = "testdata/probe"
	cmd.Env = append(append(os.Environ(), "GOPROXY=off", "GOWORK=off", "GOFLAGS=-mod=mod", "TMPDIR="+diskTmp), env...)
	if b, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("%w: %s", err, b)
	}
	return out, nil
}

// runPinned serves exe once under a hello pinning exe's own digest and returns what the stream got.
func runPinned(t *testing.T, exe string) string {
	t.Helper()
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "plugin.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() { _ = Serve(l, exe, 1, os.Getuid()) }()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	h := good
	h.PluginDigest = fmt.Sprintf("sha256:%x", sha256.Sum256(b))
	h.Flags = map[string]string{"mode": "truncate", "arg": filepath.Join(t.TempDir(), "x")}
	_, _ = c.Write([]byte(line(h)))
	got, _ := io.ReadAll(c)
	return string(got)
}

// Only a self-contained executable runs: an ELF for this machine with no interpreter and no needed
// library, so the signed digest covers all the code the kernel loads. A script (its interpreter
// would be an unsigned file), a dynamically linked executable (its libraries would be), an ELF
// for another machine, and Go's own -buildmode=pie without cgo (which names an interpreter) are
// refused with the reason; the static probe and a static PIE run.
func TestOnlyStaticExecutablesRun(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "script")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	trueBytes, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	dyn := filepath.Join(dir, "true")
	if err := os.WriteFile(dyn, trueBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	other := map[string]string{"amd64": "arm64", "arm64": "amd64"}[runtime.GOARCH]
	foreign, err := buildProbeVariant(t, []string{"CGO_ENABLED=0", "GOARCH=" + other})
	if err != nil {
		t.Fatal(err)
	}
	gopie, err := buildProbeVariant(t, []string{"CGO_ENABLED=0"}, "-buildmode=pie")
	if err != nil {
		t.Fatal(err)
	}
	for path, reason := range map[string]string{script: "not an ELF file", dyn: "has an INTERP program header", foreign: "built for", gopie: "has an INTERP program header"} {
		b, _ := os.ReadFile(path)
		_, err := Stage(t.TempDir(), path, fmt.Sprintf("sha256:%x", sha256.Sum256(b)))
		if !errors.Is(err, errNotStatic) || !strings.Contains(err.Error(), reason) {
			t.Errorf("%s: %v, want a refusal naming %q", filepath.Base(path), err, reason)
		}
		if got := runPinned(t, path); got != "" {
			t.Errorf("%s ran: %q", filepath.Base(path), got)
		}
	}
	if got := runPinned(t, probeExe(t)); !strings.HasPrefix(got, "truncate: ") {
		t.Fatalf("the static probe did not run: %q", got)
	}
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("no C toolchain here to link a static PIE probe (the static probe above ran)")
	}
	spie, err := buildProbeVariant(t, []string{"CGO_ENABLED=1"}, "-buildmode=pie", "-tags=netgo,osusergo", "-ldflags=-linkmode=external -extldflags=-static-pie")
	if err != nil {
		t.Fatal(err)
	}
	if err := checkStatic(spie); err != nil {
		t.Fatalf("static PIE refused: %v", err)
	}
	if got := runPinned(t, spie); !strings.HasPrefix(got, "truncate: ") {
		t.Fatalf("the static PIE probe did not run: %q", got)
	}

}

// Each stream gets its own copy of the service token, read once when it starts: the plugin is given
// the copy and the host scrubs for the same bytes. A Secret rotated while the stream is open changes
// nothing for it; the next stream gets the new token.
func TestEachStreamHasItsOwnTokenSnapshot(t *testing.T) {
	short := func(tok string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(tok)))[:12] }
	mounted := filepath.Join(t.TempDir(), "token")
	a, b := "conngw-snapshot-A-0123456789", "conngw-snapshot-B-0123456789"
	if err := os.WriteFile(mounted, []byte(a+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "plugin.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	exe := probeExe(t) // before any hello copies good (probeExe sets its digest)
	go func() { _ = Serve(l, exe, 2, os.Getuid()) }()
	stream := func(rotateTo string) string {
		t.Helper()
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		h := good
		h.TokenPath = mounted
		h.Flags = map[string]string{"mode": "tokensha"}
		_, _ = c.Write([]byte(line(h)))
		r := bufio.NewReader(c)
		if got, err := r.ReadString('\n'); got != "ready\n" {
			t.Fatalf("%q %v", got, err)
		}
		if err := os.WriteFile(mounted, []byte(rotateTo+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("go\n"))
		got, _ := r.ReadString('\n')
		return strings.TrimSpace(got)
	}
	if got := stream(b); got != "sha "+short(a)+" "+short(a) {
		t.Fatalf("first stream read %q, want A twice (%s)", got, short(a))
	}
	if got := stream(a); got != "sha "+short(b)+" "+short(b) {
		t.Fatalf("second stream read %q, want B twice (%s)", got, short(b))
	}
}

// No unverified byte is reachable: the plugin cannot read the directory its executable was mounted
// from (the vendor image) or the mounted token's directory, cannot execute any file but its own
// verified copy, and still reads its stream's token snapshot (running itself again is
// TestAReexecStaysTheSameSandboxedProcess). The probe's
// build directory stands for both mounts here (it holds the probe and the test token).
func TestNoUnverifiedFileIsReachable(t *testing.T) {
	exe := probeExe(t)
	run := func(mode, arg string) string {
		t.Helper()
		dial := serveProbe(t, t.TempDir(), mode, arg, 1)
		c, r := dial()
		defer c.Close()
		got, _ := r.ReadString('\n')
		return strings.TrimSpace(got)
	}
	for _, p := range []string{exe, good.TokenPath, filepath.Dir(exe)} {
		if got := run("readfile", p); got != "read: EACCES" && got != "read: error" {
			t.Errorf("the plugin read %s: %q", p, got)
		}
	}
	// Control: the same reads outside the sandbox work, so the refusal is Landlock's.
	if _, err := os.ReadFile(exe); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{exe, "/bin/true"} {
		if got := run("execother", p); got != "exec: EACCES" {
			t.Errorf("the plugin executed %s: %q", p, got)
		}
	}
	if got := run("tokensha", ""); !strings.HasPrefix(got, "ready") {
		t.Errorf("the plugin could not read its snapshot: %q", got)
	}
}

// The whole vendor image is hidden, not just the executable's directory: with the executable at
// <vendor>/bin/probe, a payload at <vendor>/lib/payload is unreadable when plughost is given the
// vendor mount. Given only the executable's directory, the payload would be readable: that is why
// plughost takes -vendor and requires it to be a mount point.
func TestTheWholeVendorImageIsHidden(t *testing.T) {
	b, err := os.ReadFile(probeExe(t))
	if err != nil {
		t.Fatal(err)
	}
	vendor := t.TempDir()
	for _, d := range []string{"bin", "lib"} {
		if err := os.Mkdir(filepath.Join(vendor, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	exe, payload := filepath.Join(vendor, "bin", "probe"), filepath.Join(vendor, "lib", "payload")
	if err := os.WriteFile(exe, b, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payload, []byte("unsigned code"), 0o644); err != nil {
		t.Fatal(err)
	}
	read := func(serve func(net.Listener) error) string {
		t.Helper()
		sock := filepath.Join(t.TempDir(), "plugin.sock")
		l, err := Listen(sock)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		go func() { _ = serve(l) }()
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		h := good
		h.Flags = map[string]string{"mode": "readfile", "arg": payload}
		_, _ = c.Write([]byte(line(h)))
		got, _ := bufio.NewReader(c).ReadString('\n')
		return strings.TrimSpace(got)
	}
	if got := read(func(l net.Listener) error { return ServeVendor(l, exe, vendor, 1, os.Getuid()) }); got != "read: EACCES" {
		t.Fatalf("with the vendor mount hidden, the payload read %q", got)
	}
	if got := read(func(l net.Listener) error { return Serve(l, exe, 1, os.Getuid()) }); got != "read: ok" {
		t.Fatalf("control (only bin/ hidden): %q", got)
	}
	if err := ServeVendor(nil, "/elsewhere/probe", vendor, 1, os.Getuid()); err == nil {
		t.Fatal("an executable outside the vendor directory was accepted")
	}
	if err := CheckVendorMount(vendor); err == nil {
		t.Fatal("a plain directory was accepted as the vendor mount")
	}
	if err := CheckVendorMount("/proc"); err != nil {
		t.Fatalf("/proc is a mount point: %v", err)
	}
}

// Concurrent streams share the host's uid, so the staging directory is hidden as a whole: a stream
// opened before a rotation cannot read the token snapshot of a stream opened after it (token B,
// which its own scrub does not know). It reads only its own snapshot.
func TestAStreamCannotReadAnotherStreamsSnapshot(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	mounted := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(mounted, []byte("conngw-concurrent-A-0123456789\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "plugin.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	exe := probeExe(t) // before any hello copies good (probeExe sets its digest)
	go func() { _ = Serve(l, exe, 2, os.Getuid()) }()
	open := func(mode, arg string) (net.Conn, *bufio.Reader) {
		t.Helper()
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		h := good
		h.TokenPath = mounted
		h.Flags = map[string]string{"mode": mode, "arg": arg}
		_, _ = c.Write([]byte(line(h)))
		r := bufio.NewReader(c)
		if got, err := r.ReadString('\n'); got != "ready\n" {
			t.Fatalf("%s: %q %v", mode, got, err)
		}
		return c, r
	}
	old, oldR := open("waitread", "")
	defer old.Close()
	if err := os.WriteFile(mounted, []byte("conngw-concurrent-B-0123456789\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	newer, _ := open("tokensha", "")
	defer newer.Close()
	snaps, _ := filepath.Glob(filepath.Join(os.Getenv("TMPDIR"), "plughost-*", "token-*"))
	if len(snaps) != 2 {
		t.Fatalf("snapshots: %v", snaps)
	}
	_, _ = old.Write([]byte(strings.Join(snaps, ":") + "\n"))
	got, _ := oldR.ReadString('\n')
	if got != "read: 1 ok 1 refused\n" {
		t.Fatalf("the older stream read %q, want only its own snapshot", got)
	}
}

// The staging directory must be memory-backed: on a disk-backed one the host refuses to start.
func TestADiskBackedStagingDirectoryIsRefused(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	var fs syscall.Statfs_t
	if syscall.Statfs(wd, &fs) != nil || int64(fs.Type) == tmpfsMagic {
		t.Skip("the source tree is not on a disk here")
	}
	disk, err := os.MkdirTemp(wd, ".staging-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(disk)
	t.Setenv("TMPDIR", disk)
	sockDir, err := os.MkdirTemp(diskTmp, "s")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	sock := filepath.Join(sockDir, "plugin.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := Serve(l, probeExe(t), 1, os.Getuid()); err == nil || !strings.Contains(err.Error(), "medium: Memory") {
		t.Fatalf("a disk-backed staging directory: %v", err)
	}
}

// The token's directory is hidden whole, and the token must resolve inside it. A Secret volume's
// layout (token -> ..data/token, ..data -> a dated directory) passes, and after a rotation the new
// dated directory is unreadable to a stream opened before it. A token that links out of its
// directory is refused, so no rotated copy elsewhere can be reached through it.
func TestTheTokenMountIsHiddenWhole(t *testing.T) {
	mount := t.TempDir()
	mkdata := func(name, tok string) {
		t.Helper()
		if err := os.Mkdir(filepath.Join(mount, name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(mount, name, "token"), []byte(tok+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(filepath.Join(mount, "..data"))
		if err := os.Symlink(name, filepath.Join(mount, "..data")); err != nil {
			t.Fatal(err)
		}
	}
	mkdata("..2026_a", "conngw-mount-A-0123456789")
	token := filepath.Join(mount, "token")
	if err := os.Symlink("..data/token", token); err != nil {
		t.Fatal(err)
	}
	staging := t.TempDir()
	if _, err := hiddenDirs(staging, filepath.Dir(probeExe(t)), token); err != nil {
		t.Fatalf("Secret volume layout refused: %v", err)
	}
	exe := probeExe(t)
	sock := filepath.Join(t.TempDir(), "plugin.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() { _ = Serve(l, exe, 1, os.Getuid()) }()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	h := good
	h.TokenPath = token
	h.Flags = map[string]string{"mode": "waitread"}
	_, _ = c.Write([]byte(line(h)))
	r := bufio.NewReader(c)
	if got, err := r.ReadString('\n'); got != "ready\n" {
		t.Fatalf("%q %v", got, err)
	}
	mkdata("..2026_b", "conngw-mount-B-0123456789") // the rotation
	_, _ = c.Write([]byte(filepath.Join(mount, "..2026_b", "token") + ":" + token + "\n"))
	if got, _ := r.ReadString('\n'); got != "read: 0 ok 2 refused\n" {
		t.Fatalf("an open stream read the mounted token after a rotation: %q", got)
	}
	// A token that links out of its directory is refused.
	alias := t.TempDir()
	if err := os.Symlink(filepath.Join(mount, "..2026_b", "token"), filepath.Join(alias, "token")); err != nil {
		t.Fatal(err)
	}
	if _, err := hiddenDirs(staging, filepath.Dir(exe), filepath.Join(alias, "token")); err == nil {
		t.Fatal("a token linking out of its directory was accepted")
	}
}

// A CA file beside the token (a projected service-account volume's layout) works: the host checks
// it and gives the plugin a fresh copy of its certificates for the stream, never the original, while
// the token beside it stays hidden. A caPath that is the token, links to it, holds a key or a
// malformed block, has any other bytes around its certificates, or is not a bounded regular file is
// refused.
func TestACAFileBesideTheTokenIsReadableAndChecked(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, IsCA: true,
		BasicConstraintsValid: true, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kder, _ := x509.MarshalECPrivateKey(key)
	mount := t.TempDir()
	token, ca := filepath.Join(mount, "token"), filepath.Join(mount, "ca.crt")
	files := map[string][]byte{token: []byte("conngw-ca-test-token-0123456789\n"), ca: append(append([]byte{}, cert...), cert...),
		filepath.Join(mount, "withkey.crt"):   append(append([]byte{}, cert...), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})...),
		filepath.Join(mount, "notpem.crt"):    []byte("not a certificate\n"),
		filepath.Join(mount, "before.crt"):    append([]byte("\x7fELF payload bytes\n"), cert...),
		filepath.Join(mount, "between.crt"):   append(append(append([]byte{}, cert...), []byte("payload between\n")...), cert...),
		filepath.Join(mount, "after.crt"):     append(append([]byte{}, cert...), []byte("trailing payload")...),
		filepath.Join(mount, "malformed.crt"): append([]byte("-----BEGIN CERTIFICATE-----\n!!payload!!\n-----END CERTIFICATE-----\n"), cert...)}
	for p, b := range files {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("token", filepath.Join(mount, "tokenlink.crt")); err != nil {
		t.Fatal(err)
	}
	if got, err := snapshotCA(t.TempDir(), ca, token); err != nil {
		t.Fatalf("CA beside the token: %q %v", got, err)
	} else if b, _ := os.ReadFile(got); !bytes.Equal(b, files[ca]) {
		t.Fatalf("the copy is not the certificates re-encoded: %q", b)
	}
	for _, bad := range []string{token, filepath.Join(mount, "tokenlink.crt"), filepath.Join(mount, "withkey.crt"), filepath.Join(mount, "notpem.crt"),
		filepath.Join(mount, "before.crt"), filepath.Join(mount, "between.crt"), filepath.Join(mount, "after.crt"),
		filepath.Join(mount, "malformed.crt"), "/dev/zero"} {
		if _, err := snapshotCA(t.TempDir(), bad, token); err == nil {
			t.Errorf("%s accepted as a CA file", filepath.Base(bad))
		}
	}
	// Live: the plugin reads the CA, not the token beside it.
	exe := probeExe(t)
	run := func(caPath, mode, arg string) string {
		t.Helper()
		sock := filepath.Join(t.TempDir(), "plugin.sock")
		l, err := Listen(sock)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		go func() { _ = Serve(l, exe, 1, os.Getuid()) }()
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		h := good
		h.TokenPath, h.CAPath = token, caPath
		h.Flags = map[string]string{"mode": mode, "arg": arg}
		_, _ = c.Write([]byte(line(h)))
		got, _ := bufio.NewReader(c).ReadString('\n')
		return strings.TrimSpace(got)
	}
	read := func(caPath, file string) string { t.Helper(); return run(caPath, "readfile", file) }
	if got := run(ca, "cafile", ""); got != "ca: ok 2 false" {
		t.Fatalf("the plugin's CA file: %q", got)
	}
	if got := read(ca, ca); got != "read: EACCES" {
		t.Fatalf("the plugin read the original CA file in the token's directory: %q", got)
	}
	if got := read(ca, token); got != "read: EACCES" {
		t.Fatalf("the plugin read the token beside its CA: %q", got)
	}
	if got := read(filepath.Join(mount, "withkey.crt"), ca); got != "" {
		t.Fatalf("a stream ran with a CA file holding a key: %q", got)
	}
}

// A plugin that writes its answer and exits at once loses nothing, and the next stream opened the
// moment this one ends is served, even with one slot: the host passes all of the plugin's output on
// before it closes the connection, and frees the slot before that. 300 back-to-back streams each
// get the whole answer.
func TestFastExitStreamsBackToBackLoseNothing(t *testing.T) {
	exe := probeExe(t)
	sock := filepath.Join(t.TempDir(), "plugin.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() { _ = Serve(l, exe, 1, os.Getuid()) }()
	scratch := filepath.Join(t.TempDir(), "x")
	h := good
	h.Flags = map[string]string{"mode": "truncate", "arg": scratch}
	hello := []byte(line(h))
	for i := 0; i < 300; i++ {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		_, _ = c.Write(hello)
		got, _ := io.ReadAll(c)
		c.Close()
		if !strings.HasPrefix(string(got), "truncate: ") || !strings.HasSuffix(string(got), "\n") {
			t.Fatalf("stream %d got %q", i, got)
		}
	}
}

// A stream refused after the host has created its descriptors (here: a CA file that holds a key,
// refused after the egress pair exists) leaves none behind: 500 refused streams leave the host's
// open descriptors where they were, within a small margin. (Without the deferred close the garbage
// collector reclaims some of the leaked ones, so the count still grows by dozens.)
func TestRefusedStreamsLeakNoDescriptors(t *testing.T) {
	exe := probeExe(t)
	mount := t.TempDir()
	token, ca := filepath.Join(mount, "token"), filepath.Join(mount, "ca.crt")
	if err := os.WriteFile(token, []byte("conngw-fd-test-token-0123456789\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keyBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE " + "KEY", Bytes: []byte{0}}) // a key block, not a key
	if err := os.WriteFile(ca, keyBlock, 0o600); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "plugin.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() { _ = Serve(l, exe, 4, os.Getuid()) }()
	h := good
	h.TokenPath, h.CAPath = token, ca
	h.Flags = map[string]string{"mode": "truncate", "arg": filepath.Join(t.TempDir(), "x")}
	hello := []byte(line(h))
	stream := func() {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		_, _ = c.Write(hello)
		if got, _ := io.ReadAll(c); len(got) != 0 {
			t.Fatalf("a refused stream answered %q", got)
		}
		c.Close()
	}
	count := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	stream() // the first stream stages the plugin; count after it
	time.Sleep(50 * time.Millisecond)
	before := count()
	for i := 0; i < 500; i++ {
		stream()
	}
	time.Sleep(100 * time.Millisecond) // the last stream's goroutine finishes its cleanup
	after := count()
	t.Logf("open descriptors: %d before, %d after", before, after)
	if after-before > 4 {
		t.Fatalf("open descriptors grew from %d to %d over 500 refused streams", before, after)
	}
}

// A stream whose second pipe cannot be made (descriptors running out) closes both ends of the
// first: 300 such streams leave the host's open descriptors where they were.
func TestAFailedPipeLeaksNoDescriptors(t *testing.T) {
	exe := probeExe(t)
	var calls atomic.Int64
	saved := osPipe
	osPipe = func() (*os.File, *os.File, error) {
		if calls.Add(1)%2 == 0 {
			return nil, nil, syscall.EMFILE
		}
		return os.Pipe()
	}
	defer func() { osPipe = saved }()
	sock := filepath.Join(t.TempDir(), "plugin.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() { _ = Serve(l, exe, 4, os.Getuid()) }()
	h := good
	h.Flags = map[string]string{"mode": "truncate", "arg": filepath.Join(t.TempDir(), "x")}
	hello := []byte(line(h))
	stream := func() {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		_, _ = c.Write(hello)
		if got, _ := io.ReadAll(c); len(got) != 0 {
			t.Fatalf("a stream with no stdout pipe answered %q", got)
		}
		c.Close()
	}
	count := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	stream()
	time.Sleep(50 * time.Millisecond)
	before := count()
	for i := 0; i < 300; i++ {
		stream()
	}
	time.Sleep(100 * time.Millisecond)
	after := count()
	t.Logf("open descriptors: %d before, %d after", before, after)
	if after-before > 4 {
		t.Fatalf("open descriptors grew from %d to %d over 300 streams with a failed pipe", before, after)
	}
}

// Containment is root-aware: a file directly under / (a CA at /ca.pem) is inside /, which a plain
// prefix test against dir+"/" ("//") would refuse.
func TestInsideHandlesTheRoot(t *testing.T) {
	for _, c := range []struct {
		p, dir string
		want   bool
	}{{"/ca.pem", "/", true}, {"/a/ca.pem", "/", true}, {"/a/ca.pem", "/a", true}, {"/a/ca.pem", "/a/", true},
		{"/", "/", false}, {"/ab", "/a", false}, {"/ab", "/a/", false}, {"/a", "/a", false}, {"/a/", "/a", false}} {
		if got := inside(c.p, c.dir); got != c.want {
			t.Errorf("inside(%q, %q) = %v", c.p, c.dir, got)
		}
	}
}

// A token in a nested projection (credentials -> ..data/credentials, so the token resolves into a
// generation directory's subdirectory) hides the whole projection root: a generation rotated in
// while a stream is open is unreadable to it, as in the plain layout.
func TestANestedProjectionHidesEveryGeneration(t *testing.T) {
	mount := t.TempDir()
	mkgen := func(name, tok string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(mount, name, "credentials"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(mount, name, "credentials", "token"), []byte(tok+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(filepath.Join(mount, "..data"))
		if err := os.Symlink(name, filepath.Join(mount, "..data")); err != nil {
			t.Fatal(err)
		}
	}
	mkgen("..2026_a", "conngw-nested-A-0123456789")
	if err := os.Symlink("..data/credentials", filepath.Join(mount, "credentials")); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(mount, "credentials", "token")
	exe := probeExe(t)
	got, err := hiddenDirs(t.TempDir(), filepath.Dir(exe), token)
	if err != nil || !strings.Contains(got, ":"+mount+":") {
		t.Fatalf("hidden %q %v, want the projection root %s", got, err, mount)
	}
	sock := filepath.Join(t.TempDir(), "plugin.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() { _ = Serve(l, exe, 1, os.Getuid()) }()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	h := good
	h.TokenPath = token
	h.Flags = map[string]string{"mode": "waitread"}
	_, _ = c.Write([]byte(line(h)))
	r := bufio.NewReader(c)
	if got, err := r.ReadString('\n'); got != "ready\n" {
		t.Fatalf("%q %v", got, err)
	}
	mkgen("..2026_b", "conngw-nested-B-0123456789") // the rotation
	_, _ = c.Write([]byte(filepath.Join(mount, "..2026_b", "credentials", "token") + ":" + token + "\n"))
	if got, _ := r.ReadString('\n'); got != "read: 0 ok 2 refused\n" {
		t.Fatalf("an open stream read a rotated token in a nested projection: %q", got)
	}
}
