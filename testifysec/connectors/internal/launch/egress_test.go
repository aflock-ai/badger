//go:build unix

package launch

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// The egress target is the profile base URL's host and port, defaulting by scheme.
func TestTheEgressTargetIsTheBaseURLsHostAndPort(t *testing.T) {
	for in, want := range map[string]string{
		"https://gitlab-1.example.invalid":           "gitlab-1.example.invalid:443",
		"https://jira.example.invalid:8443/rest/api": "jira.example.invalid:8443",
		"http://127.0.0.1:9000/api":                  "127.0.0.1:9000",
		"https://[2001:db8::1]/x":                    "[2001:db8::1]:443",
	} {
		if got, err := egressTarget(in); err != nil || got != want {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "gitlab-1.example.invalid", "ftp://x.example.invalid", "https://"} {
		if got, err := egressTarget(bad); err == nil {
			t.Errorf("%q: accepted as %q", bad, got)
		}
	}
}

// ask sends one request on the plugin's end and returns the connection passed back, or nil.
func ask(t *testing.T, plugin *os.File) net.Conn {
	t.Helper()
	pc, err := net.FileConn(plugin)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	u := pc.(*net.UnixConn)
	_ = u.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := u.Write([]byte{'D'}); err != nil {
		t.Fatal(err)
	}
	b, oob := make([]byte, 1), make([]byte, syscall.CmsgSpace(4))
	_, oobn, _, _, err := u.ReadMsgUnix(b, oob)
	if err != nil || b[0] != 'K' {
		return nil
	}
	msgs, _ := syscall.ParseSocketControlMessage(oob[:oobn])
	fds, _ := syscall.ParseUnixRights(&msgs[0])
	f := os.NewFile(uintptr(fds[0]), "conn")
	defer f.Close()
	c, err := net.FileConn(f)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Every request is answered with a connection to the one target, whatever else exists: the
// connection handed back reaches the profile's server.
func TestEgressHandsBackOnlyTheTarget(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(c, "from the profile's server\n")
			c.Close()
		}
	}()
	host, plugin, err := egressPair()
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	go serveEgress(context.Background(), host, l.Addr().String(), "test")
	c := ask(t, plugin)
	if c == nil {
		t.Fatal("no connection handed back")
	}
	defer c.Close()
	if _, ok := c.(*net.UnixConn); !ok { // never an inet socket the plugin could re-aim
		t.Fatalf("handed back a %T", c)
	}
	if got, _ := bufio.NewReader(c).ReadString('\n'); got != "from the profile's server\n" {
		t.Fatalf("%q", got)
	}
}

// Request churn cannot spend the host's resources: requests are served one at a time (one dial in
// flight per stream), and the stream's teardown ends a dial still waiting on a destination that
// never answers.
func TestEgressChurnIsBounded(t *testing.T) {
	var inFlight, peak atomic.Int32
	saved := egressDial
	t.Cleanup(func() { egressDial = saved })
	egressDial = func(ctx context.Context, _ string) (net.Conn, error) {
		n := inFlight.Add(1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		defer inFlight.Add(-1)
		<-ctx.Done() // a destination that drops every packet
		return nil, ctx.Err()
	}
	host, plugin, err := egressPair()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { serveEgress(ctx, host, "192.0.2.1:443", "test"); close(done) }()
	pc, err := net.FileConn(plugin)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	for range 200 {
		_, _ = pc.Write([]byte{'D'})
	}
	time.Sleep(200 * time.Millisecond)
	if p := peak.Load(); p != 1 {
		t.Fatalf("peak in-flight dials %d, want 1", p)
	}
	cancel()
	host.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the egress loop outlived the stream")
	}
	if n := inFlight.Load(); n != 0 {
		t.Fatalf("%d dials outlived the stream", n)
	}
}

// The host accepts only the request byte: a descriptor the plugin passes back is closed unread
// (here a pipe's write end, whose read end then sees EOF), and that stream's egress ends.
func TestEgressDropsWhatThePluginPasses(t *testing.T) {
	host, plugin, err := egressPair()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { serveEgress(context.Background(), host, "192.0.2.1:443", "test"); close(done) }()
	pc, err := net.FileConn(plugin)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, _, err := pc.(*net.UnixConn).WriteMsgUnix([]byte{'D'}, syscall.UnixRights(int(w.Fd())), nil); err != nil {
		t.Fatal(err)
	}
	w.Close()
	_ = r.SetDeadline(time.Now().Add(3 * time.Second))
	if n, err := r.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("the passed descriptor is still open in the host: %d %v", n, err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("egress went on after control data")
	}
}

// The pair is close-on-exec from creation, so a plugin of another stream starting at the same
// moment cannot inherit it; only exec.Cmd.ExtraFiles hands the plugin its own end.
func TestTheEgressPairIsCloseOnExec(t *testing.T) {
	host, plugin, err := egressPair()
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	defer plugin.Close()
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, plugin.Fd(), syscall.F_GETFD, 0)
	if errno != 0 || flags&syscall.FD_CLOEXEC == 0 {
		t.Fatalf("the plugin's end is inheritable: flags %#x %v", flags, errno)
	}
}

// holdServer accepts connections and keeps them open until the test ends.
func holdServer(t *testing.T) net.Listener {
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
			t.Cleanup(func() { c.Close() })
		}
	}()
	return l
}

// At most MaxEgress connections are open per stream; a request beyond it is refused.
func TestEgressConnectionsAreBounded(t *testing.T) {
	l := holdServer(t)
	host, plugin, err := egressPair()
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	go serveEgress(context.Background(), host, l.Addr().String(), "test")
	for i := range MaxEgress + 2 {
		c := ask(t, plugin)
		if (c != nil) != (i < MaxEgress) {
			t.Fatalf("request %d: connection %v", i, c != nil)
		}
		if c != nil {
			defer c.Close()
		}
	}
}

// A descriptor the plugin sends over a data connection is closed unread (its pipe's read end sees
// EOF), and that connection ends.
func TestADataConnectionDropsWhatThePluginPasses(t *testing.T) {
	l := holdServer(t)
	host, plugin, err := egressPair()
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	go serveEgress(context.Background(), host, l.Addr().String(), "test")
	c := ask(t, plugin)
	if c == nil {
		t.Fatal("no connection")
	}
	defer c.Close()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, _, err := c.(*net.UnixConn).WriteMsgUnix([]byte("x"), syscall.UnixRights(int(w.Fd())), nil); err != nil {
		t.Fatal(err)
	}
	w.Close()
	_ = r.SetDeadline(time.Now().Add(3 * time.Second))
	if n, err := r.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("the passed descriptor is still open in the host: %d %v", n, err)
	}
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("the connection went on: %v", err)
	}
}

// What plughost logs about a stream's egress has a fixed shape whatever the plugin does: the first
// dial with its target and outcome, at most one control-data line, and one bucketed count at the
// end. So the number and timing of its lines carry a couple of bits per stream at most.
func TestEgressLoggingIsBoundedPerStream(t *testing.T) {
	for n, bucket := range map[int]string{1: "1", 2: "2-8", 8: "2-8", 9: "more than 8", 500: "more than 8"} {
		var out bytes.Buffer
		lg := &egressLog{plugin: "p", target: "svc.example.invalid:443", w: &out}
		for i := 0; i < n; i++ {
			lg.dial(errors.New("connection refused"))
			lg.controlData()
		}
		lg.summary()
		lines := strings.Split(strings.TrimSpace(out.String()), "\n")
		if len(lines) != 3 || !strings.Contains(lines[0], "first dial") || !strings.Contains(lines[1], "control data") ||
			lines[2] != "plughost: egress p -> svc.example.invalid:443: "+bucket+" dials this stream" {
			t.Errorf("%d dials: %q", n, lines)
		}
	}
	var out bytes.Buffer
	(&egressLog{plugin: "p", target: "t", w: &out}).summary()
	if out.Len() != 0 {
		t.Errorf("a stream without egress logged: %q", out.String())
	}
}
