package main

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// preAuthServer runs the pod's listener (plain TCP; TLS changes nothing here) with short limits.
func preAuthServer(t *testing.T, lim limits) (string, *gateway) {
	t.Helper()
	lv := levels(t)
	g := &gateway{sources: map[string]source{"jira": mustSource(t, "jira", lv[1])}, labels: newLabels(),
		log: slog.New(slog.DiscardHandler), start: (&fake{}).start, maxStreams: 4, maxPerWorkspace: 4, idle: time.Hour,
		review: review{ws: "ns/a"}}
	srv := httptest.NewUnstartedServer(nil)
	srv.Config = server("", g, slog.New(slog.DiscardHandler), lim)
	srv.Start()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String(), g
}

// upgrade opens a valid stream and returns its status, or 0 when the connection was refused.
func upgrade(addr, decl string) int {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return 0
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.WriteString(c, "GET /connectors/jira HTTP/1.1\r\nHost: x\r\nUpgrade: badger-mcp\r\nConnection: Upgrade\r\nAuthorization: Bearer t\r\nBadger-Connector: "+decl+"\r\n\r\n")
	res, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return 0
	}
	return res.StatusCode
}

func declaration(t *testing.T) string {
	return `{"classification":"` + levels(t)[1] + `","writes":false,"flags":{}}`
}

// A request that declares a body it never sends is refused at once, before the body is read, and
// the gateway still serves a valid client.
func TestABodyThatNeverArrivesIsRefusedAtOnce(t *testing.T) {
	addr, _ := preAuthServer(t, limits{header: 5 * time.Second, read: 5 * time.Second, write: 5 * time.Second, idle: 5 * time.Second, preAuth: 16})
	for _, framing := range []string{"Content-Length: 1\r\n", "Transfer-Encoding: chunked\r\n"} {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		start := time.Now()
		_, _ = io.WriteString(c, "GET /connectors/jira HTTP/1.1\r\nHost: x\r\nUpgrade: badger-mcp\r\nAuthorization: Bearer t\r\n"+framing+"\r\n")
		r := bufio.NewReader(c)
		res, err := http.ReadResponse(r, nil)
		if err != nil || res.StatusCode != http.StatusBadRequest || time.Since(start) > time.Second {
			t.Fatalf("%q: %v %v after %v", framing, res, err, time.Since(start))
		}
		_, _ = io.Copy(io.Discard, res.Body)
		if _, err := r.ReadByte(); err != io.EOF {
			t.Fatalf("%q: connection left open: %v", framing, err)
		}
		c.Close()
	}
	if got := upgrade(addr, declaration(t)); got != http.StatusSwitchingProtocols {
		t.Fatalf("valid client after slow bodies: %d", got)
	}
}

// Idle connections that never finish their headers cannot shut out a valid client: past the cap a
// new connection is closed at once, and each idle one is closed at the header timeout.
func TestIdleHalfOpenConnectionsCannotExhaustTheGateway(t *testing.T) {
	addr, _ := preAuthServer(t, limits{header: 200 * time.Millisecond, read: 300 * time.Millisecond, write: time.Second, idle: time.Second, preAuth: 4})
	var idle []net.Conn
	defer func() {
		for _, c := range idle {
			c.Close()
		}
	}()
	for range 20 {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(c, "GET /connectors/jira HTTP/1.1\r\n") // never finished
		idle = append(idle, c)
	}
	// Those past the cap are closed at once: well before the header timeout, checked all together.
	var closed atomic.Int32
	var wg sync.WaitGroup
	until := time.Now().Add(100 * time.Millisecond)
	for _, c := range idle {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = c.SetReadDeadline(until)
			if _, err := c.Read(make([]byte, 1)); err == io.EOF || (err != nil && !strings.Contains(err.Error(), "timeout")) {
				closed.Add(1)
			}
		}()
	}
	wg.Wait()
	if closed.Load() < 16 {
		t.Fatalf("%d of 20 idle connections closed at once, want at least 16", closed.Load())
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if upgrade(addr, declaration(t)) == http.StatusSwitchingProtocols {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("a valid client was never served while idle connections were held open")
}

// An admin request that declares a body it never sends is answered at once and its connection
// closed, whether the admin API is off, the caller is not an administrator, or the administrator's
// body is late (bounded by the admin read limit); the gateway still serves a valid client.
func TestAnAdminBodyThatNeverArrivesIsRefusedAtOnce(t *testing.T) {
	floor := parsed(t, levels(t)[0])
	for _, tc := range []struct {
		name    string
		on      bool
		adminID string
		within  time.Duration
		status  int
	}{
		{"admin API off", false, "", time.Second, http.StatusNotFound},
		{"not an administrator", true, "", time.Second, http.StatusForbidden},
		{"administrator, body late", true, "ctl/controller", 2 * time.Second, http.StatusBadRequest},
	} {
		for _, framing := range []string{"Content-Length: 1\r\n", "Transfer-Encoding: chunked\r\n"} {
			addr, g := preAuthServer(t, limits{header: 5 * time.Second, read: 5 * time.Second, write: 5 * time.Second, idle: 5 * time.Second, preAuth: 16})
			g.review = review{ws: "ns/a", adminID: tc.adminID}
			g.adminRead = 500 * time.Millisecond
			if tc.on {
				g.floor, g.namespaces = &floor, []string{"ns"}
			}
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			_ = c.SetDeadline(time.Now().Add(4 * time.Second))
			start := time.Now()
			_, _ = io.WriteString(c, "POST /admin/register HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer t\r\n"+framing+"\r\n")
			r := bufio.NewReader(c)
			res, err := http.ReadResponse(r, nil)
			if err != nil || res.StatusCode != tc.status {
				t.Fatalf("%s %q: %v %v", tc.name, framing, res, err)
			}
			_, _ = io.Copy(io.Discard, res.Body)
			if _, err := r.ReadByte(); err != io.EOF || time.Since(start) > tc.within {
				t.Fatalf("%s %q: connection not closed at once: %v after %v", tc.name, framing, err, time.Since(start))
			}
			c.Close()
			if got := upgrade(addr, declaration(t)); got != http.StatusSwitchingProtocols {
				t.Fatalf("%s: valid client after a slow admin body: %d", tc.name, got)
			}
		}
	}
}

// The send-up routes are held to the same rule: a declared body that never arrives is answered
// and its connection closed at once (send-up off, a caller that is not a workspace), or at the
// read limit for a workspace's late body.
func TestASendUpBodyThatNeverArrivesIsRefusedAtOnce(t *testing.T) {
	for _, tc := range []struct {
		name   string
		on     bool
		ws     string
		within time.Duration
		status int
	}{
		{"send-up off", false, "ns/a", time.Second, http.StatusNotFound},
		{"not a workspace", true, "", time.Second, http.StatusForbidden},
		{"workspace, body late", true, "ns/a", 2 * time.Second, http.StatusBadRequest},
	} {
		for _, framing := range []string{"Content-Length: 1\r\n", "Transfer-Encoding: chunked\r\n"} {
			addr, g := preAuthServer(t, limits{header: 5 * time.Second, read: 5 * time.Second, write: 5 * time.Second, idle: 5 * time.Second, preAuth: 16})
			g.review = review{ws: tc.ws, err: map[bool]error{true: errNotWorkspace}[tc.ws == ""]}
			g.adminRead = 500 * time.Millisecond
			if tc.on {
				in, err := openInbox(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				g.inbox, g.namespaces = in, []string{"ns"}
			}
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			_ = c.SetDeadline(time.Now().Add(4 * time.Second))
			start := time.Now()
			_, _ = io.WriteString(c, "POST /sendup HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer t\r\n"+framing+"\r\n")
			r := bufio.NewReader(c)
			res, err := http.ReadResponse(r, nil)
			if err != nil || res.StatusCode != tc.status {
				t.Fatalf("%s %q: %v %v", tc.name, framing, res, err)
			}
			_, _ = io.Copy(io.Discard, res.Body)
			if _, err := r.ReadByte(); err != io.EOF || time.Since(start) > tc.within {
				t.Fatalf("%s %q: connection not closed at once: %v after %v", tc.name, framing, err, time.Since(start))
			}
			c.Close()
			g.review = review{ws: "ns/a"}
			if got := upgrade(addr, declaration(t)); got != http.StatusSwitchingProtocols {
				t.Fatalf("%s: valid client after a slow send-up body: %d", tc.name, got)
			}
		}
	}
}
