//go:build unix

package launch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"sync"
	"syscall"
	"time"
)

// EgressFDEnv names the one variable a plugin's environment holds: the descriptor (egressFD) of its
// only way out. The plugin has no network of its own (its filter kills socket and connect), so for
// each connection to its service it sends one byte on that descriptor, and the host answers with a
// unix socket it splices to a TCP connection it dialled to the profile's base URL host and port, and
// nowhere else, passed back as a descriptor. TLS stays inside the plugin, end to end.
const (
	EgressFDEnv = "BADGER_EGRESS_FD"
	egressFD    = 3 // the first of exec.Cmd.ExtraFiles
)

// egressTarget is the host:port of a profile base URL: the only place a plugin's traffic goes.
func egressTarget(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Hostname() == "" {
		return "", errors.New("egress: the base URL names no host")
	}
	port := u.Port()
	switch {
	case port != "":
	case u.Scheme == "https":
		port = "443"
	case u.Scheme == "http":
		port = "80"
	default:
		return "", fmt.Errorf("egress: base URL scheme %q", u.Scheme)
	}
	return net.JoinHostPort(u.Hostname(), port), nil
}

// egressPair is a connected pair of unix stream sockets: the host's end, and the plugin's, which it
// inherits as egressFD.
func egressPair() (*net.UnixConn, *os.File, error) {
	// Close-on-exec from the start (exec.Cmd.ExtraFiles still hands the plugin's end on as fd 3), so
	// another stream's plugin starting at the same moment can never inherit this pair.
	fds, err := cloexecSocketpair()
	if err != nil {
		return nil, nil, err
	}
	hf := os.NewFile(uintptr(fds[0]), "egress")
	defer hf.Close()
	c, err := net.FileConn(hf)
	if err != nil {
		syscall.Close(fds[1])
		return nil, nil, err
	}
	return c.(*net.UnixConn), os.NewFile(uintptr(fds[1]), "egress-plugin"), nil
}

// egressDial dials the target; tests replace it.
var egressDial = func(ctx context.Context, target string) (net.Conn, error) {
	return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", target)
}

// MaxEgress bounds one stream's open connections through its egress descriptor; a request beyond
// it is answered 'E', so a plugin cannot spend the host's descriptors.
const MaxEgress = 8

// serveEgress answers each byte the plugin sends on c with a connection to target, and only there:
// the host dials target and passes the plugin one end of a fresh unix socket pair whose other end it
// splices to that TCP connection (or one byte 'E' when the dial fails or MaxEgress are open). The
// plugin never holds an inet socket, so it cannot re-aim one (connect(AF_UNSPEC), shutdown plus
// MSG_FASTOPEN); the host sees only the plugin's TLS. Requests are served one at a time, so at most
// one dial is in flight. Cancelling ctx (the stream's teardown) ends every dial and connection;
// closing c ends the loop.
func serveEgress(ctx context.Context, c *net.UnixConn, target, plugin string) {
	lg := &egressLog{plugin: plugin, target: target, w: os.Stderr}
	defer lg.summary()
	open := make(chan struct{}, MaxEgress)
	refuse := func() bool { _, err := c.Write([]byte{'E'}); return err == nil }
	b, oob := make([]byte, 1), make([]byte, 256)
	for {
		n, oobn, _, _, err := c.ReadMsgUnix(b, oob)
		if oobn > 0 {
			// Nothing but the request byte is accepted: a descriptor the plugin passes is closed
			// unread, credentials are dropped, and the stream's egress ends.
			dropRights(oob[:oobn])
			lg.controlData()
			return
		}
		if err != nil || n != 1 || b[0] != 'D' {
			return
		}
		select {
		case open <- struct{}{}:
		default:
			if !refuse() {
				return
			}
			continue
		}
		up, err := egressDial(ctx, target)
		lg.dial(err)
		if err != nil {
			<-open
			if !refuse() {
				return
			}
			continue
		}
		mine, theirs, err := egressPair()
		if err != nil {
			up.Close()
			<-open
			return
		}
		_, _, err = c.WriteMsgUnix([]byte{'K'}, syscall.UnixRights(int(theirs.Fd())), nil)
		theirs.Close()
		if err != nil {
			mine.Close()
			up.Close()
			<-open
			return
		}
		go func() {
			defer func() { <-open }()
			defer mine.Close()
			defer up.Close()
			stop := context.AfterFunc(ctx, func() { mine.Close(); up.Close() })
			defer stop()
			done := make(chan struct{}, 2)
			go func() { fromPlugin(up, mine, lg); done <- struct{}{} }()
			go func() { _, _ = io.Copy(mine, up); done <- struct{}{} }()
			<-done
		}()
	}
}

// fromPlugin copies the plugin's bytes to its service until either side ends. Ancillary data on a
// data connection (a descriptor, credentials) is never accepted: what arrives is closed unread, and
// the connection ends.
func fromPlugin(up net.Conn, mine *net.UnixConn, lg *egressLog) {
	b, oob := make([]byte, 32<<10), make([]byte, 256)
	for {
		n, oobn, _, _, err := mine.ReadMsgUnix(b, oob)
		if oobn > 0 {
			dropRights(oob[:oobn])
			lg.controlData()
			return
		}
		if n > 0 {
			if _, werr := up.Write(b[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// dropRights closes every descriptor in a control message, unread.
func dropRights(oob []byte) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return
	}
	for i := range msgs {
		if fds, err := syscall.ParseUnixRights(&msgs[i]); err == nil {
			for _, fd := range fds {
				syscall.Close(fd)
			}
		}
	}
}

// egressLog bounds what plughost logs about one stream's egress, since how many lines it writes and
// when is the plugin's choice: the first dial (target, time, outcome), at most one line about
// control data, and at the end one line with the number of dials in a bucket (1, 2-8, more than 8).
// Security monitoring still sees that a plugin dialled and roughly how much; the plugin's signal in
// the log is a couple of bits per stream.
type egressLog struct {
	plugin, target string
	w              io.Writer
	mu             sync.Mutex
	dials          int
	dropped        bool
}

func (e *egressLog) dial(err error) {
	e.mu.Lock()
	e.dials++
	first := e.dials == 1
	e.mu.Unlock()
	if first {
		outcome := "connected"
		if err != nil {
			outcome = err.Error()
		}
		fmt.Fprintf(e.w, "plughost: egress %s -> %s at %s: %s (first dial of this stream; later ones are counted at its end)\n",
			e.plugin, e.target, time.Now().UTC().Format(time.RFC3339), outcome)
	}
}

func (e *egressLog) controlData() {
	e.mu.Lock()
	once := !e.dropped
	e.dropped = true
	e.mu.Unlock()
	if once {
		fmt.Fprintf(e.w, "plughost: egress %s: the plugin sent control data; dropped, and the connection closed\n", e.plugin)
	}
}

func (e *egressLog) summary() {
	e.mu.Lock()
	n := e.dials
	e.mu.Unlock()
	if n == 0 {
		return
	}
	bucket := "1"
	switch {
	case n > MaxEgress:
		bucket = "more than 8"
	case n > 1:
		bucket = "2-8"
	}
	fmt.Fprintf(e.w, "plughost: egress %s -> %s: %s dials this stream\n", e.plugin, e.target, bucket)
}
