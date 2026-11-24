//go:build unix

package egress

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"syscall"
	"testing"
)

// With EgressFD set, every connection comes from that descriptor's host, whatever host and port the
// base URL names: here the base URL's port has nothing listening, and the request still reaches the
// service the host dials.
func TestAnEgressDescriptorCarriesEveryConnection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "via host") }))
	defer srv.Close()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	hf := os.NewFile(uintptr(fds[0]), "host")
	hc, err := net.FileConn(hf)
	hf.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer hc.Close()
	go func() { // a stand-in plugin host: dial the service, pass the descriptor
		h := hc.(*net.UnixConn)
		b := make([]byte, 1)
		for {
			if _, err := h.Read(b); err != nil {
				return
			}
			up, err := net.Dial("tcp", srv.Listener.Addr().String())
			if err != nil {
				return
			}
			f, _ := up.(*net.TCPConn).File()
			up.Close()
			_, _, _ = h.WriteMsgUnix([]byte{'K'}, syscall.UnixRights(int(f.Fd())), nil)
			f.Close()
		}
	}()
	c, err := New(Config{BaseURL: "http://127.0.0.1:1/api", Token: FileToken(tokenFile(t, sentinel)), InsecureLoopbackHTTP: true, EgressFD: fds[1]})
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Get(context.Background(), "/x", nil)
	if err != nil || string(b) != "via host" {
		t.Fatalf("%q %v", b, err)
	}
}
