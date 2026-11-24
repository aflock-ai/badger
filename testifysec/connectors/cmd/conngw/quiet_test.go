package main

import (
	"bytes"
	"crypto/tls"
	stdlog "log"
	"log/slog"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

const marker = "leakmarker7f3a"

// A TLS handshake that fails on the caller's ALPN protocol and server name logs one fixed line; the
// caller's names reach neither the pod's log nor the standard logger.
func TestHandshakeErrorsLogNoCallerText(t *testing.T) {
	var logged, std syncBuffer
	stdlog.SetOutput(&std)
	defer stdlog.SetOutput(os.Stderr)
	srv := httptest.NewUnstartedServer(nil)
	srv.Config = server("", &gateway{}, slog.New(slog.NewTextHandler(&logged, nil)), defaultLimits)
	srv.StartTLS()
	defer srv.Close()
	c, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, ServerName: marker + ".example.invalid", NextProtos: []string{marker}})
	if err == nil {
		c.Close()
		t.Fatal("handshake with an unsupported protocol succeeded")
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logged.String(), "tls/http server error") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(logged.String(), "tls/http server error") {
		t.Fatalf("handshake error not routed to the fixed line: %q %q", logged.String(), std.String())
	}
	if strings.Contains(logged.String()+std.String(), marker) {
		t.Fatalf("caller text logged: %q %q", logged.String(), std.String())
	}
}

// syncBuffer is a buffer the server's goroutines and the test can share.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
