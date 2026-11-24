//go:build darwin

// jade:ring local
package main

import (
	"context"
	"errors"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDarwinPeerUIDRealConnectedUnixSocket(t *testing.T) {
	directory, err := os.MkdirTemp("/private/tmp", "hc-darwin-peer-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(directory, "peer.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err = listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for _, connection := range []*net.UnixConn{server, client} {
		uid, err := peerUID(connection)
		if err != nil || uid != uint32(os.Geteuid()) {
			t.Fatalf("kernel peer UID=%d error=%v expected fixture euid=%d", uid, err, os.Geteuid())
		}
	}
	// Exercise the existing authorization check with the kernel observation. No
	// Docker/admission executable is configured or invoked by this denied request.
	uid, err := peerUID(server)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", "/v1/execute", strings.NewReader(`{}`))
	request = request.WithContext(context.WithValue(request.Context(), peerKey{}, peer{uid, nil}))
	response := httptest.NewRecorder()
	newBroker(policy{AllowedUIDs: []uint32{uid + 1}}, "").ServeHTTP(response, request)
	if response.Code != 403 || !strings.Contains(response.Body.String(), `"code":"unauthorized_peer"`) {
		t.Fatalf("unassigned kernel UID admitted: %d %s", response.Code, response.Body.String())
	}
	if err = server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = peerUID(server); err == nil {
		t.Fatal("closed connection fell back to broker UID")
	}
}

func TestDarwinPeerUIDRejectsNonUnixAndKernelFailures(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	var nilUnix *net.UnixConn
	for _, connection := range []net.Conn{nil, nilUnix, local} {
		if _, err := peerUID(connection); err == nil {
			t.Fatal("non-Unix connection acquired identity")
		}
	}
	if _, err := darwinPeerUID(^uintptr(0)); !errors.Is(err, syscall.EBADF) {
		t.Fatal("invalid descriptor not refused", err)
	}
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	if _, err = darwinPeerUID(uintptr(fd)); err == nil {
		t.Fatal("unconnected Unix socket acquired peer identity")
	}
	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err = darwinPeerUID(file.Fd()); !errors.Is(err, syscall.ENOTSOCK) {
		t.Fatal("regular descriptor not refused", err)
	}
}

func TestDarwinPeerUIDRejectsMalformedKernelCredential(t *testing.T) {
	for _, c := range []struct {
		value darwinCredential
		size  uint32
	}{
		{darwinCredential{UID: 501, Groups: 1}, 0}, {darwinCredential{UID: 501, Groups: 1}, 75}, {darwinCredential{UID: 501, Groups: 1}, 77},
		{darwinCredential{UID: 501, Groups: 1, Version: 1}, 76}, {darwinCredential{UID: 501, Groups: 0}, 76},
		{darwinCredential{UID: 501, Groups: -1}, 76}, {darwinCredential{UID: 501, Groups: 17}, 76}, {darwinCredential{UID: ^uint32(0), Groups: 1}, 76},
	} {
		if _, err := darwinCredentialUID(c.value, c.size); err == nil {
			t.Fatal("malformed kernel credential accepted")
		}
	}
	// UID zero is a valid kernel identity; the administrator's allowlist decides
	// whether it has access. The lookup itself must not silently remap it.
	for _, uid := range []uint32{0, 501, 65534} {
		got, err := darwinCredentialUID(darwinCredential{UID: uid, Groups: 1}, 76)
		if err != nil || got != uid {
			t.Fatal("UID changed", got, err)
		}
	}
}

func TestDarwinPeerUIDDoesNotEnableProductionStartup(t *testing.T) {
	directory, err := os.MkdirTemp("/private/tmp", "hc-darwin-policy-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	p := policy{Schema: policySchema, ListenSocket: filepath.Join(directory, "broker.sock"), DockerSocket: "/no-docker.sock", Image: "sha256:" + strings.Repeat("0", 64), Workspace: workspace{"peer", filepath.Join(directory, "source")}, Limits: limits{TimeoutSeconds: 1, OutputBytes: 1024, WorkspaceBytes: 1024, WorkspaceFiles: 10}, AllowedUIDs: []uint32{65534}}
	path := filepath.Join(directory, "policy.json")
	if err = os.WriteFile(path, marshal(p), 0600); err != nil {
		t.Fatal(err)
	}
	_, _, err = loadPolicy(path)
	if failure(err).Code != "unsupported_platform" {
		t.Fatal("Darwin production guard changed", err)
	}
}
