//go:build linux

package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// When started with this env var, the test binary is only a socket peer: it connects and waits to
// be killed. It lets the liveness test have a real peer process that is not the test itself.
func init() {
	if sock := os.Getenv("CONNGW_PEER_SOCK"); sock != "" {
		if c, err := net.Dial("unix", sock); err == nil {
			defer c.Close()
			time.Sleep(60 * time.Second)
		}
		os.Exit(0)
	}
}

// Over a real socket, pidfdAlive says a running peer is alive and an exited one has exited, with no
// signal permission of its own: it polls the pidfd rather than signalling, so it works across the
// gateway's and plugin's distinct uids (pidfd_send_signal would return EPERM there). The mocked
// liveness in bound_test cannot show this; this exercises the real syscalls.
func TestPidfdLivenessOverARealSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	self, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	child := exec.Command(self)
	child.Env = append(os.Environ(), "CONNGW_PEER_SOCK="+sock)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()

	_ = l.(*net.UnixListener).SetDeadline(time.Now().Add(5 * time.Second))
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _, pr, err := peer(c.(*net.UnixConn))
	if err != nil {
		t.Skipf("SO_PEERPIDFD unavailable on this kernel: %v", err)
	}
	defer pr.close()

	if err := pr.live(); err != nil {
		t.Fatalf("the running peer read as exited: %v", err)
	}
	_ = child.Process.Kill()
	_, _ = child.Process.Wait()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if pr.live() != nil {
			return
		}
	}
	t.Fatal("the exited peer still read as alive")
}
