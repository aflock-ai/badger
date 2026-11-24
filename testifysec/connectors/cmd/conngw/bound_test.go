//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeProc writes /proc/<pid>/cgroup files under a temporary root.
func fakeProc(t *testing.T, cgroups map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for pid, content := range cgroups {
		if err := os.MkdirAll(filepath.Join(root, pid), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, pid, "cgroup"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// alive is a peer whose process is still the one that opened the socket.
func alive(pid int) peerProc { return peerProc{pid: pid, live: func() error { return nil }} }

// The process that answers a plugin socket is bound to a container by its cgroup: the container's
// runtime id must be a whole path element of it, never part of a longer one (systemd and cgroupfs
// drivers, containerd, CRI-O, cgroup v1 and v2), exactly the id pod status names. Another
// container's id, a prefix of it, an invisible pid or an unreadable cgroup is refused.
func TestThePeerIsInTheContainerStatusNames(t *testing.T) {
	id := strings.Repeat("a1", 32)
	other := strings.Repeat("b2", 32)
	proc := fakeProc(t, map[string]string{
		"10": "0::/../cri-containerd-" + id + ".scope\n",
		"11": "0::/kubepods.slice/kubepods-pod1.slice/crio-" + id + ".scope\n",
		"12": "12:memory:/kubepods/besteffort/pod1/" + id + "\n11:pids:/kubepods/besteffort/pod1/" + id + "\n",
		"13": "0::/../cri-containerd-" + other + ".scope\n",
		"14": "0::/../cri-containerd-" + id[:32] + ".scope\n",
		"15": "0::/\n",
		"16": "0::/../cri-containerd-x" + id + ".scope\n",
		"17": "0::/kubepods/pod1/" + id + "-extra/child\n",
		"18": "0::/kubepods/pod1/name-" + id + "\n",
	})
	for _, pid := range []int{10, 11, 12} {
		if err := inContainer(proc, alive(pid), "containerd://"+id); err != nil {
			t.Errorf("pid %d: %v", pid, err)
		}
	}
	for name, c := range map[string]struct {
		pid int
		id  string
	}{
		"another container": {13, "containerd://" + id},
		"prefix only":       {14, "containerd://" + id},
		"own namespace":     {15, "containerd://" + id},
		"inside an element": {16, "containerd://" + id},
		"element prefix":    {17, "containerd://" + id},
		"element suffix":    {18, "containerd://" + id},
		"invisible pid":     {0, "containerd://" + id},
		"no such pid":       {99, "containerd://" + id},
		"malformed id":      {10, "containerd://" + id[:10]},
	} {
		if inContainer(proc, alive(c.pid), c.id) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The peer is bound to the exact process that opened the socket, through its pidfd, not the bare
// pid: the cgroup is trusted only while the pidfd says that process is still alive, both before and
// after it is read. A pid reused by another process in the right container (the original listener
// exited, a child kept the socket) is refused, because its pidfd reports the original gone.
func TestAReusedPIDIsRefused(t *testing.T) {
	id := strings.Repeat("a1", 32)
	proc := fakeProc(t, map[string]string{"10": "0::/../cri-containerd-" + id + ".scope\n"})
	dead := errors.New("the plugin host's process has exited; its socket is no longer trusted")
	for name, live := range map[string]func() error{
		"exited before the cgroup is read": func() error { return dead },
		"exits while the cgroup is read":   flips(dead),
	} {
		if err := inContainer(proc, peerProc{pid: 10, live: live}, "containerd://"+id); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Alive throughout: accepted.
	if err := inContainer(proc, alive(10), "containerd://"+id); err != nil {
		t.Errorf("a live peer in the container was refused: %v", err)
	}
}

// flips returns a liveness check that passes once, then fails: the process exits between the two
// checks inContainer makes.
func flips(err error) func() error {
	first := true
	return func() error {
		if first {
			first = false
			return nil
		}
		return err
	}
}
