package main

import (
	"errors"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/aflock-ai/badger/testifysec/connectors/internal/bundle"
)

// soPeerPIDFD (SO_PEERPIDFD, Linux 6.5) returns a pidfd for the process at the far end of a unix
// socket. Unlike SO_PEERCRED's bare pid, a pidfd names one exact process for its whole life, so a
// pid reused after that process exits cannot be mistaken for it.
const soPeerPIDFD = 77

// peerProc is the process that opened a socket: its pid, and live, which reports whether that exact
// process (the pidfd's, not whatever holds the pid now) is still running.
type peerProc struct {
	pid  int
	fd   int
	live func() error
}

func (p peerProc) close() {
	if p.fd > 0 {
		_ = syscall.Close(p.fd)
	}
}

// peer is the uid and gid (SO_PEERCRED) and the process (SO_PEERPIDFD) at the far end of a unix
// socket: the plugin host's, in its own container. The pid is as this process's pid namespace sees
// it, so the pod must share one (shareProcessNamespace). Without SO_PEERPIDFD (before Linux 6.5)
// it fails, rather than trust a reusable pid. The caller closes the returned peerProc.
func peer(c *net.UnixConn) (uid, gid int, p peerProc, err error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, 0, peerProc{}, err
	}
	var cred *syscall.Ucred
	var fd int
	var cerr, ferr error
	if err := raw.Control(func(sfd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(sfd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		fd, ferr = pidfdOf(int(sfd))
	}); err != nil {
		return 0, 0, peerProc{}, err
	}
	if cerr != nil {
		return 0, 0, peerProc{}, cerr
	}
	if ferr != nil {
		return 0, 0, peerProc{}, errors.New("the kernel does not provide the plugin host's process identity (SO_PEERPIDFD needs Linux 6.5 or newer): " + ferr.Error())
	}
	live := func() error { return pidfdAlive(fd) }
	return int(cred.Uid), int(cred.Gid), peerProc{pid: int(cred.Pid), fd: fd, live: live}, nil
}

// pidfdAlive reports whether a pidfd's process is still running. A pidfd becomes readable (POLLIN)
// when its process exits, so poll with no wait says: readable -> exited, not readable -> alive. This
// needs no signal permission, unlike pidfd_send_signal, which returns EPERM across the gateway's and
// the plugin's distinct uids.
func pidfdAlive(fd int) error {
	fds := []pollFd{{fd: int32(fd), events: pollIn}}
	n, err := poll(fds, 0)
	for err == syscall.EINTR {
		n, err = poll(fds, 0)
	}
	if err != nil {
		return errors.New("cannot tell whether the plugin host's process is alive: " + err.Error())
	}
	if n > 0 {
		return errors.New("the plugin host's process has exited; its socket is no longer trusted")
	}
	return nil
}

type pollFd struct {
	fd      int32
	events  int16
	revents int16
}

const pollIn = 0x1

// poll is ppoll with a zero timeout (return at once); ppoll exists on every architecture, poll does
// not. timeout is kept for the one call site's readability and must be 0.
func poll(fds []pollFd, timeout int) (int, error) {
	var ts syscall.Timespec // zero: do not block
	n, _, errno := syscall.Syscall6(syscall.SYS_PPOLL, uintptr(unsafe.Pointer(&fds[0])), uintptr(len(fds)), uintptr(unsafe.Pointer(&ts)), 0, 0, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}

// pidfdOf reads SO_PEERPIDFD from a socket: the far end's pidfd, as a new descriptor this process owns.
func pidfdOf(sfd int) (int, error) {
	return syscall.GetsockoptInt(sfd, syscall.SOL_SOCKET, soPeerPIDFD)
}

// runtimeID is a container runtime's id for a container: 64 hex digits.
var runtimeID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// inContainer checks that the peer process is in the container whose status id is id
// ("<runtime>://<hex>"): the hex must be a whole element of the process's cgroup path, as the
// systemd driver ("cri-containerd-<hex>.scope", "crio-<hex>.scope", "docker-<hex>.scope") or the
// cgroupfs driver ("<hex>") names it. The kernel sets a process's cgroup and a container's non-root
// processes cannot move themselves out of it, so this binds the socket's listener to that exact
// container instance, whatever pod status lags behind. The cgroup is read by pid, but trusted only
// while the peer's pidfd says the process is still the one that opened the socket, before and after
// the read, so a reused pid cannot stand in for it. procRoot is /proc (tests use another).
func inContainer(procRoot string, p peerProc, id string) error {
	_, hex, _ := strings.Cut(id, "://")
	if p.pid <= 0 || !runtimeID.MatchString(hex) {
		return errors.New("the plugin host's process is not visible (the pod must share its process namespace)")
	}
	if err := p.live(); err != nil {
		return err
	}
	b, err := bundle.ReadCapped(filepath.Join(procRoot, strconv.Itoa(p.pid), "cgroup"), 64<<10)
	if err != nil {
		return err
	}
	if err := p.live(); err != nil {
		return err
	}
	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		for _, el := range strings.Split(parts[2], "/") {
			el = strings.TrimSuffix(el, ".scope")
			for _, prefix := range []string{"cri-containerd-", "crio-", "docker-"} {
				el = strings.TrimPrefix(el, prefix)
			}
			if el == hex {
				return nil
			}
		}
	}
	return errors.New("the plugin socket is not answered from the container the pod's status names")
}
