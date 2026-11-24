//go:build unix && !linux

package launch

import "syscall"

// cloexecSocketpair creates a unix stream pair close-on-exec; without SOCK_CLOEXEC it holds the
// fork lock across the two steps, so no fork sees the pair inheritable.
func cloexecSocketpair() ([2]int, error) {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err == nil {
		syscall.CloseOnExec(fds[0])
		syscall.CloseOnExec(fds[1])
	}
	return fds, err
}
