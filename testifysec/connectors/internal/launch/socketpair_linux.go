package launch

import "syscall"

// cloexecSocketpair creates a unix stream pair close-on-exec atomically (SOCK_CLOEXEC).
func cloexecSocketpair() ([2]int, error) {
	return syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
}
