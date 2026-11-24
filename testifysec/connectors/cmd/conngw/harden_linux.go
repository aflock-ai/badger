package main

import "syscall"

// hardenGateway makes the gateway non-dumpable and sets its core limit to 1, soft and hard (or keeps
// an inherited 0), before
// it reads its profile, keys or tokens: the kernel then takes no core of it (do_coredump skips a
// non-dumpable process, aborts a pipe dump at a limit of 1 and a file dump below a page), so
// neither its secrets nor the stream data it carries can be copied off the node by a crash.
func hardenGateway() error {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0); errno != 0 {
		return errno
	}
	// An inherited hard limit of 0 cannot be raised without CAP_SYS_RESOURCE; it is kept, and the
	// gateway, non-dumpable, takes no core either way.
	var l syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &l); err != nil || l.Max == 0 {
		return err
	}
	return syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 1, Max: 1})
}
