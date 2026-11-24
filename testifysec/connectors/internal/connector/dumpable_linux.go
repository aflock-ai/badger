package connector

import "syscall"

// noCoreDumps makes this process non-dumpable before it reads its token. The kernel takes no core
// dump of a non-dumpable process at all, piped collectors included, so a crash (or a seccomp
// SIGSYS) cannot copy the token out of the container. The core limit alone does not stop a piped
// collector, and execve resets dumpability, so only the connector itself can set this. A refusal
// (a seccomp policy that rejects prctl) is an error: Main stops before it reads any credential.
var noCoreDumps = func() error {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0); errno != 0 {
		return errno
	}
	return nil
}
