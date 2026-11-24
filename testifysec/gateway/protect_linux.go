package main

import "syscall"

// protectMemory marks the process not dumpable: same-uid processes cannot ptrace it or read
// /proc/<pid>/mem, environ or maps, and it writes no core file.
func protectMemory() error {
	_, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func dumpable() bool {
	r, _, _ := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0)
	return r != 0
}
