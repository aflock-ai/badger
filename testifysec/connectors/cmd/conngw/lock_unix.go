//go:build unix

package main

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive, non-blocking lock on f for as long as f stays open.
func lockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) }
