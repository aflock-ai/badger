//go:build darwin || linux

package main

import (
	"errors"
	"os"
	"syscall"
	"time"
)

func descriptorFlags(fd uintptr) (uintptr, error) {
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFL, 0)
	if errno != 0 {
		return 0, errno
	}
	return flags, nil
}
func duplicateDescriptor(fd uintptr) (int, bool, error) {
	if fd > uintptr(^uint(0)>>1) {
		return -1, false, errors.New("invalid input descriptor")
	}
	flags, err := descriptorFlags(fd)
	if err != nil {
		return -1, false, err
	}
	descriptor, err := syscall.Dup(int(fd))
	if err != nil {
		return -1, false, err
	}
	syscall.CloseOnExec(descriptor)
	if err = syscall.SetNonblock(descriptor, true); err != nil {
		return -1, false, errors.Join(err, syscall.Close(descriptor))
	}
	return descriptor, flags&syscall.O_NONBLOCK != 0, nil
}
func restoreDescriptor(raw syscall.RawConn, nonblocking bool) error {
	var restoreErr error
	controlErr := raw.Control(func(fd uintptr) {
		if fd > uintptr(^uint(0)>>1) {
			restoreErr = errors.New("invalid input descriptor")
			return
		}
		restoreErr = syscall.SetNonblock(int(fd), nonblocking)
	})
	return errors.Join(controlErr, restoreErr)
}

// Inherited fd0 can be blocking and non-pollable in Go. Closing os.Stdin from
// another goroutine then waits behind Read. Duplicate under RawConn custody,
// enable polling before NewFile, and restore shared flags only after closure.
// Only this diagnostic reads its owned stdin; it does not close the original.
func ownedInput(original *os.File) (*os.File, func() error, error) {
	info, err := original.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() && info.Mode()&(os.ModeNamedPipe|os.ModeSocket) == 0 {
		return nil, nil, errors.New("unsupported input type")
	}
	raw, err := original.SyscallConn()
	if err != nil {
		return nil, nil, err
	}
	descriptor := -1
	nonblocking := false
	var duplicateErr error
	if err = raw.Control(func(fd uintptr) { descriptor, nonblocking, duplicateErr = duplicateDescriptor(fd) }); err != nil {
		return nil, nil, err
	}
	if duplicateErr != nil {
		return nil, nil, duplicateErr
	}
	if descriptor < 0 {
		return nil, nil, errors.New("invalid input descriptor")
	}
	owned := os.NewFile(uintptr(descriptor), "owned-profile-input")
	release := func() error {
		closeErr := owned.Close()
		if errors.Is(closeErr, os.ErrClosed) {
			closeErr = nil
		}
		return errors.Join(closeErr, restoreDescriptor(raw, nonblocking))
	}
	if !info.Mode().IsRegular() {
		if err = owned.SetReadDeadline(time.Time{}); err != nil {
			return nil, nil, errors.Join(err, release())
		}
	}
	return owned, release, nil
}
