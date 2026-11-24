//go:build darwin

package main

import (
	"net"
	"os"
	"syscall"
	"unsafe"
)

// Darwin sys/un.h: SOL_LOCAL=0, LOCAL_PEERCRED=1. sys/ucred.h exports
// XUCRED_VERSION=0 and struct xucred with NGROUPS=16 (sys/param.h).
// Keep this ABI narrow and validate the returned size/version. Production
// Darwin startup remains disabled; this lookup alone is not a sandbox boundary.
type darwinCredential struct {
	Version uint32
	UID     uint32
	Groups  int16
	_       uint16
	GroupID [16]uint32
}

func darwinCredentialUID(value darwinCredential, size uint32) (uint32, error) {
	if unsafe.Sizeof(value) != 76 || size != 76 || value.Version != 0 || value.Groups < 1 || value.Groups > 16 || value.UID == ^uint32(0) {
		return 0, deny("unauthorized_peer", "Invalid kernel Unix peer credential")
	}
	return value.UID, nil
}

func darwinPeerUID(fd uintptr) (uint32, error) {
	var value darwinCredential
	size := uint32(unsafe.Sizeof(value))
	// Convert the pointers directly in Syscall6's argument list so the compiler
	// keeps the pointed-to values alive and pinned for the system call.
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, 0, 1,
		uintptr(unsafe.Pointer(&value)), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return 0, errno
	}
	return darwinCredentialUID(value, size)
}

// Read the connected peer's effective UID from the kernel, never from broker
// process identity, request data, environment or a caller-supplied descriptor.
func peerUID(connection net.Conn) (uint32, error) {
	unix, ok := connection.(*net.UnixConn)
	if !ok || unix == nil {
		return 0, deny("unauthorized_peer", "Expected Unix connection")
	}
	raw, err := unix.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var credentialErr error
	// Control holds the descriptor against Go Close/reuse until lookup returns.
	err = raw.Control(func(fd uintptr) { uid, credentialErr = darwinPeerUID(fd) })
	if err != nil {
		return 0, err
	}
	return uid, credentialErr
}

func changeTime(info os.FileInfo) int64 { return info.Sys().(*syscall.Stat_t).Ctimespec.Nano() }
