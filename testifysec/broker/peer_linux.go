//go:build linux

package main

import (
	"net"
	"os"
	"syscall"
)

func peerUID(connection net.Conn) (uint32, error) {
	unix, ok := connection.(*net.UnixConn)
	if !ok {
		return 0, deny("unauthorized_peer", "Expected Unix connection")
	}
	raw, err := unix.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var credentialErr error
	err = raw.Control(func(fd uintptr) {
		credentials, e := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		credentialErr = e
		if e == nil {
			uid = credentials.Uid
		}
	})
	if err != nil {
		return 0, err
	}
	return uid, credentialErr
}
func changeTime(info os.FileInfo) int64 { return info.Sys().(*syscall.Stat_t).Ctim.Nano() }
