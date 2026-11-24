//go:build !linux

package main

import (
	"errors"
	"net"
)

// peerProc mirrors the Linux type so the non-Linux build compiles.
type peerProc struct {
	pid  int
	fd   int
	live func() error
}

func (peerProc) close() {}

// peer needs SO_PEERCRED and SO_PEERPIDFD (Linux); elsewhere no plugin is reached.
func peer(*net.UnixConn) (int, int, peerProc, error) {
	return 0, 0, peerProc{}, errors.New("connector plugins are reached only on Linux")
}

func inContainer(string, peerProc, string) error {
	return errors.New("connector plugins are reached only on Linux")
}
