//go:build !unix

package egress

import (
	"context"
	"errors"
	"net"
	"runtime"
)

// fdDialer would take connections from a plugin host over an inherited unix socket. Off unix there
// is no plugin host, so a connector told to use one (EgressFD set) refuses to start rather than
// dial on its own.
type fdDialer struct{}

func newFDDialer(int) (*fdDialer, error) {
	return nil, errors.New("egress through a plugin host is unsupported on " + runtime.GOOS)
}

func (*fdDialer) dial(context.Context) (net.Conn, error) {
	return nil, errors.New("egress through a plugin host is unsupported on " + runtime.GOOS)
}
