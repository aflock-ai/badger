//go:build unix

package egress

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

// fdDialer asks a plugin host for connections over an inherited unix socket: one byte out, and back
// one byte 'K' with a connected descriptor, or 'E' when the host's dial failed. One request at a time.
type fdDialer struct {
	mu sync.Mutex
	c  *net.UnixConn
}

func newFDDialer(fd int) (*fdDialer, error) {
	f := os.NewFile(uintptr(fd), "egress")
	if f == nil {
		return nil, errors.New("not open")
	}
	defer f.Close()
	c, err := net.FileConn(f)
	if err != nil {
		return nil, err
	}
	u, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		return nil, errors.New("not a unix socket")
	}
	return &fdDialer{c: u}, nil
}

func (d *fdDialer) dial(ctx context.Context) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(15 * time.Second)
	}
	_ = d.c.SetDeadline(deadline)
	if _, err := d.c.Write([]byte{'D'}); err != nil {
		return nil, err
	}
	b, oob := make([]byte, 1), make([]byte, syscall.CmsgSpace(4))
	_, oobn, _, _, err := d.c.ReadMsgUnix(b, oob)
	if err != nil {
		return nil, err
	}
	if b[0] != 'K' || oobn == 0 {
		return nil, errors.New("egress: the plugin host could not reach the service")
	}
	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) != 1 {
		return nil, errors.New("egress: malformed answer from the plugin host")
	}
	fds, err := syscall.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) != 1 {
		for _, fd := range fds {
			syscall.Close(fd)
		}
		return nil, errors.New("egress: malformed answer from the plugin host")
	}
	f := os.NewFile(uintptr(fds[0]), "egress-conn")
	defer f.Close()
	return net.FileConn(f)
}
