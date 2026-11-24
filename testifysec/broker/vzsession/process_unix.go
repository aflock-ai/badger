//go:build darwin || linux

package vzsession

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type streamResult struct {
	eof      bool
	overflow bool
}
type child struct {
	cmd      *exec.Cmd
	exit     chan error
	stdout   chan streamResult
	stderr   chan streamResult
	out      *os.File
	err      *os.File
	stopOnce sync.Once
	stopped  bool
}

func drain(file *os.File, done chan streamResult) {
	defer file.Close()
	var total int
	var result streamResult
	buf := make([]byte, 4096)
	for {
		n, err := file.Read(buf)
		total += n
		if total > 16384 {
			result.overflow = true
		}
		if err != nil {
			result.eof = err == io.EOF
			done <- result
			return
		}
	}
}

// startGateway starts the gateway with token as its descriptor 3 (providerTokenFd): the only way
// its provider credential reaches it. The caller closes its copy of token afterwards.
func startGateway(ctx context.Context, d *ownedDirectory, token *os.File) (*child, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := d.verify(); err != nil {
		return nil, err
	}
	out, ow, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	serr, ew, err := os.Pipe()
	if err != nil {
		out.Close()
		ow.Close()
		return nil, err
	}
	cmd := gatewayCommand(d.path, token)
	cmd.Stdout = ow
	cmd.Stderr = ew
	c := &child{cmd: cmd, exit: make(chan error, 1), stdout: make(chan streamResult, 1), stderr: make(chan streamResult, 1), out: out, err: serr}
	if err = cmd.Start(); err != nil {
		out.Close()
		ow.Close()
		serr.Close()
		ew.Close()
		return nil, err
	}
	_ = ow.Close()
	_ = ew.Close()
	go drain(out, c.stdout)
	go drain(serr, c.stderr)
	go func() { c.exit <- cmd.Wait() }()
	return c, nil
}

// gatewayCommand is the gateway's command line, environment and descriptors. The token is a
// descriptor only: argv and the environment are fixed and carry no secret.
func gatewayCommand(dir string, token *os.File) *exec.Cmd {
	cmd := exec.Command(filepath.Join(dir, "gateway"), "--config", filepath.Join(dir, "gateway.json"))
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=" + dir, "TMPDIR=" + dir}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.ExtraFiles = []*os.File{token} // descriptor 3 = gatewayTokenFD
	return cmd
}

func (c *child) ready(ctx context.Context, d *ownedDirectory) error {
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case err := <-c.exit:
			c.exit <- err
			return refused("gateway_exit")
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return refused("gateway_start_deadline")
		case <-tick.C:
			info, err := d.root.Lstat("gateway.sock")
			if os.IsNotExist(err) {
				continue
			}
			if err != nil || info.Mode()&os.ModeSocket == 0 {
				return refused("gateway_socket")
			}
			connection, err := net.DialTimeout("unix", filepath.Join(d.path, "gateway.sock"), 100*time.Millisecond)
			if err != nil {
				continue
			}
			_ = connection.Close()
			d.socket = info
			return d.verify()
		}
	}
}

func groupAbsent(pid int) bool { return errors.Is(syscall.Kill(-pid, 0), syscall.ESRCH) }

// stop requires process exit, process-group absence and actual stdout/stderr EOF.
// It does not claim that these facts alone prove a VM stopped.
func (c *child) stop() bool {
	c.stopOnce.Do(func() { c.stopped = c.stopAndDrain() })
	return c.stopped
}

func (c *child) stopAndDrain() bool {
	pid := c.cmd.Process.Pid
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	var exitErr error
	select {
	case exitErr = <-c.exit:
	case <-time.After(6 * time.Second):
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		select {
		case exitErr = <-c.exit:
		case <-time.After(2 * time.Second):
			c.out.Close()
			c.err.Close()
			return false
		}
	}
	if !groupAbsent(pid) {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !groupAbsent(pid) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	stream := func(ch chan streamResult, f *os.File) bool {
		select {
		case r := <-ch:
			return r.eof && !r.overflow
		case <-time.After(time.Second):
			f.Close()
			return false
		}
	}
	out := stream(c.stdout, c.out)
	stderr := stream(c.stderr, c.err)
	return exitErr == nil && groupAbsent(pid) && out && stderr
}
