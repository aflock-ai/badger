//go:build darwin || linux

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func privateDirectory() (*os.Root, string, func(bool) error, error) {
	// Ignore caller-controlled TMPDIR. The system temp parent must prevent
	// other users from replacing our new owner-only child directory.
	directory, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		return nil, "", nil, err
	}
	parent, err := os.OpenRoot(directory)
	if err != nil {
		return nil, "", nil, err
	}
	info, err := parent.Stat(".")
	if err != nil {
		parent.Close()
		return nil, "", nil, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || !info.IsDir() || info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
		parent.Close()
		return nil, "", nil, errors.New("unsafe system temp directory")
	}
	var nonce [24]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		parent.Close()
		return nil, "", nil, err
	}
	name := "hardened-code-" + hex.EncodeToString(nonce[:])
	if err = parent.Mkdir(name, 0700); err != nil {
		parent.Close()
		return nil, "", nil, err
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		parent.RemoveAll(name)
		parent.Close()
		return nil, "", nil, err
	}
	clean := func(remove bool) error {
		closed := root.Close()
		if !remove {
			return errors.Join(closed, parent.Close())
		}
		return errors.Join(closed, parent.RemoveAll(name), parent.Close())
	}
	info, err = root.Stat(".")
	if err != nil || info.Mode().Perm() != 0700 {
		clean(true)
		return nil, "", nil, errors.New("private directory permission")
	}
	return root, filepath.Join(directory, name), clean, nil
}

func childEnvironment(scratch string) ([]string, error) {
	return []string{"PATH=/usr/bin:/bin", "LANG=C", "TMPDIR=" + scratch, "HOME=" + scratch}, nil
}

func supervise(command *exec.Cmd) (int, bool, error) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return superviseUnix(ctx, command, syscall.Kill, (*exec.Cmd).Wait, 5*time.Second)
}

// Dependencies are explicit for fault tests; no invocation/environment switch
// can replace them in a packaged application.
func superviseUnix(ctx context.Context, command *exec.Cmd, kill func(int, syscall.Signal) error, wait func(*exec.Cmd) error, grace time.Duration) (int, bool, error) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.WaitDelay = grace
	if err := command.Start(); err != nil {
		return 2, true, err
	}
	done := make(chan error, 1)
	go func() { done <- wait(command) }()
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = kill(-command.Process.Pid, syscall.SIGTERM)
		select {
		case err = <-done:
		case <-time.After(grace):
			_ = kill(-command.Process.Pid, syscall.SIGKILL)
			select {
			case err = <-done:
			case <-time.After(grace):
				return 2, false, errors.New("entrypoint did not stop")
			}
		}
	}
	// The fixed trusted entry must not leave helpers behind when it exits.
	if cleanup := kill(-command.Process.Pid, syscall.SIGKILL); cleanup != nil && !errors.Is(cleanup, syscall.ESRCH) {
		return 2, false, cleanup
	}
	// A successful SIGKILL is only a request. Observe the group disappear before
	// deleting bytes a surviving helper could still be using.
	deadline := time.Now().Add(grace)
	for {
		if observed := kill(-command.Process.Pid, 0); errors.Is(observed, syscall.ESRCH) {
			break
		} else if observed != nil && !errors.Is(observed, syscall.EPERM) {
			return 2, false, errors.New("entrypoint group drain unavailable")
		}
		// EPERM is not absence. The group may still be shutting down; keep
		// waiting for ESRCH and retain the payload if observation stays blocked.
		if !time.Now().Before(deadline) {
			return 2, false, errors.New("entrypoint group did not drain")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// WaitDelay forcibly closes retained Go pipe readers; that is not proof of
	// a completed drain. Preserve the payload on any unexplained Wait failure.
	if err != nil {
		if _, exited := err.(*exec.ExitError); !exited {
			return 2, false, err
		}
	}
	if err == nil {
		return 0, true, nil
	}
	if exit, ok := err.(*exec.ExitError); ok {
		if code := exit.ExitCode(); code >= 0 {
			return code, true, nil
		}
		if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return 128 + int(status.Signal()), true, nil
		}
	}
	return 2, false, err
}
