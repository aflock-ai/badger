//go:build darwin || linux

package vzbackend

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func protectCommand(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return nil
		}
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
}

func hostAttributes(command *exec.Cmd) { command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
func signalHost(command *exec.Cmd, force bool) error {
	if command.Process == nil {
		return nil
	}
	signal := syscall.SIGTERM
	if force {
		signal = syscall.SIGKILL
	}
	err := syscall.Kill(-command.Process.Pid, signal)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}

// The pinned verifier is trusted not to escape its process group. Require
// observed group absence, including descendants which close inherited pipes.
// This is a trusted-child lifecycle check, not untrusted-process isolation.
func finishCommand(command *exec.Cmd) error {
	if command.Process == nil {
		return nil
	}
	return finishGroup(command.Process.Pid, 2*time.Second)
}

// signalGroup is kill(2) on a process group; tests replace it to drive each errno.
var signalGroup = func(group int, signal syscall.Signal) error { return syscall.Kill(-group, signal) }

// onlyZombies reports, from the kernel's process table, whether every member of the group has
// exited or is already exiting (an unreaped zombie, or P_WEXIT set). Tests replace it.
var onlyZombies = zombieGroup

// finishGroup requires the group to be gone. Darwin answers EPERM, not ESRCH, when a group's only
// members are exiting or unreaped zombies (a descendant reparented after the leader was waited
// for; observed under load as head with P_WEXIT set). EPERM also means a live member this user may
// not signal, so it is accepted only while the process table shows exiting members alone;
// anything else fails cleanup. A live, signalable member is killed and
// reported as a descendant.
func finishGroup(group int, limit time.Duration) error {
	err := signalGroup(group, 0)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	exited := errors.Is(err, syscall.EPERM)
	if exited && !onlyZombies(group) || err != nil && !exited {
		return errCleanup
	}
	if !exited {
		if err := signalGroup(group, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return errCleanup
		}
	}
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		err := signalGroup(group, 0)
		switch {
		case errors.Is(err, syscall.ESRCH):
			if exited {
				return nil
			}
			return refused("admission_descendants")
		case err == nil && exited:
			// A member answered after all: it was live, not only zombies. Kill it and report it.
			exited = false
			if err := signalGroup(group, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
				return errCleanup
			}
		case errors.Is(err, syscall.EPERM) && !onlyZombies(group):
			return errCleanup
		case err != nil && !errors.Is(err, syscall.EPERM):
			return errCleanup
		}
		time.Sleep(10 * time.Millisecond)
	}
	return errCleanup
}
