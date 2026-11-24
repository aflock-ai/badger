//go:build !darwin && !linux

package vzbackend

import "os/exec"

func protectCommand(*exec.Cmd)         {}
func finishCommand(*exec.Cmd) error    { return refused("unsupported_platform") }
func hostAttributes(*exec.Cmd)         {}
func signalHost(*exec.Cmd, bool) error { return refused("unsupported_platform") }
