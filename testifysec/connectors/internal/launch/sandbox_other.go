//go:build !linux

package launch

import (
	"errors"
	"net"
	"os"
	"runtime"
)

const shimFlagName = "--conngw-sandboxed-exec"

// CheckSandbox reports whether plugins can be sandboxed here: only on Linux (Landlock and seccomp).
// Elsewhere the host refuses to start, so no plugin ever runs unsandboxed.
func CheckSandbox() error {
	return errors.New("plugin hosting is unsupported on " + runtime.GOOS + ": plugins run only on Linux, sandboxed")
}

// Shim refuses to run a plugin: it cannot be sandboxed here.
func Shim() {
	if len(os.Args) >= 3 && os.Args[1] == shimFlagName {
		os.Exit(2)
	}
}

func hardenHost() error             { return CheckSandbox() }
func peerUID(net.Conn) (int, error) { return 0, CheckSandbox() }
