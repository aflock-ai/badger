//go:build unix

package launch

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// A plugin's core dump is refused by the kernel itself: the shim sets RLIMIT_CORE to 1, soft and
// hard, and the filter stops the plugin changing it. do_coredump (fs/coredump.c) aborts a pipe dump
// when the limit is 1 (its recursion guard) and skips a file dump below a page (min_coredump). That
// holds for any collector, so the only pattern left to refuse is one that is neither.

// socketCoreKernel is the first kernel that reads a leading @ in core_pattern as a socket collector
// (Linux 6.16, "coredump: add coredump socket"). The limit guard is not shown to cover that path, so
// a socket pattern is refused there; on an older kernel a leading @ is only a file name.
var socketCoreKernel = [2]int{6, 16}

// readCorePattern and readRelease read the node's kernel.core_pattern and kernel.osrelease (neither
// is namespaced: the container sees the node's).
var (
	readCorePattern = func() ([]byte, error) { return os.ReadFile("/proc/sys/kernel/core_pattern") }
	readRelease     = func() ([]byte, error) { return os.ReadFile("/proc/sys/kernel/osrelease") }
	// readCoreHard is this process's hard RLIMIT_CORE, which the plugins it starts inherit.
	readCoreHard = func() (uint64, error) {
		var l syscall.Rlimit
		err := syscall.Getrlimit(syscall.RLIMIT_CORE, &l)
		return uint64(l.Max), err
	}
)

// CheckCores refuses a node whose core dumps could carry a plugin's memory, and so its token, off the
// node. plughost checks it at start and again before every plugin it starts.
func CheckCores() error { return checkCorePattern(readCorePattern, readRelease, readCoreHard) }

// checkCorePattern also covers an inherited hard core limit of 0 (LimitCORE=0), which no unprivileged
// process can raise to 1: the kernel pipes a core whatever a limit of 0, so then a pipe collector is
// refused too, while a file pattern stays safe (a limit of 0 skips the file).
func checkCorePattern(pattern, release func() ([]byte, error), coreHard func() (uint64, error)) error {
	b, err := pattern()
	if err != nil {
		return fmt.Errorf("cannot read kernel.core_pattern (%v); plugins run only where it is known; see the connector deploy notes, \"Preflight\"", err)
	}
	p := strings.TrimRight(string(b), "\n")
	if strings.HasPrefix(p, "|") {
		if hard, err := coreHard(); err != nil || hard == 0 {
			return fmt.Errorf("kernel.core_pattern is %q, a pipe, and the core limit plugins inherit is 0 (or unreadable), which the kernel does not apply to a pipe: give the container a hard core limit of at least 1; see the connector deploy notes, \"Preflight\"", p)
		}
	}
	if !strings.HasPrefix(p, "@") {
		return nil
	}
	if r, err := release(); err == nil && kernelBefore(string(r), socketCoreKernel) {
		return nil
	}
	return fmt.Errorf("kernel.core_pattern is %q, a socket collector, which the core limit is not shown to stop: a core dump of a plugin could carry its token off the node; see the connector deploy notes, \"Preflight\"", p)
}

// kernelBefore reports whether a kernel release ("6.6.157.1-1.azl3") is older than v; an
// unreadable release is not.
func kernelBefore(release string, v [2]int) bool {
	f := strings.FieldsFunc(release, func(r rune) bool { return r < '0' || r > '9' })
	if len(f) < 2 {
		return false
	}
	major, err1 := strconv.Atoi(f[0])
	minor, err2 := strconv.Atoi(f[1])
	return err1 == nil && err2 == nil && (major < v[0] || major == v[0] && minor < v[1])
}
