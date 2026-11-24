package launch

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// Landlock (include/uapi/linux/landlock.h); syscall does not name it. The numbers are the same on
// every architecture.
const (
	sysCreateRuleset = 444
	sysAddRule       = 445
	sysRestrictSelf  = 446
	rulesetVersion   = 1 // LANDLOCK_CREATE_RULESET_VERSION
	rulePathBeneath  = 1
	prSetNoNewPrivs  = 38
	prSetDumpable    = 4

	fsExecute    = 1 << 0
	fsWriteFile  = 1 << 1
	fsReadFile   = 1 << 2
	fsReadDir    = 1 << 3
	fsTruncate   = 1 << 14                                                                       // ABI 3
	fsRefer      = 1 << 13                                                                       // ABI 2
	fsWriteABI1  = fsWriteFile | 1<<4 | 1<<5 | 1<<6 | 1<<7 | 1<<8 | 1<<9 | 1<<10 | 1<<11 | 1<<12 // write, remove, make any kind
	oPath        = 0x200000
	shimFlagName = "--conngw-sandboxed-exec"
)

// abi is the kernel's Landlock ABI, or the error that says why there is none (tests replace it).
var abi = landlockABI

func landlockABI() (int, syscall.Errno) {
	v, _, errno := syscall.RawSyscall(sysCreateRuleset, 0, 0, rulesetVersion)
	if errno != 0 {
		return 0, errno
	}
	return int(v), 0
}

// peerUID is the uid of the process at the other end of a unix connection (SO_PEERCRED).
func peerUID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if serr != nil {
		return 0, serr
	}
	return int(cred.Uid), nil
}

// CheckSandbox reports whether plugins can be sandboxed here, naming the cause when not: Landlock
// ABI 3 (Linux 6.2), the first that can refuse truncate.
func CheckSandbox() error {
	v, errno := abi()
	if v < 1 {
		return errors.New("landlock not available on this node: " + landlockReason(errno))
	}
	if v < 3 {
		return fmt.Errorf("landlock not available on this node: the kernel's Landlock is ABI %d; plugins need ABI 3 (Linux 6.2 or newer), the first that can refuse truncate", v)
	}
	return nil
}

// landlockReason is why landlock_create_ruleset failed, in an operator's words.
func landlockReason(errno syscall.Errno) string {
	switch errno {
	case syscall.EOPNOTSUPP:
		return "the kernel has Landlock but it is not enabled (add landlock to the lsm= boot list; see /sys/kernel/security/lsm)"
	case syscall.ENOSYS:
		return "the kernel has no Landlock, or the container's seccomp profile blocks landlock_create_ruleset"
	case syscall.EPERM:
		return "the container's seccomp profile refuses landlock_create_ruleset"
	}
	return "landlock_create_ruleset failed: " + errno.Error()
}

// ruleset is the filesystem rights the sandbox handles (all refused) and the ones it allows on
// /dev/null. Every one is from Landlock ABI 3 or earlier, so a newer kernel enforces exactly what a
// 6.2-6.6 kernel does. Execute is handled too: the plugin may run only its own verified copy.
func ruleset() (handled, allowed uint64) {
	return fsExecute | fsWriteABI1 | fsRefer | fsTruncate | fsReadFile | fsReadDir, fsWriteFile | fsTruncate
}

// readable is where the plugin may read: beneath every top-level entry of its container's root
// except /proc, and its own /proc/<pid> (so /proc/self and its threads' /proc/self/task/<tid>).
// Every other process's /proc files (cmdline, comm, environ, the gateway's or another plugin's in
// the pod's shared pid namespace) are refused, so no plugin reads what another writes into its own
// argv or name. Listing / itself is refused too (a rule on / would cover /proc). Each hidden
// directory, and everything beneath it, is left out: an entry that holds one is replaced by rules
// for its other children, down to the hidden one. Paths are compared resolved, as Landlock sees
// them.
func readable(hidden []string) ([]string, error) {
	var hide []string
	for _, h := range hidden {
		r, err := filepath.EvalSymlinks(h)
		if err != nil {
			return nil, err
		}
		hide = append(hide, r)
	}
	under := func(p, dir string) bool { return p == dir || strings.HasPrefix(p, dir+"/") }
	var paths []string
	seen := map[string]bool{}
	var visit func(dir string) error
	visit = func(dir string) error {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			p := filepath.Join(dir, e.Name())
			r, err := filepath.EvalSymlinks(p)
			if err != nil || r == "/" || under(r, "/proc") || seen[r] {
				continue // /proc itself, a link into it or to /, a dangling link, or seen already
			}
			seen[r] = true
			holds, hidden := false, false
			for _, h := range hide {
				hidden = hidden || under(r, h)
				holds = holds || under(h, r)
			}
			switch {
			case hidden:
			case holds:
				if err := visit(r); err != nil {
					return err
				}
			default:
				paths = append(paths, p)
			}
		}
		return nil
	}
	if err := visit("/"); err != nil {
		return nil, err
	}
	return append(paths, "/proc/"+strconv.Itoa(os.Getpid())), nil
}

// sandboxedExec replaces this process with the plugin, after taking away every way to write the
// filesystem except /dev/null and every read of another process's /proc (Landlock), setting a core limit of 0 and applying the seccomp filter.
// It never returns on success.
func sandboxedExec(path string, argv []string) error {
	runtime.LockOSThread() // the Landlock domain is the calling thread's, and execve keeps only it
	if err := CheckSandbox(); err != nil {
		return err
	}
	handled, allowed := ruleset()
	if _, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); errno != 0 {
		return errno
	}
	attr := handled
	rs, _, errno := syscall.RawSyscall(sysCreateRuleset, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return errno
	}
	null, err := syscall.Open("/dev/null", oPath|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	// struct landlock_path_beneath_attr is packed: u64 allowed_access, s32 parent_fd.
	var rule [12]byte
	*(*uint64)(unsafe.Pointer(&rule[0])) = allowed
	*(*int32)(unsafe.Pointer(&rule[8])) = int32(null)
	if _, _, errno := syscall.RawSyscall6(sysAddRule, rs, rulePathBeneath, uintptr(unsafe.Pointer(&rule[0])), 0, 0, 0); errno != 0 {
		return errno
	}
	var hidden []string
	if v := os.Getenv(HideEnv); v != "" {
		hidden = strings.Split(v, ":")
	}
	paths, err := readable(hidden)
	if err != nil {
		return err
	}
	// Single files it may read in otherwise hidden directories: its own stream's token snapshot and,
	// when the profile names one, its CA file (checked by the host: certificates only).
	if v := os.Getenv(ReadEnv); v != "" {
		for _, f := range strings.Split(v, ":") {
			fd, err := syscall.Open(f, oPath|syscall.O_CLOEXEC, 0)
			if err != nil {
				return err
			}
			*(*uint64)(unsafe.Pointer(&rule[0])) = fsReadFile
			*(*int32)(unsafe.Pointer(&rule[8])) = int32(fd)
			_, _, errno := syscall.RawSyscall6(sysAddRule, rs, rulePathBeneath, uintptr(unsafe.Pointer(&rule[0])), 0, 0, 0)
			syscall.Close(fd)
			if errno != 0 {
				return errno
			}
		}
	}
	// The one file it may run: its own verified copy (and so re-run it, as the runtime may).
	exe, err := syscall.Open(path, oPath|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	*(*uint64)(unsafe.Pointer(&rule[0])) = fsExecute | fsReadFile
	*(*int32)(unsafe.Pointer(&rule[8])) = int32(exe)
	_, _, errno = syscall.RawSyscall6(sysAddRule, rs, rulePathBeneath, uintptr(unsafe.Pointer(&rule[0])), 0, 0, 0)
	syscall.Close(exe)
	if errno != 0 {
		return errno
	}
	for _, p := range paths {
		fd, err := syscall.Open(p, oPath|syscall.O_CLOEXEC, 0)
		if err != nil {
			continue // gone since it was listed
		}
		var st syscall.Stat_t
		read := uint64(fsReadFile)
		if syscall.Fstat(fd, &st) == nil && st.Mode&syscall.S_IFMT == syscall.S_IFDIR {
			read |= fsReadDir
		}
		*(*uint64)(unsafe.Pointer(&rule[0])) = read
		*(*int32)(unsafe.Pointer(&rule[8])) = int32(fd)
		_, _, errno := syscall.RawSyscall6(sysAddRule, rs, rulePathBeneath, uintptr(unsafe.Pointer(&rule[0])), 0, 0, 0)
		syscall.Close(fd)
		if errno != 0 {
			return errno
		}
	}
	if _, _, errno := syscall.RawSyscall(sysRestrictSelf, rs, 0, 0); errno != 0 {
		return errno
	}
	// RLIMIT_CORE 1, soft and hard, so the kernel refuses every core dump of the plugin: do_coredump
	// aborts a pipe dump at a limit of 1 and skips a file dump below a page (see corepattern.go). It
	// survives execve, unlike dumpability; the filter stops the plugin changing it.
	if err := coreLimitOne(); err != nil {
		return err
	}
	if err := installFilter(); err != nil {
		return err
	}
	env := []string{} // the plugin's environment holds only its egress descriptor
	if v, ok := os.LookupEnv(EgressFDEnv); ok {
		env = append(env, EgressFDEnv+"="+v)
	}
	return syscall.Exec(path, argv, env)
}

// Shim runs the plugin sandboxed when this process was started as the shim (Serve starts the host's
// own executable that way): call it first thing in main, and in a TestMain that serves plugins. It
// returns at once otherwise.
func Shim() {
	if len(os.Args) < 3 || os.Args[1] != shimFlagName {
		return
	}
	_ = sandboxedExec(os.Args[2], os.Args[2:])
	os.Exit(2) // the plugin did not start; nothing runs unsandboxed
}

// hardenHost makes the host non-dumpable, so no process of its uid (a plugin) may ptrace it or open
// its /proc files (mem, environ, fd) without CAP_SYS_PTRACE, which none has, and so the kernel takes
// no core of it: stream data (connector responses) passes through it. RLIMIT_CORE 1, soft and hard,
// refuses a core too (see corepattern.go), and the shim it starts inherits it.
func hardenHost() error {
	if _, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, prSetDumpable, 0, 0, 0, 0, 0); errno != 0 {
		return errno
	}
	return coreLimitOne()
}

// coreLimitOne sets RLIMIT_CORE to 1, soft and hard. An inherited hard limit of 0 cannot be raised
// without CAP_SYS_RESOURCE, so it is kept: a non-dumpable host takes no core anyway, and CheckCores
// refuses a pipe collector when plugins would inherit 0.
func coreLimitOne() error {
	var l syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &l); err != nil {
		return err
	}
	if l.Max == 0 {
		return nil
	}
	return syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 1, Max: 1})
}
