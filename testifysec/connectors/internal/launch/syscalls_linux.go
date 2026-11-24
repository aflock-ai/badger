package launch

// The default-deny allow-list, by syscall name, and each architecture's number for it. The names
// are every syscall the Go runtime, the connector SDK (net/http over TLS, the MCP stdio loop) and
// the shim's own work make, found by running the connectors and the end-to-end plugin under the
// filter until none is denied. clone, clone3, tgkill, prlimit64, fcntl and prctl are not here: the
// filter gives them argument rules of their own. bind, listen, ioctl and the signal and xattr calls are not
// here on purpose, so a plugin cannot squat the pod's network, run another program, aim SIGIO at
// the host, or shut the gateway out of the socket.
//
// A name need not exist on both architectures: open and poll are amd64-only, and the arm64 table
// simply omits them (TestEveryAllowedNameResolves checks that each name is on at least one). A
// wrong number is caught by the runtime validation, amd64 on an x86 worker and arm64 on the twin.
var allowNames = []string{
	// core runtime and scheduling
	"rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "rt_sigtimedwait", "sigaltstack",
	"nanosleep", "clock_gettime", "clock_nanosleep", "gettimeofday",
	"futex", "futex_waitv", "sched_yield", "sched_getaffinity",
	"getpid", "getppid", "gettid", "getrandom", "uname", "getcpu",
	"arch_prctl", "set_robust_list", "set_tid_address", "rseq", "membarrier", "restart_syscall",
	"exit", "exit_group", "execve",
	// memory
	"mmap", "munmap", "mprotect", "madvise", "mremap", "brk",
	// files and polling
	"read", "write", "readv", "writev", "pread64", "pwrite64", "lseek",
	"open", "openat", "close", "fstat", "newfstatat", "statx",
	"getdents64", "dup", "dup2", "dup3", "pipe2", "readlink", "readlinkat",
	"poll", "ppoll", "epoll_create1", "epoll_ctl", "epoll_pwait", "epoll_pwait2", "eventfd2",
	// sockets: only those the host passes (no socket, socketpair, connect, bind, listen or accept:
	// the plugin has no socket API and no network of its own; see EgressFDEnv)
	"getsockname", "getpeername", "getsockopt", "setsockopt",
	"sendto", "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg", "shutdown",
}

// number is each name's syscall number per architecture. A name absent from an architecture's map
// does not exist there.
var number = map[string]map[string]uint32{
	"amd64": {
		"rt_sigaction": 13, "rt_sigprocmask": 14, "rt_sigreturn": 15, "rt_sigtimedwait": 128, "sigaltstack": 131,
		"nanosleep": 35, "clock_gettime": 228, "clock_nanosleep": 230, "gettimeofday": 96,
		"futex": 202, "futex_waitv": 449, "sched_yield": 24, "sched_getaffinity": 204,
		"getpid": 39, "getppid": 110, "gettid": 186, "getrandom": 318, "uname": 63, "getcpu": 309,
		"arch_prctl": 158, "prctl": 157, "set_robust_list": 273, "set_tid_address": 218, "rseq": 334, "membarrier": 324, "restart_syscall": 219,
		"exit": 60, "exit_group": 231, "execve": 59,
		"mmap": 9, "munmap": 11, "mprotect": 10, "madvise": 28, "mremap": 25, "brk": 12,
		"read": 0, "write": 1, "readv": 19, "writev": 20, "pread64": 17, "pwrite64": 18, "lseek": 8,
		"open": 2, "openat": 257, "close": 3, "fstat": 5, "newfstatat": 262, "statx": 332, "fsync": 74, "ftruncate": 77,
		"fcntl": 72, "getdents64": 217, "dup": 32, "dup2": 33, "dup3": 292, "pipe2": 293, "readlink": 89, "readlinkat": 267,
		"poll": 7, "ppoll": 271, "epoll_create1": 291, "epoll_ctl": 233, "epoll_pwait": 281, "epoll_pwait2": 441, "eventfd2": 290,
		"socket": 41, "connect": 42, "getsockname": 51, "getpeername": 52, "getsockopt": 55, "setsockopt": 54,
		"sendto": 44, "recvfrom": 45, "sendmsg": 46, "recvmsg": 47, "sendmmsg": 307, "recvmmsg": 299, "shutdown": 48,
	},
	"arm64": {
		"rt_sigaction": 134, "rt_sigprocmask": 135, "rt_sigreturn": 139, "rt_sigtimedwait": 137, "sigaltstack": 132,
		"nanosleep": 101, "clock_gettime": 113, "clock_nanosleep": 115, "gettimeofday": 169,
		"futex": 98, "futex_waitv": 449, "sched_yield": 124, "sched_getaffinity": 123,
		"getpid": 172, "getppid": 173, "gettid": 178, "getrandom": 278, "uname": 160, "getcpu": 168,
		"prctl": 167, "set_robust_list": 99, "set_tid_address": 96, "rseq": 293, "membarrier": 283, "restart_syscall": 128,
		"exit": 93, "exit_group": 94, "execve": 221,
		"mmap": 222, "munmap": 215, "mprotect": 226, "madvise": 233, "mremap": 216, "brk": 214,
		"read": 63, "write": 64, "readv": 65, "writev": 66, "pread64": 67, "pwrite64": 68, "lseek": 62,
		"openat": 56, "close": 57, "fstat": 80, "newfstatat": 79, "statx": 291, "fsync": 82, "ftruncate": 46,
		"fcntl": 25, "getdents64": 61, "dup": 23, "dup3": 24, "pipe2": 59, "readlinkat": 78,
		"ppoll": 73, "epoll_create1": 20, "epoll_ctl": 21, "epoll_pwait": 22, "epoll_pwait2": 441, "eventfd2": 19,
		"socket": 198, "connect": 203, "getsockname": 204, "getpeername": 205, "getsockopt": 209, "setsockopt": 208,
		"sendto": 206, "recvfrom": 207, "sendmsg": 211, "recvmsg": 212, "sendmmsg": 269, "recvmmsg": 243, "shutdown": 210,
	},
}

// allowed is the allow-list for an architecture: every name's number, omitting names it lacks.
func allowed(goarch string) []uint32 {
	m := number[goarch]
	out := make([]uint32, 0, len(allowNames))
	for _, n := range allowNames {
		if nr, ok := m[n]; ok {
			out = append(out, nr)
		}
	}
	return out
}

var allowAMD64 = allowed("amd64")
var allowARM64 = allowed("arm64")
