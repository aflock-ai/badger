package launch

import (
	"errors"
	"runtime"
	"syscall"
	"unsafe"
)

// The plugin runs as the host's own user, so the filesystem sandbox (Landlock) is not enough: it
// could still signal the host, change its limits, squat the pod's network, or leave IPC for the
// next stream. Rather than name every such call (the deny-list lost that race), the filter is
// default-deny: any syscall not on the allow-list fails with EPERM and does not run. The allow-list is every syscall the Go runtime, the connector SDK (net/http, TLS, the
// MCP stdio loop) and the shim's own setup make, by name, resolved per architecture. It is
// validated by running the connectors and the end-to-end plugin under it. A few calls carry an
// argument rule: clone may not create a namespace or reparent, clone3 answers ENOSYS so libc falls
// back to clone, tgkill and prlimit64 may target only this process (and prlimit64 may not set
// RLIMIT_CORE), fcntl may not set where or which signal a file's I/O signals go, and prctl passes
// only the options the Go runtime and the SDK use. See the connector deploy notes.

// fcntlSignalCmds set which process a file's I/O signals go to, and which signal: F_SETOWN,
// F_SETSIG, F_SETOWN_EX. With them a plugin could make the kernel signal its same-uid host.
var fcntlSignalCmds = []uint32{8, 10, 15}

const (
	bpfLd   = 0x20 // BPF_LD | BPF_W | BPF_ABS
	bpfJeq  = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	bpfJset = 0x45 // BPF_JMP | BPF_JSET | BPF_K
	bpfRet  = 0x06 // BPF_RET | BPF_K

	retAllow = 0x7fff0000
	// SECCOMP_RET_ERRNO with EPERM: an off-list call fails and never runs. Unlike a kill it writes
	// no audit record, also on a node whose audit rules select the plugin's task:
	//   - seccomp_log (kernel/seccomp.c) logs an errno action only when the filter asked for it
	//     with SECCOMP_FILTER_FLAG_LOG, and audit_seccomp has no other caller. PR_SET_SECCOMP
	//     takes no flags. Auditing errno actions for audited tasks was removed in v4.18 (commit
	//     326bee0286d7); plughost refuses kernels below 6.5.
	//   - A denied call returns before the syscall audit entry hook (syscall_trace_enter, both
	//     kernel/entry/common.c and arm64), so no SYSCALL or PATH record exists for it either.
	// A kill's record (type=1326) carries a syscall number and an instruction address the plugin
	// chooses, a channel into the node's log. Calls the filter allows can still be audited by the
	// node's rules (a refused openat's PATH name): see the deploy notes, node audit configuration.
	retDeny  = 0x00050000 | uint32(syscall.EPERM)
	retNosys = 0x00050000 | uint32(syscall.ENOSYS)

	offNr   = 0
	offArch = 4
	offArg0 = 16
	offArg1 = 24
	offArg2 = 32 // low half; offArg2+4 is the high half (little-endian)

	rlimitCore = 4 // RLIMIT_CORE, the same on amd64 and arm64

	prSeccomp  = 22 // PR_SET_SECCOMP
	modeFilter = 2  // SECCOMP_MODE_FILTER

	sysClone3 = 435 // same on amd64 and arm64

	prGetDumpable = 3
	prSetVMA      = 0x53564d41 // PR_SET_VMA; its only sub-option, PR_SET_VMA_ANON_NAME, is 0

	// clone flags a plugin must not use: a new namespace (its process would leave the group's reach)
	// or CLONE_PARENT (a child reparented onto the host, a zombie the stream teardown cannot reap).
	cloneDenied = 0x7e020000 | 0x00008000 // NEWNS|NEWCGROUP|NEWUTS|NEWIPC|NEWUSER|NEWPID|NEWNET | CLONE_PARENT
	cloneThread = 0x00010000              // CLONE_THREAD: a new thread, not a new process
)

// arch is one architecture's filter facts: its audit id, the allowed syscalls by number, and the
// numbers of clone and tgkill (which carry argument rules). The x32 ABI (amd64) is always denied.
type arch struct {
	audit                  uint32
	allow                  []uint32
	clone, tgkill, prlimit uint32
	fcntl, prctl           uint32
	x32                    uint32
}

type sockFilter struct {
	code   uint16
	jt, jf uint8
	k      uint32
}

// program assembles BPF with forward jumps to labels: an instruction's true branch goes to the
// label marked later (or nowhere, -1), its false branch to the next instruction.
type program struct {
	ins    []sockFilter
	target []int
	labels map[int]int
}

func (p *program) add(code uint16, k uint32, label int) {
	p.ins = append(p.ins, sockFilter{code: code, k: k})
	p.target = append(p.target, label)
}
func (p *program) mark(label int) { p.labels[label] = len(p.ins) }
func (p *program) assemble() []sockFilter {
	for i, l := range p.target {
		if l >= 0 {
			p.ins[i].jt = uint8(p.labels[l] - i - 1)
		}
	}
	return p.ins
}

// filter is the program for a plugin whose own thread-group id is self (unused today beyond tgkill,
// which Go aims only at its own group).
func filter() ([]sockFilter, error) {
	a, err := archOf(runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	return filterFor(a), nil
}

// filterFor is the program for one architecture's facts (filter's, or a test's for the other one).
func filterFor(a arch) []sockFilter {
	// Labels are jumped to only from earlier instructions (BPF has no backward jump), so ALLOW and
	// DENY sit at the very end and every rule reaches a verdict by a forward jump or an inline ret.
	const ALLOW, DENY, CLONE, NOSYS, TGKILL, PRLIMIT, FCNTL, PRCORE, PRCTL, ARG1ZERO = 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
	p := &program{labels: map[int]int{}}
	p.add(bpfLd, offArch, -1)
	p.add(bpfJeq, a.audit, -2) // the right architecture: skip the next instruction
	p.ins[len(p.ins)-1].jt = 1
	p.add(bpfRet, retDeny, -1) // wrong architecture
	p.add(bpfLd, offNr, -1)
	if a.x32 != 0 {
		p.add(bpfJeq, a.x32, DENY) // (jset) an x32 call; set below
		p.ins[len(p.ins)-1].code = bpfJset
	}
	p.add(bpfJeq, a.clone, CLONE)
	p.add(bpfJeq, sysClone3, NOSYS)
	p.add(bpfJeq, a.tgkill, TGKILL)
	p.add(bpfJeq, a.prlimit, PRLIMIT)
	p.add(bpfJeq, a.fcntl, FCNTL)
	p.add(bpfJeq, a.prctl, PRCTL)
	for _, nr := range a.allow {
		p.add(bpfJeq, nr, ALLOW)
	}
	p.add(bpfRet, retDeny, -1) // not on the allow-list: EPERM
	p.mark(CLONE)
	p.add(bpfLd, offArg0, -1)
	p.add(bpfJset, cloneDenied, DENY)  // a namespace or CLONE_PARENT
	p.add(bpfJset, cloneThread, ALLOW) // a new thread is the only clone a connector makes
	p.add(bpfRet, retDeny, -1)         // a plain fork: a plugin does not spawn processes
	p.mark(NOSYS)
	p.add(bpfRet, retNosys, -1) // clone3's flags are out of reach; libc retries with clone
	p.mark(TGKILL)
	p.add(bpfLd, offArg0, -1)
	p.add(bpfJeq, uint32(syscall.Getpid()), ALLOW) // only this thread group
	p.add(bpfRet, retDeny, -1)
	// prlimit64: only for this process (pid 0 or its own pid), and never setting RLIMIT_CORE, which
	// the shim leaves at 1 so the kernel refuses every file and pipe core dump.
	p.mark(PRLIMIT)
	p.add(bpfLd, offArg1, -1)
	p.add(bpfJeq, rlimitCore, PRCORE)
	p.add(bpfLd, offArg0, -1)
	p.add(bpfJeq, 0, ALLOW)                        // pid 0 is the caller itself (Go reads its own RLIMIT)
	p.add(bpfJeq, uint32(syscall.Getpid()), ALLOW) // or this process by pid; never the host
	p.add(bpfRet, retDeny, -1)
	p.mark(PRCORE)
	p.add(bpfLd, offArg2, -1)
	p.add(bpfJset, 0xffffffff, DENY) // a new limit (a non-NULL pointer): denied, whatever the pid
	p.add(bpfLd, offArg2+4, -1)
	p.add(bpfJset, 0xffffffff, DENY)
	p.add(bpfLd, offArg0, -1) // reading it (new NULL): the same pid rule
	p.add(bpfJeq, 0, ALLOW)
	p.add(bpfJeq, uint32(syscall.Getpid()), ALLOW)
	p.add(bpfRet, retDeny, -1)
	p.mark(FCNTL)
	p.add(bpfLd, offArg1, -1)
	for _, cmd := range fcntlSignalCmds {
		p.add(bpfJeq, cmd, DENY) // fcntl may not aim SIGIO (or any signal) at another process
	}
	p.add(bpfRet, retAllow, -1)
	// prctl: the Go runtime names its anonymous mappings (PR_SET_VMA, PR_SET_VMA_ANON_NAME; Go 1.25+)
	// and the SDK reads and clears dumpability (to 0 only). Everything else is denied: PR_SET_NAME
	// above all, since comm reaches node logs (any audit record about the process), so a name of the
	// plugin's choosing (a token) would reach the node's log. The option is an int (the kernel
	// ignores its high half); the second argument is compared whole.
	p.mark(PRCTL)
	p.add(bpfLd, offArg0, -1)
	p.add(bpfJeq, prGetDumpable, ALLOW)
	p.add(bpfJeq, prSetDumpable, ARG1ZERO)
	p.add(bpfJeq, prSetVMA, ARG1ZERO)
	p.add(bpfRet, retDeny, -1)
	p.mark(ARG1ZERO)
	p.add(bpfLd, offArg1, -1)
	p.add(bpfJset, 0xffffffff, DENY)
	p.add(bpfLd, offArg1+4, -1)
	p.add(bpfJset, 0xffffffff, DENY)
	p.add(bpfRet, retAllow, -1)
	p.mark(ALLOW)
	p.add(bpfRet, retAllow, -1)
	p.mark(DENY)
	p.add(bpfRet, retDeny, -1)
	return p.assemble()
}

// installFilter applies the filter to this thread (no_new_privs must be set).
func installFilter() error {
	p, err := filter()
	if err != nil {
		return err
	}
	prog := struct {
		n uint16
		f *sockFilter
	}{uint16(len(p)), &p[0]}
	if _, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, prSeccomp, modeFilter, uintptr(unsafe.Pointer(&prog)), 0, 0, 0); errno != 0 {
		return errno
	}
	return nil
}

func archOf(goarch string) (arch, error) {
	switch goarch {
	case "amd64":
		return arch{audit: 0xc000003e, allow: allowAMD64, clone: 56, tgkill: 234, prlimit: 302, fcntl: 72, prctl: 157, x32: 0x40000000}, nil
	case "arm64":
		return arch{audit: 0xc00000b7, allow: allowARM64, clone: 220, tgkill: 131, prlimit: 261, fcntl: 25, prctl: 167}, nil
	}
	return arch{}, errors.New("plugins are sandboxed only on amd64 and arm64")
}
