package launch

import (
	"runtime"
	"syscall"
	"testing"
)

// run evaluates a filter over one call (seccomp_data: nr, arch, args[0..2], each 64-bit) as the
// kernel would, and returns the action.
func run(t *testing.T, p []sockFilter, nr, arch uint32, args ...uint64) uint32 {
	t.Helper()
	data := map[uint32]uint32{offNr: nr, offArch: arch}
	for i, v := range args {
		data[offArg0+uint32(8*i)], data[offArg0+uint32(8*i)+4] = uint32(v), uint32(v>>32)
	}
	var a uint32
	for pc := 0; pc < len(p); pc++ {
		in := p[pc]
		switch in.code {
		case bpfLd:
			a = data[in.k]
		case bpfJeq, bpfJset:
			if (in.code == bpfJeq && a == in.k) || (in.code == bpfJset && a&in.k != 0) {
				pc += int(in.jt)
			}
		case bpfRet:
			return in.k
		default:
			t.Fatalf("instruction %#x", in.code)
		}
	}
	t.Fatal("fell off the end")
	return 0
}

// Every allowed name is on at least one architecture's table (a typo would be on neither), and each
// architecture's numbers are distinct (a copy-paste error would collide two names).
func TestEveryAllowedNameResolves(t *testing.T) {
	for _, n := range allowNames {
		if number["amd64"][n] == 0 && number["arm64"][n] == 0 && n != "read" {
			t.Errorf("%q resolves on neither architecture", n)
		}
	}
	for _, goarch := range []string{"amd64", "arm64"} {
		seen := map[uint32]string{}
		for n, nr := range number[goarch] {
			if prev, ok := seen[nr]; ok {
				t.Errorf("%s: %q and %q are both number %d", goarch, prev, n, nr)
			}
			seen[nr] = n
		}
	}
}

// The filter is default-deny: a syscall not on the list is denied (EPERM); an allowed one passes;
// clone3 answers ENOSYS; clone with a namespace or CLONE_PARENT flag is denied while a thread's clone
// passes; tgkill passes only for this thread group; fcntl may not set a file's signal owner or
// signal (F_SETOWN, F_SETSIG, F_SETOWN_EX: with O_ASYNC the kernel would signal the same-uid host)
// while its ordinary commands pass; prlimit64 may read RLIMIT_CORE but setting it (a non-NULL new
// limit, either half) is denied for any pid; the socket API (socket, socketpair, connect, bind,
// listen, accept, accept4) is denied whatever the family: the plugin has no network of its own;
// and a call from another architecture, or an x32 call on amd64, is denied.
func TestTheAllowListFilterDecides(t *testing.T) {
	a, err := archOf(runtime.GOARCH)
	if err != nil {
		t.Skip(err)
	}
	p, err := filter()
	if err != nil {
		t.Fatal(err)
	}
	read := number[runtime.GOARCH]["read"]
	socket := number[runtime.GOARCH]["socket"]
	for name, tc := range map[string]struct {
		nr         uint32
		arg0, arg1 uint64
		want       uint32
		arg2       uint64
	}{
		"an allowed call (read)":   {read, 0, 0, retAllow, 0},
		"socket AF_UNIX":           {socket, syscall.AF_UNIX, 0, retDeny, 0},
		"socket AF_INET":           {socket, syscall.AF_INET, 0, retDeny, 0},
		"an off-list call (ioctl)": {a.clone + 10000, 0, 0, retDeny, 0}, // some number not on the list
		"clone3":                   {sysClone3, 0, 0, retNosys, 0},
		"clone, a thread":          {a.clone, uint64(syscall.CLONE_VM | syscall.CLONE_THREAD), 0, retAllow, 0},
		"clone, a plain child":     {a.clone, uint64(syscall.SIGCHLD), 0, retDeny, 0},
		"clone, a new user ns":     {a.clone, uint64(syscall.SIGCHLD | syscall.CLONE_NEWUSER), 0, retDeny, 0},
		"clone, a new pid ns":      {a.clone, uint64(syscall.SIGCHLD | syscall.CLONE_NEWPID), 0, retDeny, 0},
		"clone, reparented":        {a.clone, uint64(syscall.CLONE_VM | syscall.CLONE_THREAD | 0x00008000), 0, retDeny, 0},
		"tgkill, this group":       {a.tgkill, uint64(syscall.Getpid()), 0, retAllow, 0},
		"tgkill, another group":    {a.tgkill, uint64(syscall.Getpid() + 1), 0, retDeny, 0},
		"fcntl F_SETOWN":           {a.fcntl, 3, syscall.F_SETOWN, retDeny, 0},
		"fcntl F_SETSIG":           {a.fcntl, 3, syscall.F_SETSIG, retDeny, 0},
		"fcntl F_SETOWN_EX":        {a.fcntl, 3, 15, retDeny, 0},
		"fcntl F_GETFL":            {a.fcntl, 3, syscall.F_GETFL, retAllow, 0},
		"fcntl F_SETFL":            {a.fcntl, 3, syscall.F_SETFL, retAllow, 0},
		"fcntl F_DUPFD_CLOEXEC":    {a.fcntl, 3, syscall.F_DUPFD_CLOEXEC, retAllow, 0},
		"prlimit read RLIMIT_CORE": {a.prlimit, 0, rlimitCore, retAllow, 0},
		"prlimit set RLIMIT_CORE":  {a.prlimit, 0, rlimitCore, retDeny, 0xc000123450},
		"prlimit set CORE, self":   {a.prlimit, uint64(syscall.Getpid()), rlimitCore, retDeny, 0x7ffd0000},
		"prlimit set CORE, high":   {a.prlimit, 0, rlimitCore, retDeny, 1 << 40},
		"prlimit set NOFILE":       {a.prlimit, 0, syscall.RLIMIT_NOFILE, retAllow, 0xc000123450},
		"prlimit read, the host":   {a.prlimit, uint64(syscall.Getppid()), rlimitCore, retDeny, 0},
	} {
		if got := run(t, p, tc.nr, a.audit, tc.arg0, tc.arg1, tc.arg2); got != tc.want {
			t.Errorf("%s: %#x, want %#x", name, got, tc.want)
		}
	}
	if got := run(t, p, read, a.audit^1, 0, 0); got != retDeny {
		t.Errorf("another architecture: %#x", got)
	}
	if a.x32 != 0 {
		if got := run(t, p, read|a.x32, a.audit, 0, 0); got != retDeny {
			t.Errorf("x32: %#x", got)
		}
	}
	// No socket API at all, on either architecture's numbers (a passed, connected TCP socket cannot
	// be re-aimed: connect, with AF_UNSPEC, would dissolve it).
	sockAPI := map[string][]uint32{"amd64": {41, 53, 42, 49, 50, 43, 288}, "arm64": {198, 199, 203, 200, 201, 202, 242}}[runtime.GOARCH]
	for _, nr := range sockAPI {
		if got := run(t, p, nr, a.audit, syscall.AF_UNIX); got != retDeny {
			t.Errorf("socket API call %d: %#x", nr, got)
		}
	}
	// Every allow-listed number reaches ALLOW: a jump past 255 instructions would wrap silently.
	for _, nr := range a.allow {
		if got := run(t, p, nr, a.audit, 0, 0); got != retAllow {
			t.Errorf("allow-listed %d: %#x", nr, got)
		}
	}
}

// prctl passes only for what the Go runtime and the SDK use: PR_GET_DUMPABLE, PR_SET_DUMPABLE to 0,
// and PR_SET_VMA naming an anonymous mapping (the runtime labels its heap since Go 1.25). Anything
// else is denied, PR_SET_NAME above all: a name of the plugin's choosing would reach node logs in
// any record about the process. Checked on both architectures' tables.
func TestPrctlPassesOnlyTheRuntimesOptions(t *testing.T) {
	const prSetVMA, prSetName, prSetMM = 0x53564d41, 15, 35
	for _, goarch := range []string{"amd64", "arm64"} {
		a, err := archOf(goarch)
		if err != nil {
			t.Fatal(err)
		}
		p := filterFor(a)
		for name, tc := range map[string]struct {
			arg0, arg1 uint64
			want       uint32
		}{
			"PR_GET_DUMPABLE":           {3, 0, retAllow},
			"PR_SET_DUMPABLE 0":         {prSetDumpable, 0, retAllow},
			"PR_SET_DUMPABLE 1":         {prSetDumpable, 1, retDeny},
			"PR_SET_DUMPABLE high":      {prSetDumpable, 1 << 32, retDeny},
			"PR_SET_VMA anon name":      {prSetVMA, 0, retAllow},
			"PR_SET_VMA other":          {prSetVMA, 1, retDeny},
			"PR_SET_NAME":               {prSetName, 0x4b4f54, retDeny},
			"PR_SET_MM":                 {prSetMM, 0, retDeny},
			"PR_SET_NO_NEW_PRIVS":       {prSetNoNewPrivs, 1, retDeny},
			"PR_SET_SECCOMP":            {prSeccomp, modeFilter, retDeny},
			"PR_SET_NAME, high garbage": {prSetName | 1<<32, 0, retDeny},
		} {
			if got := run(t, p, a.prctl, a.audit, tc.arg0, tc.arg1); got != tc.want {
				t.Errorf("%s %s: %#x, want %#x", goarch, name, got, tc.want)
			}
		}
		if got := run(t, p, number[goarch]["read"], a.audit); got != retAllow {
			t.Errorf("%s: read %#x", goarch, got)
		}
	}
}

// No verdict the filter can return is one the kernel logs: every return is allow, EPERM or ENOSYS,
// never a kill, trap, trace, user notification or log action, whose audit records (type=1326)
// would carry a syscall number and an instruction address of the plugin's choosing to the node's
// log. Checked on both architectures' programs.
func TestTheFilterLeavesNoAuditRecord(t *testing.T) {
	for _, goarch := range []string{"amd64", "arm64"} {
		a, err := archOf(goarch)
		if err != nil {
			t.Fatal(err)
		}
		for i, in := range filterFor(a) {
			if in.code == bpfRet && in.k != retAllow && in.k != retDeny && in.k != retNosys {
				t.Errorf("%s: instruction %d returns %#x", goarch, i, in.k)
			}
		}
	}
	if retDeny&0xffff0000 != 0x00050000 || retNosys&0xffff0000 != 0x00050000 { // SECCOMP_RET_ERRNO
		t.Fatalf("deny %#x, nosys %#x are not errno actions", retDeny, retNosys)
	}
}
