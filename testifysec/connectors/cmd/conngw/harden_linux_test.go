package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

// The gateway leaves no core dump: it is non-dumpable with a core limit of 1, soft and hard, or of 0
// when it inherited a hard 0 (LimitCORE=0, which it cannot raise; it still starts). Each case runs
// in a child process.
func TestTheGatewayTakesNoCoreDump(t *testing.T) {
	if os.Getenv("CONNGW_TEST_HARDEN") != "" {
		if os.Getenv("CONNGW_TEST_HARDEN") == "zero" {
			_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})
		}
		err := hardenGateway()
		d, _, _ := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0)
		var l syscall.Rlimit
		_ = syscall.Getrlimit(syscall.RLIMIT_CORE, &l)
		fmt.Printf("HARDEN %v %d %d %d\n", err, d, l.Cur, l.Max)
		os.Exit(0)
	}
	cases := map[string]string{"inherited": "HARDEN <nil> 0 1 1", "zero": "HARDEN <nil> 0 0 0"}
	var own syscall.Rlimit
	if syscall.Getrlimit(syscall.RLIMIT_CORE, &own) == nil && own.Max == 0 {
		delete(cases, "inherited") // this test run itself has a hard 0
	}
	for start, want := range cases {
		cmd := exec.Command(os.Args[0], "-test.run=^TestTheGatewayTakesNoCoreDump$")
		cmd.Env = append(os.Environ(), "CONNGW_TEST_HARDEN="+start)
		if out, err := cmd.Output(); err != nil || !strings.Contains(string(out), want+"\n") {
			t.Errorf("%s: %v %q, want %q", start, err, out, want)
		}
	}
}
