//go:build unix

package launch

import (
	"errors"
	"strings"
	"testing"
)

// The kernel refuses a plugin's file and pipe core dumps (the limit of 1), so the gate refuses only
// an @ socket collector on a kernel that has them (6.16+), or a pattern it cannot read. The refusal
// names the value and the deploy notes.
func TestTheCorePatternGate(t *testing.T) {
	read := func(s string, err error) func() ([]byte, error) {
		return func() ([]byte, error) { return []byte(s), err }
	}
	old, sockets := read("6.6.157.1-1.azl3\n", nil), read("6.16.0-1-generic\n", nil)
	one := func() (uint64, error) { return 1, nil }
	for name, tc := range map[string]struct {
		pattern, release func() ([]byte, error)
		ok               bool
	}{
		"file":                   {read("core\n", nil), sockets, true},
		"empty":                  {read("\n", nil), sockets, true},
		"systemd-coredump":       {read("|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h\n", nil), sockets, true},
		"any pipe":               {read("|/usr/share/apport/apport -p%p -s%s -c%c -- %E\n", nil), sockets, true},
		"a socket, 6.16":         {read("@/run/collector.sock\n", nil), sockets, false},
		"a socket protocol, 7.0": {read("@@/run/systemd/coredump\n", nil), read("7.0.1\n", nil), false},
		"an @ file name, 6.6":    {read("@core\n", nil), old, true},
		"an @, 6.15":             {read("@x\n", nil), read("6.15.9\n", nil), true},
		"an @, release unknown":  {read("@x\n", nil), read("", errors.New("no such file")), false},
		"an @, release garbled":  {read("@x\n", nil), read("linux\n", nil), false},
		"unreadable":             {read("", errors.New("permission denied")), old, false},
	} {
		err := checkCorePattern(tc.pattern, tc.release, one)
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil && !strings.Contains(err.Error(), "Preflight") {
			t.Errorf("%s: the refusal does not point at the deploy notes: %v", name, err)
		}
	}
	if err := checkCorePattern(read("@/run/collector.sock\n", nil), sockets, one); err == nil || !strings.Contains(err.Error(), `"@/run/collector.sock"`) {
		t.Errorf("the refusal does not name the value found: %v", err)
	}
}

// An inherited hard core limit of 0 cannot be raised to 1, and the kernel ignores 0 for a pipe: then
// a pipe collector is refused, while a file pattern (which a limit of 0 does stop) still runs.
func TestAZeroCoreLimitRefusesPipes(t *testing.T) {
	read := func(s string) func() ([]byte, error) { return func() ([]byte, error) { return []byte(s), nil } }
	zero := func() (uint64, error) { return 0, nil }
	unknown := func() (uint64, error) { return 0, errors.New("no") }
	pipe, file, rel := read("|/usr/lib/systemd/systemd-coredump %P\n"), read("core\n"), read("6.6.0\n")
	if err := checkCorePattern(pipe, rel, zero); err == nil || !strings.Contains(err.Error(), "core limit") {
		t.Errorf("pipe with limit 0: %v", err)
	}
	if err := checkCorePattern(pipe, rel, unknown); err == nil {
		t.Error("pipe with an unreadable limit: accepted")
	}
	if err := checkCorePattern(file, rel, zero); err != nil {
		t.Errorf("file with limit 0: %v", err)
	}
}
