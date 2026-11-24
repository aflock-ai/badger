//go:build darwin || linux

// jade:ring local
package vzbackend

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestNativeOwnedProcessGroup(t *testing.T) {
	// An actual child closes all inherited pipes and remains alive after the
	// leader exits. No crypto admission claim is made by this shell fixture.
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	script := []byte("/bin/sleep 30 </dev/null >/dev/null 2>&1 &\necho $! > child.pid\necho '{}'\n")
	_, err = runAdmission(context.Background(), "/bin/sh", directory, script)
	if err == nil {
		t.Fatal("surviving child accepted")
	}
	raw, e := os.ReadFile(filepath.Join(directory, "child.pid"))
	if e != nil {
		t.Fatal(e)
	}
	pid, e := strconv.Atoi(strings.TrimSpace(string(raw)))
	if e != nil {
		t.Fatal(e)
	}
	defer syscall.Kill(pid, syscall.SIGKILL)
	if !errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
		t.Fatal("owned child still exists", err)
	}
	if Code(err) != "admission_descendants" {
		t.Fatal("group absence was not observed", err)
	}
}
func TestNativeCancellation(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = runAdmission(ctx, "/bin/sh", directory, []byte("exec /bin/sleep 30\n"))
	if err == nil || time.Since(start) > 3*time.Second {
		t.Fatal("native cancellation unbounded", err)
	}
}
func TestCleanupUncertaintyRetainsStage(t *testing.T) {
	f := newFixture(t)
	p, err := newStage(context.Background(), f.stage)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.retain(); !errors.Is(err, errCleanup) {
		t.Fatal(err)
	}
	if _, err = os.Stat(p.path); err != nil {
		t.Fatal("uncertain stage removed", err)
	}
	if _, err = p.Inspect(context.Background()); Code(err) != "prepared_closed" {
		t.Fatal(err)
	}
	if err = p.Close(); !errors.Is(err, errCleanup) {
		t.Fatal("retained cleanup relabeled success", err)
	}
}

func TestFinishGroupAcceptsEPERMOnlyForZombies(t *testing.T) {
	originalSignal, originalZombies := signalGroup, onlyZombies
	t.Cleanup(func() { signalGroup, onlyZombies = originalSignal, originalZombies })
	cleanup := func(err error) bool { return errors.Is(err, errCleanup) }
	descendants := func(err error) bool { return Code(err) == "admission_descendants" }
	for _, item := range []struct {
		name    string
		answers []error
		zombies []bool
		killed  bool
		want    func(error) bool
	}{
		{"absent", []error{syscall.ESRCH}, nil, false, func(err error) bool { return err == nil }},
		{"zombies then gone", []error{syscall.EPERM, syscall.EPERM, syscall.ESRCH}, []bool{true}, false, func(err error) bool { return err == nil }},
		{"zombies never gone", []error{syscall.EPERM}, []bool{true}, false, cleanup},
		{"live unsignalable member", []error{syscall.EPERM, syscall.ESRCH}, []bool{false}, false, cleanup},
		{"zombies, then a live unsignalable member", []error{syscall.EPERM, syscall.EPERM, syscall.ESRCH}, []bool{true, false}, false, cleanup},
		{"zombies, then a live signalable member", []error{syscall.EPERM, nil, syscall.ESRCH}, []bool{true}, true, descendants},
		{"live member killed, zombie while reaped", []error{nil, nil, syscall.EPERM, syscall.ESRCH}, []bool{true}, true, descendants},
		{"live member killed, unsignalable member remains", []error{nil, syscall.EPERM}, []bool{false}, true, cleanup},
		{"live member survives", []error{nil}, nil, true, cleanup},
		{"probe fails", []error{syscall.EINVAL}, nil, false, cleanup},
	} {
		t.Run(item.name, func(t *testing.T) {
			answers, zombies, killed := append([]error(nil), item.answers...), append([]bool(nil), item.zombies...), false
			signalGroup = func(group int, signal syscall.Signal) error {
				if signal == syscall.SIGKILL {
					killed = true
					return nil
				}
				answer := answers[0]
				if len(answers) > 1 {
					answers = answers[1:]
				}
				return answer
			}
			onlyZombies = func(int) bool {
				if len(zombies) == 0 {
					t.Fatal("process table consulted without an EPERM")
				}
				answer := zombies[0]
				if len(zombies) > 1 {
					zombies = zombies[1:]
				}
				return answer
			}
			err := finishGroup(12345, 100*time.Millisecond)
			if !item.want(err) || killed != item.killed {
				t.Fatalf("finishGroup = %v, killed %v", err, killed)
			}
		})
	}
}
