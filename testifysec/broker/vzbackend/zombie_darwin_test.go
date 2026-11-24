//go:build darwin

// jade:ring local
package vzbackend

import (
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// The real process table: an exited, unreaped child reads as exited; a live one does not.
func TestZombieGroupReadsTheProcessTable(t *testing.T) {
	start := func(name string, arg ...string) *exec.Cmd {
		command := exec.Command(name, arg...)
		command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		return command
	}
	live := start("/bin/sleep", "30")
	t.Cleanup(func() { _ = live.Process.Kill(); _ = live.Wait() })
	if zombieGroup(live.Process.Pid) {
		t.Fatal("a live process read as a zombie")
	}
	exited := start("/usr/bin/true")
	t.Cleanup(func() { _ = exited.Wait() })
	deadline := time.Now().Add(5 * time.Second)
	for !zombieGroup(exited.Process.Pid) {
		if time.Now().After(deadline) {
			t.Fatal("an exited, unreaped child never read as a zombie")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
