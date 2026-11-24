//go:build darwin || linux

// jade:ring local
package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This entrypoint exists only in the compiled Go test executable. Production
// packaging has no environment-controlled execution or lifecycle test mode.
func TestPackagingNativeFixture(t *testing.T) {
	mode := os.Getenv("PACKAGING_NATIVE_FIXTURE")
	if mode == "" {
		return
	}
	if err := os.WriteFile("started", []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}
	switch mode {
	case "child", "sleep":
		time.Sleep(time.Minute)
	case "exit7":
		os.Exit(7)
	case "descendant":
		child := exec.Command(os.Args[0], "-test.run=^TestPackagingNativeFixture$")
		child.Env = []string{"PACKAGING_NATIVE_FIXTURE=child"}
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("child.pid", []byte(strconv.Itoa(child.Process.Pid)), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLaunchCleanupRequiresObservedLifecycle(t *testing.T) {
	spec, entries := specFixture(t)
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	oldManifest, oldPayload, oldDigest := embeddedManifest, embeddedPayload, manifestDigest
	embeddedManifest, embeddedPayload, manifestDigest = raw, archiveFixture(t, entries), digest(raw)
	t.Cleanup(func() { embeddedManifest, embeddedPayload, manifestDigest = oldManifest, oldPayload, oldDigest })
	for _, mode := range []string{"normal", "exit7", "descendant", "cancel", "unobserved-exit", "kill-failure", "group-drain-failure", "group-permission-failure", "pipe-drain-failure"} {
		t.Run(mode, func(t *testing.T) {
			var directory string
			var pid int
			var descendant int
			t.Cleanup(func() {
				// Failure diagnostics must not leave a disposable test payload
				// after the real native group is independently confirmed absent.
				if directory == "" || pid <= 1 || !errors.Is(syscall.Kill(-pid, 0), syscall.ESRCH) {
					return
				}
				root, err := os.OpenRoot(directory)
				if os.IsNotExist(err) {
					return
				}
				if err != nil {
					t.Error(err)
					return
				}
				err = verifyMaterialized(root, spec)
				root.Close()
				if err != nil {
					t.Error(err)
					return
				}
				if err := os.RemoveAll(directory); err != nil {
					t.Error(err)
				}
			})
			releaseWait := make(chan struct{})
			realWait := make(chan struct{})
			defer close(releaseWait)
			code, failure := launchWith([]string{"packaged"}, func(command *exec.Cmd) (int, bool, error) {
				directory = command.Dir
				command.Args = []string{command.Path, "-test.run=^TestPackagingNativeFixture$"}
				fixture := mode
				if mode == "cancel" {
					fixture = "sleep"
				}
				command.Env = append(command.Env, "PACKAGING_NATIVE_FIXTURE="+fixture)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if mode == "cancel" || mode == "unobserved-exit" {
					go func() {
						for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
							if _, err := os.Stat(filepath.Join(directory, "started")); err == nil {
								break
							}
							time.Sleep(time.Millisecond)
						}
						cancel()
					}()
				}
				kill := func(group int, signal syscall.Signal) error {
					if mode == "kill-failure" && signal == syscall.SIGKILL {
						return syscall.EPERM
					}
					if mode == "group-drain-failure" && signal == 0 {
						return nil // Simulate a group whose disappearance cannot be observed.
					}
					if mode == "group-permission-failure" && signal == 0 {
						return syscall.EPERM
					}
					return syscall.Kill(group, signal)
				}
				wait := func(cmd *exec.Cmd) error {
					err := cmd.Wait()
					close(realWait)
					if mode == "unobserved-exit" {
						<-releaseWait
					}
					if mode == "pipe-drain-failure" {
						return exec.ErrWaitDelay
					}
					return err
				}
				grace := 5 * time.Second
				if strings.HasSuffix(mode, "failure") || mode == "unobserved-exit" {
					grace = 50 * time.Millisecond
				}
				code, safe, err := superviseUnix(ctx, command, kill, wait, grace)
				pid = command.Process.Pid
				if mode == "descendant" {
					raw, readErr := os.ReadFile(filepath.Join(directory, "child.pid"))
					if readErr != nil {
						t.Error(readErr)
					}
					descendant, readErr = strconv.Atoi(string(raw))
					if readErr != nil || descendant <= 1 {
						t.Error("missing native descendant PID")
					}
				}
				return code, safe, err
			})
			select {
			case <-realWait:
			case <-time.After(3 * time.Second):
				t.Fatal("real native fixture exit was not observed by harness")
			}
			if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
				t.Fatalf("fixture process remains: %v", err)
			}
			if descendant > 1 {
				for deadline := time.Now().Add(2 * time.Second); ; {
					if err := syscall.Kill(descendant, 0); errors.Is(err, syscall.ESRCH) {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("native descendant remains")
					}
					time.Sleep(time.Millisecond)
				}
			}
			retained := strings.HasSuffix(mode, "failure") || mode == "unobserved-exit"
			if !retained {
				expected := 0
				if mode == "exit7" {
					expected = 7
				}
				if mode == "cancel" {
					expected = 143
				}
				if code != expected || failure != nil {
					t.Fatalf("normal lifecycle: code=%d error=%v", code, failure)
				}
				if _, err := os.Lstat(directory); !os.IsNotExist(err) {
					t.Fatalf("confirmed payload was not removed: %v", err)
				}
				return
			}
			if code != 2 || failure == nil || !strings.Contains(failure.Error(), "payload retained") {
				t.Fatalf("unconfirmed lifecycle accepted: code=%d error=%v", code, failure)
			}
			root, err := os.OpenRoot(directory)
			if err != nil {
				t.Fatal("unconfirmed payload was removed", err)
			}
			if err := verifyMaterialized(root, spec); err != nil {
				t.Error(err)
			}
			if info, err := root.Stat("."); err != nil || info.Mode().Perm() != 0700 {
				t.Error("retained payload is not private")
			}
			root.Close()
			// Remove only this test's retained, verified payload after the harness
			// has independently observed its real native process exit.
			if err := os.RemoveAll(directory); err != nil {
				t.Error(err)
			}
		})
	}
}
