//go:build darwin || linux

// jade:ring local
package vzbackend

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func hostScript(t *testing.T, body string) (string, string) {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "host")
	writeTest(t, path, []byte("#!/bin/sh\n"+body+"\n"), 0700)
	return path, directory
}
func assertHostDrained(t *testing.T, got hostProcess, code int) {
	t.Helper()
	if !got.invoked || !got.exitObserved || got.exitCode == nil || *got.exitCode != code || !got.groupAbsent || !got.stdout.eof || !got.stderr.eof {
		t.Fatalf("unobserved lifecycle: %+v", got)
	}
}
func TestRunHostActualExitAndEOF(t *testing.T) {
	for _, item := range []struct {
		name, body, output string
		code               int
	}{{"success", "printf 'observation'; printf 'diagnostic' >&2", "observation", 0}, {"failure", "printf 'failure'; exit 3", "failure", 3}} {
		t.Run(item.name, func(t *testing.T) {
			path, dir := hostScript(t, item.body)
			got, err := runHost(context.Background(), path, "config.json", dir, realHostLimits)
			if err != nil {
				t.Fatal(err)
			}
			assertHostDrained(t, got, item.code)
			if string(got.stdout.bytes) != item.output {
				t.Fatal("output bytes changed")
			}
		})
	}
}
func waitHostReady(t *testing.T, directory string, done <-chan struct{}) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			t.Fatal("host exited before cancellation")
		default:
		}
		if _, err := os.Stat(filepath.Join(directory, "ready")); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("host did not reach installed signal handler")
}
func TestRunHostCancellationAndForcedStop(t *testing.T) {
	for _, forced := range []bool{false, true} {
		t.Run(map[bool]string{false: "graceful", true: "forced"}[forced], func(t *testing.T) {
			trap := "trap 'printf stopped; exit 3' TERM"
			if forced {
				trap = "trap '' TERM"
			}
			path, dir := hostScript(t, trap+"\nprintf ready > ready\nwhile :; do :; done")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			var got hostProcess
			var err error
			go func() {
				got, err = runHost(ctx, path, "config.json", dir, hostLimits{100 * time.Millisecond, time.Second, time.Second})
				close(done)
			}()
			waitHostReady(t, dir, done)
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("host cleanup exceeded bound")
			}
			if !got.groupAbsent || !got.exitObserved || !got.stdout.eof || !got.stderr.eof {
				t.Fatalf("missing cleanup facts %+v %v", got, err)
			}
			if forced {
				if !got.forced || !errors.Is(err, errCleanup) {
					t.Fatal("forced kill counted safe", err)
				}
			} else {
				assertHostDrained(t, got, 3)
				if Code(err) != "run_cancelled" || string(got.stdout.bytes) != "stopped" {
					t.Fatal("graceful cancellation missing", err)
				}
			}
		})
	}
}
func TestRunHostBoundsAndDescendants(t *testing.T) {
	t.Run("bounds", func(t *testing.T) {
		path, dir := hostScript(t, "/usr/bin/head -c 2100000 /dev/zero")
		got, err := runHost(context.Background(), path, "config.json", dir, hostLimits{time.Second, time.Second, time.Second})
		if !got.stdout.overflow || len(got.stdout.bytes) != runObservationLimit || !got.groupAbsent || err == nil {
			t.Fatal("unbounded output or false success", err)
		}
	})
	t.Run("descendant-closed-pipes", func(t *testing.T) {
		path, dir := hostScript(t, "/bin/sleep 30 </dev/null >/dev/null 2>&1 &\nprintf done")
		got, err := runHost(context.Background(), path, "config.json", dir, realHostLimits)
		if !got.groupAbsent || Code(err) != "host_descendants" {
			t.Fatal("surviving descendant not refused and drained", err)
		}
	})
}
func TestHostPipeRequiresRealEOF(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	if _, err = write.WriteString("partial"); err != nil {
		t.Fatal(err)
	}
	done := readHostPipe(read, 64, func() {})
	got := joinHostPipe(read, done, 20*time.Millisecond)
	if got.eof || got.err == nil || string(got.bytes) != "partial" {
		t.Fatal("closed reader invented EOF")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	got = joinHostPipe(r, readHostPipe(r, 64, func() {}), time.Second)
	if !got.eof || got.err != nil {
		t.Fatal("actual EOF refused", got.err)
	}
}
func TestRunHostFixedEnvironmentAndStartRefusal(t *testing.T) {
	t.Setenv("AFLOCK_SYNTHETIC_SECRET", "must-not-reach-host")
	path, dir := hostScript(t, "printf '%s|%s|%s|%s' \"$1\" \"$PWD\" \"$HOME\" \"$AFLOCK_SYNTHETIC_SECRET\"")
	got, err := runHost(context.Background(), path, "fixed-config", dir, realHostLimits)
	if err != nil || !strings.HasPrefix(string(got.stdout.bytes), "fixed-config|") || strings.Contains(string(got.stdout.bytes), "must-not-reach-host") {
		t.Fatal("fixed argv/env contract failed", err)
	}
	got, err = runHost(context.Background(), filepath.Join(dir, "missing"), "config", dir, realHostLimits)
	if got.invoked || Code(err) != "host_start" {
		t.Fatal("missing host reported invoked", err)
	}
}
