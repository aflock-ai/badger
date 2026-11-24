//go:build darwin || linux

// jade:ring local
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestInheritedInputCancellation(t *testing.T) {
	if os.Getenv("AFLOCK_INPUT_CHILD") == "1" {
		flags, err := descriptorFlags(os.Stdin.Fd())
		if err != nil || flags&syscall.O_NONBLOCK != 0 {
			os.Exit(98)
		}
		os.Args = []string{"checker", "--assignment", os.Getenv("AFLOCK_INPUT_ASSIGNMENT")}
		os.Exit(run())
	}
	for _, partial := range []string{"", `{"payload":`} {
		t.Run(partial, func(t *testing.T) { inheritedInputCase(t, partial) })
	}
}
func inheritedInputCase(t *testing.T, partial string) {
	t.Helper()
	assignment := inputAssignment(t)
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer writer.Close()
	fd := input.Fd()
	before, err := descriptorFlags(fd)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestInheritedInputCancellation$")
	command.Env = []string{"AFLOCK_INPUT_CHILD=1", "AFLOCK_INPUT_ASSIGNMENT=" + assignment}
	command.Stdin = input
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	if partial != "" {
		if _, err = writer.Write([]byte(partial)); err != nil {
			_ = command.Process.Kill()
			<-done
			t.Fatal(err)
		}
	}
	select {
	case early := <-done:
		t.Fatal("child exited before cancellation", early, stdout.String(), stderr.String())
	case <-time.After(150 * time.Millisecond):
	}
	if err = command.Process.Signal(syscall.SIGTERM); err != nil {
		_ = command.Process.Kill()
		<-done
		t.Fatal(err)
	}
	err = <-done
	checkInputRefusal(t, ctx, command, err, stdout.Bytes(), stderr.Bytes())
	after, err := descriptorFlags(fd)
	if err != nil || after != before {
		t.Fatal("parent input flags changed", before, after, err)
	}
}

func inputAssignment(t *testing.T) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	assignment := filepath.Join(base, "assignment.json")
	raw, err := json.Marshal(map[string]any{"schema": "testifysec.aflock.vz-backend-assignment/v1", "installationDirectory": base + "/install", "stagingDirectory": base + "/stage", "manifestSha256": strings.Repeat("a", 64), "profileSha256": strings.Repeat("b", 64), "admissionExecutable": base + "/admission", "admissionSha256": strings.Repeat("c", 64), "tenantId": "tenant", "deploymentId": "deployment", "profileId": "profile"})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(assignment, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return assignment
}

func TestOwnedInputPreservesFlags(t *testing.T) {
	for _, nonblocking := range []bool{false, true} {
		original, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := original.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		if err = restoreDescriptor(raw, nonblocking); err != nil {
			t.Fatal(err)
		}
		owned, release, err := ownedInput(original)
		if err != nil {
			t.Fatal(err)
		}
		if err = owned.SetReadDeadline(time.Now().Add(time.Millisecond)); err != nil {
			t.Fatal("duplicate is not pollable", err)
		}
		if err = release(); err != nil {
			t.Fatal(err)
		}
		var flags uintptr
		var flagErr error
		if err = raw.Control(func(fd uintptr) { flags, flagErr = descriptorFlags(fd) }); err != nil || flagErr != nil || (flags&syscall.O_NONBLOCK != 0) != nonblocking {
			t.Fatal("original flags not restored", flags, err, flagErr)
		}
		if err = original.Close(); err != nil {
			t.Fatal(err)
		}
		if err = writer.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func checkInputRefusal(t *testing.T, ctx context.Context, command *exec.Cmd, err error, stdout, stderr []byte) {
	t.Helper()
	if ctx.Err() != nil || err == nil || command.ProcessState.ExitCode() != 1 {
		t.Fatalf("inherited input cancellation failed: %v %s", err, string(stderr))
	}
	var result map[string]any
	if err = json.Unmarshal(stdout, &result); err != nil || result["prepared"] != false || result["executionEnabled"] != false {
		t.Fatal("missing bounded refusal", err, string(stdout))
	}
}
