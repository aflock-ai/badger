// jade:ring local
package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestCLIReportsAndRefuses(t *testing.T) {
	for _, item := range []struct {
		name string
		args []string
		code int
	}{
		{"inspect", []string{"inspect"}, 0}, {"preflight", []string{"preflight"}, 3},
		{"matrix", []string{"matrix"}, 0}, {"empty", nil, 2},
		{"execute", []string{"execute"}, 2}, {"host-command", []string{"/bin/sh"}, 2},
		{"force", []string{"preflight", "--force"}, 2},
		{"docker-fallback", []string{"preflight", "--backend=docker"}, 2},
		{"remote-fallback", []string{"preflight", "--backend=remote"}, 2},
	} {
		t.Run(item.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(item.args, &stdout, &stderr); got != item.code {
				t.Fatalf("exit %d, want %d", got, item.code)
			}
			if item.code == 2 {
				if stdout.Len() != 0 || !strings.Contains(stderr.String(), "execution is not available") {
					t.Fatal("invalid arguments were not refused clearly")
				}
				return
			}
			var report map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &report); err != nil || stderr.Len() != 0 {
				t.Fatal("invalid diagnostic JSON", err, stderr.String())
			}
			if item.name != "matrix" && report["executionAllowed"] != false {
				t.Fatal("report allowed execution")
			}
		})
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, bytes.ErrTooLarge }

func TestOutputFailureDoesNotSucceed(t *testing.T) {
	for _, command := range []string{"inspect", "preflight", "matrix"} {
		if run([]string{command}, failingWriter{}, &bytes.Buffer{}) != 1 {
			t.Fatalf("output failure succeeded for %s", command)
		}
	}
}
