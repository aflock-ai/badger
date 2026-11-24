package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/aflock-ai/badger/testifysec/connectors/internal/egress"
)

// A connector run through Main is non-dumpable once it has read its token, so no core dump of it is
// taken at all, by any collector, piped ones included (the kernel checks dumpability first). The
// child runs Main with real flags; its one tool reads the token by calling the service, then reports
// the process's dumpability.
func TestMainMakesTheConnectorNonDumpable(t *testing.T) {
	if base := os.Getenv("CONNECTOR_TEST_MAIN_BASE"); base != "" {
		os.Args = []string{"connector", "--base-url=" + base, "--token-file=" + os.Getenv("CONNECTOR_TEST_MAIN_TOKEN"),
			"--classification=SECRET", "--insecure-loopback-http"}
		if os.Getenv("CONNECTOR_TEST_MAIN_REFUSE") == "1" { // as a seccomp policy rejecting prctl would
			noCoreDumps = func() error { return syscall.EPERM }
		}
		Main(Spec{Name: "dump", Tools: func(c *egress.Client) []Tool {
			return []Tool{{Name: "dump_check", Description: "d", Handler: func(ctx context.Context, _ json.RawMessage) (Result, error) {
				if _, err := c.Get(ctx, "/t", nil); err != nil {
					return Result{}, err
				}
				d, _, _ := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0)
				return Result{Text: fmt.Sprintf("dumpable=%d", d)}, nil
			}}}
		}})
		os.Exit(0)
	}
	const canary = "canary-token-0123456789"
	var sawToken atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawToken.Store(r.Header.Get("Authorization") == "Bearer "+canary)
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte(canary), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainMakesTheConnectorNonDumpable$")
	cmd.Env = append(os.Environ(), "CONNECTOR_TEST_MAIN_BASE="+srv.URL, "CONNECTOR_TEST_MAIN_TOKEN="+tok)
	cmd.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"dump_check","arguments":{}}}` + "\n")
	out, err := cmd.Output()
	if err != nil || !sawToken.Load() || !strings.Contains(string(out), "dumpable=0") {
		t.Fatalf("token read %v, %v: %s", sawToken.Load(), err, out)
	}
}

// If the kernel refuses to make the connector non-dumpable (a seccomp policy that rejects prctl),
// Main stops with an error before it reads its token: the service is never called.
func TestMainStopsWhenCoreDumpsCannotBeDisabled(t *testing.T) {
	var called atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called.Store(true) }))
	defer srv.Close()
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte("canary-token-0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainMakesTheConnectorNonDumpable$")
	cmd.Env = append(os.Environ(), "CONNECTOR_TEST_MAIN_BASE="+srv.URL, "CONNECTOR_TEST_MAIN_TOKEN="+tok, "CONNECTOR_TEST_MAIN_REFUSE=1")
	cmd.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"dump_check","arguments":{}}}` + "\n")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	ee, ok := err.(*exec.ExitError)
	if !ok || ee.ExitCode() != 2 || called.Load() || !strings.Contains(stderr.String(), "cannot disable core dumps") {
		t.Fatalf("exit %v, service called %v, stdout %q, stderr %q", err, called.Load(), out, stderr.String())
	}
}
