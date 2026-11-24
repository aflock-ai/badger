// jade:ring local

package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// A retained run keeps no connector tokens: the request fails after the tokens were provisioned
// (the engine refuses the workspace volume) and the run directory is retained for finalization,
// yet tokens/ is gone. This fails if the service stops removing them.
func TestRetainedRunKeepsNoTokens(t *testing.T) {
	b, base := finalizationFixture(t, "valid")
	socket := filepath.Join(base, "engine.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch path := strings.TrimPrefix(r.URL.Path, "/v1.47"); {
		case path == "/info":
			json.NewEncoder(w).Encode(map[string]any{"OSType": "linux", "SecurityOptions": []string{"name=seccomp,profile=builtin"}})
		case strings.HasPrefix(path, "/images/"):
			json.NewEncoder(w).Encode(map[string]any{"Id": "sha256:" + strings.Repeat("a", 64), "Os": "linux", "Architecture": "arm64", "Config": map[string]any{}})
		default:
			w.WriteHeader(500)
		}
	})}
	go server.Serve(listener)
	defer server.Close()
	b.policy.Image, b.policy.DockerSocket = "sha256:"+strings.Repeat("a", 64), socket
	b.policy.Limits = limits{TimeoutSeconds: 1, OutputBytes: 1024, WorkspaceBytes: 1024, WorkspaceFiles: 4, MemoryMiB: 128, WorkspaceMiB: 64}
	b.policy.ConnectorTokenDir = tokenDir(t, strconv.Itoa(os.Getuid()), map[string]string{"jira.token": "secret"})
	b.engine = newEngine(socket)
	b.admission = make(chan struct{}, 1)
	b.admit = func(context.Context, policy, string) (string, error) { return b.policy.ProfileSHA256, nil }
	_, _ = b.executeWorker(context.Background(), marshal(executionRequest{Schema: requestSchema, Workspace: b.policy.Workspace.ID, Command: "true"}), uint32(os.Getuid()))
	runs, _ := filepath.Glob(filepath.Join(base, "retained", "*", "run"))
	if len(runs) != 1 {
		t.Fatalf("expected one retained run directory, found %v", runs)
	}
	if _, err := os.Stat(filepath.Join(runs[0], "profile")); err != nil {
		t.Fatalf("the run was not provisioned: %v", err)
	}
	if _, err := os.Stat(filepath.Join(runs[0], "tokens")); !os.IsNotExist(err) {
		t.Fatal("a retained run kept its connector tokens")
	}
}
