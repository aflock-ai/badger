// jade:ring local

package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The daemon commits resources before deliberately dropping/malforming its
// response. These tests exercise execute's real ownership cleanup scope, not
// a mock that reports failure before any side effect occurs.
func TestCreateResponseUncertaintyCleanup(t *testing.T) {
	for _, scenario := range []string{"volume-drop", "volume-malformed", "container-drop", "container-malformed", "container-invalid-id", "nothing-created", "unowned-container", "delete-failure"} {
		t.Run(scenario, func(t *testing.T) {
			directory, err := os.MkdirTemp("", "hc-lifecycle-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(directory)
			directory, err = filepath.EvalSymlinks(directory)
			if err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(directory, "source")
			if err = os.Mkdir(source, 0700); err != nil {
				t.Fatal(err)
			}
			socket := filepath.Join(directory, "engine.sock")
			listener, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			var mu sync.Mutex
			var volume map[string]any
			var container *inspected
			deletions := []string{}
			containerID := strings.Repeat("b", 64)
			imageID := "sha256:" + strings.Repeat("a", 64)
			write := func(w http.ResponseWriter, value any) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(value)
			}
			drop := func(w http.ResponseWriter) {
				connection, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					connection.Close()
				}
			}
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				path := strings.TrimPrefix(r.URL.Path, "/v1.47")
				switch {
				case path == "/info":
					write(w, map[string]any{"OSType": "linux", "SecurityOptions": []string{"name=seccomp,profile=builtin"}})
				case strings.HasPrefix(path, "/images/"):
					write(w, map[string]any{"Id": imageID, "Os": "linux", "Architecture": "arm64", "Config": map[string]any{}})
				case path == "/volumes/create":
					var request struct {
						Name, Driver       string
						DriverOpts, Labels map[string]string
					}
					if json.NewDecoder(r.Body).Decode(&request) != nil {
						w.WriteHeader(400)
						return
					}
					if scenario == "nothing-created" {
						drop(w)
						return
					}
					volume = map[string]any{"Name": request.Name, "Driver": request.Driver, "Scope": "local", "Options": request.DriverOpts, "Labels": request.Labels}
					if scenario == "volume-drop" {
						drop(w)
						return
					}
					if scenario == "volume-malformed" {
						w.Write([]byte("{"))
						return
					}
					write(w, volume)
				case path == "/containers/create":
					var config containerConfig
					if json.NewDecoder(r.Body).Decode(&config) != nil {
						w.WriteHeader(400)
						return
					}
					container = &inspected{ID: containerID, Name: "/" + r.URL.Query().Get("name"), Config: config}
					if scenario == "unowned-container" {
						container.Config.Labels["io.testifysec.hardened.operation"] = "other"
					}
					if scenario == "container-malformed" {
						w.Write([]byte("{"))
						return
					}
					if scenario == "container-invalid-id" {
						write(w, map[string]string{"Id": "bad"})
						return
					}
					drop(w)
				case strings.HasPrefix(path, "/containers/") && r.Method == "GET":
					if container == nil {
						w.WriteHeader(404)
						return
					}
					write(w, container)
				case strings.HasPrefix(path, "/containers/") && r.Method == "DELETE":
					if scenario == "delete-failure" {
						w.WriteHeader(500)
						return
					}
					deletions = append(deletions, "container")
					container = nil
					w.WriteHeader(204)
				case strings.HasPrefix(path, "/volumes/") && r.Method == "GET":
					if volume == nil {
						w.WriteHeader(404)
						return
					}
					write(w, volume)
				case strings.HasPrefix(path, "/volumes/") && r.Method == "DELETE":
					if container != nil {
						w.WriteHeader(409)
						return
					}
					deletions = append(deletions, "volume")
					volume = nil
					w.WriteHeader(204)
				default:
					w.WriteHeader(500)
				}
			})
			server := &http.Server{Handler: handler}
			go server.Serve(listener)
			defer server.Close()
			p := policy{Schema: policySchema, Image: imageID, DockerSocket: socket, Workspace: workspace{ID: "test", Source: source}, Limits: limits{TimeoutSeconds: 1, OutputBytes: 1024, WorkspaceBytes: 1024, WorkspaceFiles: 10, MemoryMiB: 128, WorkspaceMiB: 64}, DevelopmentAllowSameUID: true}
			b := newBroker(p, strings.Repeat("c", 64))
			// No verifier here: this test is about the lifecycle after admission.
			b.admit = func(context.Context, policy, string) (string, error) { return "", nil }
			answer, err := b.execute(context.Background(), marshal(executionRequest{Schema: requestSchema, Workspace: "test", Command: "true"}), uint32(os.Getuid()))
			if err == nil {
				t.Fatal("uncertain create unexpectedly succeeded")
			}
			mu.Lock()
			defer mu.Unlock()
			if scenario == "unowned-container" || scenario == "delete-failure" {
				if answer.Cleanup || container == nil || failure(err).Code != "cleanup_failed" {
					t.Fatalf("cleanup incorrectly asserted: %+v %v", answer, err)
				}
				if b.beginHandler() || b.waitHandlers(context.Background()) == nil {
					t.Fatal("cleanup failure did not close admission and propagate to shutdown")
				}
				if scenario == "unowned-container" && len(deletions) != 0 {
					t.Fatal("deleted an unowned object")
				}
				return
			}
			if !answer.Cleanup || container != nil || volume != nil {
				t.Fatalf("uncertain resource leaked: cleanup=%v container=%v volume=%v error=%v", answer.Cleanup, container != nil, volume != nil, err)
			}
			if strings.HasPrefix(scenario, "container-") && strings.Join(deletions, ",") != "container,volume" {
				t.Fatalf("wrong cleanup order: %v", deletions)
			}
		})
	}
}

func TestDrainWaitsAndRefusesLateRegistrations(t *testing.T) {
	b := &broker{}
	if !b.beginHandler() {
		t.Fatal("initial registration refused")
	}
	b.beginDrain()
	for i := 0; i < 100; i++ {
		if b.beginHandler() {
			t.Fatal("late registration admitted")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if b.waitHandlers(ctx) == nil {
		t.Fatal("drain completed while active handler remained")
	}
	b.handlers.Done()
	if err := b.waitHandlers(context.Background()); err != nil {
		t.Fatal(err)
	}
}
