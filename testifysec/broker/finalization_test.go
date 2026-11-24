// jade:ring local
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The compiled Go test binary is a protocol fixture, not the real producer.
// The separate producer UAT exercises its actual Git, admission and signing path.
func TestMain(m *testing.M) {
	if len(os.Args) == 5 && strings.HasPrefix(os.Args[1], "produce-") {
		os.Exit(finalizerFixture())
	}
	os.Exit(m.Run())
}

func finalizerFixture() int {
	raw, err := os.ReadFile(os.Args[2])
	if err != nil || hash(raw) != os.Args[3] || os.Getenv("AFLOCK_FIXTURE_AMBIENT") != "" || os.Getenv("HTTPS_PROXY") != "" {
		return 3
	}
	var configuration struct {
		Mode string `json:"mode"`
	}
	if json.Unmarshal(raw, &configuration) != nil {
		return 3
	}
	directory, operation := os.Args[4], os.Args[1]
	if err := os.WriteFile(filepath.Join(directory, "called-"+operation), []byte("called"), 0600); err != nil {
		return 3
	}
	prepared := []byte(`{"fixture":"prepared"}`)
	response := finalizationResponse{Schema: "testifysec.hardened-code.producer-response/v1", Status: "prepared", SessionID: filepath.Base(directory), PreparedSHA256: hash(prepared)}
	if operation == "produce-prepare" {
		if os.WriteFile(filepath.Join(directory, "prepared.json"), prepared, 0600) != nil {
			return 3
		}
	} else {
		record := []byte(`{"fixture":"registered"}`)
		response.Status, response.RecordSHA256 = "finalized", hash(record)
		if os.WriteFile(filepath.Join(directory, "registration.json"), record, 0600) != nil {
			return 3
		}
		if os.WriteFile(filepath.Join(directory, "finalized.json"), marshal(response), 0600) != nil {
			return 3
		}
	}
	if configuration.Mode == "lost-finalize-ack" && operation == "produce-finalize" {
		return 4
	}
	return fixtureResponse(configuration.Mode, response)
}

func fixtureResponse(mode string, response finalizationResponse) int {
	switch mode {
	case "wrong-session":
		response.SessionID = "session-" + strings.Repeat("0", 32)
	case "wrong-prepared":
		response.PreparedSHA256 = strings.Repeat("0", 64)
	case "oversized":
		fmt.Print(strings.Repeat("x", inputLimit+1))
		return 0
	case "malformed":
		fmt.Print("not-json")
		return 0
	case "duplicate":
		fmt.Printf(`{"schema":"%s","status":"prepared","status":"finalized"}`, response.Schema)
		return 0
	case "case-alias":
		fmt.Printf(`{"schema":"%s","Status":"prepared"}`, response.Schema)
		return 0
	}
	if json.NewEncoder(os.Stdout).Encode(response) != nil {
		return 3
	}
	return 0
}

func finalizationFixture(t *testing.T, mode string) (*broker, string) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"source", "retained"} {
		if err = os.Mkdir(filepath.Join(base, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.WriteFile(filepath.Join(base, "source", "original.txt"), []byte("before\n"), 0644); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(base, "producer")
	if err = os.WriteFile(helper, raw, 0700); err != nil {
		t.Fatal(err)
	}
	assignment := filepath.Join(base, "assignment.json")
	assignmentRaw := marshal(map[string]string{"mode": mode})
	if err = os.WriteFile(assignment, assignmentRaw, 0600); err != nil {
		t.Fatal(err)
	}
	p := policy{Workspace: workspace{ID: "fixture", Source: filepath.Join(base, "source")}, AdmissionExecutable: helper, ProfileSHA256: strings.Repeat("a", 64), Limits: limits{WorkspaceBytes: 1024, WorkspaceFiles: 4}, Finalization: &finalizationPolicy{Executable: helper, SHA256: hash(raw), AssignmentFile: assignment, AssignmentSHA256: hash(assignmentRaw), RetentionDirectory: filepath.Join(base, "retained")}}
	return &broker{policy: p, policyHash: strings.Repeat("b", 64), binaryHash: strings.Repeat("c", 64)}, base
}

func prepareFixtureRun(t *testing.T, b *broker) (string, []byte, []material, error) {
	t.Helper()
	directory, retained, err := executionScratch(b.policy)
	if err != nil || !retained {
		t.Fatalf("allocate retained run: %v", err)
	}
	materials, err := snapshot(context.Background(), b.policy.Workspace.Source, filepath.Join(directory, "inputs"), b.policy.Limits)
	if err != nil {
		t.Fatal(err)
	}
	raw := marshal(executionRequest{Schema: requestSchema, Workspace: b.policy.Workspace.ID, Command: "fixed-worker"})
	err = b.prepareFinalization(context.Background(), directory, raw, materials, b.policy.ProfileSHA256)
	return directory, raw, materials, err
}

func completedFixture(b *broker, directory string, raw []byte, materials []material) result {
	return result{Schema: "testifysec.hardened-opencode.exec-result/v1", Status: "completed", ExitCode: 0, Cleanup: true, RequestSHA256: hash(raw), PolicySHA256: b.policyHash, BinarySHA256: b.binaryHash, ProfileSHA256: b.policy.ProfileSHA256, Materials: materials, MaterialsSHA256: hash(marshal(materials)), Artifact: &artifactEnvelope{}, retainedRun: directory}
}

func finalizationRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func finalizationMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != mode {
		t.Fatalf("unexpected mode for %s", path)
	}
}

func TestFinalizationRetainsExactBrokerInputsAndCompletion(t *testing.T) {
	b, _ := finalizationFixture(t, "valid")
	t.Setenv("AFLOCK_FIXTURE_AMBIENT", "must-not-inherit")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	directory, raw, materials, err := prepareFixtureRun(t, b)
	if err != nil {
		t.Fatal(err)
	}
	stored := finalizationRead(t, filepath.Join(directory, "request.json"))
	if string(stored) != string(raw) {
		t.Fatal("raw admitted request changed")
	}
	var run finalizationRun
	stored = finalizationRead(t, filepath.Join(directory, "run.json"))
	if strict(stored, &run) != nil || run.SessionID != filepath.Base(directory) || run.MaterialsSHA256 != hash(marshal(materials)) || run.BrokerPolicySHA256 != b.policyHash || run.ProfileSHA256 != b.policy.ProfileSHA256 {
		t.Fatal("service tuple was not pinned")
	}
	finalizationMode(t, filepath.Join(directory, "inputs"), 0755)
	if err = os.WriteFile(filepath.Join(b.policy.Workspace.Source, "original.txt"), []byte("after\n"), 0644); err != nil {
		t.Fatal(err)
	}
	answer := completedFixture(b, directory, raw, materials)
	if strings.Contains(string(marshal(answer)), directory) {
		t.Fatal("private retained path escaped result JSON")
	}
	if err = b.finalizeExecution(context.Background(), answer); err != nil {
		t.Fatal(err)
	}
	stored = finalizationRead(t, filepath.Join(directory, "result.json"))
	if string(stored) != string(marshal(answer)) {
		t.Fatal("completed observation changed")
	}
	stored = finalizationRead(t, filepath.Join(directory, "inputs", "original.txt"))
	if string(stored) != "before\n" {
		t.Fatal("finalization reread mutable source")
	}
	finalizationMode(t, filepath.Join(directory, "inputs"), 0700)
}

func TestFinalizationProtocolRefusesAmbiguousAcknowledgements(t *testing.T) {
	for _, mode := range []string{"wrong-session", "wrong-prepared", "oversized", "malformed", "duplicate", "case-alias"} {
		t.Run(mode, func(t *testing.T) {
			b, _ := finalizationFixture(t, mode)
			directory, _, _, err := prepareFixtureRun(t, b)
			if err == nil {
				t.Fatal("invalid producer acknowledgement accepted")
			}
			if _, err = os.Stat(filepath.Join(directory, "request.json")); err != nil {
				t.Fatal("uncertain run was deleted")
			}
			if _, err = os.Stat(filepath.Join(directory, "called-produce-finalize")); !os.IsNotExist(err) {
				t.Fatal("preparation finalized a record")
			}
		})
	}
}

func TestFinalizationLostAcknowledgementRetainsCompletionWithoutRetry(t *testing.T) {
	b, _ := finalizationFixture(t, "lost-finalize-ack")
	directory, raw, materials, err := prepareFixtureRun(t, b)
	if err != nil {
		t.Fatal(err)
	}
	answer := completedFixture(b, directory, raw, materials)
	if err = b.finalizeExecution(context.Background(), answer); err == nil {
		t.Fatal("lost acknowledgement accepted")
	}
	before, err := os.ReadFile(filepath.Join(directory, "result.json"))
	if err != nil || string(before) != string(marshal(answer)) {
		t.Fatal("completed observation lost after registration uncertainty")
	}
	if _, err = os.Stat(filepath.Join(directory, "registration.json")); err != nil {
		t.Fatal("ambiguous registered fixture removed")
	}
	if err = b.finalizeExecution(context.Background(), answer); err == nil {
		t.Fatal("automatic retry overwrote original completed result")
	}
	after, err := os.ReadFile(filepath.Join(directory, "result.json"))
	if err != nil || string(after) != string(before) {
		t.Fatal("retry changed observation")
	}
}

func TestFinalizationHTTPFailurePreservesCompletedObservation(t *testing.T) {
	b, _ := finalizationFixture(t, "lost-finalize-ack")
	directory, raw, materials, err := prepareFixtureRun(t, b)
	if err != nil {
		t.Fatal(err)
	}
	completed := completedFixture(b, directory, raw, materials)
	answer, err := b.completeExecution(context.Background(), completed, nil)
	if err == nil {
		t.Fatal("ambiguous registration reported success")
	}
	response := httptest.NewRecorder()
	b.respondExecution(response, raw, 65534, answer, err)
	var public result
	if response.Code != http.StatusBadRequest || strict(response.Body.Bytes(), &public) != nil || public.Status != "rejected" || public.Code != "finalization_failed" || !public.Cleanup || public.CallerUID != 65534 {
		t.Fatal("HTTP response did not distinguish finalization failure")
	}
	if strings.Contains(response.Body.String(), directory) || strings.Contains(response.Body.String(), "fixture") {
		t.Fatal("private producer details escaped HTTP error")
	}
	if string(finalizationRead(t, filepath.Join(directory, "result.json"))) != string(marshal(completed)) {
		t.Fatal("workflow refusal lost completed worker observation")
	}
}

func TestIncompleteWorkerResultsCannotFinalize(t *testing.T) {
	b, _ := finalizationFixture(t, "valid")
	for _, mode := range []string{"exit-nonzero", "cleanup-unconfirmed", "missing-artifact", "worker-error"} {
		t.Run(mode, func(t *testing.T) {
			answer := completedFixture(b, "/no-retained-job", nil, nil)
			var prior error
			switch mode {
			case "exit-nonzero":
				answer.ExitCode = 7
			case "cleanup-unconfirmed":
				answer.Cleanup = false
			case "missing-artifact":
				answer.Artifact = nil
			case "worker-error":
				prior = fmt.Errorf("worker failure")
			}
			actual, err := b.completeExecution(context.Background(), answer, prior)
			if err != prior || string(marshal(actual)) != string(marshal(answer)) {
				t.Fatal("incomplete worker entered finalization")
			}
		})
	}
}

func TestFinalizationAuthorityAndRetentionBounds(t *testing.T) {
	for _, mode := range []string{"binary-digest", "assignment-digest", "assignment-link", "script", "unsafe-ancestor", "inside-workspace", "missing-admission"} {
		t.Run(mode, func(t *testing.T) {
			b, base := finalizationFixture(t, "valid")
			mutateFinalizationAuthority(t, b, base, mode)
			if _, _, err := executionScratch(b.policy); err == nil {
				t.Fatal("untrusted authority admitted")
			}
		})
	}
	b, _ := finalizationFixture(t, "valid")
	root, err := finalizationRoot(b.policy.Finalization.RetentionDirectory, true)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for i := 0; i < 64; i++ {
		if _, err = allocateFinalization(root); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = allocateFinalization(root); err == nil {
		t.Fatal("retention limit exceeded")
	}
	if _, err = root.Lstat(".allocation.lock"); !os.IsNotExist(err) {
		t.Fatal("completed allocation retained lock")
	}
}

func mutateFinalizationAuthority(t *testing.T, b *broker, base, mode string) {
	t.Helper()
	f := b.policy.Finalization
	switch mode {
	case "binary-digest":
		f.SHA256 = strings.Repeat("0", 64)
	case "assignment-digest":
		f.AssignmentSHA256 = strings.Repeat("0", 64)
	case "assignment-link":
		original := f.AssignmentFile + ".original"
		if err := os.Rename(f.AssignmentFile, original); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(original, f.AssignmentFile); err != nil {
			t.Fatal(err)
		}
	case "script":
		raw := []byte("#!/bin/sh\nexit 0\n")
		if err := os.WriteFile(f.Executable, raw, 0700); err != nil {
			t.Fatal(err)
		}
		f.SHA256 = hash(raw)
	case "unsafe-ancestor":
		if err := os.Chmod(base, 0777); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.Chmod(base, 0700); err != nil {
				t.Error(err)
			}
		})
	case "inside-workspace":
		f.RetentionDirectory = b.policy.Workspace.Source
	case "missing-admission":
		b.policy.AdmissionExecutable = ""
	}
}

func TestWorkerCannotChooseFinalizationAuthority(t *testing.T) {
	for _, raw := range []string{`{"schema":"testifysec.hardened-opencode.exec/v1","finalization":{}}`, `{"schema":"testifysec.hardened-opencode.exec/v1","retainedRun":"/tmp/forged"}`} {
		var request executionRequest
		if strict([]byte(raw), &request) == nil {
			t.Fatal("worker request chose protected producer state")
		}
	}
	var p policy
	for _, raw := range []string{`{"finalization":null}`, `{"finalization":{"Executable":"/tmp/x"}}`, `{"finalization":{"sha256":"one","sha256":"two"}}`} {
		if strict([]byte(raw), &p) == nil {
			t.Fatal("ambiguous administrative finalization config admitted")
		}
	}
}

// The producer is optional (pushgate cannot be built from this repository). A policy that
// assigns none retains nothing, invokes nothing and completes a successful run unchanged.
func TestFinalizationAbsentProducerIsSkipped(t *testing.T) {
	b, base := finalizationFixture(t, "unused")
	b.policy.Finalization = nil
	if err := validateFinalization(b.policy); err != nil {
		t.Fatal(err)
	}
	directory, retained, err := executionScratch(b.policy)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	if retained || beneath(directory, filepath.Join(base, "retained")) {
		t.Fatal("a run was retained with no producer assigned")
	}
	answer := result{Schema: "testifysec.hardened-opencode.exec-result/v1", Status: "completed", Cleanup: true, Artifact: &artifactEnvelope{}}
	got, err := b.completeExecution(context.Background(), answer, nil)
	if err != nil || got.Status != "completed" {
		t.Fatalf("completion without a producer: %v", err)
	}
	if entries, err := os.ReadDir(filepath.Join(base, "retained")); err != nil || len(entries) != 0 {
		t.Fatalf("retention directory touched: %v %d", err, len(entries))
	}
}
