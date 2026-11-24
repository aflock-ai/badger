//go:build darwin || linux

// jade:ring local
package vzbackend

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func preparedRunFixture(t *testing.T) (*Prepared, fixture) {
	t.Helper()
	f := newFixture(t)
	p, err := newStage(context.Background(), f.stage)
	if err != nil {
		t.Fatal(err)
	}
	p.notBefore = time.Now().Add(-time.Minute)
	p.expires = time.Now().Add(time.Minute)
	p.assignment = f.v.assignment
	p.envelope = []byte("{}")
	if err = f.v.populate(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p, f
}
func requestFixture() RunRequest {
	return RunRequest{SessionID: "session-fixture", Prompt: "Write a file and test it", TimeoutSeconds: 5, NotAfter: time.Now().Add(time.Minute)}
}
func gatewayRunFixture(t *testing.T, p *Prepared, f fixture) RunRequest {
	t.Helper()
	request := requestFixture()
	// A short, symlink-free root keeps the socket path under sun_path's limit.
	// macOS /tmp is a symlink to /private/tmp; Linux /tmp is already canonical.
	root := "/tmp"
	if runtime.GOOS == "darwin" {
		root = "/private/tmp"
	}
	dir, err := os.MkdirTemp(root, "vzrun-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "gateway.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err = os.Chmod(socket, 0666); err != nil {
		t.Fatal(err)
	}
	raw := encodedTest(t, map[string]any{"schema": "testifysec.hardened-opencode.gateway/v2", "session": request.SessionID, "profileDigest": p.observation.ProfileSHA256, "backend": backendReference{"darwin-vz/v1", p.observation.ManifestSHA256}, "socket": socket})
	request.GatewayConfigFile = filepath.Join(dir, "gateway.json")
	request.GatewayConfigSHA256 = hash(raw)
	writeTest(t, request.GatewayConfigFile, raw, 0400)
	return request
}
func TestRunJobTypedByteBindings(t *testing.T) {
	p, _ := preparedRunFixture(t)
	request := requestFixture()
	raw := []byte("hello\n")
	request.Materials = []RunMaterial{{"nested/file.txt", hash(raw), int64(len(raw)), false, base64.StdEncoding.EncodeToString(raw)}}
	got, err := p.buildRunJob(request)
	if err != nil {
		t.Fatal(err)
	}
	var job runJob
	if strictVM(got.JobJSON, &job) != nil {
		t.Fatal("job is not strict v3")
	}
	if job.Schema != "testifysec.vm-job/v3" || job.Binding.RequestSHA256 != hash(job.Request) || job.Binding.MaterialsSHA256 != hash(job.Materials) || got.JobSHA256 != hash(got.JobJSON) {
		t.Fatal("original job bytes not bound")
	}
	request.Materials[0].Path = "changed"
	if got.Materials[0].Path != "nested/file.txt" {
		t.Fatal("caller slice retained")
	}
	empty, err := p.buildRunJob(requestFixture())
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(empty.JobJSON, &job); err != nil || string(job.Materials) != "[]" {
		t.Fatal("empty materials must be array", err)
	}
}
func TestRunRequestRefusals(t *testing.T) {
	p, _ := preparedRunFixture(t)
	for name, mutate := range map[string]func(*RunRequest){
		"expired": func(r *RunRequest) { r.NotAfter = time.Now().Add(-time.Second) },
		"timeout": func(r *RunRequest) { r.TimeoutSeconds = 46 },
		"session": func(r *RunRequest) { r.SessionID = "../workspace" },
		"prompt":  func(r *RunRequest) { r.Prompt = string([]byte{0xff}) },
		"path":    func(r *RunRequest) { r.Materials = []RunMaterial{{".git/config", hash(nil), 0, false, ""}} },
		"digest":  func(r *RunRequest) { r.Materials = []RunMaterial{{"file", strings.Repeat("1", 64), 1, false, "YQ=="}} },
	} {
		t.Run(name, func(t *testing.T) {
			r := requestFixture()
			mutate(&r)
			if _, err := p.buildRunJob(r); err == nil {
				t.Fatal("unsafe request accepted")
			}
		})
	}
}
func TestRunGeneratedInputsAndSocketCustody(t *testing.T) {
	p, f := preparedRunFixture(t)
	r := gatewayRunFixture(t, p, f)
	expected, err := p.buildRunJob(r)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.createRunFiles(context.Background(), r, expected); err != nil {
		t.Fatal(err)
	}
	if err = p.verifyRunFiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, err := p.runStage.root.ReadFile("config.json")
	if err != nil {
		t.Fatal(err)
	}
	var config runConfig
	if strictVM(raw, &config) != nil || !matchesGeneratedConfig(config, expected, p) || hash(raw) != p.runConfigSHA256 {
		t.Fatal("generated config not bound")
	}
	// Cancellation/expiry does not excuse the separate post-run integrity check.
	p.expires = time.Now().Add(-time.Second)
	p.cancel()
	if err = p.verifyAfterRun(); err != nil {
		t.Fatal("cleanup integrity confused with execution authority", err)
	}
	path := filepath.Join(p.runStage.path, "config.json")
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	writeTest(t, path, []byte("{}"), 0600)
	if err = os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	if err = p.verifyAfterRun(); !errors.Is(err, errCleanup) {
		t.Fatal("changed generated config accepted", err)
	}
}
func installAdmissionFixture(t *testing.T, p *Prepared, f fixture, action string) {
	t.Helper()
	output := encodedTest(t, validOutput(f, p.envelope))
	// Fixture output is data, quoted as a single shell argument. This process is
	// a native-call lifecycle seam, not a DSSE verification implementation.
	quoted := "'" + strings.ReplaceAll(string(output), "'", "'\\''") + "'"
	body := []byte("#!/bin/sh\n" + action + "\nprintf '%s' " + quoted + "\n")
	writeTest(t, p.assignment.AdmissionExecutable, body, 0700)
	p.assignment.AdmissionSHA256 = hash(body)
}
func TestRunReadmissionTamperConsumesAndRetains(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("public Run deliberately requires Darwin ARM64")
	}
	p, f := preparedRunFixture(t)
	r := gatewayRunFixture(t, p, f)
	installAdmissionFixture(t, p, f, "/bin/chmod 0600 config.json\nprintf '{}' > config.json\n/bin/chmod 0400 config.json")
	got, err := p.Run(context.Background(), r)
	if !errors.Is(err, errCleanup) || got.HostInvoked || got.Completed || got.CleanupSafe || !hexDigest.MatchString(got.ConfigSHA256) {
		t.Fatalf("tamper reached host or appeared safe: %+v %v", got, err)
	}
	if _, err = p.Run(context.Background(), r); Code(err) != "run_consumed" {
		t.Fatal("run retried", err)
	}
	if err = p.Close(); !errors.Is(err, errCleanup) {
		t.Fatal("uncertain input stage deleted", err)
	}
	entries, err := os.ReadDir(f.stage)
	if err != nil || len(entries) != 2 {
		t.Fatal("tamper state not retained", err)
	}
}
func TestRunCloseSerializesAndRetainLatches(t *testing.T) {
	p, f := preparedRunFixture(t)
	if err := p.beginRun(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- p.Close() }()
	select {
	case <-p.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel")
	}
	select {
	case <-done:
		t.Fatal("Close deleted active stage")
	case <-time.After(20 * time.Millisecond):
	}
	if _, err := os.Stat(p.path); err != nil {
		t.Fatal("active stage disappeared", err)
	}
	close(p.runDone)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join run")
	}
	emptyStage(t, f.stage)
	other, g := preparedRunFixture(t)
	if err := other.Retain(); !errors.Is(err, errCleanup) {
		t.Fatal("retention not explicit", err)
	}
	if err := other.Close(); !errors.Is(err, errCleanup) {
		t.Fatal("retention latch lost", err)
	}
	entries, err := os.ReadDir(g.stage)
	if err != nil || len(entries) != 1 {
		t.Fatal("retained stage removed", err)
	}
}

func matchesGeneratedConfig(config runConfig, expected runExpected, p *Prepared) bool {
	return config.Schema == "testifysec.vm-config/v4" && config.MemoryMiB == 1024 && config.CPUs == 1 && config.JobSHA256 == expected.JobSHA256 && config.BackendManifestSHA256 == p.observation.ManifestSHA256
}

func TestRunCompletionRequiresHostLifecycle(t *testing.T) {
	expected, observation := observationFixture(t)
	raw := resultBytes(t, observation)
	for name, change := range map[string]func(*hostProcess){
		"missing-exit":        func(p *hostProcess) { p.exitObserved = false },
		"missing-code":        func(p *hostProcess) { p.exitCode = nil },
		"wrong-exit":          func(p *hostProcess) { code := 3; p.exitCode = &code },
		"stdout-not-EOF":      func(p *hostProcess) { p.stdout.eof = false },
		"stderr-not-EOF":      func(p *hostProcess) { p.stderr.eof = false },
		"group-still-present": func(p *hostProcess) { p.groupAbsent = false },
	} {
		t.Run(name, func(t *testing.T) {
			code := 0
			process := hostProcess{invoked: true, exitObserved: true, groupAbsent: true, exitCode: &code, stdout: hostOutput{bytes: raw, eof: true}, stderr: hostOutput{eof: true}}
			change(&process)
			var prepared Prepared
			result := RunResult{CleanupSafe: true}
			if err := prepared.completeRun(&result, expected, process, nil); err == nil || result.Completed || result.CleanupSafe {
				t.Fatal("host lifecycle gap accepted", err)
			}
		})
	}
}
func TestRunReadmissionFreshnessAndVersionRefusal(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("public Run deliberately requires Darwin ARM64")
	}
	for _, name := range []string{"expired-during-admission", "v1-output"} {
		t.Run(name, func(t *testing.T) {
			p, f := preparedRunFixture(t)
			request := gatewayRunFixture(t, p, f)
			want := "run_not_after"
			if name == "expired-during-admission" {
				request.NotAfter = time.Now().Add(100 * time.Millisecond)
				installAdmissionFixture(t, p, f, "/bin/sleep 0.2")
			} else {
				want = "admission_binding"
				output := validOutput(f, p.envelope)
				output.SchemaVersion = 1
				body := []byte("#!/bin/sh\nprintf '%s' '" + string(encodedTest(t, output)) + "'\n")
				writeTest(t, p.assignment.AdmissionExecutable, body, 0700)
				p.assignment.AdmissionSHA256 = hash(body)
			}
			result, err := p.Run(context.Background(), request)
			if Code(err) != want || result.HostInvoked || !result.CleanupSafe || result.Completed {
				t.Fatal("freshness/version refusal changed lifecycle", Code(err))
			}
			if err = p.Close(); err != nil {
				t.Fatal(err)
			}
			emptyStage(t, f.stage)
		})
	}
}
