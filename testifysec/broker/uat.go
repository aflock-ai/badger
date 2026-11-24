// jade:ring local

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type uatCheck struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}
type uatReport struct {
	Schema        string            `json:"schema"`
	StartedAt     string            `json:"startedAt"`
	Passed        bool              `json:"passed"`
	BinarySHA256  string            `json:"binarySha256"`
	SourceHashes  map[string]string `json:"sourceHashes"`
	Revision      string            `json:"declaredRevision"`
	WorktreeState string            `json:"declaredWorktreeState"`
	Checks        []uatCheck        `json:"checks"`
	Receipts      []result          `json:"receipts"`
	Failure       string            `json:"failure,omitempty"`
	Limitations   []string          `json:"limitations"`
	LinuxPeer     map[string]any    `json:"linuxPeer,omitempty"`
	Shutdown      map[string]any    `json:"shutdown,omitempty"`
}

func launchFixture(p policy, directory string) (func(), error) {
	configuration := filepath.Join(directory, "policy-"+fmt.Sprint(time.Now().UnixNano())+".json")
	if err := os.WriteFile(configuration, marshal(p), 0600); err != nil {
		return nil, err
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	command := exec.Command(executable, "serve", "--config", configuration)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err = command.Start(); err != nil {
		return nil, err
	}
	cleanup := func() {
		command.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { command.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			command.Process.Kill()
			<-done
		}
	}
	for i := 0; i < 100; i++ {
		connection, err := net.DialTimeout("unix", p.ListenSocket, 50*time.Millisecond)
		if err == nil {
			connection.Close()
			return cleanup, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	cleanup()
	return nil, fmt.Errorf("fixture service startup failed: %s", output.String())
}
func sendFixture(socket string, raw []byte) (result, error) {
	request, err := http.NewRequest("POST", "http://broker/v1/execute", bytes.NewReader(raw))
	if err != nil {
		return result{}, err
	}
	client := unixClient(socket)
	client.Timeout = 100 * time.Second
	response, err := client.Do(request)
	if err != nil {
		return result{}, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return result{}, err
	}
	var answer result
	if err = json.Unmarshal(data, &answer); err != nil {
		return answer, err
	}
	if (response.StatusCode == 200) != (answer.Status == "completed") {
		return answer, fmt.Errorf("IPC status contradicts response")
	}
	return answer, nil
}
func runUAT(arguments []string) (returned error) {
	flags := flag.NewFlagSet("uat", flag.ContinueOnError)
	socket := flags.String("docker-socket", "", "local Docker Unix socket")
	image := flags.String("image", "", "existing immutable Linux image ID")
	output := flags.String("report", ".cache/native-uat.json", "report file")
	revision := flags.String("revision", "unrecorded", "build source revision, supplied by operator")
	worktreeState := flags.String("worktree-state", "unrecorded", "operator-observed source state: clean, dirty, or unrecorded")
	admissionExecutable := flags.String("admission-executable", "", "optional actual native admission bundle launcher")
	profileFile := flags.String("profile", "", "valid signed profile fixture")
	profileSHA := flags.String("profile-sha256", "", "exact assigned profile payload digest")
	expiredFile := flags.String("expired-profile", "", "expired signed profile fixture")
	wrongKeyFile := flags.String("wrong-key-profile", "", "wrong-key signed profile fixture")
	linuxBinary := flags.String("linux-binary", "", "optional compiled Linux broker for real SO_PEERCRED fixture")
	tenantID := flags.String("tenant-id", "", "tenant the profile fixture is assigned to")
	deploymentID := flags.String("deployment-id", "", "deployment the profile fixture is assigned to")
	profileID := flags.String("profile-id", "", "profile id of the profile fixture")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if !developmentNoProfile {
		return fmt.Errorf("uat runs unsigned sandbox fixtures; build this broker with -tags uatnoprofile")
	}
	if *worktreeState != "clean" && *worktreeState != "dirty" && *worktreeState != "unrecorded" {
		return fmt.Errorf("invalid worktree-state")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		return err
	}
	report := uatReport{Schema: "testifysec.hardened-opencode.native-broker-uat/v1", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), BinarySHA256: hash(binary), Revision: *revision, SourceHashes: map[string]string{}, Limitations: []string{"Native binary uses Docker HTTP API directly; Docker daemon and approved image remain trusted administrator inputs.", "This run explicitly allows same-UID development use; it is not separate-user or ALPS qualification.", "No signing, SPIFFE or tenant identity is asserted; peer UID is a local OS credential only.", "Bounded exact-byte regular-file changes are retained in the receipt; automatic host application and Pushgate submission are separate phases.", "No worker public egress, model gateway or hardware attestation is exercised by this harness."}}
	report.WorktreeState = *worktreeState
	files, _ := filepath.Glob("*.go")
	files = append(files, "go.mod")
	for _, name := range files {
		if raw, e := os.ReadFile(name); e == nil {
			report.SourceHashes[name] = hash(raw)
		}
	}
	defer func() {
		report.Passed = returned == nil
		if returned != nil {
			report.Failure = returned.Error()
		}
		os.MkdirAll(filepath.Dir(*output), 0755)
		raw, _ := json.MarshalIndent(report, "", "  ")
		if err := os.WriteFile(*output, append(raw, '\n'), 0644); err != nil && returned == nil {
			returned = err
		}
		fmt.Println(*output)
	}()
	check := func(name string, passed bool, detail string) error {
		report.Checks = append(report.Checks, uatCheck{name, passed, detail})
		fmt.Printf("%s %s\n", map[bool]string{true: "PASS", false: "FAIL"}[passed], name)
		if !passed {
			return fmt.Errorf("%s: %s", name, detail)
		}
		return nil
	}
	directory, err := os.MkdirTemp("", "hc-native-uat-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		return err
	}
	source := filepath.Join(directory, "source")
	os.Mkdir(source, 0755)
	os.WriteFile(filepath.Join(source, "hello.txt"), []byte("original\n"), 0644)
	os.MkdirAll(filepath.Join(source, ".git", "hooks"), 0755)
	os.WriteFile(filepath.Join(source, ".git", "hooks", "pre-commit"), []byte("exit 91\n"), 0644)
	secret := filepath.Join(directory, "controller-secret")
	os.WriteFile(secret, []byte("SYNTHETIC_NATIVE_SECRET"), 0600)
	p := policy{Schema: policySchema, ListenSocket: filepath.Join(directory, "broker.sock"), DockerSocket: *socket, Image: *image, Workspace: workspace{"uat", source}, Limits: limits{TimeoutSeconds: 5, OutputBytes: 8192, WorkspaceBytes: 1 << 20, WorkspaceFiles: 100, MemoryMiB: 128, WorkspaceMiB: 64}, AllowedUIDs: []uint32{uint32(os.Getuid())}, DevelopmentAllowSameUID: true}
	cleanup, err := launchFixture(p, directory)
	if err != nil {
		return err
	}
	defer cleanup()
	run := func(command string) (result, error) {
		answer, err := sendFixture(p.ListenSocket, marshal(executionRequest{Schema: requestSchema, Workspace: "uat", Command: "set -eu\n" + command}))
		if err == nil {
			report.Receipts = append(report.Receipts, answer)
		}
		return answer, err
	}
	answer, err := run("test \"$(cat hello.txt)\" = original; printf changed >hello.txt; test ! -e .git; printf native-ok")
	if err != nil {
		return err
	}
	if err = check("native-execution-and-snapshot-edit", answer.Status == "completed" && answer.ExitCode == 0 && answer.Output == "native-ok", fmt.Sprintf("binary Docker API execution returned status=%s code=%s output=%q", answer.Status, answer.Code, answer.Output)); err != nil {
		return err
	}
	original, _ := os.ReadFile(filepath.Join(source, "hello.txt"))
	if err = check("source-checkout-unchanged", string(original) == "original\n", "Worker writes only its bounded tmpfs copy"); err != nil {
		return err
	}
	if err = verifyArtifactUAT(answer, map[string][]byte{"hello.txt": []byte("changed")}, nil); err != nil {
		return err
	}
	if err = check("artifact-retains-edit-after-worker-cleanup", answer.Cleanup && answer.Artifact != nil, "Broker pauses the complete worker then captures exact final contents and a diff before removal"); err != nil {
		return err
	}
	answer, err = run(`rm hello.txt; mkdir nested; printf '\377\000\376' >nested/binary; chmod 755 nested/binary`)
	if err != nil {
		return err
	}
	if err = verifyArtifactUAT(answer, map[string][]byte{"nested/binary": {255, 0, 254}}, []string{"hello.txt"}); err != nil {
		return err
	}
	if err = check("artifact-retains-deletion-and-nonutf8", answer.Cleanup && answer.Artifact.ChangedFiles == 1 && answer.Artifact.RemovedFiles == 1, "Payload, manifest and file digests verify against the retained base64 bytes"); err != nil {
		return err
	}
	answer, err = run(`(while true; do printf background >pending; mv pending hello.txt; done) >/dev/null 2>&1 & printf descendants-active`)
	if err != nil {
		return err
	}
	if err = check("artifact-freezes-active-descendants", answer.Status == "completed" && answer.ExitCode == 0 && answer.Cleanup && answer.Artifact != nil, "The whole container is confirmed paused before the daemon reads mutable workspace files"); err != nil {
		return err
	}
	os.WriteFile(filepath.Join(source, "unchanged-large"), bytes.Repeat([]byte("x"), 300<<10), 0644)
	answer, err = run("true")
	os.Remove(filepath.Join(source, "unchanged-large"))
	if err != nil {
		return err
	}
	if err = verifyArtifactUAT(answer, map[string][]byte{}, nil); err != nil {
		return err
	}
	if err = check("artifact-streams-large-unchanged-file", answer.Artifact.ChangedFiles == 0, "Unchanged files larger than the changed-content budget are hashed without being re-exported"); err != nil {
		return err
	}
	answer, err = sendFixture(p.ListenSocket, marshal(executionRequest{Schema: requestSchema, Workspace: "uat", Command: "cat", Stdin: "bounded native stdin"}))
	if err != nil {
		return err
	}
	report.Receipts = append(report.Receipts, answer)
	if err = check("bounded-stdin-delivery", answer.Output == "bounded native stdin" && answer.ExitCode == 0, "Read-only request input is passed to the worker without host command execution"); err != nil {
		return err
	}
	answer, err = run(`printf '\377\000'`)
	if err != nil {
		return err
	}
	exact, decodeErr := base64.StdEncoding.DecodeString(answer.OutputBase64)
	if err = check("binary-output-digest-bound", decodeErr == nil && bytes.Equal(exact, []byte{255, 0}) && answer.OutputSHA256 == hash(exact), "Non-UTF8 output remains exactly recoverable through base64 and its digest"); err != nil {
		return err
	}
	for _, test := range []struct{ name, command, expected string }{
		{"nonroot-and-no-capabilities", `test "$(id -u)" = 65534; grep -q '^CapEff:[[:space:]]*0000000000000000$' /proc/self/status; grep -q '^NoNewPrivs:[[:space:]]*1$' /proc/self/status; printf isolated`, "isolated"},
		{"host-secret-denied", fmt.Sprintf("if cat '%s' >/dev/null 2>&1; then exit 7; fi; test ! -S /var/run/docker.sock; printf secret-denied", secret), "secret-denied"},
		{"read-only-root", `if touch /hc-native-write 2>/tmp/denial; then exit 7; fi; grep -q 'Read-only file system' /tmp/denial; printf root-denied`, "root-denied"},
		{"workspace-storage-limit", `if dd if=/dev/zero of=/workspace/quota bs=1048576 count=65 2>/tmp/denial; then exit 7; fi; grep -q 'No space left on device' /tmp/denial; rm /workspace/quota; printf quota-denied`, "quota-denied"},
		{"network-none", `command -v nc >/dev/null; if nc -v -w 1 172.17.0.254 43891 </dev/null 2>/tmp/denial; then exit 7; fi; grep -Eq 'Network (is )?unreachable|No route to host' /tmp/denial; printf network-denied`, "network-denied"},
	} {
		answer, err = run(test.command)
		if err != nil {
			return err
		}
		if err = check(test.name, answer.Status == "completed" && answer.ExitCode == 0 && answer.Output == test.expected, fmt.Sprintf("Observed output=%q status=%s code=%s", answer.Output, answer.Status, answer.Code)); err != nil {
			return err
		}
	}
	for _, test := range []struct{ name, command, code string }{
		{"artifact-symlink-refused", `ln -s /etc/passwd exported`, "unsafe_artifact"},
		{"artifact-hardlink-refused", `ln hello.txt exported`, "unsafe_artifact"},
		{"artifact-fifo-refused", `mkfifo exported`, "unsafe_artifact"},
		{"artifact-git-metadata-refused", `mkdir .GiT; printf dangerous >.GiT/config`, "unsafe_artifact"},
		{"artifact-case-collision-refused", `touch HELLO.txt`, "unsafe_artifact"},
		{"artifact-final-bytes-refused", `dd if=/dev/zero of=large bs=1048576 count=2 2>/dev/null`, "artifact_limit"},
		{"artifact-changed-bytes-refused", `dd if=/dev/zero of=large bs=1024 count=257 2>/dev/null`, "artifact_limit"},
		{"artifact-final-entry-limit", `i=0; while test "$i" -lt 101; do touch "entry-$i"; i=$((i+1)); done`, "artifact_limit"},
	} {
		answer, err = run(test.command)
		if err != nil {
			return err
		}
		if err = check(test.name, answer.Status == "rejected" && answer.Code == test.code && answer.Artifact == nil && answer.Cleanup, fmt.Sprintf("status=%s code=%s cleanup=%t", answer.Status, answer.Code, answer.Cleanup)); err != nil {
			return err
		}
	}
	for _, test := range []struct{ name, raw, code string }{
		{"unknown-mount-field", `{"schema":"` + requestSchema + `","workspace":"uat","command":"true","mounts":[]}`, "invalid_schema"},
		{"duplicate-json-key", `{"schema":"one","schema":"two"}`, "invalid_json"},
		{"invalid-unicode", `{"schema":"` + requestSchema + `","workspace":"uat","command":"\ud800"}`, "invalid_json"},
		{"unassigned-workspace", `{"schema":"` + requestSchema + `","workspace":"other","command":"true"}`, "workspace_denied"},
		{"caller-cannot-assert-uid", `{"schema":"` + requestSchema + `","workspace":"uat","command":"true","callerUid":0}`, "invalid_schema"},
		{"case-alias-refused", `{"schema":"` + requestSchema + `","workspace":"uat","command":"true","Command":"false"}`, "invalid_schema"},
	} {
		answer, err = sendFixture(p.ListenSocket, []byte(test.raw))
		if err != nil {
			return err
		}
		report.Receipts = append(report.Receipts, answer)
		if err = check(test.name, answer.Status == "rejected" && answer.Code == test.code, "Strict bounded IPC admission refuses caller-selected authority"); err != nil {
			return err
		}
	}
	os.Symlink(secret, filepath.Join(source, "escape"))
	answer, err = run("true")
	os.Remove(filepath.Join(source, "escape"))
	if err != nil {
		return err
	}
	if err = check("workspace-symlink-refused", answer.Code == "unsafe_workspace", "Descriptor-based snapshot refuses a host-secret symlink"); err != nil {
		return err
	}
	os.Link(secret, filepath.Join(source, "hardlink"))
	answer, err = run("true")
	os.Remove(filepath.Join(source, "hardlink"))
	if err != nil {
		return err
	}
	if err = check("workspace-hardlink-refused", answer.Code == "unsafe_workspace", "Snapshot refuses linked file aliases"); err != nil {
		return err
	}
	for i := 0; i < 100; i++ {
		os.WriteFile(filepath.Join(source, fmt.Sprintf("budget-%03d", i)), nil, 0644)
	}
	answer, err = run("true")
	for i := 0; i < 100; i++ {
		os.Remove(filepath.Join(source, fmt.Sprintf("budget-%03d", i)))
	}
	if err != nil {
		return err
	}
	if err = check("bounded-directory-enumeration", answer.Code == "workspace_limit", "Directory entries exceed the configured bound before container creation"); err != nil {
		return err
	}
	answer, err = sendFixture(p.ListenSocket, marshal(executionRequest{Schema: requestSchema, Workspace: "uat", Command: "sleep 20", TimeoutSeconds: 1}))
	if err != nil {
		return err
	}
	report.Receipts = append(report.Receipts, answer)
	if err = check("timeout-removes-worker", answer.Code == "execution_timeout", "Native deadline tears down the entire worker"); err != nil {
		return err
	}
	answer, err = run("yes synthetic-output")
	if err != nil {
		return err
	}
	if err = check("output-limit-with-no-daemon-log", answer.Code == "output_limit", "Live stream is bounded and daemon logging driver is verified none"); err != nil {
		return err
	}
	answer, err = run("exit 23")
	if err != nil {
		return err
	}
	if err = check("command-exit-preserved", answer.Status == "completed" && answer.ExitCode == 23, "Observed exit status is separate from admission and test semantics"); err != nil {
		return err
	}
	other := p
	other.ListenSocket = filepath.Join(directory, "large-output.sock")
	other.Limits.OutputBytes = 1 << 20
	stopLarge, err := launchFixture(other, directory)
	if err != nil {
		return err
	}
	answer, err = sendFixture(other.ListenSocket, marshal(executionRequest{Schema: requestSchema, Workspace: "uat", Command: "dd if=/dev/zero bs=1024 count=1024 2>/dev/null"}))
	stopLarge()
	if err != nil {
		return err
	}
	report.Receipts = append(report.Receipts, answer)
	if err = check("complete-response-budget-refused", answer.Code == "response_limit" && answer.Artifact == nil && answer.Cleanup, "Exact output plus artifact must fit the 2 MiB IPC response budget; oversize results are refused atomically"); err != nil {
		return err
	}
	other = p
	other.ListenSocket = filepath.Join(directory, "other.sock")
	other.AllowedUIDs = []uint32{uint32(os.Getuid() + 1)}
	stopOther, err := launchFixture(other, directory)
	if err != nil {
		return err
	}
	answer, err = sendFixture(other.ListenSocket, marshal(executionRequest{Schema: requestSchema, Workspace: "uat", Command: "true"}))
	stopOther()
	if err != nil {
		return err
	}
	if err = check("unassigned-os-peer-refused", answer.Code == "unauthorized_peer", "A request cannot replace the locally established peer UID"); err != nil {
		return err
	}
	other = p
	other.ListenSocket = filepath.Join(directory, "missing.sock")
	other.DockerSocket = filepath.Join(directory, "absent-engine.sock")
	stopOther, err = launchFixture(other, directory)
	if err != nil {
		return err
	}
	answer, err = sendFixture(other.ListenSocket, marshal(executionRequest{Schema: requestSchema, Workspace: "uat", Command: "true"}))
	stopOther()
	if err != nil {
		return err
	}
	if err = check("missing-engine-no-host-fallback", answer.Code == "engine_unavailable", "No Python, Docker CLI, registry pull or host execution fallback exists"); err != nil {
		return err
	}
	if *admissionExecutable != "" {
		launcher, err := os.ReadFile(*admissionExecutable)
		if err != nil {
			return err
		}
		envelope, err := os.ReadFile(*profileFile)
		if err != nil {
			return err
		}
		admissionPolicy := p
		admissionPolicy.ListenSocket = filepath.Join(directory, "admission.sock")
		admissionPolicy.AdmissionExecutable = *admissionExecutable
		admissionPolicy.AdmissionSHA256 = hash(launcher)
		admissionPolicy.ProfileSHA256 = *profileSHA
		admissionPolicy.TenantID, admissionPolicy.DeploymentID, admissionPolicy.ProfileID = *tenantID, *deploymentID, *profileID
		stopAdmission, err := launchFixture(admissionPolicy, directory)
		if err != nil {
			return err
		}
		defer stopAdmission()
		verified := executionRequest{Schema: requestSchema, Workspace: "uat", Command: "printf admitted-native", ProfileEnvelope: string(envelope)}
		answer, err = sendFixture(admissionPolicy.ListenSocket, marshal(verified))
		if err != nil {
			return err
		}
		report.Receipts = append(report.Receipts, answer)
		if err = check("real-native-profile-admitted", answer.Status == "completed" && answer.Output == "admitted-native" && answer.ProfileSHA256 == *profileSHA, fmt.Sprintf("Per-call native Rookery admission returns status=%s code=%s message=%s", answer.Status, answer.Code, answer.Message)); err != nil {
			return err
		}
		verified.ProfileEnvelope = ""
		answer, err = sendFixture(admissionPolicy.ListenSocket, marshal(verified))
		if err != nil {
			return err
		}
		if err = check("missing-profile-refused", answer.Code == "profile_required", "Host admission cannot substitute for independent broker admission"); err != nil {
			return err
		}
		for _, fixture := range []struct{ name, path string }{{"expired-profile-refused", *expiredFile}, {"wrong-key-profile-refused", *wrongKeyFile}} {
			if fixture.path == "" {
				return fmt.Errorf("all native admission fixtures are required")
			}
			raw, err := os.ReadFile(fixture.path)
			if err != nil {
				return err
			}
			verified.ProfileEnvelope = string(raw)
			answer, err = sendFixture(admissionPolicy.ListenSocket, marshal(verified))
			if err != nil {
				return err
			}
			if err = check(fixture.name, answer.Code == "profile_denied", "Fresh native verifier rejects invalid authority before worker creation"); err != nil {
				return err
			}
		}
		pinned := admissionPolicy
		pinned.ListenSocket = filepath.Join(directory, "wrong-pin.sock")
		pinned.ProfileSHA256 = strings.Repeat("0", 64)
		stopPinned, err := launchFixture(pinned, directory)
		if err != nil {
			return err
		}
		verified.ProfileEnvelope = string(envelope)
		answer, err = sendFixture(pinned.ListenSocket, marshal(verified))
		stopPinned()
		if err != nil {
			return err
		}
		if err = check("different-profile-assignment-refused", answer.Code == "profile_denied", "Valid signatures cannot select a profile outside the administrator's exact payload digest"); err != nil {
			return err
		}
		pinned = admissionPolicy
		pinned.ListenSocket = filepath.Join(directory, "wrong-verifier.sock")
		pinned.AdmissionSHA256 = strings.Repeat("0", 64)
		stopPinned, err = launchFixture(pinned, directory)
		if err != nil {
			return err
		}
		answer, err = sendFixture(pinned.ListenSocket, marshal(verified))
		stopPinned()
		if err != nil {
			return err
		}
		if err = check("different-verifier-binary-refused", answer.Code == "verifier_digest_mismatch", "Only the administrator-pinned native verifier may execute"); err != nil {
			return err
		}
		pinned = admissionPolicy
		pinned.ListenSocket = filepath.Join(directory, "wrong-tenant.sock")
		pinned.TenantID = "another-tenant"
		if admissionPolicy.TenantID == pinned.TenantID {
			pinned.TenantID = "another-tenant-b"
		}
		stopPinned, err = launchFixture(pinned, directory)
		if err != nil {
			return err
		}
		answer, err = sendFixture(pinned.ListenSocket, marshal(verified))
		stopPinned()
		if err != nil {
			return err
		}
		if err = check("other-tenant-policy-refused", answer.Code == "profile_denied", "The broker checks the admitted tenant against its own policy, not only the payload digest"); err != nil {
			return err
		}
	}
	if *linuxBinary != "" {
		linuxPath, err := filepath.Abs(*linuxBinary)
		if err != nil {
			return err
		}
		linuxPath, err = filepath.EvalSymlinks(linuxPath)
		if err != nil {
			return err
		}
		socketPolicy := p
		socketPolicy.ListenSocket = filepath.Join(directory, "artifact-socket.sock")
		socketPolicy.Toolpack = filepath.Dir(linuxPath)
		stopSocket, err := launchFixture(socketPolicy, directory)
		if err != nil {
			return err
		}
		answer, err = sendFixture(socketPolicy.ListenSocket, marshal(executionRequest{Schema: requestSchema, Workspace: "uat", Command: "/toolpack/" + filepath.Base(linuxPath) + " artifact-socket-uat"}))
		stopSocket()
		if err != nil {
			return err
		}
		report.Receipts = append(report.Receipts, answer)
		if err = verifyArtifactUAT(answer, map[string][]byte{}, nil); err != nil {
			return err
		}
		if err = check("archive-socket-omission-scope", answer.Cleanup && answer.Artifact.Scope == "regular-files-only", "Docker silently omits the synthetic Unix socket; the exported regular files remain exact, and whole-filesystem special-entry rejection is explicitly not asserted"); err != nil {
			return err
		}
		report.Limitations = append(report.Limitations, "Docker archive omits Unix sockets. This evidence proves regular-file export only, not absence of non-exported special entries; all emitted links/special records are refused.")
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		receipt, err := runLinuxPeerFixture(ctx, newEngine(*socket), *image, *linuxBinary)
		cancel()
		if err != nil {
			return err
		}
		report.LinuxPeer = receipt
		if err = check("linux-separate-uid-peer-credentials", receipt["passed"] == true, "Real Linux broker UID0 admits UID65534 to profile checking and refuses UID0; no Docker socket mounted in this fixture"); err != nil {
			return err
		}
	}
	report.Shutdown, err = shutdownUAT(p, directory)
	if err != nil {
		return err
	}
	if err = check("sigterm-drains-active-worker", report.Shutdown["passed"] == true, "Actual broker SIGTERM cancels the active request and waits until its Docker worker and tmpfs volume are absent before exiting"); err != nil {
		return err
	}
	// Check only containers carrying this fixture's policy identity; no global cleanup.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	configurationRaw := marshal(p)
	filters := map[string][]string{"label": {"io.testifysec.hardened.policy=" + hash(configurationRaw)}}
	var remaining []json.RawMessage
	query := "/containers/json?all=1&filters=" + strings.ReplaceAll(urlQuery(marshal(filters)), "+", "%20")
	if err = newEngine(*socket).call(ctx, "GET", query, nil, &remaining); err != nil {
		return err
	}
	if err = check("no-worker-containers-remain", len(remaining) == 0, "Only this fixture's worker identity is inspected; all workers were removed"); err != nil {
		return err
	}
	var volumes struct{ Volumes []json.RawMessage }
	if err = newEngine(*socket).call(ctx, "GET", "/volumes?filters="+urlQuery(marshal(filters)), nil, &volumes); err != nil {
		return err
	}
	return check("no-workspace-volumes-remain", len(volumes.Volumes) == 0, "The broker removed all temporary workspace tmpfs volumes for this fixture policy")
}

// Internal native fixture, invoked only inside the UAT worker with its fixed
// workspace. Docker's archive omission must be observed and documented, not
// mistaken for proof that the complete filesystem has no special entries.
func artifactSocketUAT() error {
	if runtime.GOOS != "linux" || os.Getuid() != 65534 {
		return deny("fixture_only", "Socket fixture requires the isolated Linux worker UID")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: "/workspace/omitted-socket", Net: "unix"})
	if err != nil {
		return err
	}
	listener.SetUnlinkOnClose(false)
	return listener.Close()
}

func verifyArtifactUAT(answer result, expected map[string][]byte, removed []string) error {
	if answer.Status != "completed" || answer.ExitCode != 0 || answer.Artifact == nil {
		return fmt.Errorf("artifact missing: status=%s code=%s message=%s", answer.Status, answer.Code, answer.Message)
	}
	artifact := answer.Artifact
	payload, err := base64.StdEncoding.Strict().DecodeString(artifact.PayloadBase64)
	if err != nil || hash(payload) != artifact.SHA256 {
		return fmt.Errorf("artifact payload digest mismatch")
	}
	var bundle workspaceBundle
	if json.Unmarshal(payload, &bundle) != nil || bundle.MaterialsSHA256 != answer.MaterialsSHA256 || hash(marshal(answer.Materials)) != bundle.MaterialsSHA256 || hash(marshal(bundle.Files)) != bundle.FinalManifestSHA256 || artifact.FinalManifestSHA256 != bundle.FinalManifestSHA256 || len(bundle.Changes) != len(expected) || len(bundle.Removed) != len(removed) {
		return fmt.Errorf("artifact manifest or diff mismatch")
	}
	for _, change := range bundle.Changes {
		content, err := base64.StdEncoding.Strict().DecodeString(change.ContentBase64)
		want, found := expected[change.Path]
		if err != nil || !found || !bytes.Equal(content, want) || hash(content) != change.SHA256 || int64(len(content)) != change.Size {
			return fmt.Errorf("artifact content mismatch for %s", change.Path)
		}
	}
	for i, name := range removed {
		if bundle.Removed[i] != name {
			return fmt.Errorf("artifact removal mismatch")
		}
	}
	return nil
}
func urlQuery(raw []byte) string {
	var result strings.Builder
	for _, b := range raw {
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_' || b == '.' || b == '~' {
			result.WriteByte(b)
		} else {
			fmt.Fprintf(&result, "%%%02X", b)
		}
	}
	return result.String()
}
