// jade:ring local

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// Runs only in a disposable Linux fixture with CAP_SETUID/CAP_SETGID. Those
// capabilities are never added to repository workers. No Docker socket is mounted.
func peerUAT() error {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		return fmt.Errorf("peer UAT requires its disposable Linux root fixture")
	}
	root, err := os.MkdirTemp("", "hc-peer-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	os.Chmod(root, 0755)
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		return err
	}
	verifier := filepath.Join(root, "trusted-verifier")
	if err = os.WriteFile(verifier, binary, 0755); err != nil {
		return err
	}
	source := filepath.Join(root, "source")
	os.Mkdir(source, 0755)
	p := policy{Schema: policySchema, ListenSocket: filepath.Join(root, "broker.sock"), DockerSocket: "/no-docker.sock", Image: "sha256:" + strings.Repeat("0", 64), Workspace: workspace{"peer", source}, Limits: limits{TimeoutSeconds: 1, OutputBytes: 1024, WorkspaceBytes: 1024, WorkspaceFiles: 10}, AllowedUIDs: []uint32{65534}, AdmissionExecutable: verifier, AdmissionSHA256: hash(binary), ProfileSHA256: strings.Repeat("0", 64), TenantID: "peer-tenant", DeploymentID: "peer-deployment", ProfileID: "peer-profile"}
	stop, err := launchFixture(p, root)
	if err != nil {
		return err
	}
	defer stop()
	raw := marshal(executionRequest{Schema: requestSchema, Workspace: "peer", Command: "true"})
	unauthorized, err := sendFixture(p.ListenSocket, raw)
	if err != nil || unauthorized.Code != "unauthorized_peer" {
		return fmt.Errorf("unassigned uid0 was not refused")
	}
	requestPath := filepath.Join(root, "request.json")
	os.WriteFile(requestPath, raw, 0644)
	command := exec.Command(executable, "execute", "--socket", p.ListenSocket, "--request", requestPath)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	err = command.Run()
	if err == nil {
		return fmt.Errorf("request without profile unexpectedly executed")
	}
	var admittedPeer result
	if json.Unmarshal(output.Bytes(), &admittedPeer) != nil || admittedPeer.Code != "profile_required" || admittedPeer.CallerUID != 65534 {
		return fmt.Errorf("kernel peer UID was not preserved: %s", output.String())
	}
	fmt.Println(string(marshal(map[string]any{"passed": true, "brokerUid": 0, "callerUid": admittedPeer.CallerUID, "unauthorizedCode": unauthorized.Code, "authorizedPeerReachedAdmission": true, "profileStillRequired": true, "authority": "Linux SO_PEERCRED", "qualification": "credential boundary fixture only; no ALPS claim"})))
	return nil
}

func runLinuxPeerFixture(ctx context.Context, e *engine, image, binary string) (map[string]any, error) {
	absolute, err := filepath.Abs(binary)
	if err != nil {
		return nil, err
	}
	absolute, err = filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(absolute)
	if err != nil {
		return nil, err
	}
	configuration := containerConfig{Image: image, User: "0:0", Entrypoint: []string{"/peer-broker"}, Cmd: []string{"peer-uat"}, Env: []string{"PATH=/usr/bin:/bin", "HOME=/tmp"}, WorkingDir: "/tmp", AttachStdout: true, AttachStderr: true}
	host := &configuration.HostConfig
	host.ReadonlyRootfs = true
	host.NetworkMode = "none"
	host.CapDrop = []string{"ALL"}
	host.CapAdd = []string{"SETUID", "SETGID"}
	host.SecurityOpt = []string{"no-new-privileges=true"}
	host.PidsLimit = 64
	host.Memory = 128 << 20
	host.MemorySwap = 128 << 20
	host.NanoCpus = 1_000_000_000
	host.LogConfig.Type = "none"
	host.Tmpfs = map[string]string{"/tmp": "rw,nosuid,nodev,size=64m,mode=1777"}
	host.Mounts = []mount{{Type: "bind", Source: absolute, Target: "/peer-broker", ReadOnly: true}}
	var created struct {
		ID string `json:"Id"`
	}
	if err = e.call(ctx, "POST", "/containers/create", configuration, &created); err != nil {
		return nil, err
	}
	if !validID(created.ID) {
		return nil, fmt.Errorf("invalid fixture ID")
	}
	defer e.remove(created.ID)
	bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	connection, reader, err := e.attach(bounded, created.ID)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	if err = e.call(bounded, "POST", "/containers/"+created.ID+"/start", nil, nil); err != nil {
		return nil, err
	}
	output, err := streamOutput(bounded, connection, reader, 128<<10)
	if err != nil {
		return nil, err
	}
	var waited struct{ StatusCode int }
	if err = e.call(bounded, "POST", "/containers/"+created.ID+"/wait", nil, &waited); err != nil {
		return nil, err
	}
	if waited.StatusCode != 0 {
		return nil, fmt.Errorf("Linux peer fixture failed: %s", output)
	}
	var receipt map[string]any
	if err = json.Unmarshal(output, &receipt); err != nil {
		return nil, err
	}
	receipt["binarySha256"] = hash(raw)
	return receipt, nil
}
