package vzbackend

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type runConfig struct {
	Schema                string     `json:"schema"`
	Kernel                string     `json:"kernel"`
	KernelSHA256          string     `json:"kernelSha256"`
	RootDisk              string     `json:"rootDisk"`
	RootDiskSHA256        string     `json:"rootDiskSha256"`
	JobFile               string     `json:"jobFile"`
	JobSHA256             string     `json:"jobSha256"`
	Binding               RunBinding `json:"binding"`
	MemoryMiB             int        `json:"memoryMiB"`
	CPUs                  int        `json:"cpus"`
	TimeoutSeconds        int        `json:"timeoutSeconds"`
	GatewayConfigFile     string     `json:"gatewayConfigFile"`
	GatewayConfigSHA256   string     `json:"gatewayConfigSha256"`
	BackendManifestSHA256 string     `json:"backendManifestSha256"`
}

func (p *Prepared) createRunFiles(ctx context.Context, request RunRequest, expected runExpected) error {
	stage, err := newStage(ctx, p.assignment.StagingDirectory)
	if err != nil {
		return err
	}
	stage.ownedNames = []string{"job.json", "gateway.json", "config.json"}
	p.mu.Lock()
	p.runStage = stage
	p.mu.Unlock()
	gateway, err := p.readGateway(ctx, request)
	if err != nil {
		return err
	}
	config := runConfig{"testifysec.vm-config/v4", filepath.Join(p.path, "kernel"), expected.KernelSHA256, filepath.Join(p.path, "root.ext4"), expected.RootDiskSHA256, filepath.Join(stage.path, "job.json"), expected.JobSHA256, expected.Binding, 1024, 1, request.TimeoutSeconds + 10, filepath.Join(stage.path, "gateway.json"), request.GatewayConfigSHA256, p.observation.ManifestSHA256}
	raw, err := json.Marshal(config)
	if err != nil || len(raw) > 4096 {
		return refused("run_config_bounds")
	}
	p.runConfigSHA256 = hash(raw)
	for _, file := range []struct {
		name  string
		bytes []byte
	}{{"job.json", expected.JobJSON}, {"gateway.json", gateway}, {"config.json", raw}} {
		if err = writeRunFile(stage.root, file.name, file.bytes); err != nil {
			return err
		}
		p.runInputs = append(p.runInputs, role{name: file.name, file: File{hash(file.bytes), int64(len(file.bytes))}, limit: int64(len(file.bytes))})
	}
	return stage.checkDirectory()
}
func writeRunFile(root *os.Root, name string, raw []byte) (resultErr error) {
	file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	if _, err = file.Write(raw); err != nil {
		return err
	}
	return file.Chmod(0400)
}
func (p *Prepared) readGateway(ctx context.Context, request RunRequest) (raw []byte, resultErr error) {
	if !absolute(request.GatewayConfigFile) || !hexDigest.MatchString(request.GatewayConfigSHA256) {
		return nil, refused("run_gateway_assignment")
	}
	c, err := openCustody(filepath.Dir(request.GatewayConfigFile), true)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, c.close()) }()
	info, err := c.root().Lstat(filepath.Base(request.GatewayConfigFile))
	if err != nil || info.Mode().Perm()&0077 != 0 {
		return nil, refused("run_gateway_custody")
	}
	raw, err = readBounded(ctx, c.root(), filepath.Base(request.GatewayConfigFile), 32<<10)
	if err != nil {
		return nil, err
	}
	if hash(raw) != request.GatewayConfigSHA256 {
		return nil, refused("run_gateway_digest")
	}
	if err = p.validateGateway(raw, request.SessionID); err != nil {
		return nil, err
	}
	if err = c.check(); err != nil {
		return nil, err
	}
	return raw, nil
}
func (p *Prepared) validateGateway(raw []byte, session string) error {
	var object map[string]json.RawMessage
	if strictVM(raw, &object) != nil {
		return refused("run_gateway_json")
	}
	var schema, assignedSession, profile, socket string
	var backend backendReference
	if json.Unmarshal(object["schema"], &schema) != nil || json.Unmarshal(object["session"], &assignedSession) != nil || json.Unmarshal(object["profileDigest"], &profile) != nil || json.Unmarshal(object["socket"], &socket) != nil || strict(object["backend"], &backend) != nil {
		return refused("run_gateway_assignment")
	}
	if schema != "testifysec.hardened-opencode.gateway/v2" || assignedSession != session || profile != p.observation.ProfileSHA256 || backend.Kind != backendKind || backend.ManifestSHA256 != p.observation.ManifestSHA256 {
		return refused("run_gateway_assignment")
	}
	if !absolute(socket) || len(socket) >= 104 {
		return refused("run_gateway_socket")
	}
	return checkGatewaySocket(socket)
}
func checkGatewaySocket(socket string) (resultErr error) {
	c, err := openCustody(filepath.Dir(socket), true)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, c.close()) }()
	info, err := c.root().Lstat(filepath.Base(socket))
	if err != nil {
		return refused("run_gateway_socket")
	}
	uid, _, _, ok := fileIdentity(info)
	if !ok || uid != int64(os.Geteuid()) || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0666 {
		return refused("run_gateway_socket")
	}
	return c.check()
}

// The trusted admission child runs before this check. Revalidate exact generated
// bytes and the complete inventory; a changed input prevents host invocation.
func (p *Prepared) verifyRunFiles(ctx context.Context) error {
	if p.runStage == nil || len(p.runInputs) != 3 {
		return errCleanup
	}
	stage := p.runStage
	if err := stage.checkDirectory(); err != nil {
		return errors.Join(errCleanup, err)
	}
	if _, err := inventoryKnown(stage.root, true, stage.ownedNames); err != nil {
		return errors.Join(errCleanup, err)
	}
	for _, r := range p.runInputs {
		info, err := stage.root.Lstat(r.name)
		if err != nil || info.Mode().Perm() != 0400 {
			return errors.Join(errCleanup, refused("run_input_custody"))
		}
		if err = verifyRole(ctx, stage.root, r); err != nil {
			return errors.Join(errCleanup, err)
		}
	}
	if _, err := inventoryKnown(stage.root, true, stage.ownedNames); err != nil {
		return errors.Join(errCleanup, err)
	}
	return stage.checkDirectory()
}
