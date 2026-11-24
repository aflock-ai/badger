package vzbackend

import (
	"encoding/json"
	"regexp"
	"time"
	"unicode/utf8"
)

var runSession = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

type runCommand struct {
	Prompt         string `json:"prompt"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
}
type runJob struct {
	Schema    string          `json:"schema"`
	Binding   RunBinding      `json:"binding"`
	Request   json.RawMessage `json:"request"`
	Materials json.RawMessage `json:"materials"`
}

func (p *Prepared) buildRunJob(request RunRequest) (runExpected, error) {
	var expected runExpected
	if !runSession.MatchString(request.SessionID) || !utf8.ValidString(request.Prompt) || len(request.Prompt) > 4096 || request.TimeoutSeconds < 1 || request.TimeoutSeconds > 45 || request.NotAfter.IsZero() || !time.Now().Before(request.NotAfter) {
		return expected, refused("run_request")
	}
	materials := make([]RunMaterial, len(request.Materials))
	copy(materials, request.Materials)
	if err := validateMaterials(materials); err != nil {
		return expected, err
	}
	command, _ := json.Marshal(runCommand{request.Prompt, request.TimeoutSeconds})
	files, _ := json.Marshal(materials)
	binding := RunBinding{hash(command), p.observation.ProfileSHA256, request.SessionID, hash(files), hash([]byte(p.observation.Files.Kernel.SHA256 + "\n" + p.observation.Files.RootDisk.SHA256 + "\n"))}
	raw, err := json.Marshal(runJob{"testifysec.vm-job/v3", binding, command, files})
	if err != nil || len(raw) > runJobLimit {
		return expected, refused("run_job_bounds")
	}
	expected = runExpected{Binding: binding, JobSHA256: hash(raw), JobJSON: raw, InitialManifestSHA256: materialManifest(materials), Materials: materials, KernelSHA256: p.observation.Files.Kernel.SHA256, RootDiskSHA256: p.observation.Files.RootDisk.SHA256, GatewayConfigSHA256: request.GatewayConfigSHA256}
	return expected, nil
}
