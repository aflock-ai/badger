package vzbackend

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"
)

type backendReference struct {
	Kind           string `json:"kind"`
	ManifestSHA256 string `json:"manifestSha256"`
}
type admissionProfile struct {
	ProfileID    string           `json:"profileId"`
	TenantID     string           `json:"tenantId"`
	DeploymentID string           `json:"deploymentId"`
	Sequence     uint64           `json:"sequence"`
	NotBefore    string           `json:"notBefore"`
	ExpiresAt    string           `json:"expiresAt"`
	Backend      backendReference `json:"backend"`
}
type admissionOutput struct {
	SchemaVersion  int              `json:"schemaVersion"`
	Admitted       bool             `json:"admitted"`
	Scope          string           `json:"scope"`
	Profile        admissionProfile `json:"profile"`
	EnvelopeSHA256 string           `json:"envelopeSha256"`
	PayloadSHA256  string           `json:"payloadSha256"`
	SignerKeyIDs   []string         `json:"signerKeyIds"`
	TrustSHA256    string           `json:"trustSha256"`
	NativeSHA256   string           `json:"nativeSha256"`
}
type validity struct{ notBefore, expires time.Time }

var secondUTC = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)

func (v *Verifier) validateAdmission(raw, envelope []byte) (validity, error) {
	var a admissionOutput
	if strict(raw, &a) != nil {
		return validity{}, refused("admission_output")
	}
	if a.SchemaVersion != 2 || !a.Admitted || a.Scope != "profile-admission-only" || a.EnvelopeSHA256 != hash(envelope) || a.PayloadSHA256 != v.assignment.ProfileSHA256 {
		return validity{}, refused("admission_binding")
	}
	if a.Profile.TenantID != v.assignment.TenantID || a.Profile.DeploymentID != v.assignment.DeploymentID || a.Profile.ProfileID != v.assignment.ProfileID || a.Profile.Backend.Kind != backendKind || a.Profile.Backend.ManifestSHA256 != v.assignment.ManifestSHA256 {
		return validity{}, refused("admission_assignment")
	}
	if !validAdmissionMetadata(a) {
		return validity{}, refused("admission_output")
	}
	return admissionValidity(a.Profile)
}
func admissionValidity(profile admissionProfile) (validity, error) {
	start, err := time.Parse(time.RFC3339, profile.NotBefore)
	end, e := time.Parse(time.RFC3339, profile.ExpiresAt)
	now := time.Now()
	if err != nil || e != nil || !secondUTC.MatchString(profile.NotBefore) || !secondUTC.MatchString(profile.ExpiresAt) || !end.After(start) || now.Before(start) || !now.Before(end) {
		return validity{}, refused("profile_expired")
	}
	return validity{start, end}, nil
}

func validAdmissionMetadata(a admissionOutput) bool {
	if a.Profile.Sequence < 1 || a.Profile.Sequence > 9007199254740991 || !hexDigest.MatchString(a.TrustSHA256) || !hexDigest.MatchString(a.NativeSHA256) || len(a.SignerKeyIDs) < 1 || len(a.SignerKeyIDs) > 16 {
		return false
	}
	seen := map[string]bool{}
	for _, key := range a.SignerKeyIDs {
		if !hexDigest.MatchString(key) || seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}

type boundedOutput struct {
	buffer   bytes.Buffer
	cancel   context.CancelFunc
	overflow bool
}

func (b *boundedOutput) Write(data []byte) (int, error) {
	if len(data) > 16<<10-b.buffer.Len() {
		b.overflow = true
		b.cancel()
		return 0, io.ErrShortWrite
	}
	return b.buffer.Write(data)
}
func (v *Verifier) admit(ctx context.Context, envelope []byte, working string) (_ validity, resultErr error) {
	c, err := openCustody(filepath.Dir(v.assignment.AdmissionExecutable), false)
	if err != nil {
		return validity{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, c.close()) }()
	name := filepath.Base(v.assignment.AdmissionExecutable)
	file, before, err := openChecked(c.root(), name, true)
	if err != nil {
		return validity{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	observed, err := stream(ctx, io.Discard, file, 64<<20)
	if err != nil {
		return validity{}, err
	}
	if observed.SHA256 != v.assignment.AdmissionSHA256 {
		return validity{}, refused("admission_digest")
	}
	if err = checkFile(c.root(), name, file, before); err != nil {
		return validity{}, err
	}
	if err = c.check(); err != nil {
		return validity{}, err
	}
	output, err := runAdmission(ctx, v.assignment.AdmissionExecutable, working, envelope)
	if err != nil {
		return validity{}, err
	}
	if err = checkFile(c.root(), name, file, before); err != nil {
		return validity{}, err
	}
	if err = c.check(); err != nil {
		return validity{}, err
	}
	return v.validateAdmission(output, envelope)
}
func runAdmission(ctx context.Context, executable, working string, envelope []byte) ([]byte, error) {
	run, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output := &boundedOutput{cancel: cancel}
	command := exec.CommandContext(run, executable)
	command.Dir = working
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + working, "TMPDIR=" + working, "LANG=C"}
	command.Stdin = bytes.NewReader(envelope)
	command.Stdout = output
	command.Stderr = io.Discard
	command.WaitDelay = time.Second
	protectCommand(command)
	err := command.Run()
	cleanupErr := finishCommand(command)
	if err != nil || output.overflow || run.Err() != nil {
		return nil, errors.Join(refused("profile_denied"), cleanupErr)
	}
	if cleanupErr != nil {
		return nil, cleanupErr
	}
	return output.buffer.Bytes(), nil
}
