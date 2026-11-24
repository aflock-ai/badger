package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

type admissionOutput struct {
	SchemaVersion  int      `json:"schemaVersion"`
	Admitted       bool     `json:"admitted"`
	Scope          string   `json:"scope"`
	Reason         string   `json:"reason,omitempty"`
	EnvelopeSHA256 string   `json:"envelopeSha256,omitempty"`
	PayloadSHA256  string   `json:"payloadSha256,omitempty"`
	SignerKeyIDs   []string `json:"signerKeyIds,omitempty"`
	TrustSHA256    string   `json:"trustSha256,omitempty"`
	NativeSHA256   string   `json:"nativeSha256,omitempty"`
	Profile        struct {
		ProfileID    string `json:"profileId"`
		TenantID     string `json:"tenantId"`
		DeploymentID string `json:"deploymentId"`
		Sequence     uint64 `json:"sequence"`
		NotBefore    string `json:"notBefore"`
		ExpiresAt    string `json:"expiresAt"`
	} `json:"profile"`
}
type cappedOutput struct {
	buffer   bytes.Buffer
	cancel   context.CancelFunc
	overflow bool
}

func (w *cappedOutput) Write(raw []byte) (int, error) {
	if len(raw) > inputLimit-w.buffer.Len() {
		w.overflow = true
		w.cancel()
		return 0, io.ErrShortWrite
	}
	return w.buffer.Write(raw)
}

func verifyAdmission(ctx context.Context, p policy, envelope string) (string, error) {
	if p.AdmissionExecutable == "" {
		// Running with no profile at all exists only in a build tagged uatnoprofile
		// (admission_uat.go); in every other build developmentNoProfile is the constant false
		// and this branch always refuses.
		if !developmentNoProfile || !p.DevelopmentAllowSameUID || envelope != "" {
			return "", deny("profile_required", "No qualified profile verifier is configured")
		}
		return "", nil
	}
	if envelope == "" || len(envelope) > 65536 {
		return "", deny("profile_required", "A bounded signed profile envelope is required")
	}
	// The only host child is this exact administrator-pinned native verifier.
	// Repository code and arbitrary caller executables are never launched here.
	root, err := secureRoot(filepath.Dir(p.AdmissionExecutable))
	if err != nil {
		return "", err
	}
	defer root.Close()
	parent, err := root.Stat(".")
	if err != nil || !ownedPrivate(parent, false) {
		return "", deny("unsafe_verifier", "Admission bundle directory is not protected")
	}
	before, err := root.Lstat(filepath.Base(p.AdmissionExecutable))
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0022 != 0 || before.Mode().Perm()&0111 == 0 {
		return "", deny("unsafe_verifier", "Admission executable is not protected")
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 {
		return "", deny("unsafe_verifier", "Admission executable is not broker-owned")
	}
	file, err := root.OpenFile(filepath.Base(p.AdmissionExecutable), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	opened, err := file.Stat()
	if err != nil || !stable(before, opened) {
		file.Close()
		return "", deny("unsafe_verifier", "Admission executable changed")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 64<<20+1))
	after, statErr := file.Stat()
	file.Close()
	if err != nil || statErr != nil || !stable(opened, after) || len(raw) > 64<<20 || hash(raw) != p.AdmissionSHA256 {
		return "", deny("verifier_digest_mismatch", "Native admission executable does not match policy")
	}
	working, err := os.MkdirTemp("", "hc-native-admission-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(working)
	run, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output := &cappedOutput{cancel: cancel}
	command := exec.CommandContext(run, p.AdmissionExecutable)
	command.Dir = working
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + working, "TMPDIR=" + working, "LANG=C"}
	command.Stdin = bytes.NewBufferString(envelope)
	command.Stdout = output
	command.Stderr = io.Discard
	command.WaitDelay = time.Second
	if err = command.Run(); err != nil || output.overflow {
		return "", deny("profile_denied", "Native verifier rejected the profile or was unavailable")
	}
	var admission admissionOutput
	if err = strict(output.buffer.Bytes(), &admission); err != nil {
		return "", deny("profile_denied", "Native verifier returned invalid admission")
	}
	notBefore, startErr := time.Parse(time.RFC3339, admission.Profile.NotBefore)
	expires, endErr := time.Parse(time.RFC3339, admission.Profile.ExpiresAt)
	now := time.Now()
	if admission.SchemaVersion != 1 || !admission.Admitted || admission.Scope != "profile-admission-only" || admission.EnvelopeSHA256 != hash([]byte(envelope)) || admission.PayloadSHA256 != p.ProfileSHA256 || len(admission.SignerKeyIDs) == 0 || startErr != nil || endErr != nil || now.Before(notBefore) || !now.Before(expires) || !expires.After(notBefore) {
		return "", deny("profile_denied", "Profile admission is expired, unbound, or not assigned to this policy")
	}
	// The native verifier checks the assignment against the trust compiled into it; the broker
	// checks it again against its own policy, so a verifier built for another tenant, deployment
	// or profile cannot admit here even when the payload digest is pinned.
	if !assigned(p, admission) {
		return "", deny("profile_denied", "Profile is not assigned to this tenant, deployment and profile")
	}
	return admission.PayloadSHA256, nil
}

// assigned also binds, under activation records, the admitted profile's sequence to exactly the
// one the activation names (its profile high-water): a profile above it would leave the durable
// floor below the profile that ran, and a later activation could roll back to it.
func assigned(p policy, a admissionOutput) bool {
	return a.Profile.TenantID == p.TenantID && a.Profile.DeploymentID == p.DeploymentID && a.Profile.ProfileID == p.ProfileID && a.Profile.Sequence >= 1 && a.Profile.Sequence <= 9007199254740991 && (!p.activated || a.Profile.Sequence == p.activatedSequence)
}
