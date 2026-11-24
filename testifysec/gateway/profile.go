package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/aflock-ai/badger/testifysec/connectors/marking"
)

// admitted is what a request may rely on from the profile: when it expires, and under v3 (signed
// or unsigned) the marking this gateway is accredited for and each admitted connector's marking
// (nil before v3: no connector content is admitted).
type admitted struct {
	expires    time.Time
	accredited *marking.Marking
	connectors []marking.Marking
}

func profileConfiguration(c Config) error {
	if err := profileVersionConfiguration(c); err != nil {
		return err
	}
	if c.ProfileFile != "" {
		return unsignedProfileConfiguration(c)
	}
	if c.SignedProfileFile == "" && c.AdmissionExecutable == "" && c.AdmissionSHA256 == "" && c.DevelopmentLoopback {
		return nil
	}
	for _, path := range []string{c.SignedProfileFile, c.AdmissionExecutable} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("protected signed profile and native admission executable required")
		}
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(c.AdmissionSHA256) {
		return errors.New("native admission executable digest required")
	}
	return nil
}

type profileAdmission struct {
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

type admissionBuffer struct {
	bytes.Buffer
	cancel context.CancelFunc
}

func (b *admissionBuffer) Write(data []byte) (int, error) {
	if len(data) > 16384-b.Len() {
		b.cancel()
		return 0, io.ErrShortWrite
	}
	return b.Buffer.Write(data)
}

// Execute only the administrator-pinned, protected native admission launcher.
// It reuses the existing Rookery/typed-profile contract instead of interpreting
// profile signatures or policy controls in a second gateway implementation.
func checkProfile(ctx context.Context, c Config) (admitted, error) {
	if err := profileConfiguration(c); err != nil {
		return admitted{}, err
	}
	if c.ProfileFile != "" {
		profile, _, err := readUnsignedProfile(c, time.Now())
		return profile, err
	}
	if c.SignedProfileFile == "" {
		return admitted{}, nil // explicit local development fixture only
	}
	envelope, err := privateFile(c.SignedProfileFile, 65536)
	if err != nil || len(envelope) == 0 {
		return admitted{}, errors.New("signed profile unavailable")
	}
	if err := privateDirectory(filepath.Dir(c.AdmissionExecutable)); err != nil {
		return admitted{}, err
	}
	file, err := os.OpenFile(c.AdmissionExecutable, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return admitted{}, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 {
		file.Close()
		return admitted{}, errors.New("protected admission executable required")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 {
		file.Close()
		return admitted{}, errors.New("service-owned admission executable required")
	}
	hash := sha256.New()
	size, copyErr := io.Copy(hash, io.LimitReader(file, (64<<20)+1))
	file.Close()
	if copyErr != nil || size > 64<<20 || hex.EncodeToString(hash.Sum(nil)) != c.AdmissionSHA256 {
		return admitted{}, errors.New("admission executable digest mismatch")
	}
	working, err := os.MkdirTemp("", "hc-gateway-admission-")
	if err != nil {
		return admitted{}, err
	}
	defer os.RemoveAll(working)
	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output := &admissionBuffer{cancel: cancel}
	command := exec.CommandContext(operation, c.AdmissionExecutable)
	command.Dir = working
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + working, "TMPDIR=" + working, "LANG=C"}
	command.Stdin = bytes.NewReader(envelope)
	command.Stdout = output
	command.Stderr = io.Discard
	command.WaitDelay = time.Second
	if err := command.Run(); err != nil {
		return admitted{}, errors.New("native profile admission refused")
	}
	var result profileAdmission
	var accredited *marking.Marking
	var connectors []marking.Marking
	version := 1
	if c.Schema == gatewayV3 {
		version = 3
		var m marking.Marking
		result, m, connectors, err = decodeProfileV3(output.Bytes())
		accredited = &m
	} else if c.Schema == gatewayV2 {
		version = 2
		result, err = decodeProfileV2(output.Bytes(), *c.Backend)
	} else {
		err = strictJSON(output.Bytes(), &result)
	}
	if err != nil {
		return admitted{}, errors.New("invalid profile admission")
	}
	digest := sha256.Sum256(envelope)
	start, startErr := time.Parse(time.RFC3339, result.Profile.NotBefore)
	end, endErr := time.Parse(time.RFC3339, result.Profile.ExpiresAt)
	now := time.Now()
	if result.SchemaVersion != version || !result.Admitted || result.Scope != "profile-admission-only" ||
		result.EnvelopeSHA256 != hex.EncodeToString(digest[:]) || result.PayloadSHA256 != c.ProfileDigest ||
		result.Profile.TenantID != c.Tenant || len(result.SignerKeyIDs) == 0 || startErr != nil || endErr != nil ||
		!end.After(start) || now.Before(start) || !now.Before(end) {
		return admitted{}, errors.New("profile admission binding or validity refused")
	}
	return admitted{expires: end, accredited: accredited, connectors: connectors}, nil
}
