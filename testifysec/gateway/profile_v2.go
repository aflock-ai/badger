package main

import (
	"errors"
	"regexp"
)

const gatewayV2 = "testifysec.hardened-opencode.gateway/v2"

// This is a protected configuration assignment, never a worker request field.
// Matching a profile's backend reference does not observe or authorize VM boot.
type BackendAssignment struct {
	Kind           string `json:"kind"`
	ManifestSHA256 string `json:"manifestSha256"`
}

func profileVersionConfiguration(c Config) error {
	if c.Schema == gatewayV3 {
		if c.Backend != nil || (c.SignedProfileFile == "") == (c.ProfileFile == "") {
			return errors.New("gateway v3 requires exactly one profile, signed or unsigned, and no backend assignment")
		}
		return nil
	}
	if c.ProfileFile != "" {
		return errors.New("an unsigned profile requires gateway v3")
	}
	if c.Schema != gatewayV2 {
		if c.Backend != nil {
			return errors.New("backend assignment requires gateway v2")
		}
		return nil
	}
	if c.Backend == nil || c.Backend.Kind != "darwin-vz/v1" ||
		!regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(c.Backend.ManifestSHA256) || c.SignedProfileFile == "" {
		return errors.New("gateway v2 requires an assigned backend and signed profile")
	}
	return nil
}

type profileAdmissionV2 struct {
	SchemaVersion  int      `json:"schemaVersion"`
	Admitted       bool     `json:"admitted"`
	Scope          string   `json:"scope"`
	EnvelopeSHA256 string   `json:"envelopeSha256"`
	PayloadSHA256  string   `json:"payloadSha256"`
	SignerKeyIDs   []string `json:"signerKeyIds"`
	TrustSHA256    string   `json:"trustSha256"`
	NativeSHA256   string   `json:"nativeSha256"`
	Profile        struct {
		ProfileID    string            `json:"profileId"`
		TenantID     string            `json:"tenantId"`
		DeploymentID string            `json:"deploymentId"`
		Sequence     uint64            `json:"sequence"`
		NotBefore    string            `json:"notBefore"`
		ExpiresAt    string            `json:"expiresAt"`
		Backend      BackendAssignment `json:"backend"`
	} `json:"profile"`
}

func decodeProfileV2(raw []byte, assigned BackendAssignment) (profileAdmission, error) {
	var v2 profileAdmissionV2
	var result profileAdmission
	if err := strictV2(raw, &v2); err != nil {
		return result, err
	}
	if v2.SchemaVersion != 2 || v2.Profile.Backend != assigned {
		return result, errors.New("profile backend assignment refused")
	}
	result.SchemaVersion, result.Admitted, result.Scope = v2.SchemaVersion, v2.Admitted, v2.Scope
	result.EnvelopeSHA256, result.PayloadSHA256 = v2.EnvelopeSHA256, v2.PayloadSHA256
	result.SignerKeyIDs, result.TrustSHA256, result.NativeSHA256 = v2.SignerKeyIDs, v2.TrustSHA256, v2.NativeSHA256
	result.Profile.ProfileID, result.Profile.TenantID = v2.Profile.ProfileID, v2.Profile.TenantID
	result.Profile.DeploymentID, result.Profile.Sequence = v2.Profile.DeploymentID, v2.Profile.Sequence
	result.Profile.NotBefore, result.Profile.ExpiresAt = v2.Profile.NotBefore, v2.Profile.ExpiresAt
	return result, nil
}
