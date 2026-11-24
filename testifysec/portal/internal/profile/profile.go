// Package profile builds the signed profile payload that native admission
// (testifysec/managed/profile.ts) accepts. It emits that format; it does not define one.
package profile

import (
	"encoding/json"
	"errors"
	"regexp"
	"time"
)

// PayloadType is the DSSE payload type admission v1 requires.
const PayloadType = "application/vnd.testifysec.hardened-opencode.profile.v1+json"

// MaxSequence is the largest sequence admission accepts (a JavaScript safe integer).
const MaxSequence = 1<<53 - 1

// Controls are fixed in v1: admission refuses any other value.
type Controls struct {
	RuntimePackageDownloads bool   `json:"runtimePackageDownloads"`
	Execution               string `json:"execution"`
	Audit                   string `json:"audit"`
}

// Fixed is the only control set v1 admission accepts.
var Fixed = Controls{RuntimePackageDownloads: false, Execution: "broker-only", Audit: "required"}

// V1 is the signed payload, field for field. Field order is the order admission's fixtures use.
type V1 struct {
	SchemaVersion int      `json:"schemaVersion"`
	ProfileID     string   `json:"profileId"`
	TenantID      string   `json:"tenantId"`
	DeploymentID  string   `json:"deploymentId"`
	Sequence      uint64   `json:"sequence"`
	NotBefore     string   `json:"notBefore"`
	ExpiresAt     string   `json:"expiresAt"`
	Controls      Controls `json:"controls"`
}

var (
	identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	instant    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)
)

// ValidIdentifier is admission's identifier grammar.
func ValidIdentifier(s string) bool { return identifier.MatchString(s) }

// Instant parses admission's second-precision UTC form and refuses anything that does not
// round-trip (so 2026-02-30 and offsets are refused here rather than at the workstation).
func Instant(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || !instant.MatchString(s) || t.UTC().Format(time.RFC3339) != s {
		return time.Time{}, errors.New("instant must be YYYY-MM-DDTHH:MM:SSZ")
	}
	return t, nil
}

// Validate applies every rule admission applies to the payload alone. Assignment, rollback
// floor and the current time are checked by the caller against the deployment's trust.
func (p V1) Validate() error {
	if p.SchemaVersion != 1 {
		return errors.New("schemaVersion must be 1")
	}
	for _, id := range []string{p.ProfileID, p.TenantID, p.DeploymentID} {
		if !ValidIdentifier(id) {
			return errors.New("profileId, tenantId and deploymentId must be identifiers")
		}
	}
	if p.Sequence < 1 || p.Sequence > MaxSequence {
		return errors.New("sequence out of range")
	}
	start, err := Instant(p.NotBefore)
	if err != nil {
		return err
	}
	end, err := Instant(p.ExpiresAt)
	if err != nil {
		return err
	}
	if !end.After(start) {
		return errors.New("expiresAt must be after notBefore")
	}
	if p.Controls != Fixed {
		return errors.New("v1 controls are fixed")
	}
	return nil
}

// Payload returns the exact bytes to sign.
func (p V1) Payload() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(p)
}
