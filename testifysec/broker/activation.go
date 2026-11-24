package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"regexp"
	"time"

	"github.com/aflock-ai/badger/testifysec/broker/activation"
)

// activationPolicy pins the management backend by its root CAs and names this device's state
// directory and key. With it the broker's profile pin is the digest the latest admitted
// activation record names, kept in the device's state (testifysec/PORTAL.md).
type activationPolicy struct {
	StateDir        string   `json:"stateDir"`
	RootCAs         []string `json:"rootCas"`
	SignerSAN       string   `json:"signerSan"`
	DeviceKeySHA256 string   `json:"deviceKeySpkiSha256"`
	// The compiled floor a freshly installed device starts from.
	ActivationFloor uint64 `json:"activationFloor"`
	ProfileFloor    uint64 `json:"profileFloor"`
}

var deviceKeyDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

func activationTrust(p policy) (activation.Trust, error) {
	a := p.Activation
	t := activation.Trust{SAN: a.SignerSAN, TenantID: p.TenantID, DeploymentID: p.DeploymentID, ProfileID: p.ProfileID, DeviceKeySHA256: a.DeviceKeySHA256}
	if len(a.RootCAs) == 0 || len(a.RootCAs) > 8 || a.SignerSAN == "" || len(a.SignerSAN) > 1024 || !deviceKeyDigest.MatchString(a.DeviceKeySHA256) || a.ActivationFloor > 1<<53-1 || a.ProfileFloor > 1<<53-1 {
		return t, errors.New("invalid activation policy")
	}
	for _, encoded := range a.RootCAs {
		block, rest := pem.Decode([]byte(encoded))
		if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
			return t, errors.New("invalid root CA")
		}
		root, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !root.IsCA || !root.BasicConstraintsValid {
			return t, errors.New("invalid root CA")
		}
		t.Roots = append(t.Roots, root)
	}
	return t, nil
}

// activate applies a request's reset and activation records, in that order, to the device's
// durable state, then returns the policy to admit the profile under: pinned to the activated
// digest, with the profile high-water as its sequence floor. A record that is refused refuses the
// request; with no usable state (not installed, or activated and the state lost) every request is
// refused until a reset record for this device is admitted.
func activate(p policy, request executionRequest, now time.Time) (policy, error) {
	trust, err := activationTrust(p)
	if err != nil {
		return p, deny("invalid_policy", "Activation policy is invalid")
	}
	store, err := activation.Open(p.Activation.StateDir, activation.State{ActivationHighWater: p.Activation.ActivationFloor, ProfileHighWater: p.Activation.ProfileFloor})
	if err != nil {
		return p, deny("activation_state", "Device activation state is unavailable")
	}
	defer store.Close()
	for _, record := range []string{request.ResetEnvelope, request.ActivationEnvelope} {
		if record == "" {
			continue
		}
		if _, err = store.Apply(trust, []byte(record), now); err != nil {
			return p, deny("activation_refused", "Signed activation or reset record refused: "+refusalKind(err))
		}
	}
	state, err := store.Load()
	if err != nil || state.ProfileSHA256 == "" {
		return p, deny("activation_required", "No admitted activation record pins a profile on this device")
	}
	p.ProfileSHA256, p.activatedSequence, p.activated = state.ProfileSHA256, state.ProfileHighWater, true
	return p, nil
}

func refusalKind(err error) string {
	var r activation.Refusal
	if errors.As(err, &r) {
		return string(r)
	}
	return "io"
}
