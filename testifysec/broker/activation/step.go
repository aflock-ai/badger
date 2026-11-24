package activation

import "time"

// State is a device's high-water counters and the profile digest it runs: Backends.DState.
type State struct {
	ProfileHighWater    uint64 `json:"profileHighWater"`
	ActivationHighWater uint64 `json:"activationHighWater"`
	ResetHighWater      uint64 `json:"resetHighWater"`
	ProfileSHA256       string `json:"profileSha256"`
}

// Step is Backends.step after the chain check (Verify): the clock, then the assignment, then the
// high-water. An activation must be strictly above the activation high-water and at or above the
// profile high-water, and moves the pinned digest; a reset for this device must be above the reset
// high-water and sets both counters to its floors. A refused record leaves the state as it was.
func Step(t Trust, s State, now time.Time, r Record) (State, error) {
	if now.Before(r.NotBefore) || !now.Before(r.ExpiresAt) {
		return s, RefuseExpired
	}
	switch {
	case r.Activation != nil:
		a := r.Activation
		if a.TenantID != t.TenantID || a.DeploymentID != t.DeploymentID || a.ProfileID != t.ProfileID {
			return s, RefuseAssignment
		}
		if s.ActivationHighWater >= a.Sequence || s.ProfileHighWater > a.ProfileSequence {
			return s, RefuseRollback
		}
		s.ActivationHighWater, s.ProfileHighWater, s.ProfileSHA256 = a.Sequence, a.ProfileSequence, a.ProfileSHA256
	case r.Reset != nil:
		x := r.Reset
		if x.TenantID != t.TenantID || x.DeploymentID != t.DeploymentID || x.DeviceKeySHA256 != t.DeviceKeySHA256 {
			return s, RefuseAssignment
		}
		if s.ResetHighWater >= x.ResetSequence {
			return s, RefuseRollback
		}
		s.ResetHighWater, s.ProfileHighWater, s.ActivationHighWater = x.ResetSequence, x.ProfileFloor, x.ActivationFloor
	default:
		return s, RefuseMalformed
	}
	return s, nil
}

// AdmitProfile is the profile high-water rule (Spec.admit, the `admissionSequence` vectors): a
// profile sequence below the high-water is a rollback; anything else is admitted and becomes the
// high-water.
func AdmitProfile(s State, sequence uint64) (State, error) {
	if sequence < s.ProfileHighWater {
		return s, RefuseRollback
	}
	s.ProfileHighWater = sequence
	return s, nil
}
