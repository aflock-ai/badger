// Package issue creates a signed profile version: validate, assign the next sequence, sign,
// store, audit. It is the only code path that uses the signing key.
package issue

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aflock-ai/badger/testifysec/portal/internal/profile"
	"github.com/aflock-ai/badger/testifysec/portal/internal/sign"
	"github.com/aflock-ai/badger/testifysec/portal/internal/store"
)

// MaxEnvelope is the broker's bound on a signed profile envelope.
const MaxEnvelope = 65536

// Request is what an administrator supplies; the portal assigns tenant and sequence. SchemaVersion
// left out is 1; 3 adds the gateway's marking and the admitted connectors, both required.
type Request struct {
	SchemaVersion int                 `json:"schemaVersion,omitempty"`
	ProfileID     string              `json:"profileId"`
	DeploymentID  string              `json:"deploymentId"`
	NotBefore     string              `json:"notBefore"`
	ExpiresAt     string              `json:"expiresAt"`
	Gateway       *profile.Gateway    `json:"gateway,omitempty"`
	Connectors    []profile.Connector `json:"connectors,omitempty"`
}

// Invalid is a request error the API reports as 400.
type Invalid struct{ Reason string }

func (e Invalid) Error() string { return e.Reason }

type Issuer struct {
	TenantID        string
	MinimumSequence uint64 // the floor compiled into this deployment's admission trust
	Signers         []sign.Signer
	Profiles        store.ProfileStore
	Assignments     store.AssignmentStore
	Audit           store.AuditSink
	Now             func() time.Time
	mu              sync.Mutex
}

func (i *Issuer) Issue(actor, role string, r Request) (store.Version, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if !profile.ValidIdentifier(r.ProfileID) || !profile.ValidIdentifier(r.DeploymentID) {
		return store.Version{}, Invalid{"profileId and deploymentId must be identifiers"}
	}
	last, ok, err := i.Profiles.Latest(r.ProfileID)
	if err != nil {
		return store.Version{}, err
	}
	next := i.MinimumSequence
	if ok {
		if last.DeploymentID != r.DeploymentID {
			return store.Version{}, Invalid{"profileId is assigned to another deployment"}
		}
		next = max(next, last.Sequence+1)
	}
	payloadType, payload, err := i.payload(r, next)
	if err != nil {
		return store.Version{}, Invalid{err.Error()}
	}
	if payloadType == profile.PayloadTypeV3 && admissionSize(payload, len(i.Signers)) > MaxAdmissionOutput {
		return store.Version{}, Invalid{"profile too large: its admission would exceed gateway v3's 16 KiB bound"}
	}
	env, err := sign.Envelop(payloadType, payload, i.Signers...)
	if err != nil {
		return store.Version{}, err
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return store.Version{}, err
	}
	if len(raw) > MaxEnvelope {
		return store.Version{}, Invalid{"signed envelope exceeds the broker's 64 KiB bound"}
	}
	v := store.Version{ProfileID: r.ProfileID, TenantID: i.TenantID, DeploymentID: r.DeploymentID, Sequence: next,
		NotBefore: r.NotBefore, ExpiresAt: r.ExpiresAt, PayloadSHA256: hash(payload), EnvelopeSHA256: hash(raw),
		CreatedAt: i.Now().UTC(), CreatedBy: actor, Envelope: raw}
	for _, s := range env.Signatures {
		v.SignerKeyIDs = append(v.SignerKeyIDs, s.KeyID)
	}
	rec := store.Record{Time: v.CreatedAt, Actor: actor, Role: role, Action: "profile.sign",
		Object: fmt.Sprintf("profile/%s/%d", v.ProfileID, v.Sequence), After: v.EnvelopeSHA256}
	if ok {
		rec.Before = last.EnvelopeSHA256
	}
	// Audit before storing: a version is never servable without its record. A failed Put leaves
	// a record of an attempt whose digest matches nothing stored, which is the safe side.
	if err = i.Audit.Append(rec); err != nil {
		return store.Version{}, err
	}
	if err = i.Profiles.Put(v); errors.Is(err, store.ErrExists) {
		return store.Version{}, fmt.Errorf("sequence %d already issued: %w", next, err)
	} else if err != nil {
		return store.Version{}, err
	}
	return v, nil
}

// payload builds and validates the signed payload the request asks for.
func (i *Issuer) payload(r Request, sequence uint64) (string, []byte, error) {
	switch r.SchemaVersion {
	case 0, 1:
		if r.Gateway != nil || r.Connectors != nil {
			return "", nil, errors.New("gateway and connectors need schemaVersion 3")
		}
		p := profile.V1{SchemaVersion: 1, ProfileID: r.ProfileID, TenantID: i.TenantID, DeploymentID: r.DeploymentID,
			Sequence: sequence, NotBefore: r.NotBefore, ExpiresAt: r.ExpiresAt, Controls: profile.Fixed}
		b, err := p.Payload()
		return profile.PayloadType, b, err
	case 3:
		if r.Gateway == nil || r.Connectors == nil {
			return "", nil, errors.New("schemaVersion 3 needs gateway and connectors ([] for none)")
		}
		p := profile.V3{SchemaVersion: 3, ProfileID: r.ProfileID, TenantID: i.TenantID, DeploymentID: r.DeploymentID,
			Sequence: sequence, NotBefore: r.NotBefore, ExpiresAt: r.ExpiresAt, Controls: profile.Fixed,
			Gateway: *r.Gateway, Connectors: r.Connectors}
		b, err := p.Payload()
		return profile.PayloadTypeV3, b, err
	}
	return "", nil, errors.New("schemaVersion must be 1 or 3")
}

// MaxAdmissionOutput is gateway v3's bound on what native admission prints (admissionBuffer in
// testifysec/gateway/profile.go): admission prints the admitted profile back, so a v3 payload
// that fits the envelope bound can still be one the gateway never reads.
const MaxAdmissionOutput = 16384

// admissionSize is the length of the line admission-cli.ts prints for this payload: the profile
// without schemaVersion and controls, and fixed-length digests. Go's encoding is never shorter
// than JSON.stringify's for these values (it also escapes <, > and &), so this is an upper bound.
func admissionSize(payload []byte, signers int) int {
	var p struct {
		ProfileID    string          `json:"profileId"`
		TenantID     string          `json:"tenantId"`
		DeploymentID string          `json:"deploymentId"`
		Sequence     uint64          `json:"sequence"`
		NotBefore    string          `json:"notBefore"`
		ExpiresAt    string          `json:"expiresAt"`
		Gateway      json.RawMessage `json:"gateway"`
		Connectors   json.RawMessage `json:"connectors"`
	}
	if json.Unmarshal(payload, &p) != nil {
		return math.MaxInt // never: payload is this package's own encoding
	}
	digest := strings.Repeat("0", 64)
	out, err := json.Marshal(map[string]any{"schemaVersion": 3, "admitted": true, "scope": "profile-admission-only", "profile": p,
		"envelopeSha256": digest, "payloadSha256": digest, "signerKeyIds": slices.Repeat([]string{digest}, signers),
		"trustSha256": digest, "nativeSha256": digest})
	if err != nil {
		return math.MaxInt
	}
	return len(out) + 1 // and the newline
}

// Missing is reported as 404; Rollback as 409.
var (
	Missing  = errors.New("no such profile version")
	Rollback = errors.New("a deployment never moves to an older version; sign a new one")
)

// Assign points a deployment at one signed version of its profile. Only forward: rolling back
// is signing the old content again as a new, higher version (PORTAL.md).
func (i *Issuer) Assign(actor, role, deploymentID, profileID string, sequence uint64) (store.Assignment, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if !profile.ValidIdentifier(deploymentID) || !profile.ValidIdentifier(profileID) {
		return store.Assignment{}, Invalid{"deploymentId and profileId must be identifiers"}
	}
	v, ok, err := i.Profiles.Get(profileID, sequence)
	if err != nil {
		return store.Assignment{}, err
	} else if !ok {
		return store.Assignment{}, Missing
	}
	if v.DeploymentID != deploymentID {
		return store.Assignment{}, Invalid{"that profile is signed for another deployment"}
	}
	cur, assigned, err := i.Assignments.Assignment(deploymentID)
	if err != nil {
		return store.Assignment{}, err
	}
	if assigned && cur.ProfileID == profileID && cur.Sequence == sequence {
		return cur, nil
	}
	if assigned && (cur.ProfileID != profileID || cur.Sequence > sequence) {
		return store.Assignment{}, Rollback
	}
	a := store.Assignment{DeploymentID: deploymentID, ProfileID: profileID, Sequence: sequence,
		PayloadSHA256: v.PayloadSHA256, AssignedAt: i.Now().UTC(), AssignedBy: actor}
	rec := store.Record{Time: a.AssignedAt, Actor: actor, Role: role, Action: "deployment.assign",
		Object: "deployment/" + deploymentID, After: v.PayloadSHA256}
	if assigned {
		rec.Before = cur.PayloadSHA256
	}
	if err = i.Audit.Append(rec); err != nil {
		return store.Assignment{}, err
	}
	if err := i.Assignments.PutAssignment(a); err != nil {
		if errors.Is(err, store.ErrRollback) {
			return store.Assignment{}, Rollback
		}
		return store.Assignment{}, err
	}
	return a, nil
}

// Trust is the build-provisioned admission trust input (testifysec/managed/README.md) for
// a version: this portal's keys, its assignment, and its sequence as the floor.
func (i *Issuer) Trust(v store.Version) map[string]any {
	keys := make([]string, 0, len(i.Signers))
	for _, k := range i.Signers {
		keys = append(keys, string(k.PublicKeyPEM()))
	}
	return map[string]any{"schemaVersion": schemaOf(v), "publicKeys": keys, "threshold": len(keys),
		"tenantId": v.TenantID, "deploymentId": v.DeploymentID, "profileId": v.ProfileID, "minimumSequence": v.Sequence}
}

// schemaOf is the profile schema of a stored version, read from its envelope's payload type: the
// trust input must name the same schema, since admission is built for one. A version without a
// readable envelope gets 0, which the build refuses as a trust input.
func schemaOf(v store.Version) int {
	var env struct{ PayloadType string }
	if json.Unmarshal(v.Envelope, &env) != nil {
		return 0
	}
	switch env.PayloadType {
	case profile.PayloadType:
		return 1
	case profile.PayloadTypeV3:
		return 3
	}
	return 0
}

func hash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
