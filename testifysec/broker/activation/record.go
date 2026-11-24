// Package activation is the workstation side of the management plane's signed records: an
// activation record ("deployment X runs profile digest D at sequence N, valid until T") moves the
// broker's pinned profile digest, and a reset record, bound to one device key, is the only thing
// that lowers the device's high-water counters. It follows testifysec/PORTAL.md and the contract
// model's Backends.step (testifysec/formal/contract/Contract/Backends.lean), whose `backends`
// vectors its tests replay.
package activation

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"time"
)

const (
	ActivationType = "application/vnd.testifysec.badger.activation.v1+json"
	ResetType      = "application/vnd.testifysec.badger.reset.v1+json"
	maxSequence    = 1<<53 - 1
)

// Activation is the signed body of an activation record.
type Activation struct {
	TenantID, DeploymentID, ProfileID string
	ProfileSHA256                     string
	ProfileSequence, Sequence         uint64
}

// Reset is the signed body of a high-water reset record for one device key.
type Reset struct {
	TenantID, DeploymentID, DeviceKeySHA256 string
	ResetSequence, ProfileFloor             uint64
	ActivationFloor                         uint64
}

// Record is a verified record: exactly one of Activation and Reset, and its signed window.
type Record struct {
	Activation *Activation
	Reset      *Reset
	NotBefore  time.Time
	ExpiresAt  time.Time
}

var (
	identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	hexDigest  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	decimal    = regexp.MustCompile(`^(0|[1-9][0-9]{0,15})$`)
)

var errShape = errors.New("record does not match its schema")

// parseRecord reads a payload of the given type, exactly: no unknown, missing, duplicate or
// case-aliased field, canonical integers only, a window that ends after it starts.
func parseRecord(payloadType string, raw []byte) (Record, error) {
	keys := []string{"schemaVersion", "tenantId", "deploymentId", "notBefore", "expiresAt"}
	switch payloadType {
	case ActivationType:
		keys = append(keys, "profileId", "profileSha256", "profileSequence", "sequence")
	case ResetType:
		keys = append(keys, "deviceKeySpkiSha256", "resetSequence", "profileFloor", "activationFloor")
	default:
		return Record{}, errShape
	}
	f, err := fields(raw, keys...)
	if err != nil {
		return Record{}, err
	}
	p := parser{f: f}
	if p.number("schemaVersion", 1, 1) != 1 {
		p.err = errShape
	}
	r := Record{NotBefore: p.time("notBefore"), ExpiresAt: p.time("expiresAt")}
	tenant, deployment := p.match("tenantId", identifier), p.match("deploymentId", identifier)
	if payloadType == ActivationType {
		r.Activation = &Activation{TenantID: tenant, DeploymentID: deployment, ProfileID: p.match("profileId", identifier),
			ProfileSHA256: p.match("profileSha256", hexDigest), ProfileSequence: p.number("profileSequence", 1, maxSequence),
			Sequence: p.number("sequence", 1, maxSequence)}
	} else {
		r.Reset = &Reset{TenantID: tenant, DeploymentID: deployment, DeviceKeySHA256: p.match("deviceKeySpkiSha256", hexDigest),
			ResetSequence: p.number("resetSequence", 1, maxSequence), ProfileFloor: p.number("profileFloor", 0, maxSequence),
			ActivationFloor: p.number("activationFloor", 0, maxSequence)}
	}
	if p.err == nil && !r.ExpiresAt.After(r.NotBefore) {
		p.err = errShape
	}
	return r, p.err
}

type parser struct {
	f   map[string]json.RawMessage
	err error
}

// match reads a JSON string that pattern matches whole (anything, with a nil pattern).
func (p *parser) match(key string, pattern *regexp.Regexp) string {
	var s string
	if p.err == nil && (!bytes.HasPrefix(p.f[key], []byte(`"`)) || json.Unmarshal(p.f[key], &s) != nil || (pattern != nil && !pattern.MatchString(s))) {
		p.err = errShape
	}
	return s
}

func (p *parser) number(key string, low, high uint64) uint64 {
	if p.err != nil {
		return 0
	}
	n, err := strconv.ParseUint(string(p.f[key]), 10, 64)
	if !decimal.Match(p.f[key]) || err != nil || n < low || n > high {
		p.err = errShape
	}
	return n
}

// time reads YYYY-MM-DDTHH:MM:SSZ exactly: it must survive a round trip, so no offset, no
// fraction and no February 30. Nothing before 2000 is a real record, and refusing it keeps the zero
// time out: x509 verification reads a zero CurrentTime as "now", which would let a record's chain
// be checked at the wrong time.
func (p *parser) time(key string) time.Time {
	s := p.match(key, nil)
	t, err := time.Parse(time.RFC3339, s)
	if p.err == nil && (err != nil || t.UTC().Format(time.RFC3339) != s || t.Year() < 2000) {
		p.err = errShape
	}
	return t
}

// fields decodes one JSON object whose keys are exactly keys, each once.
func fields(raw []byte, keys ...string) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return nil, errShape
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		t, err := d.Token()
		key, ok := t.(string)
		if err != nil || !ok || out[key] != nil {
			return nil, errShape
		}
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			return nil, errShape
		}
		out[key] = value
	}
	if _, err := d.Token(); err != nil {
		return nil, errShape
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errShape // trailing input
	}
	if len(out) != len(keys) {
		return nil, errShape
	}
	for _, key := range keys {
		if out[key] == nil {
			return nil, errShape
		}
	}
	return out, nil
}
