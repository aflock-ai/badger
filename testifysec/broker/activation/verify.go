package activation

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strconv"
)

// Trust is what a device pins: root CAs, the identity a signing leaf must carry, and its own
// assignment and key. Like Backends.Trust, it names a backend only through its roots.
type Trust struct {
	Roots                             []*x509.Certificate
	SAN                               string // exact URI, email or DNS subject alternative name
	TenantID, DeploymentID, ProfileID string
	DeviceKeySHA256                   string // hex SHA-256 of this device key's SPKI
}

// Refusal is why a record was refused, in Backends.Refuse's terms.
type Refusal string

const (
	RefuseChain      Refusal = "chain"      // bad signature, unpinned root, wrong identity, window outside the leaf
	RefuseExpired    Refusal = "expired"    // now outside the signed window
	RefuseAssignment Refusal = "assignment" // another tenant, deployment, profile or device
	RefuseRollback   Refusal = "rollback"   // not above the high-water
	RefuseMalformed  Refusal = "malformed"  // not a record of a known type and exact shape
	RefuseState      Refusal = "state"      // the device's high-water state is missing or unusable
)

func (r Refusal) Error() string { return "activation: refused: " + string(r) }

const maxEnvelope = 65536

// Verify checks a DSSE envelope holding an activation or reset record. It returns the record if
// at least one signature passes Backends.ChainOk: an ECDSA P-256 signature over the DSSE
// pre-authentication encoding by a leaf that chains to a pinned root at the record's signed
// notBefore, is an end-entity code-signing certificate carrying the trusted SAN, and whose
// validity contains the record's whole window [notBefore, expiresAt). Verify does not look at the
// clock; Step does.
func Verify(t Trust, envelope []byte) (Record, error) {
	if len(envelope) > maxEnvelope {
		return Record{}, RefuseMalformed
	}
	e, err := fields(envelope, "payloadType", "payload", "signatures")
	if err != nil {
		return Record{}, RefuseMalformed
	}
	var payloadType, encoded string
	var signatures []json.RawMessage
	if json.Unmarshal(e["payloadType"], &payloadType) != nil || json.Unmarshal(e["payload"], &encoded) != nil ||
		json.Unmarshal(e["signatures"], &signatures) != nil || len(signatures) == 0 || len(signatures) > 16 {
		return Record{}, RefuseMalformed
	}
	payload, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return Record{}, RefuseMalformed
	}
	record, err := parseRecord(payloadType, payload)
	if err != nil {
		return Record{}, RefuseMalformed
	}
	pae := []byte("DSSEv1 " + strconv.Itoa(len(payloadType)) + " " + payloadType + " " + strconv.Itoa(len(payload)) + " ")
	pae = append(pae, payload...)
	digest := sha256.Sum256(pae)
	for _, raw := range signatures {
		if signedBy(t, raw, digest[:], record) {
			return record, nil
		}
	}
	return Record{}, RefuseChain
}

func signedBy(t Trust, raw json.RawMessage, digest []byte, r Record) bool {
	s, err := fields(raw, "keyid", "sig", "certificate", "intermediates")
	if err != nil {
		if s, err = fields(raw, "keyid", "sig", "certificate"); err != nil {
			return false
		}
	}
	var sig, certificate []byte
	var intermediates [][]byte
	if json.Unmarshal(s["sig"], &sig) != nil || json.Unmarshal(s["certificate"], &certificate) != nil ||
		(s["intermediates"] != nil && json.Unmarshal(s["intermediates"], &intermediates) != nil) || len(intermediates) > 4 {
		return false
	}
	leaf, err := certificateFrom(certificate)
	if err != nil {
		return false
	}
	pool, roots := x509.NewCertPool(), x509.NewCertPool()
	for _, raw := range intermediates {
		c, err := certificateFrom(raw)
		if err != nil {
			return false
		}
		pool.AddCert(c)
	}
	for _, root := range t.Roots {
		roots.AddCert(root)
	}
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() || !carries(leaf, t.SAN) {
		return false
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: pool, CurrentTime: r.NotBefore,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}); err != nil {
		return false
	}
	// The window rule: a stolen leaf key's records die with the leaf.
	if r.NotBefore.Before(leaf.NotBefore) || r.ExpiresAt.After(leaf.NotAfter) {
		return false
	}
	return ecdsa.VerifyASN1(key, digest, sig)
}

func carries(leaf *x509.Certificate, san string) bool {
	codeSigning := false
	for _, usage := range leaf.ExtKeyUsage {
		codeSigning = codeSigning || usage == x509.ExtKeyUsageCodeSigning
	}
	if !codeSigning || leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || san == "" {
		return false
	}
	names := append(append([]string{}, leaf.EmailAddresses...), leaf.DNSNames...)
	for _, uri := range leaf.URIs {
		names = append(names, uri.String())
	}
	for _, name := range names {
		if name == san {
			return true
		}
	}
	return false
}

// certificateFrom reads one PEM certificate, as Rookery puts it in a DSSE signature.
func certificateFrom(raw []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected one certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}
