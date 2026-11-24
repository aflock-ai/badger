package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
)

const maxRequest = 4 * 1024 * 1024

type request struct {
	Envelope            json.RawMessage `json:"envelope"`
	PublicKeys          []string        `json:"publicKeys,omitempty"`
	RootCAs             []string        `json:"rootCas,omitempty"`
	SignerIdentity      *identity       `json:"signerIdentity,omitempty"`
	ExpectedPayloadType string          `json:"expectedPayloadType"`
	Threshold           int             `json:"threshold"`
}

// identity is what a signing leaf must carry in chain mode: one subject alternative name (URI,
// email or DNS, matched exactly) and the code-signing extended key usage.
type identity struct {
	SAN              string `json:"san"`
	ExtendedKeyUsage string `json:"extendedKeyUsage"`
}

// signerCertificate is a counted chain-mode signer's leaf validity. The caller, which parses the
// payload, requires the payload's signed window to lie inside it.
type signerCertificate struct {
	KeyID     string `json:"keyId"`
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
}

type response struct {
	ABIVersion    int      `json:"abiVersion"`
	OK            bool     `json:"ok"`
	Error         string   `json:"error,omitempty"`
	PayloadType   string   `json:"payloadType,omitempty"`
	PayloadBase64 string   `json:"payloadBase64,omitempty"`
	PayloadSHA256 string   `json:"payloadSha256,omitempty"`
	SignerKeyIDs  []string `json:"signerKeyIds,omitempty"`
	// SignerCertificates is set in chain mode only, one per signer key id.
	SignerCertificates []signerCertificate `json:"signerCertificates,omitempty"`
}

func verifyJSON(data []byte) []byte {
	result, err := verify(data)
	if err != nil {
		result = response{Error: err.Error()}
	}
	result.ABIVersion = 1
	encoded, err := json.Marshal(result)
	if err != nil {
		return []byte(`{"abiVersion":1,"ok":false,"error":"response encoding failed"}`)
	}
	return encoded
}

func verify(data []byte) (response, error) {
	if len(data) == 0 || len(data) > maxRequest {
		return response{}, errors.New("invalid request size")
	}
	// Reject ambiguous objects before typed decoding, including envelope fields.
	if err := unambiguousJSON(json.NewDecoder(bytes.NewReader(data)), 0); err != nil {
		return response{}, err
	}
	if err := exactFields(data, "envelope", "publicKeys", "rootCas", "signerIdentity", "expectedPayloadType", "threshold"); err != nil {
		return response{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var input request
	if err := decoder.Decode(&input); err != nil {
		return response{}, fmt.Errorf("invalid request: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return response{}, errors.New("trailing JSON input")
	}
	if input.ExpectedPayloadType == "" || len(input.ExpectedPayloadType) > 256 {
		return response{}, errors.New("expectedPayloadType is required and bounded")
	}
	// One trust input selects one mode: pinned keys, or a chain to pinned roots with a signer
	// identity. Never both, and never a fallback from one to the other.
	chain := len(input.RootCAs) > 0
	if chain {
		if len(input.PublicKeys) != 0 || len(input.RootCAs) > 8 || input.SignerIdentity == nil || input.Threshold < 1 || input.Threshold > 16 {
			return response{}, errors.New("invalid trust configuration or threshold")
		}
		if err := exactFields(data, "envelope", "rootCas", "signerIdentity", "expectedPayloadType", "threshold"); err != nil {
			return response{}, err
		}
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(data, &fields)
		if err := exactFields(fields["signerIdentity"], "san", "extendedKeyUsage"); err != nil || input.SignerIdentity.SAN == "" || len(input.SignerIdentity.SAN) > 1024 || input.SignerIdentity.ExtendedKeyUsage != "codeSigning" {
			return response{}, errors.New("invalid signer identity")
		}
	} else if input.SignerIdentity != nil || len(input.PublicKeys) == 0 || len(input.PublicKeys) > 16 || input.Threshold < 1 || input.Threshold > len(input.PublicKeys) {
		return response{}, errors.New("invalid trust configuration or threshold")
	}
	var envelope dsse.Envelope
	if err := exactFields(input.Envelope, "payloadType", "payload", "signatures"); err != nil {
		return response{}, err
	}
	var encodedEnvelope struct {
		Signatures []json.RawMessage `json:"signatures"`
	}
	if err := json.Unmarshal(input.Envelope, &encodedEnvelope); err != nil {
		return response{}, errors.New("invalid DSSE envelope")
	}
	for _, signature := range encodedEnvelope.Signatures {
		// Pinned-key mode takes no certificate; chain mode requires one. Timestamps are not
		// accepted in either mode (see testifysec/native/README.md, signing-time evidence).
		if !chain {
			if err := exactFields(signature, "keyid", "sig"); err != nil {
				return response{}, err
			}
			continue
		}
		var fields map[string]json.RawMessage
		if err := exactFields(signature, "keyid", "sig", "certificate", "intermediates"); err != nil || json.Unmarshal(signature, &fields) != nil || len(fields["certificate"]) == 0 || string(fields["certificate"]) == "null" {
			return response{}, errors.New("chain mode needs a certificate on every signature")
		}
	}
	if err := json.Unmarshal(input.Envelope, &envelope); err != nil {
		return response{}, errors.New("invalid DSSE envelope")
	}
	if envelope.PayloadType != input.ExpectedPayloadType {
		return response{}, errors.New("unexpected payload type")
	}
	if len(envelope.Payload) > 2*1024*1024 || len(envelope.Signatures) == 0 || len(envelope.Signatures) > 16 {
		return response{}, errors.New("invalid envelope size or signature count")
	}
	if chain {
		return verifyChain(envelope, input)
	}
	verifiers := make([]cryptoutil.Verifier, 0, len(input.PublicKeys))
	for _, encoded := range input.PublicKeys {
		if len(encoded) > 16384 {
			return response{}, errors.New("public key too large")
		}
		block, rest := pem.Decode([]byte(encoded))
		if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
			return response{}, errors.New("expected one SPKI public key PEM")
		}
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return response{}, errors.New("invalid public key")
		}
		verifier, err := cryptoutil.NewVerifier(key)
		if err != nil {
			return response{}, fmt.Errorf("unsupported public key: %w", err)
		}
		verifiers = append(verifiers, verifier)
	}
	checked, err := envelope.Verify(dsse.VerifyWithVerifiers(verifiers...), dsse.VerifyWithThreshold(input.Threshold))
	if err != nil {
		return response{}, errors.New("signature verification failed")
	}
	identities := map[string]bool{}
	for _, item := range checked {
		if item.Error != nil || item.Verifier == nil {
			continue
		}
		id, err := item.Verifier.KeyID()
		if err != nil {
			return response{}, errors.New("verified signer has no stable identity")
		}
		identities[id] = true
	}
	if len(identities) < input.Threshold {
		return response{}, errors.New("insufficient distinct verified signers")
	}
	ids := make([]string, 0, len(identities))
	for id := range identities {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	digest := sha256.Sum256(envelope.Payload)
	return response{OK: true, PayloadType: envelope.PayloadType, PayloadBase64: base64.StdEncoding.EncodeToString(envelope.Payload), PayloadSHA256: hex.EncodeToString(digest[:]), SignerKeyIDs: ids}, nil
}

// encoding/json matches Go struct fields case-insensitively. Reject aliases
// before decoding so signed/admission fields have exactly one spelling.
func exactFields(data []byte, allowed ...string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return errors.New("expected JSON object")
	}
	for name := range fields {
		found := false
		for _, candidate := range allowed {
			if name == candidate {
				found = true
				break
			}
		}
		if !found {
			return errors.New("unknown or noncanonical field")
		}
	}
	return nil
}

func unambiguousJSON(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting limit exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return errors.New("invalid JSON")
	}
	delim, nested := token.(json.Delim)
	if !nested {
		return nil
	}
	switch delim {
	case '{':
		keys := map[string]bool{}
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return errors.New("invalid JSON key")
			}
			key, ok := token.(string)
			if !ok || keys[key] {
				return errors.New("duplicate or invalid JSON key")
			}
			keys[key] = true
			if err := unambiguousJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := unambiguousJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}
