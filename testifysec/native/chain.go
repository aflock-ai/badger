package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"sort"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
)

// verifyChain is chain mode: every counted signature's certificate chains to a pinned root at
// the time of verification, and its leaf carries the signer identity. The payload's signed window
// is the caller's to check against signerCertificates; without that rule a stolen leaf key could
// sign a window that outlives the leaf.
func verifyChain(envelope dsse.Envelope, input request) (response, error) {
	roots := make([]*x509.Certificate, 0, len(input.RootCAs))
	for _, encoded := range input.RootCAs {
		root, err := onePEMCertificate(encoded)
		if err != nil || !root.IsCA || !root.BasicConstraintsValid {
			return response{}, errors.New("invalid root CA")
		}
		roots = append(roots, root)
	}
	checked, err := envelope.Verify(dsse.VerifyWithRoots(roots...), dsse.VerifyWithThreshold(input.Threshold))
	if err != nil {
		return response{}, errors.New("signature verification failed")
	}
	leaves := map[string]*x509.Certificate{}
	for _, item := range checked {
		verifier, ok := item.Verifier.(*cryptoutil.X509Verifier)
		if item.Error != nil || !ok {
			continue
		}
		leaf := verifier.Certificate()
		if !carries(leaf, *input.SignerIdentity) {
			continue
		}
		id, err := verifier.KeyID()
		if err != nil {
			return response{}, errors.New("verified signer has no stable identity")
		}
		// One key under two leaves would let the caller check the window against the wrong one.
		if seen, ok := leaves[id]; ok && !bytes.Equal(seen.Raw, leaf.Raw) {
			return response{}, errors.New("a signer key appears under two certificates")
		}
		leaves[id] = leaf
	}
	if len(leaves) < input.Threshold {
		return response{}, errors.New("insufficient distinct verified signers")
	}
	ids := make([]string, 0, len(leaves))
	for id := range leaves {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	certificates := make([]signerCertificate, 0, len(ids))
	for _, id := range ids {
		certificates = append(certificates, signerCertificate{KeyID: id,
			NotBefore: leaves[id].NotBefore.UTC().Format(time.RFC3339), NotAfter: leaves[id].NotAfter.UTC().Format(time.RFC3339)})
	}
	digest := sha256.Sum256(envelope.Payload)
	return response{OK: true, PayloadType: envelope.PayloadType, PayloadBase64: base64.StdEncoding.EncodeToString(envelope.Payload),
		PayloadSHA256: hex.EncodeToString(digest[:]), SignerKeyIDs: ids, SignerCertificates: certificates}, nil
}

// carries reports whether a leaf is an end-entity signing certificate with the code-signing
// extended key usage and the required subject alternative name.
func carries(leaf *x509.Certificate, want identity) bool {
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return false
	}
	codeSigning := false
	for _, usage := range leaf.ExtKeyUsage {
		codeSigning = codeSigning || usage == x509.ExtKeyUsageCodeSigning
	}
	if !codeSigning {
		return false
	}
	names := append(append([]string{}, leaf.EmailAddresses...), leaf.DNSNames...)
	for _, uri := range leaf.URIs {
		names = append(names, uri.String())
	}
	for _, name := range names {
		if name == want.SAN {
			return true
		}
	}
	return false
}

func onePEMCertificate(encoded string) (*x509.Certificate, error) {
	if len(encoded) > 16384 {
		return nil, errors.New("certificate too large")
	}
	block, rest := pem.Decode([]byte(encoded))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected one certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}
