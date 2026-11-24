package activation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"strconv"
	"testing"
	"time"
)

const portalSAN = "spiffe://enclave.example/badger/portal"

// now is the verifier's clock in every test, whole seconds like a certificate's validity.
var now = time.Now().UTC().Truncate(time.Second)

type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func create(t *testing.T, template *x509.Certificate, parent *authority, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	template.SerialNumber, _ = rand.Int(rand.Reader, big.NewInt(1<<62))
	issuer, signer := template, key
	if parent != nil {
		issuer, signer = parent.cert, parent.key
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func newRoot(t *testing.T, name string) *authority {
	key := mustKey(t)
	return &authority{create(t, &x509.Certificate{Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-30 * 24 * time.Hour),
		NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil, key), key}
}

// signer is one signature's leaf: its issuer, validity in seconds from now, and SAN.
type signer struct {
	issuer          *authority
	notBefore, last int64
	san             string
	corrupt         bool
	adjust          func(*x509.Certificate) // changes the leaf template, for negative tests
}

func envelope(t *testing.T, payloadType string, body map[string]any, s signer) []byte {
	t.Helper()
	key := mustKey(t)
	san, _ := url.Parse(s.san)
	template := &x509.Certificate{Subject: pkix.Name{CommonName: "badger portal"}, NotBefore: now.Add(time.Duration(s.notBefore) * time.Second),
		NotAfter: now.Add(time.Duration(s.last) * time.Second), URIs: []*url.URL{san}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
	if s.adjust != nil {
		s.adjust(template)
	}
	leaf := create(t, template, s.issuer, key)
	payload, _ := json.Marshal(body)
	pae := []byte("DSSEv1 " + strconv.Itoa(len(payloadType)) + " " + payloadType + " " + strconv.Itoa(len(payload)) + " " + string(payload))
	digest := sha256.Sum256(pae)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if s.corrupt {
		sig[len(sig)-1] ^= 1
	}
	raw, _ := json.Marshal(map[string]any{"payloadType": payloadType, "payload": base64.StdEncoding.EncodeToString(payload),
		"signatures": []map[string]any{{"keyid": "", "sig": sig, "certificate": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})}}})
	return raw
}

func at(seconds int64) string {
	return now.Add(time.Duration(seconds) * time.Second).Format(time.RFC3339)
}
func digestOf(n int) string { return fmt.Sprintf("%064x", n) }

func trustFor(roots ...*authority) Trust {
	t := Trust{SAN: portalSAN, TenantID: "tenant-a", DeploymentID: "deploy-a", ProfileID: "engineering", DeviceKeySHA256: digestOf(7)}
	for _, r := range roots {
		t.Roots = append(t.Roots, r.cert)
	}
	return t
}

func activationBody(seq, profileSeq, digest int, nb, exp int64) map[string]any {
	return map[string]any{"schemaVersion": 1, "tenantId": "tenant-a", "deploymentId": "deploy-a", "profileId": "engineering",
		"profileSha256": digestOf(digest), "profileSequence": profileSeq, "sequence": seq, "notBefore": at(nb), "expiresAt": at(exp)}
}

func resetBody(device, rseq, pfloor, afloor int, nb, exp int64) map[string]any {
	return map[string]any{"schemaVersion": 1, "tenantId": "tenant-a", "deploymentId": "deploy-a", "deviceKeySpkiSha256": digestOf(device),
		"resetSequence": rseq, "profileFloor": pfloor, "activationFloor": afloor, "notBefore": at(nb), "expiresAt": at(exp)}
}

// apply is Verify then Step, the decision without persistence; "ok" or the refusal.
func apply(t Trust, s State, raw []byte) (State, string) {
	r, err := Verify(t, raw)
	if err == nil {
		s, err = Step(t, s, now, r)
	}
	if err != nil {
		return s, string(err.(Refusal))
	}
	return s, "ok"
}
