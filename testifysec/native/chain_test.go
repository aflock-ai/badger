package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
)

const portalSAN = "spiffe://enclave.example/badger/portal"

type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func issue(t *testing.T, template *x509.Certificate, parent *authority, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	signer, issuer := key, template
	if parent != nil {
		signer, issuer = parent.key, parent.cert
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template.SerialNumber = serial
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
	t.Helper()
	key := newKey(t)
	now := time.Now()
	return &authority{issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-48 * time.Hour),
		NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil, key), key}
}

// leafSpec is a leaf certificate for the portal's signing key, relative to now.
type leafSpec struct {
	from, until time.Duration
	san         string
	usage       []x509.ExtKeyUsage
	isCA        bool
}

func goodLeaf() leafSpec {
	return leafSpec{-24 * time.Hour, 6 * 24 * time.Hour, portalSAN, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, false}
}

func chainRequest(t *testing.T, root, issuer *authority, intermediates []*x509.Certificate, specs ...leafSpec) request {
	t.Helper()
	signers := []cryptoutil.Signer{}
	now := time.Now()
	for _, spec := range specs {
		key := newKey(t)
		san, _ := url.Parse(spec.san)
		leaf := issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "badger portal"}, NotBefore: now.Add(spec.from),
			NotAfter: now.Add(spec.until), URIs: []*url.URL{san}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: spec.usage,
			IsCA: spec.isCA, BasicConstraintsValid: spec.isCA}, issuer, key)
		signer, err := cryptoutil.NewSigner(key, cryptoutil.SignWithCertificate(leaf), cryptoutil.SignWithIntermediates(intermediates))
		if err != nil {
			t.Fatal(err)
		}
		signers = append(signers, signer)
	}
	envelope, err := dsse.Sign("application/vnd.testifysec.hardened-opencode.profile.v1+json", bytes.NewBufferString(`{"profile":"synthetic"}`), dsse.SignWithSigners(signers...))
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(envelope)
	return request{Envelope: encoded, RootCAs: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.cert.Raw}))},
		SignerIdentity: &identity{SAN: portalSAN, ExtendedKeyUsage: "codeSigning"}, ExpectedPayloadType: envelope.PayloadType, Threshold: 1}
}

func runChain(t *testing.T, input request) (response, error) {
	t.Helper()
	encoded, _ := json.Marshal(input)
	return verify(encoded)
}

func TestChainMode(t *testing.T) {
	root := newRoot(t, "enclave root")
	result, err := runChain(t, chainRequest(t, root, root, nil, goodLeaf()))
	if err != nil || !result.OK || len(result.SignerKeyIDs) != 1 || len(result.SignerCertificates) != 1 {
		t.Fatalf("valid chain refused: %+v %v", result, err)
	}
	// The leaf window the caller checks the payload's window against.
	got := result.SignerCertificates[0]
	if got.KeyID != result.SignerKeyIDs[0] || got.NotBefore >= got.NotAfter || len(got.NotAfter) != len("2006-01-02T15:04:05Z") {
		t.Fatalf("signer certificate not reported: %+v", got)
	}
	// Through an intermediate the signature carries.
	intermediateKey := newKey(t)
	now := time.Now()
	intermediate := &authority{issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "enclave issuing"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, root, intermediateKey), intermediateKey}
	if result, err = runChain(t, chainRequest(t, root, intermediate, []*x509.Certificate{intermediate.cert}, goodLeaf())); err != nil || !result.OK {
		t.Fatalf("chain through an intermediate refused: %v", err)
	}
	two := chainRequest(t, root, root, nil, goodLeaf(), goodLeaf())
	two.Threshold = 2
	if result, err = runChain(t, two); err != nil || len(result.SignerKeyIDs) != 2 {
		t.Fatalf("two distinct leaves refused: %v", err)
	}
}

func TestChainModeRefusals(t *testing.T) {
	root, other := newRoot(t, "enclave root"), newRoot(t, "another root")
	expired := goodLeaf()
	expired.from, expired.until = -8*24*time.Hour, -time.Hour
	future := goodLeaf()
	future.from = time.Hour
	wrongSAN := goodLeaf()
	wrongSAN.san = "spiffe://enclave.example/badger/someone-else"
	noUsage := goodLeaf()
	noUsage.usage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	caLeaf := goodLeaf()
	caLeaf.isCA = true
	with := func(change func(*request)) func() request {
		return func() request { r := chainRequest(t, root, root, nil, goodLeaf()); change(&r); return r }
	}
	cases := map[string]func() request{
		"wrong root":            func() request { return chainRequest(t, root, other, nil, goodLeaf()) },
		"expired leaf":          func() request { return chainRequest(t, root, root, nil, expired) },
		"leaf not yet valid":    func() request { return chainRequest(t, root, root, nil, future) },
		"another SAN":           func() request { return chainRequest(t, root, root, nil, wrongSAN) },
		"no code signing usage": func() request { return chainRequest(t, root, root, nil, noUsage) },
		"leaf is a CA":          func() request { return chainRequest(t, root, root, nil, caLeaf) },
		"intermediate missing": func() request {
			key := newKey(t)
			now := time.Now()
			intermediate := &authority{issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "unlisted"}, NotBefore: now.Add(-time.Hour),
				NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, root, key), key}
			return chainRequest(t, root, intermediate, nil, goodLeaf())
		},
		"threshold above signers": with(func(r *request) { r.Threshold = 2 }),
		"pinned keys too":         with(func(r *request) { r.PublicKeys = fixture(t).PublicKeys }),
		"no signer identity":      with(func(r *request) { r.SignerIdentity = nil }),
		"other usage asked":       with(func(r *request) { r.SignerIdentity.ExtendedKeyUsage = "serverAuth" }),
		"root is a leaf": func() request {
			r := chainRequest(t, root, root, nil, goodLeaf())
			var e dsse.Envelope
			_ = json.Unmarshal(r.Envelope, &e)
			r.RootCAs = []string{string(e.Signatures[0].Certificate)}
			return r
		},
		"signature without a certificate": func() request {
			r := chainRequest(t, root, root, nil, goodLeaf())
			var e dsse.Envelope
			_ = json.Unmarshal(r.Envelope, &e)
			e.Signatures[0].Certificate = nil
			r.Envelope, _ = json.Marshal(e)
			return r
		},
		"tampered payload": func() request {
			r := chainRequest(t, root, root, nil, goodLeaf())
			var e dsse.Envelope
			_ = json.Unmarshal(r.Envelope, &e)
			e.Payload = []byte(`{"profile":"changed"}`)
			r.Envelope, _ = json.Marshal(e)
			return r
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			if result, err := runChain(t, build()); err == nil || result.OK {
				t.Fatalf("accepted: %+v", result)
			}
		})
	}
}

// A pinned-key build is unchanged: its envelopes carry no certificate, and a certificate on one
// is refused rather than ignored.
func TestPinnedKeyModeRefusesCertificates(t *testing.T) {
	input := fixture(t)
	var e dsse.Envelope
	_ = json.Unmarshal(input.Envelope, &e)
	e.Signatures[0].Certificate = []byte("-----BEGIN CERTIFICATE-----\n")
	input.Envelope, _ = json.Marshal(e)
	if result, err := runChain(t, input); err == nil || result.OK {
		t.Fatal("pinned-key mode accepted a certificate")
	}
	root := newRoot(t, "enclave root")
	exact, _ := json.Marshal(chainRequest(t, root, root, nil, goodLeaf()))
	if result, err := verify(exact); err != nil || !result.OK {
		t.Fatalf("unaliased request refused: %v", err)
	}
	alias := bytes.Replace(exact, []byte(`"san"`), []byte(`"SAN"`), 1)
	if result, err := verify(alias); err == nil || result.OK {
		t.Fatal("aliased signer identity accepted")
	}
}

// The distinct-signer rules: one key under two certificates is refused outright, and the same
// signature repeated does not count twice toward the threshold.
func TestChainModeDistinctSigners(t *testing.T) {
	root := newRoot(t, "enclave root")
	key := newKey(t)
	now := time.Now()
	san, _ := url.Parse(portalSAN)
	signers := []cryptoutil.Signer{}
	for i := 0; i < 2; i++ {
		leaf := issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "badger portal"}, NotBefore: now.Add(-time.Hour),
			NotAfter: now.Add(time.Duration(24+i) * time.Hour), URIs: []*url.URL{san}, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}, root, key)
		signer, err := cryptoutil.NewSigner(key, cryptoutil.SignWithCertificate(leaf))
		if err != nil {
			t.Fatal(err)
		}
		signers = append(signers, signer)
	}
	envelope, err := dsse.Sign("application/vnd.testifysec.hardened-opencode.profile.v1+json", bytes.NewBufferString(`{"profile":"synthetic"}`), dsse.SignWithSigners(signers...))
	if err != nil {
		t.Fatal(err)
	}
	two := chainRequest(t, root, root, nil, goodLeaf())
	two.Envelope, _ = json.Marshal(envelope)
	if result, err := runChain(t, two); err == nil || result.OK {
		t.Fatal("one key under two certificates accepted")
	}
	repeated := chainRequest(t, root, root, nil, goodLeaf())
	var e dsse.Envelope
	_ = json.Unmarshal(repeated.Envelope, &e)
	e.Signatures = append(e.Signatures, e.Signatures[0])
	repeated.Envelope, _ = json.Marshal(e)
	repeated.Threshold = 2
	if result, err := runChain(t, repeated); err == nil || result.OK {
		t.Fatal("a repeated signature met threshold 2")
	}
}
