// jade:ring local

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/badger/testifysec/broker/activation"
)

const testSAN = "spiffe://enclave.example/badger/portal"

// testPortal signs activation records the way the portal does: a 7-day leaf under its root.
type testPortal struct {
	root    *x509.Certificate
	rootKey *ecdsa.PrivateKey
}

func newTestPortal(t *testing.T) testPortal {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "enclave root"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(raw)
	return testPortal{root, key}
}

func (c testPortal) activation(t *testing.T, now time.Time, seq, profileSeq int, digest string) string {
	t.Helper()
	now = now.UTC().Truncate(time.Second)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	san, _ := url.Parse(testSAN)
	raw, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(int64(seq) + 2), NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(7 * 24 * time.Hour), URIs: []*url.URL{san}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}, c.root, &key.PublicKey, c.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"schemaVersion": 1, "tenantId": "tenant-a", "deploymentId": "deployment-a", "profileId": "profile-a",
		"profileSha256": digest, "profileSequence": profileSeq, "sequence": seq, "notBefore": now.Format(time.RFC3339),
		"expiresAt": now.Add(time.Hour).Format(time.RFC3339)})
	pae := "DSSEv1 " + strconv.Itoa(len(activation.ActivationType)) + " " + activation.ActivationType + " " + strconv.Itoa(len(payload)) + " " + string(payload)
	sum := sha256.Sum256([]byte(pae))
	sig, _ := ecdsa.SignASN1(rand.Reader, key, sum[:])
	envelope, _ := json.Marshal(map[string]any{"payloadType": activation.ActivationType, "payload": base64.StdEncoding.EncodeToString(payload),
		"signatures": []map[string]any{{"keyid": "", "sig": sig, "certificate": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})}}})
	return string(envelope)
}

func code(err error) string {
	var r *refusal
	if errors.As(err, &r) {
		return r.Code
	}
	return "none"
}

// The pin a profile is admitted under is the digest the device's latest admitted activation names,
// kept on disk: it moves only forward, and without its state the device refuses everything.
func TestActivationPinsTheProfile(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || activation.Install(dir) != nil {
		t.Fatal(err)
	}
	portal := newTestPortal(t)
	now := time.Now().UTC().Truncate(time.Second) // one clock for the records and the broker
	envelope := `{"payloadType":"test-only"}`
	profile := func(seq int) map[string]any {
		return map[string]any{"tenantId": "tenant-a", "deploymentId": "deployment-a", "profileId": "profile-a", "sequence": seq,
			"notBefore": now.Add(-time.Hour).Format(time.RFC3339), "expiresAt": now.Add(time.Hour).Format(time.RFC3339)}
	}
	base := fakeVerifier(t, envelope, profile(3)) // admits payload digest a...a at sequence 3
	base.ProfileSHA256 = ""
	base.Activation = &activationPolicy{StateDir: dir, RootCAs: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: portal.root.Raw}))},
		SignerSAN: testSAN, DeviceKeySHA256: strings.Repeat("d", 64)}
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)

	if _, err = activate(base, executionRequest{}, now); code(err) != "activation_required" {
		t.Fatalf("no activation yet: %v", err)
	}
	pinned, err := activate(base, executionRequest{ActivationEnvelope: portal.activation(t, now, 1, 3, a)}, now)
	if err != nil || pinned.ProfileSHA256 != a || pinned.activatedSequence != 3 {
		t.Fatalf("activation did not pin: %+v %v", pinned, err)
	}
	if _, err = verifyAdmission(context.Background(), pinned, envelope); err != nil {
		t.Fatalf("activated profile refused: %v", err)
	}
	// The pin survives without the record, from the device's state.
	if pinned, err = activate(base, executionRequest{}, now); err != nil || pinned.ProfileSHA256 != a {
		t.Fatalf("state not kept: %v", err)
	}
	// Under the pinned digest the profile's sequence must be exactly the one the activation names
	// (3): below it, or above it (which would leave the durable floor under the profile that ran,
	// so a later activation could roll back to sequence 4), is refused.
	for _, seq := range []int{2, 10} {
		other := fakeVerifier(t, envelope, profile(seq))
		other.ProfileSHA256, other.Activation = "", base.Activation
		if otherPinned, _ := activate(other, executionRequest{}, now); code(func() error { _, e := verifyAdmission(context.Background(), otherPinned, envelope); return e }()) != "profile_denied" {
			t.Fatalf("profile sequence %d admitted under an activation naming 3", seq)
		}
	}
	// Replaying activation 1 is refused; activation 2 moves the pin to b, and a's profile is refused.
	if _, err = activate(base, executionRequest{ActivationEnvelope: portal.activation(t, now, 1, 3, a)}, now); code(err) != "activation_refused" {
		t.Fatalf("replay: %v", err)
	}
	if pinned, err = activate(base, executionRequest{ActivationEnvelope: portal.activation(t, now, 2, 4, b)}, now); err != nil || pinned.ProfileSHA256 != b {
		t.Fatalf("second activation: %v", err)
	}
	if _, err = verifyAdmission(context.Background(), pinned, envelope); code(err) != "profile_denied" {
		t.Fatalf("superseded profile admitted: %v", err)
	}
	// Deleting the state fails closed: no pin, and a valid new activation is refused too.
	if err = os.Remove(filepath.Join(dir, "state.json")); err != nil {
		t.Fatal(err)
	}
	if _, err = activate(base, executionRequest{}, now); code(err) != "activation_required" {
		t.Fatalf("lost state: %v", err)
	}
	if _, err = activate(base, executionRequest{ActivationEnvelope: portal.activation(t, now, 3, 5, a)}, now); code(err) != "activation_refused" {
		t.Fatalf("activation admitted without state: %v", err)
	}
}

// A policy pins its profile one way: a digest in the file, or activation records, never both.
func TestPolicyPinsOneWay(t *testing.T) {
	p := testPolicy(t)
	p.AdmissionExecutable, p.AdmissionSHA256 = "/opt/badger/admission", strings.Repeat("a", 64)
	p.TenantID, p.DeploymentID, p.ProfileID = "tenant-a", "deployment-a", "profile-a"
	root := newTestPortal(t).root
	p.Activation = &activationPolicy{StateDir: "/var/lib/badger/device", RootCAs: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}))},
		SignerSAN: testSAN, DeviceKeySHA256: strings.Repeat("d", 64)}
	if _, _, err := loadPolicy(writePolicy(t, p)); err != nil {
		t.Fatalf("activation policy refused: %v", err)
	}
	p.ProfileSHA256 = strings.Repeat("b", 64)
	if _, _, err := loadPolicy(writePolicy(t, p)); err == nil {
		t.Fatal("both pins loaded")
	}
	p.ProfileSHA256 = ""
	for _, broken := range []func(*activationPolicy){
		func(a *activationPolicy) { a.RootCAs = nil },
		func(a *activationPolicy) { a.SignerSAN = "" },
		func(a *activationPolicy) { a.DeviceKeySHA256 = "D" },
		func(a *activationPolicy) { a.StateDir = "relative" },
		func(a *activationPolicy) { a.StateDir = "/srv/badger-test/source/state" },
	} {
		saved := *p.Activation
		broken(p.Activation)
		if _, _, err := loadPolicy(writePolicy(t, p)); err == nil {
			t.Fatalf("broken activation policy loaded: %+v", p.Activation)
		}
		*p.Activation = saved
	}
}

// Codex suggestion: executeWorker applies the request's activation record before the profile is
// admitted, and admits under the newly activated digest (activate's own tests cover resets).
func TestRequestPathActivatesBeforeAdmission(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || activation.Install(dir) != nil {
		t.Fatal(err)
	}
	portal := newTestPortal(t)
	p := testPolicy(t)
	p.AdmissionExecutable, p.AdmissionSHA256 = "/opt/badger/admission", strings.Repeat("a", 64)
	p.TenantID, p.DeploymentID, p.ProfileID = "tenant-a", "deployment-a", "profile-a"
	p.Workspace.ID = "test"
	p.Activation = &activationPolicy{StateDir: dir, RootCAs: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: portal.root.Raw}))},
		SignerSAN: testSAN, DeviceKeySHA256: strings.Repeat("d", 64)}
	b := newBroker(p, strings.Repeat("c", 64))
	var admittedPin string
	b.admit = func(_ context.Context, admitted policy, _ string) (string, error) {
		admittedPin = admitted.ProfileSHA256
		return "", deny("test_stop", "stop after admission")
	}
	digest := strings.Repeat("e", 64)
	request := executionRequest{Schema: requestSchema, Workspace: "test", Command: "true",
		ActivationEnvelope: portal.activation(t, time.Now(), 1, 3, digest)}
	if _, err = b.executeWorker(context.Background(), marshal(request), uint32(os.Getuid())); code(err) != "test_stop" {
		t.Fatalf("request did not reach admission: %v", err)
	}
	if admittedPin != digest {
		t.Fatalf("admitted under %q, want the activated digest", admittedPin)
	}
}
