package vzbackend

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// The formal step's replay of the contract's admission vectors against vzbackend: each verifier
// output and the refusal code it must produce, in the contract's order. The runner's file
// (.pushgate/steps/formal-harness), copied by formal.sh into a scratch copy of the package with the
// commit's own test files removed. CONTRACT_VECTORS is the vectors file to replay.
func TestContractVectorsAdmission(t *testing.T) {
	path := os.Getenv("CONTRACT_VECTORS")
	if path == "" {
		t.Fatal("CONTRACT_VECTORS is not set; run .pushgate/steps/formal.sh")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Schema    string
		Admission []struct {
			Name                                          string
			SchemaVersion                                 int
			Admitted                                      bool
			Scope, Envelope, Payload, Tenant, Deployment  string
			Profile, Backend, Manifest                    string
			Sequence                                      uint64
			NotBefore, Expires                            int64
			Signers                                       int
			DuplicateSigner, SignerIdsValid, DigestsValid bool
			Expect                                        string
		}
		AdmissionSequence []json.RawMessage
		Backends          []json.RawMessage
	}
	if err = json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	if d.Schema != "badger.contract.vectors/v1" || len(d.Admission) == 0 {
		t.Fatalf("contract vectors %s: unexpected schema or no admission vectors", path)
	}
	digest := func(s string) string { return hash([]byte(s)) }
	v := &Verifier{Assignment{TenantID: "tenant-a", DeploymentID: "deployment-a", ProfileID: "profile-a",
		ProfileSHA256: digest("payload"), ManifestSHA256: digest("manifest")}}
	envelope := []byte("test-only envelope")
	pick := func(which, assigned, other string) string {
		if which == "assigned" {
			return assigned
		}
		return other
	}
	now := time.Now().UTC().Truncate(time.Second)
	for _, c := range d.Admission {
		var o admissionOutput
		o.SchemaVersion, o.Admitted, o.Scope = c.SchemaVersion, c.Admitted, c.Scope
		o.EnvelopeSHA256 = digest("another envelope")
		if c.Envelope == "match" {
			o.EnvelopeSHA256 = hash(envelope)
		}
		o.PayloadSHA256 = pick(c.Payload, v.assignment.ProfileSHA256, digest("another payload"))
		o.Profile = admissionProfile{ProfileID: pick(c.Profile, "profile-a", "profile-b"),
			TenantID: pick(c.Tenant, "tenant-a", "tenant-b"), DeploymentID: pick(c.Deployment, "deployment-a", "deployment-b"),
			Sequence: c.Sequence, NotBefore: now.Add(time.Duration(c.NotBefore) * time.Second).Format(time.RFC3339),
			ExpiresAt: now.Add(time.Duration(c.Expires) * time.Second).Format(time.RFC3339),
			Backend: backendReference{Kind: pick(c.Backend, backendKind, "docker/v1"),
				ManifestSHA256: pick(c.Manifest, v.assignment.ManifestSHA256, digest("another manifest"))}}
		for i := range c.Signers {
			key := digest(fmt.Sprint("signer ", i))
			if c.DuplicateSigner {
				key = digest("signer 0")
			}
			if !c.SignerIdsValid {
				key = strings.ToUpper(key)
			}
			o.SignerKeyIDs = append(o.SignerKeyIDs, key)
		}
		o.TrustSHA256, o.NativeSHA256 = digest("trust"), digest("native")
		if !c.DigestsValid {
			o.TrustSHA256 = "invalid"
		}
		encoded, err := json.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		got := "ok"
		if _, err := v.validateAdmission(encoded, envelope); err != nil {
			var r *refusal
			if !errors.As(err, &r) {
				t.Fatalf("%s: unexpected error %v", c.Name, err)
			}
			got = r.code
		}
		if got != c.Expect {
			t.Errorf("admission %q: verifier says %s, contract says %s", c.Name, got, c.Expect)
		}
	}
	// The device high-water rule (admissionSequence) and certificate-chain admission with
	// activation and reset records (backends) have no Go implementation yet: the verifier is
	// stateless, pins keys, and rollback is stopped only by the administrator's payload pin.
	t.Logf("%d admission vectors replayed; %d admissionSequence and %d backends vectors have no Go consumer yet",
		len(d.Admission), len(d.AdmissionSequence), len(d.Backends))
}
