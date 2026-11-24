package issue_test

// The portal must emit exactly what native admission accepts. This test signs with the
// portal and then verifies with what admission runs:
//   - signature: the Rookery dsse/cryptoutil packages at the version testifysec/native pins,
//     called the way native/verify.go calls them (pinned SPKI keys, threshold, exact fields);
//   - payload: a line-for-line Go port of admitProfile in testifysec/managed/profile.ts;
//   - output binding: the fields broker/admission.go and vzbackend/admission.go then check.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"

	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb/pgtest"
	"github.com/aflock-ai/badger/testifysec/portal/internal/issue"
	"github.com/aflock-ai/badger/testifysec/portal/internal/profile"
	"github.com/aflock-ai/badger/testifysec/portal/internal/sign"
	"github.com/aflock-ai/badger/testifysec/portal/internal/store"
)

type trust struct {
	publicKeys                        []string
	threshold                         int
	tenantID, deploymentID, profileID string
	minimumSequence                   uint64
}

// exactKeys mirrors native exactFields and profile.ts object(): these keys, no others, no duplicates.
func exactKeys(raw []byte, keys ...string) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return errors.New("invalid-schema")
	}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		k, ok := t.(string)
		if err != nil || !ok || seen[k] {
			return errors.New("duplicate-json-key")
		}
		seen[k] = true
		var skip json.RawMessage
		if err = dec.Decode(&skip); err != nil {
			return err
		}
	}
	if len(seen) != len(keys) {
		return errors.New("invalid-schema")
	}
	for _, k := range keys {
		if !seen[k] {
			return errors.New("invalid-schema")
		}
	}
	return nil
}

// verifyNative reproduces native/verify.go for one v1 envelope.
func verifyNative(raw []byte, tr trust) (payload []byte, payloadSHA string, keyIDs []string, err error) {
	return verifyNativeType(raw, tr, profile.PayloadType)
}

// verifyNativeType is verifyNative for the payload type the deployment's trust expects.
func verifyNativeType(raw []byte, tr trust, payloadType string) (payload []byte, payloadSHA string, keyIDs []string, err error) {
	if err = exactKeys(raw, "payloadType", "payload", "signatures"); err != nil {
		return
	}
	var shape struct{ Signatures []json.RawMessage }
	if err = json.Unmarshal(raw, &shape); err != nil {
		return
	}
	for _, s := range shape.Signatures {
		if err = exactKeys(s, "keyid", "sig"); err != nil {
			return
		}
	}
	var env dsse.Envelope
	if err = json.Unmarshal(raw, &env); err != nil || env.PayloadType != payloadType {
		return nil, "", nil, errors.Join(err, errors.New("unexpected payload type"))
	}
	var verifiers []cryptoutil.Verifier
	for _, k := range tr.publicKeys {
		block, _ := pem.Decode([]byte(k))
		pub, perr := x509.ParsePKIXPublicKey(block.Bytes)
		v, verr := cryptoutil.NewVerifier(pub)
		if perr != nil || verr != nil {
			return nil, "", nil, errors.Join(perr, verr)
		}
		verifiers = append(verifiers, v)
	}
	checked, err := env.Verify(dsse.VerifyWithVerifiers(verifiers...), dsse.VerifyWithThreshold(tr.threshold))
	if err != nil {
		return nil, "", nil, errors.New("profile-signature-invalid")
	}
	ids := map[string]bool{}
	for _, c := range checked {
		if c.Error == nil && c.Verifier != nil {
			id, _ := c.Verifier.KeyID()
			ids[id] = true
		}
	}
	for id := range ids {
		keyIDs = append(keyIDs, id)
	}
	sort.Strings(keyIDs)
	sum := sha256.Sum256(env.Payload)
	return env.Payload, hex.EncodeToString(sum[:]), keyIDs, nil
}

var number = regexp.MustCompile(`":\s*(-?[0-9][0-9.eE+-]*)`)

// admitV1 is profile.ts admitProfile. Errors use its reason strings.
func admitV1(payload []byte, tr trust, now time.Time) error {
	if len(payload) == 0 || len(payload) > 256*1024 {
		return errors.New("invalid-profile-size")
	}
	for _, m := range number.FindAllSubmatch(payload, -1) { // strict-json.ts number grammar
		if !regexp.MustCompile(`^(0|[1-9][0-9]{0,15})$`).Match(m[1]) || (len(m[1]) == 16 && string(m[1]) > "9007199254740991") {
			return errors.New("invalid-json-number")
		}
	}
	if err := exactKeys(payload, "schemaVersion", "profileId", "tenantId", "deploymentId", "sequence", "notBefore", "expiresAt", "controls"); err != nil {
		return err
	}
	var p profile.V1
	var c struct{ Controls json.RawMessage }
	if json.Unmarshal(payload, &p) != nil || json.Unmarshal(payload, &c) != nil {
		return errors.New("invalid-schema")
	}
	if err := exactKeys(c.Controls, "runtimePackageDownloads", "execution", "audit"); err != nil {
		return err
	}
	if p.SchemaVersion != 1 {
		return errors.New("unsupported-profile-version")
	}
	for _, id := range []string{p.ProfileID, p.TenantID, p.DeploymentID} {
		if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`).MatchString(id) {
			return errors.New("invalid-schema")
		}
	}
	if p.Sequence < 1 || p.Sequence > 1<<53-1 {
		return errors.New("invalid-schema")
	}
	start, e1 := time.Parse(time.RFC3339, p.NotBefore)
	end, e2 := time.Parse(time.RFC3339, p.ExpiresAt)
	second := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)
	if e1 != nil || e2 != nil || !second.MatchString(p.NotBefore) || !second.MatchString(p.ExpiresAt) {
		return errors.New("invalid-schema")
	}
	if p.Controls != (profile.Controls{RuntimePackageDownloads: false, Execution: "broker-only", Audit: "required"}) {
		return errors.New("unsupported-controls")
	}
	if p.ProfileID != tr.profileID || p.TenantID != tr.tenantID || p.DeploymentID != tr.deploymentID {
		return errors.New("assignment-mismatch")
	}
	if now.Before(start) || !end.After(start) || !now.Before(end) {
		return errors.New("profile-time-invalid")
	}
	if p.Sequence < tr.minimumSequence {
		return errors.New("profile-rollback")
	}
	return nil
}

type memAudit struct{ records []store.Record }

func (m *memAudit) Append(r store.Record) error { m.records = append(m.records, r); return nil }

func newIssuer(t *testing.T, signers int) (*issue.Issuer, *memAudit) {
	t.Helper()
	files := store.NewPG(testDB(t), testLabel)
	var ss []sign.Signer
	for i := range signers {
		ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err, i)
		}
		k, err := sign.NewKey(ec)
		if err != nil {
			t.Fatal(err)
		}
		ss = append(ss, k)
	}
	a := &memAudit{}
	return &issue.Issuer{TenantID: "tenant-example", MinimumSequence: 10, Signers: ss, Profiles: files, Audit: a,
		Now: time.Now}, a
}

func trustFor(i *issue.Issuer, floor uint64) trust {
	tr := trust{threshold: len(i.Signers), tenantID: "tenant-example", deploymentID: "deploy-a", profileID: "engineering", minimumSequence: floor}
	for _, s := range i.Signers {
		tr.publicKeys = append(tr.publicKeys, string(s.PublicKeyPEM()))
	}
	return tr
}

func window(from, to time.Duration) issue.Request {
	now := time.Now().UTC().Truncate(time.Second)
	return issue.Request{ProfileID: "engineering", DeploymentID: "deploy-a",
		NotBefore: now.Add(from).Format(time.RFC3339), ExpiresAt: now.Add(to).Format(time.RFC3339)}
}

func TestAdmissionAcceptsPortalProfile(t *testing.T) {
	for _, n := range []int{1, 2} {
		iss, audit := newIssuer(t, n)
		v, err := iss.Issue("CN=Admin One", "admin", window(-time.Hour, 24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		tr := trustFor(iss, 10)
		payload, payloadSHA, ids, err := verifyNative(v.Envelope, tr)
		if err != nil {
			t.Fatalf("native verifier refused a portal envelope: %v", err)
		}
		if err = admitV1(payload, tr, time.Now()); err != nil {
			t.Fatalf("admission refused a portal payload: %v", err)
		}
		// broker/admission.go and vzbackend/admission.go bind these output fields.
		envSum := sha256.Sum256(v.Envelope)
		if payloadSHA != v.PayloadSHA256 || hex.EncodeToString(envSum[:]) != v.EnvelopeSHA256 || len(v.Envelope) > 65536 {
			t.Fatal("digest binding differs from what the broker checks")
		}
		want := append([]string(nil), v.SignerKeyIDs...)
		sort.Strings(want)
		if strings.Join(ids, ",") != strings.Join(want, ",") || len(ids) != n {
			t.Fatalf("signer key IDs %v, Rookery computed %v", want, ids)
		}
		if v.Sequence != 10 || len(audit.records) != 1 || audit.records[0].After != v.EnvelopeSHA256 {
			t.Fatalf("sequence %d, audit %+v", v.Sequence, audit.records)
		}
	}
}

func TestAdmissionRefusals(t *testing.T) {
	iss, _ := newIssuer(t, 1)
	first, err := iss.Issue("CN=Admin One", "admin", window(-time.Hour, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	second, err := iss.Issue("CN=Admin One", "admin", window(-time.Hour, time.Hour))
	if err != nil || second.Sequence != first.Sequence+1 {
		t.Fatalf("second version: %v sequence %d", err, second.Sequence)
	}
	tr := trustFor(iss, 10)

	tampered := bytes.Replace(first.Envelope, []byte(`"payload":"`), []byte(`"payload":"A`), 1)
	if _, _, _, err := verifyNative(tampered, tr); err == nil {
		t.Fatal("tampered envelope verified")
	}
	other, _ := newIssuer(t, 1)
	if _, _, _, err := verifyNative(first.Envelope, trustFor(other, 10)); err == nil {
		t.Fatal("envelope verified under another portal's key")
	}
	payload, _, _, err := verifyNative(first.Envelope, tr)
	if err != nil {
		t.Fatal(err)
	}
	raised := tr
	raised.minimumSequence = second.Sequence // the build floor moved past the first version
	if err := admitV1(payload, raised, time.Now()); err == nil || err.Error() != "profile-rollback" {
		t.Fatalf("rollback: %v", err)
	}
	moved := tr
	moved.deploymentID = "deploy-b"
	if err := admitV1(payload, moved, time.Now()); err == nil || err.Error() != "assignment-mismatch" {
		t.Fatalf("assignment: %v", err)
	}
	if err := admitV1(payload, tr, time.Now().Add(2*time.Hour)); err == nil || err.Error() != "profile-time-invalid" {
		t.Fatalf("expiry: %v", err)
	}
}

func TestIssuerRefusesWhatAdmissionWould(t *testing.T) {
	iss, audit := newIssuer(t, 1)
	bad := []issue.Request{
		window(time.Hour, -time.Hour),
		{ProfileID: "../etc", DeploymentID: "deploy-a", NotBefore: "2026-01-01T00:00:00Z", ExpiresAt: "2026-01-02T00:00:00Z"},
		{ProfileID: "engineering", DeploymentID: "deploy-a", NotBefore: "2026-02-30T00:00:00Z", ExpiresAt: "2026-03-02T00:00:00Z"},
		{ProfileID: "engineering", DeploymentID: "deploy-a", NotBefore: "2026-01-01T00:00:00+01:00", ExpiresAt: "2026-01-02T00:00:00Z"},
	}
	for _, r := range bad {
		var invalid issue.Invalid
		if _, err := iss.Issue("CN=Admin One", "admin", r); !errors.As(err, &invalid) {
			t.Errorf("%+v: want Invalid, got %v", r, err)
		}
	}
	if _, err := iss.Issue("CN=Admin One", "admin", window(-time.Hour, time.Hour)); err != nil {
		t.Fatal(err)
	}
	moved := window(-time.Hour, time.Hour)
	moved.DeploymentID = "deploy-b"
	if _, err := iss.Issue("CN=Admin One", "admin", moved); err == nil {
		t.Fatal("a profile ID moved to another deployment")
	}
	if len(audit.records) != 1 {
		t.Fatalf("refused requests were audited as signatures: %d records", len(audit.records))
	}
}

// testDB is a fresh migrated database; testLabel the ceiling the tests run at.
func testDB(t *testing.T) *sql.DB {
	t.Helper()
	_, db := pgtest.Migrated(t, pgdb.Core, store.Schema)
	return db
}

var testLabel = func() pgdb.Label {
	l, err := pgdb.ParseLabel("SECRET")
	if err != nil {
		panic(err)
	}
	return l
}()
