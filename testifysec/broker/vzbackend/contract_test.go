// jade:ring local
package vzbackend

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestStrictManifest(t *testing.T) {
	f := newFixture(t)
	if _, e := parseManifest(f.raw); e != nil {
		t.Fatal(e)
	}
	mutations := map[string]string{
		"duplicate":         strings.Replace(string(f.raw), `"kind":`, `"kind":"darwin-vz/v1","kind":`, 1),
		"escaped-duplicate": strings.Replace(string(f.raw), `"kind":`, `"\u006bind":"darwin-vz/v1","kind":`, 1),
		"case-alias":        strings.Replace(string(f.raw), `"kind":`, `"Kind":`, 1),
		"null-role":         strings.Replace(string(f.raw), `"host":{`, `"host":null,"extra":{`, 1),
		"legacy-job":        strings.Replace(string(f.raw), "testifysec.vm-job/v3", "testifysec.vm-job/v2", 1),
		"wrong-backend":     strings.Replace(string(f.raw), "darwin-vz/v1", "docker/v1", 1),
		"wrong-transport":   strings.Replace(string(f.raw), "HCMDL2", "HCMDL1", 1),
		"null-size":         strings.Replace(string(f.raw), `"size":32`, `"size":null`, 1),
		"float-size":        strings.Replace(string(f.raw), `"size":32`, `"size":32.0`, 1),
		"exponent-size":     strings.Replace(string(f.raw), `"size":32`, `"size":32e0`, 1),
		"oversized-role":    strings.Replace(string(f.raw), `"size":32`, `"size":67108865`, 1),
		"zero-role":         strings.Replace(string(f.raw), `"size":32`, `"size":0`, 1),
		"unknown":           strings.TrimSuffix(string(f.raw), "}") + `,"ignored":true}`,
		"trailing":          string(f.raw) + "{}",
	}
	for name, raw := range mutations {
		t.Run(name, func(t *testing.T) {
			if _, e := parseManifest([]byte(raw)); e == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
}
func TestStrictUnicode(t *testing.T) {
	for _, raw := range []string{`{"value":"\ud800"}`, `{"value":"\udfff"}`, `{"value":"\ud800\u0041"}`, `{"value":"\ud800x"}`, "{\"value\":\"\xff\"}"} {
		var value struct {
			Value string `json:"value"`
		}
		if e := strict([]byte(raw), &value); e == nil {
			t.Fatalf("invalid Unicode accepted %q", raw)
		}
	}
	for _, raw := range []string{`{"value":"\ud83d\ude00"}`, `{"value":"😀"}`, `{"value":"\\ud800"}`} {
		var value struct {
			Value string `json:"value"`
		}
		if e := strict([]byte(raw), &value); e != nil {
			t.Fatal(e)
		}
	}
	f := newFixture(t)
	raw := strings.Replace(string(encodedTest(t, f.v.assignment)), f.install, `/private/tmp/\ud800`, 1)
	var a Assignment
	if e := strict([]byte(raw), &a); e == nil {
		t.Fatal("authority path surrogate accepted")
	}
}
func validOutput(f fixture, envelope []byte) admissionOutput {
	return admissionOutput{2, true, "profile-admission-only", admissionProfile{"profile", "tenant", "deployment", 1, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), time.Now().Add(time.Minute).UTC().Format(time.RFC3339), backendReference{"darwin-vz/v1", f.v.assignment.ManifestSHA256}}, hash(envelope), f.v.assignment.ProfileSHA256, []string{strings.Repeat("a", 64)}, strings.Repeat("b", 64), strings.Repeat("c", 64)}
}
func TestAdmissionOutputBinding(t *testing.T) {
	f := newFixture(t)
	envelope := []byte("test-only envelope")
	a := validOutput(f, envelope)
	if _, e := f.v.validateAdmission(encodedTest(t, a), envelope); e != nil {
		t.Fatal(e)
	}
	mutations := map[string]func(*admissionOutput){
		"v1": func(a *admissionOutput) { a.SchemaVersion = 1 }, "refused": func(a *admissionOutput) { a.Admitted = false }, "scope": func(a *admissionOutput) { a.Scope = "execution" },
		"envelope": func(a *admissionOutput) { a.EnvelopeSHA256 = strings.Repeat("0", 64) }, "payload": func(a *admissionOutput) { a.PayloadSHA256 = strings.Repeat("0", 64) },
		"tenant": func(a *admissionOutput) { a.Profile.TenantID = "other" }, "deployment": func(a *admissionOutput) { a.Profile.DeploymentID = "other" }, "profile": func(a *admissionOutput) { a.Profile.ProfileID = "other" },
		"manifest": func(a *admissionOutput) { a.Profile.Backend.ManifestSHA256 = strings.Repeat("0", 64) }, "backend": func(a *admissionOutput) { a.Profile.Backend.Kind = "docker/v1" },
		"expired": func(a *admissionOutput) {
			a.Profile.ExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
		}, "future": func(a *admissionOutput) { a.Profile.NotBefore = time.Now().Add(time.Second).UTC().Format(time.RFC3339) },
		"missing-signers": func(a *admissionOutput) { a.SignerKeyIDs = nil }, "duplicate-signers": func(a *admissionOutput) { a.SignerKeyIDs = append(a.SignerKeyIDs, a.SignerKeyIDs[0]) },
		"trust-hash": func(a *admissionOutput) { a.TrustSHA256 = "invalid" }, "sequence": func(a *admissionOutput) { a.Profile.Sequence = 9007199254740992 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := validOutput(f, envelope)
			mutate(&changed)
			if _, e := f.v.validateAdmission(encodedTest(t, changed), envelope); e == nil {
				t.Fatal("unbound native output accepted")
			}
		})
	}
}
func TestAssignmentVersionAndOverlap(t *testing.T) {
	f := newFixture(t)
	for _, mutate := range []func(*Assignment){func(a *Assignment) { a.Schema = "other" }, func(a *Assignment) { a.StagingDirectory = a.InstallationDirectory }, func(a *Assignment) { a.InstallationDirectory = "/" }, func(a *Assignment) { a.AdmissionExecutable = a.StagingDirectory + "/tool" }, func(a *Assignment) { a.ManifestSHA256 = strings.Repeat("A", 64) }} {
		a := f.v.assignment
		mutate(&a)
		if _, e := New(a); e == nil {
			t.Fatal("invalid assignment accepted")
		}
	}
	raw := encodedTest(t, f.v.assignment)
	var a Assignment
	if e := json.Unmarshal(raw, &a); e != nil {
		t.Fatal(e)
	}
	if a != f.v.assignment {
		t.Fatal("assignment copy changed")
	}
}
