// jade:ring local
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func v2ConfigFixture(t *testing.T) Config {
	t.Helper()
	root := privateTemp(t)
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return Config{Schema: gatewayV2, Socket: filepath.Join(root, "gateway.sock"), Spool: filepath.Join(root, "spool"),
		ProviderURL: "http://127.0.0.1:1/v1/chat/completions", ProviderTokenFile: filepath.Join(root, "provider.token"),
		CollectorURL: "http://127.0.0.1:1/v1/logs", Model: "approved", Tenant: "fixture", Session: "fixture-session",
		Agent: "spiffe://fixture.test/tenant/fixture/agent/fixture", ProfileDigest: strings.Repeat("a", 64),
		MaxRecords: 4, MaxOfflineSeconds: 60, TimeoutSeconds: 10, DevelopmentLoopback: true,
		SignedProfileFile: filepath.Join(root, "profile.json"), AdmissionExecutable: filepath.Join(root, "admission"),
		AdmissionSHA256: strings.Repeat("b", 64), Backend: &BackendAssignment{"darwin-vz/v1", strings.Repeat("c", 64)}}
}

func TestGatewayV2RequiresExplicitProtectedContract(t *testing.T) {
	for _, name := range []string{"valid", "v1-crossed", "missing-backend", "wrong-kind", "bad-digest", "missing-profile", "missing-verifier", "missing-verifier-digest"} {
		t.Run(name, func(t *testing.T) {
			c := v2ConfigFixture(t)
			switch name {
			case "v1-crossed":
				c.Schema = "testifysec.hardened-opencode.gateway/v1"
			case "missing-backend":
				c.Backend = nil
			case "wrong-kind":
				c.Backend.Kind = "docker"
			case "bad-digest":
				c.Backend.ManifestSHA256 = strings.Repeat("C", 64)
			case "missing-profile":
				c.SignedProfileFile = ""
			case "missing-verifier":
				c.AdmissionExecutable = ""
			case "missing-verifier-digest":
				c.AdmissionSHA256 = ""
			}
			if err := profileConfiguration(c); (err == nil) != (name == "valid") {
				t.Fatalf("configuration result: %v", err)
			}
			data, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(filepath.Dir(c.Spool), "config.json")
			if err = os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = readConfig(path); (err == nil) != (name == "valid") {
				t.Fatalf("file configuration result: %v", err)
			}
		})
	}
	legacy := v2ConfigFixture(t)
	legacy.Schema = "testifysec.hardened-opencode.gateway/v1"
	legacy.Backend = nil
	legacy.SignedProfileFile, legacy.AdmissionExecutable, legacy.AdmissionSHA256 = "", "", ""
	if err := profileConfiguration(legacy); err != nil {
		t.Fatal("legacy explicit development fixture changed", err)
	}
}

func TestGatewayV2RejectsAmbiguousConfigFields(t *testing.T) {
	c := v2ConfigFixture(t)
	data, _ := json.Marshal(c)
	backend, _ := json.Marshal(c.Backend)
	raw := string(data)
	for name, altered := range map[string]string{
		"alias":       strings.Replace(raw, `"manifestSha256":`, `"ManifestSha256":`, 1),
		"duplicate":   strings.Replace(raw, `"kind":"darwin-vz/v1"`, `"kind":"darwin-vz/v1","kind":"darwin-vz/v1"`, 1),
		"null":        strings.Replace(raw, `"backend":`+string(backend), `"backend":null`, 1),
		"nested-null": strings.Replace(raw, `"kind":"darwin-vz/v1"`, `"kind":null`, 1),
		"surrogate":   strings.Replace(raw, `"model":"approved"`, `"model":"\ud800"`, 1),
		"fraction":    strings.Replace(raw, `"maxRecords":4`, `"maxRecords":4.0`, 1),
		"exponent":    strings.Replace(raw, `"maxRecords":4`, `"maxRecords":4e0`, 1),
		"unknown":     strings.Replace(raw, `"kind":"darwin-vz/v1"`, `"kind":"darwin-vz/v1","allow":true`, 1),
		"missing":     strings.Replace(raw, `"session":"fixture-session",`, "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(filepath.Dir(c.Spool), "config.json")
			if err := os.WriteFile(path, []byte(altered), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := readConfig(path); err == nil {
				t.Fatal("ambiguous configuration accepted")
			}
		})
	}
}

func TestGatewayV2AdmissionIsTypedAndBackendBound(t *testing.T) {
	assigned := BackendAssignment{"darwin-vz/v1", strings.Repeat("c", 64)}
	var v2 profileAdmissionV2
	v2.SchemaVersion, v2.Admitted, v2.Scope = 2, true, "profile-admission-only"
	v2.EnvelopeSHA256, v2.PayloadSHA256 = strings.Repeat("a", 64), strings.Repeat("b", 64)
	v2.SignerKeyIDs, v2.TrustSHA256, v2.NativeSHA256 = []string{"fixture"}, strings.Repeat("d", 64), strings.Repeat("e", 64)
	v2.Profile.ProfileID, v2.Profile.TenantID, v2.Profile.DeploymentID = "profile", "tenant", "deployment"
	v2.Profile.Sequence, v2.Profile.NotBefore, v2.Profile.ExpiresAt = 1, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z"
	v2.Profile.Backend = assigned
	data, _ := json.Marshal(v2)
	raw := string(data)
	result, err := decodeProfileV2(data, assigned)
	if err != nil || result.SchemaVersion != 2 || result.Profile.TenantID != "tenant" || result.PayloadSHA256 != v2.PayloadSHA256 {
		t.Fatal("valid typed v2 result refused", err)
	}
	var legacy profileAdmission
	if strictJSON(data, &legacy) == nil {
		t.Fatal("v2 output accepted by unchanged v1 output type")
	}
	for name, altered := range map[string]string{
		"v1":                  strings.Replace(raw, `"schemaVersion":2`, `"schemaVersion":1`, 1),
		"backend":             strings.Replace(raw, assigned.ManifestSHA256, strings.Repeat("f", 64), 1),
		"kind":                strings.Replace(raw, "darwin-vz/v1", "darwin-vz/v2", 1),
		"alias":               strings.Replace(raw, `"manifestSha256":`, `"ManifestSha256":`, 1),
		"duplicate":           strings.Replace(raw, `"schemaVersion":2`, `"schemaVersion":2,"schemaVersion":2`, 1),
		"null-signers":        strings.Replace(raw, `"signerKeyIds":["fixture"]`, `"signerKeyIds":null`, 1),
		"missing-sequence":    strings.Replace(raw, `"sequence":1,`, "", 1),
		"fractional-sequence": strings.Replace(raw, `"sequence":1`, `"sequence":1.0`, 1),
		"negative-zero":       strings.Replace(raw, `"sequence":1`, `"sequence":-0`, 1),
		"overflow":            strings.Replace(raw, `"sequence":1`, `"sequence":18446744073709551616`, 1),
		"surrogate":           strings.Replace(raw, `"profileId":"profile"`, `"profileId":"\ud800"`, 1),
		"extra":               strings.TrimSuffix(raw, "}") + `,"authority":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeProfileV2([]byte(altered), assigned); err == nil {
				t.Fatal("invalid native admission output accepted")
			}
		})
	}
}
