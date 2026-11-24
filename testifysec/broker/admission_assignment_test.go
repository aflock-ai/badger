// jade:ring local

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeVerifier writes a pinned, broker-owned executable that prints one admission output for the
// envelope it is given, and returns a policy that runs it.
func fakeVerifier(t *testing.T, envelope string, profile map[string]any) policy {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	output, err := json.Marshal(map[string]any{
		"schemaVersion": 1, "admitted": true, "scope": "profile-admission-only",
		"envelopeSha256": hash([]byte(envelope)), "payloadSha256": strings.Repeat("a", 64),
		"signerKeyIds": []string{strings.Repeat("b", 64)}, "profile": profile,
	})
	if err != nil {
		t.Fatal(err)
	}
	script := []byte("#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '" + string(output) + "'\n")
	path := filepath.Join(dir, "verifier")
	if err = os.WriteFile(path, script, 0700); err != nil {
		t.Fatal(err)
	}
	return policy{AdmissionExecutable: path, AdmissionSHA256: hash(script), ProfileSHA256: strings.Repeat("a", 64),
		TenantID: "tenant-a", DeploymentID: "deployment-a", ProfileID: "profile-a"}
}

// The schema-1 path used to bind a profile only through the pinned payload digest (#160): a
// verifier that admitted another tenant's profile with that digest was believed. The broker now
// checks the assignment against its own policy.
func TestAdmissionChecksAssignment(t *testing.T) {
	now := time.Now().UTC()
	assigned := map[string]any{"tenantId": "tenant-a", "deploymentId": "deployment-a", "profileId": "profile-a",
		"sequence": 3, "notBefore": now.Add(-time.Hour).Format(time.RFC3339), "expiresAt": now.Add(time.Hour).Format(time.RFC3339)}
	envelope := `{"payloadType":"test-only"}`
	if digest, err := verifyAdmission(context.Background(), fakeVerifier(t, envelope, assigned), envelope); err != nil || digest != strings.Repeat("a", 64) {
		t.Fatalf("assigned profile refused: %q %v", digest, err)
	}
	for name, change := range map[string][2]any{
		"another tenant":     {"tenantId", "tenant-b"},
		"another deployment": {"deploymentId", "deployment-b"},
		"another profile":    {"profileId", "profile-b"},
		"sequence zero":      {"sequence", 0},
		"sequence 2^53":      {"sequence", int64(9007199254740992)},
	} {
		t.Run(name, func(t *testing.T) {
			profile := map[string]any{}
			for k, v := range assigned {
				profile[k] = v
			}
			profile[change[0].(string)] = change[1]
			_, err := verifyAdmission(context.Background(), fakeVerifier(t, envelope, profile), envelope)
			var refused *refusal
			if !errors.As(err, &refused) || refused.Code != "profile_denied" {
				t.Fatalf("admitted or wrong refusal: %v", err)
			}
		})
	}
}

// A policy that names a verifier must name the assignment too.
func TestPolicyRequiresAssignmentWithVerifier(t *testing.T) {
	p := testPolicy(t)
	p.AdmissionExecutable, p.AdmissionSHA256, p.ProfileSHA256 = "/opt/badger/admission", strings.Repeat("a", 64), strings.Repeat("b", 64)
	p.TenantID, p.DeploymentID, p.ProfileID = "tenant-a", "deployment-a", "profile-a"
	if _, _, err := loadPolicy(writePolicy(t, p)); err != nil {
		t.Fatalf("complete policy refused: %v", err)
	}
	for _, id := range []*string{&p.TenantID, &p.DeploymentID, &p.ProfileID} {
		saved := *id
		*id = ""
		if _, _, err := loadPolicy(writePolicy(t, p)); err == nil {
			t.Fatal("policy without the whole assignment loaded")
		}
		*id = "../escape"
		if _, _, err := loadPolicy(writePolicy(t, p)); err == nil {
			t.Fatal("policy with an invalid identifier loaded")
		}
		*id = saved
	}
}

func testPolicy(t *testing.T) policy {
	t.Helper()
	return policy{Schema: policySchema, ListenSocket: "/run/badger-test/broker.sock", DockerSocket: "/run/badger-test/docker.sock",
		Image: "sha256:" + strings.Repeat("0", 64), Workspace: workspace{"test", "/srv/badger-test/source"},
		Limits: limits{TimeoutSeconds: 1, OutputBytes: 1024, WorkspaceBytes: 1024, WorkspaceFiles: 10}, AllowedUIDs: []uint32{65534},
		DevelopmentAllowSameUID: true}
}

func writePolicy(t *testing.T, p policy) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.json")
	if err = os.WriteFile(path, marshal(p), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The sequence's upper bound is inclusive: 2^53-1 is admitted (2^53 is refused above).
func TestAdmissionAcceptsTheLargestSequence(t *testing.T) {
	now := time.Now().UTC()
	profile := map[string]any{"tenantId": "tenant-a", "deploymentId": "deployment-a", "profileId": "profile-a",
		"sequence": int64(9007199254740991), "notBefore": now.Add(-time.Hour).Format(time.RFC3339), "expiresAt": now.Add(time.Hour).Format(time.RFC3339)}
	envelope := `{"payloadType":"test-only"}`
	if _, err := verifyAdmission(context.Background(), fakeVerifier(t, envelope, profile), envelope); err != nil {
		t.Fatalf("sequence 2^53-1 refused: %v", err)
	}
}
