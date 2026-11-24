//go:build uatnoprofile

// jade:ring local

package main

import (
	"context"
	"encoding/pem"
	"strings"
	"testing"
)

// Only the uatnoprofile build runs unsigned sandbox fixtures, and even there a supplied profile is
// never ignored and a policy without the development flag still needs a verifier.
func TestUATBuildRunsUnsignedFixturesOnly(t *testing.T) {
	if _, err := verifyAdmission(context.Background(), policy{DevelopmentAllowSameUID: true}, ""); err != nil {
		t.Fatalf("uat build refused its unsigned fixture: %v", err)
	}
	if _, err := verifyAdmission(context.Background(), policy{}, ""); err == nil {
		t.Fatal("unsigned request admitted without the development flag")
	}
	if _, _, err := loadPolicy(writePolicy(t, testPolicy(t))); err != nil {
		t.Fatalf("uat build refused its development policy: %v", err)
	}
	p := testPolicy(t)
	p.DevelopmentAllowSameUID = false
	if _, _, err := loadPolicy(writePolicy(t, p)); err == nil {
		t.Fatal("production policy without a verifier loaded")
	}
	// An activation block is a profile pin: even here it needs the verifier and the whole
	// assignment. Start from a complete, valid activation policy and drop one requirement at a time.
	valid := testPolicy(t)
	valid.AdmissionExecutable, valid.AdmissionSHA256 = "/opt/badger/admission", strings.Repeat("a", 64)
	valid.TenantID, valid.DeploymentID, valid.ProfileID = "tenant-a", "deployment-a", "profile-a"
	valid.Activation = &activationPolicy{StateDir: "/var/lib/badger/device", SignerSAN: testSAN, DeviceKeySHA256: strings.Repeat("d", 64),
		RootCAs: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newTestPortal(t).root.Raw}))}}
	if _, _, err := loadPolicy(writePolicy(t, valid)); err != nil {
		t.Fatalf("complete activation policy refused: %v", err)
	}
	for name, drop := range map[string]func(*policy){
		"no verifier":   func(p *policy) { p.AdmissionExecutable, p.AdmissionSHA256 = "", "" },
		"no tenant":     func(p *policy) { p.TenantID = "" },
		"no deployment": func(p *policy) { p.DeploymentID = "" },
		"no profile id": func(p *policy) { p.ProfileID = "" },
	} {
		p := valid
		activationCopy := *valid.Activation
		p.Activation = &activationCopy
		drop(&p)
		if _, _, err := loadPolicy(writePolicy(t, p)); err == nil {
			t.Fatalf("development policy with activation and %s loaded", name)
		}
	}
}
