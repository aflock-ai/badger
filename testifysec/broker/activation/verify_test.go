package activation

import (
	"crypto/x509"
	"strings"
	"testing"
)

func TestVerifyRefusesMalformedRecords(t *testing.T) {
	root := newRoot(t, "enclave root")
	trust := trustFor(root)
	leaf := signer{issuer: root, notBefore: -86400, last: 6 * 86400, san: portalSAN}
	good := activationBody(21, 10, 1, -60, 3600)
	for name, change := range map[string]func(map[string]any){
		"unknown field":      func(b map[string]any) { b["extra"] = true },
		"missing field":      func(b map[string]any) { delete(b, "profileSequence") },
		"case alias":         func(b map[string]any) { b["TenantId"] = b["tenantId"]; delete(b, "tenantId") },
		"sequence zero":      func(b map[string]any) { b["sequence"] = 0 },
		"fraction":           func(b map[string]any) { b["sequence"] = 21.5 },
		"schema 2":           func(b map[string]any) { b["schemaVersion"] = 2 },
		"empty window":       func(b map[string]any) { b["expiresAt"] = b["notBefore"] },
		"offset instant":     func(b map[string]any) { b["notBefore"] = strings.Replace(b["notBefore"].(string), "Z", "+00:00", 1) },
		"digest in capitals": func(b map[string]any) { b["profileSha256"] = strings.Repeat("A", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			body := map[string]any{}
			for k, v := range good {
				body[k] = v
			}
			change(body)
			_, err := Verify(trust, envelope(t, ActivationType, body, leaf))
			refused(t, err, RefuseMalformed)
		})
	}
	_, err := Verify(trust, envelope(t, ResetType, good, leaf)) // an activation body under the reset type
	refused(t, err, RefuseMalformed)
	raw := envelope(t, ActivationType, good, leaf)
	_, err = Verify(trust, append(raw[:len(raw)-1:len(raw)-1], []byte(`,"payloadType":"x"}`)...))
	refused(t, err, RefuseMalformed) // duplicate envelope key
}

// The leaf restrictions in carries: a CA, no code-signing EKU, no digital-signature key usage.
func TestVerifyRefusesNonSigningLeaves(t *testing.T) {
	root := newRoot(t, "enclave root")
	for name, change := range map[string]func(*x509.Certificate){
		"CA leaf": func(c *x509.Certificate) {
			c.IsCA, c.BasicConstraintsValid, c.KeyUsage = true, true, x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign
		},
		"no code signing":      func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} },
		"no digital signature": func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment },
	} {
		t.Run(name, func(t *testing.T) {
			raw := envelope(t, ActivationType, activationBody(41, 12, 200, -60, 3600),
				signer{issuer: root, notBefore: -86400, last: 6 * 86400, san: portalSAN, adjust: change})
			_, err := Verify(trustFor(root), raw)
			refused(t, err, RefuseChain)
		})
	}
}
