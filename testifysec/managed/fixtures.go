// jade:ring local
// Build-time synthetic fixture generator. Keys are ephemeral and never persisted.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
)

const mediaType = "application/vnd.testifysec.hardened-opencode.profile.v1+json"

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

func main() {
	if len(os.Args) != 2 {
		panic("usage: fixture-generator OUTPUT")
	}
	directory := os.Args[1]
	if err := os.MkdirAll(directory, 0700); err != nil {
		panic(err)
	}
	signer := must(cryptoutil.NewSigner(must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))))
	verifier := must(signer.Verifier())
	public := must(verifier.Bytes())
	write := func(name string, value any) {
		if err := os.WriteFile(filepath.Join(directory, name+".json"), must(json.Marshal(value)), 0600); err != nil {
			panic(err)
		}
	}
	write("trust", map[string]any{
		"schemaVersion": 1, "publicKeys": []string{string(public)}, "threshold": 1,
		"tenantId": "uat-tenant", "deploymentId": "uat-deployment", "profileId": "uat-managed", "minimumSequence": 10,
	})
	now := time.Now().UTC()
	profile := func() map[string]any {
		return map[string]any{
			"schemaVersion": 1, "tenantId": "uat-tenant", "deploymentId": "uat-deployment", "profileId": "uat-managed",
			"sequence": 10, "notBefore": now.Add(-time.Hour).Format(time.RFC3339), "expiresAt": now.Add(24 * time.Hour).Format(time.RFC3339),
			"controls": map[string]any{"runtimePackageDownloads": false, "execution": "broker-only", "audit": "required"},
		}
	}
	cases := []string{"valid", "tampered", "wrong-key", "expired", "not-yet-valid", "wrong-tenant", "wrong-deployment", "wrong-profile", "rollback", "unknown-field", "unknown-control", "duplicate-payload", "unsupported-version", "weakened-controls", "fractional-sequence", "invalid-utf8", "rounded-sequence", "rounded-schema-version", "exponent-sequence", "unsafe-sequence", "negative-zero"}
	for _, name := range cases {
		value := profile()
		switch name {
		case "expired":
			value["expiresAt"] = now.Add(-time.Minute).Format(time.RFC3339)
		case "not-yet-valid":
			value["notBefore"] = now.Add(time.Hour).Format(time.RFC3339)
		case "wrong-tenant":
			value["tenantId"] = "another-tenant"
		case "wrong-deployment":
			value["deploymentId"] = "another-deployment"
		case "wrong-profile":
			value["profileId"] = "another-profile"
		case "rollback":
			value["sequence"] = 9
		case "unknown-field":
			value["publicKeys"] = []string{string(public)}
		case "unknown-control":
			value["controls"].(map[string]any)["allowShell"] = true
		case "unsupported-version":
			value["schemaVersion"] = 2
		case "weakened-controls":
			value["controls"].(map[string]any)["runtimePackageDownloads"] = true
		case "fractional-sequence":
			value["sequence"] = 10.5
		}
		payload := must(json.Marshal(value))
		// Preserve raw numeric lexemes; constructing these as floats would erase
		// the very precision attacks these signed fixtures must exercise.
		switch name {
		case "rounded-sequence":
			payload = bytes.Replace(payload, []byte(`"sequence":10`), []byte(`"sequence":9.999999999999999999`), 1)
		case "rounded-schema-version":
			payload = bytes.Replace(payload, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1.00000000000000001`), 1)
		case "exponent-sequence":
			payload = bytes.Replace(payload, []byte(`"sequence":10`), []byte(`"sequence":1e1`), 1)
		case "unsafe-sequence":
			payload = bytes.Replace(payload, []byte(`"sequence":10`), []byte(`"sequence":9007199254740993`), 1)
		case "negative-zero":
			payload = bytes.Replace(payload, []byte(`"sequence":10`), []byte(`"sequence":-0`), 1)
		}
		if name == "duplicate-payload" {
			payload = append([]byte(`{"\u0074enantId":"unapproved",`), payload[1:]...)
		}
		if name == "invalid-utf8" {
			payload = []byte{'"', 0xff, '"'}
		}
		selected := signer
		if name == "wrong-key" {
			selected = must(cryptoutil.NewSigner(must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))))
		}
		envelope := must(dsse.Sign(mediaType, bytes.NewReader(payload), dsse.SignWithSigners(selected)))
		if name == "tampered" {
			envelope.Payload = append(envelope.Payload, ' ')
		}
		write(name, envelope)
	}
}
