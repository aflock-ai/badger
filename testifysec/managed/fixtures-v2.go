//go:build ignore

// jade:ring local
// Local signed compatibility fixtures. Ephemeral private keys never leave memory.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
)

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

func main() {
	if len(os.Args) != 2 {
		panic("fixture output required")
	}
	directory := os.Args[1]
	if err := os.Mkdir(directory, 0700); err != nil {
		panic(err)
	}
	write := func(name string, raw []byte) {
		if err := os.WriteFile(filepath.Join(directory, name+".json"), raw, 0600); err != nil {
			panic(err)
		}
	}
	manifest := []byte(`{"schema":"testifysec.synthetic-backend-manifest/v1","executable":false}`)
	write("backend-manifest", manifest)
	hash := sha256.Sum256(manifest)
	pin := hex.EncodeToString(hash[:])
	backend := func() map[string]any { return map[string]any{"kind": "darwin-vz/v1", "manifestSha256": pin} }
	signer := must(cryptoutil.NewSigner(must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))))
	public := must(must(signer.Verifier()).Bytes())
	for _, version := range []int{1, 2} {
		trust := map[string]any{"schemaVersion": version, "publicKeys": []string{string(public)}, "threshold": 1, "tenantId": "uat-tenant", "deploymentId": "uat-deployment", "profileId": "uat-managed", "minimumSequence": 10}
		if version == 2 {
			trust["backend"] = backend()
		}
		write("trust-v"+string(rune('0'+version)), must(json.Marshal(trust)))
	}
	now := time.Now().UTC()
	for _, name := range []string{"valid-v1", "valid-v2", "tampered", "wrong-key", "expired", "future", "wrong-tenant", "rollback", "wrong-backend", "wrong-pin", "uppercase-pin", "short-pin", "missing-backend", "null-backend", "extra-backend", "unknown-field", "duplicate-backend", "rounded-version", "rounded-sequence", "weakened-controls", "type1-schema2", "type2-schema1", "unsupported-version", "unsupported-type"} {
		value := map[string]any{"schemaVersion": 2, "tenantId": "uat-tenant", "deploymentId": "uat-deployment", "profileId": "uat-managed", "sequence": 10, "notBefore": now.Add(-time.Minute).Format(time.RFC3339), "expiresAt": now.Add(time.Hour).Format(time.RFC3339), "controls": map[string]any{"runtimePackageDownloads": false, "execution": "broker-only", "audit": "required"}, "backend": backend()}
		media := "application/vnd.testifysec.hardened-opencode.profile.v2+json"
		switch name {
		case "valid-v1":
			value["schemaVersion"] = 1
			delete(value, "backend")
			media = "application/vnd.testifysec.hardened-opencode.profile.v1+json"
		case "expired":
			value["expiresAt"] = now.Add(-time.Second).Format(time.RFC3339)
		case "future":
			value["notBefore"] = now.Add(time.Minute).Format(time.RFC3339)
		case "wrong-tenant":
			value["tenantId"] = "other"
		case "rollback":
			value["sequence"] = 9
		case "wrong-backend":
			value["backend"].(map[string]any)["kind"] = "linux-docker/v1"
		case "wrong-pin":
			value["backend"].(map[string]any)["manifestSha256"] = strings.Repeat("0", 64)
		case "uppercase-pin":
			value["backend"].(map[string]any)["manifestSha256"] = strings.Repeat("A", 64)
		case "short-pin":
			value["backend"].(map[string]any)["manifestSha256"] = "a"
		case "missing-backend":
			delete(value, "backend")
		case "null-backend":
			value["backend"] = nil
		case "extra-backend":
			value["backend"].(map[string]any)["override"] = true
		case "unknown-field":
			value["publicKeys"] = []string{string(public)}
		case "weakened-controls":
			value["controls"].(map[string]any)["audit"] = "optional"
		case "type1-schema2":
			media = "application/vnd.testifysec.hardened-opencode.profile.v1+json"
		case "type2-schema1":
			value["schemaVersion"] = 1
		case "unsupported-version":
			value["schemaVersion"] = 3
		case "unsupported-type":
			media = "application/vnd.testifysec.hardened-opencode.profile.v3+json"
		}
		payload := must(json.Marshal(value))
		switch name {
		case "duplicate-backend":
			payload = bytes.Replace(payload, []byte(`"kind":"darwin-vz/v1"`), []byte(`"kind":"darwin-vz/v1","\u006bind":"darwin-vz/v1"`), 1)
		case "rounded-version":
			payload = bytes.Replace(payload, []byte(`"schemaVersion":2`), []byte(`"schemaVersion":2.00000000000000001`), 1)
		case "rounded-sequence":
			payload = bytes.Replace(payload, []byte(`"sequence":10`), []byte(`"sequence":9.999999999999999999`), 1)
		}
		selected := signer
		if name == "wrong-key" {
			selected = must(cryptoutil.NewSigner(must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))))
		}
		envelope := must(dsse.Sign(media, bytes.NewReader(payload), dsse.SignWithSigners(selected)))
		if name == "tampered" {
			envelope.Payload = append(envelope.Payload, ' ')
		}
		write(name, must(json.Marshal(envelope)))
	}
}
