package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
)

func fixture(t *testing.T) request {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptoutil.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := signer.Verifier()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := verifier.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if block, _ := pem.Decode(pub); block == nil {
		t.Fatal("expected PEM verifier bytes")
	}
	envelope, err := dsse.Sign("application/vnd.in-toto+json", bytes.NewBufferString(`{"message":"synthetic native binding fixture"}`), dsse.SignWithSigners(signer))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return request{Envelope: encoded, PublicKeys: []string{string(pub)}, ExpectedPayloadType: envelope.PayloadType, Threshold: 1}
}

func TestVerification(t *testing.T) {
	good := fixture(t)
	for _, name := range []string{"valid", "tampered", "wrong-key", "wrong-type", "unsigned", "duplicate-signer", "zero-threshold", "missing-trust"} {
		t.Run(name, func(t *testing.T) {
			input := good
			var envelope dsse.Envelope
			if err := json.Unmarshal(input.Envelope, &envelope); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "tampered":
				envelope.Payload = []byte("changed")
			case "wrong-key":
				input.PublicKeys = fixture(t).PublicKeys
			case "wrong-type":
				input.ExpectedPayloadType = "different"
			case "unsigned":
				envelope.Signatures = nil
			case "duplicate-signer":
				envelope.Signatures = append(envelope.Signatures, envelope.Signatures[0])
				input.PublicKeys = []string{good.PublicKeys[0], good.PublicKeys[0]}
				input.Threshold = 2
			case "zero-threshold":
				input.Threshold = 0
			case "missing-trust":
				input.PublicKeys = nil
			}
			input.Envelope, _ = json.Marshal(envelope)
			encoded, _ := json.Marshal(input)
			result, err := verify(encoded)
			if name == "valid" {
				if err != nil || !result.OK || len(result.SignerKeyIDs) != 1 {
					t.Fatalf("result=%+v err=%v", result, err)
				}
				return
			}
			if err == nil || result.OK {
				t.Fatal("invalid input accepted")
			}
		})
	}
}

func TestMalformed(t *testing.T) {
	for _, data := range [][]byte{nil, []byte(`{`), []byte(`{"threshold":1,"threshold":2}`), []byte(`{} {}`), bytes.Repeat([]byte("x"), maxRequest+1)} {
		var result response
		if err := json.Unmarshal(verifyJSON(data), &result); err != nil {
			t.Fatal(err)
		}
		if result.OK || result.Error == "" || result.ABIVersion != 1 {
			t.Fatal("invalid error response")
		}
	}
}

func TestCanonicalFields(t *testing.T) {
	good := fixture(t)
	encoded, _ := json.Marshal(good)
	for _, data := range [][]byte{
		append(append([]byte{}, encoded[:len(encoded)-1]...), []byte(`,"Threshold":1}`)...),
		bytes.Replace(encoded, []byte(`"payloadType"`), []byte(`"PayloadType"`), 1),
		bytes.Replace(encoded, []byte(`"sig"`), []byte(`"Sig"`), 1),
	} {
		if result, err := verify(data); err == nil || result.OK {
			t.Fatal("noncanonical input accepted")
		}
	}
}

func TestExportSyntheticFixtures(t *testing.T) {
	directory := os.Getenv("ROOKERY_TEST_FIXTURES")
	if directory == "" {
		t.Skip("fixture export not requested")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	input := fixture(t)
	encoded, _ := json.Marshal(input)
	if err := os.WriteFile(filepath.Join(directory, "valid.json"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	input.PublicKeys = fixture(t).PublicKeys
	encoded, _ = json.Marshal(input)
	if err := os.WriteFile(filepath.Join(directory, "invalid.json"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
}
