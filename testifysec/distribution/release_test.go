// jade:ring local
package main

import (
	"archive/tar"
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
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
)

func hash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func TestStrictReleaseNumbers(t *testing.T) {
	for _, text := range []string{`{"sequence":9.999999999999999999}`, `{"sequence":10,"Sequence":1}`, `{"sequence":10,"sequence":1}`, `{"sequence":9223372036854775808}`} {
		var value manifest
		if strictDecode([]byte(text), &value) == nil {
			t.Fatalf("accepted ambiguous number: %s", text)
		}
	}
}

func TestUnsafeArchivePaths(t *testing.T) {
	for _, name := range []string{"../escape", "/escape", "bin/../../escape", "bin//tool", "bin/./tool", "bin\\tool", ".git/config", "C:/escape", "bin/tool\n", "bin/\ufffd"} {
		if safePath(name) {
			t.Fatalf("unsafe path accepted: %q", name)
		}
	}
}

// This export uses actual Rookery signatures from ephemeral test-only keys.
// It never accepts, serializes, or persists a release signing credential.
func TestExportReleaseUATFixtures(t *testing.T) {
	dir := os.Getenv("HC_DISTRIBUTION_FIXTURES")
	if dir == "" {
		t.Skip("fixture export not requested")
	}
	input, err := os.ReadFile(filepath.Join(dir, "manifest.unsigned.json"))
	if err != nil {
		t.Fatal(err)
	}
	var base manifest
	if err := strictDecode(input, &base); err != nil {
		t.Fatal(err)
	}
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
	public, err := verifier.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	var license string
	for _, file := range base.Artifacts {
		if file.Path == "LICENSES/OpenCode.LICENSE" {
			license = file.SHA256
		}
	}
	trusted := trust{Schema: "testifysec.release-trust/v1", Purpose: "release-verification", Product: base.Product, Tenant: base.Tenant, Channel: base.Channel,
		MinimumSequence: base.Sequence, UpstreamCommit: base.UpstreamCommit, UpstreamTree: base.UpstreamTree, UpstreamLicenseSHA256: license, PublicKeys: []string{string(public)}, Threshold: 1}
	writeJSON := func(name string, value any) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	sign := func(name string, value manifest) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := dsse.Sign(releaseType, bytes.NewReader(data), dsse.SignWithSigners(signer))
		if err != nil {
			t.Fatal(err)
		}
		writeJSON(name+".dsse.json", envelope)
	}
	writeJSON("trust.json", trusted)
	sign("valid", base)
	for _, name := range []string{"downgrade", "wrong-tenant", "wrong-channel", "wrong-upstream", "expired", "future", "license-substitution"} {
		value := base
		value.Artifacts = append([]artifact(nil), base.Artifacts...)
		switch name {
		case "downgrade":
			value.Sequence--
		case "wrong-tenant":
			value.Tenant = "different-tenant"
		case "wrong-channel":
			value.Channel = "different-channel"
		case "wrong-upstream":
			value.UpstreamCommit = strings.Repeat("0", 40)
		case "expired":
			value.ExpiresAt = time.Now().UTC().Add(-time.Minute).Format("2006-01-02T15:04:05Z")
		case "future":
			value.NotBefore = time.Now().UTC().Add(time.Hour).Format("2006-01-02T15:04:05Z")
		case "license-substitution":
			for i := range value.Artifacts {
				if value.Artifacts[i].Path == "LICENSES/OpenCode.LICENSE" {
					value.Artifacts[i].SHA256 = strings.Repeat("0", 64)
				}
			}
		}
		sign(name, value)
	}
	// Archives below are correctly hashed and signed. Their refusal must come
	// from archive structure validation, not an unrelated signature/hash failure.
	for _, name := range []string{"traversal", "symlink", "hardlink", "duplicate-entry", "extra-entry", "missing-entry", "artifact-tamper", "appended-archive"} {
		var buffer bytes.Buffer
		tarWriter := tar.NewWriter(&buffer)
		value := base
		licenseBytes := []byte("synthetic fixture license")
		value.Artifacts = []artifact{{Path: "LICENSES/OpenCode.LICENSE", SHA256: hash(licenseBytes), Size: int64(len(licenseBytes)), Mode: 0644}, {Path: "bin/tool", SHA256: hash([]byte("good")), Size: 4, Mode: 0755}}
		// Use a matching dedicated trust for these synthetic archive fixtures.
		fixtureTrust := trusted
		fixtureTrust.UpstreamLicenseSHA256 = hash(licenseBytes)
		writeJSON("archive-trust.json", fixtureTrust)
		writeEntry := func(header *tar.Header, data []byte) {
			t.Helper()
			header.Format = tar.FormatUSTAR
			if err := tarWriter.WriteHeader(header); err != nil {
				t.Fatal(err)
			}
			if _, err := tarWriter.Write(data); err != nil {
				t.Fatal(err)
			}
		}
		writeEntry(&tar.Header{Name: "LICENSES/OpenCode.LICENSE", Typeflag: tar.TypeReg, Size: int64(len(licenseBytes)), Mode: 0644}, licenseBytes)
		header := &tar.Header{Name: "bin/tool", Typeflag: tar.TypeReg, Size: 4, Mode: 0755}
		data := []byte("good")
		switch name {
		case "traversal":
			header.Name = "../escape"
		case "symlink":
			header.Typeflag = tar.TypeSymlink
			header.Linkname = "/etc/passwd"
			header.Size = 0
			data = nil
		case "hardlink":
			header.Typeflag = tar.TypeLink
			header.Linkname = "LICENSES/OpenCode.LICENSE"
			header.Size = 0
			data = nil
		case "artifact-tamper":
			data = []byte("evil")
		}
		if name != "missing-entry" {
			writeEntry(header, data)
		}
		if name == "duplicate-entry" {
			writeEntry(header, data)
		}
		if name == "extra-entry" {
			writeEntry(&tar.Header{Name: "unlisted", Typeflag: tar.TypeReg, Mode: 0644}, nil)
		}
		if err := tarWriter.Close(); err != nil {
			t.Fatal(err)
		}
		if name == "appended-archive" {
			buffer.WriteString("hidden second archive")
		}
		value.ArchiveSHA256 = hash(buffer.Bytes())
		value.ArchiveSize = int64(buffer.Len())
		if err := os.WriteFile(filepath.Join(dir, name+".tar"), buffer.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		sign(name, value)
		if err := admitted(fixtureTrust, value, time.Now().UTC()); err != nil {
			t.Fatal("malicious archive fixture must pass signed manifest admission: ", err)
		}
		if err := verifyArchive(filepath.Join(dir, name+".tar"), value); err == nil {
			t.Fatal("accepted malicious archive ", name)
		}
	}
}
