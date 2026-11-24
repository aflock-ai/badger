package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// write lays out a bundle: a manifest, signed by priv.
func write(t *testing.T, manifest string, priv ed25519.PrivateKey) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ManifestFile), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if priv != nil {
		if err := os.WriteFile(filepath.Join(dir, SigFile), Sign(priv, []byte(manifest)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func manifest(digest, extra string) string {
	return `{"schema":1,"name":"demo","version":"1.0.0","digest":"` + digest + `","tools":[` +
		`{"name":"demo_get","description":"Get.","inputSchema":{"type":"object"}},` +
		`{"name":"demo_put","description":"Put.","write":true,"inputSchema":{"type":"object"}}]` + extra + `}`
}

func TestLoadVerifiesSignatureAndDigest(t *testing.T) {
	pub, priv := keys(t)
	other, otherPriv := keys(t)
	d := Digest([]byte("an image manifest"))

	m, err := Load(write(t, manifest(d, ""), priv), pub)
	if err != nil || m.Digest != d || len(m.Tools) != 2 || !m.Tools[1].Write {
		t.Fatalf("good bundle: %v %+v", err, m)
	}
	for name, dir := range map[string]string{
		"unsigned":         write(t, manifest(d, ""), nil),
		"other signer":     write(t, manifest(d, ""), otherPriv),
		"bad digest form":  write(t, manifest("md5:00", ""), priv),
		"bad tool name":    write(t, strings.Replace(manifest(d, ""), "demo_get", "Demo Get", 1), priv),
		"repeated tool":    write(t, strings.Replace(manifest(d, ""), "demo_put", "demo_get", 1), priv),
		"no description":   write(t, strings.Replace(manifest(d, ""), `"Get."`, `""`, 1), priv),
		"schema not obj":   write(t, strings.Replace(manifest(d, ""), `{"type":"object"}}`, `{"type":"string"}}`, 1), priv),
		"unknown schema v": write(t, strings.Replace(manifest(d, ""), `"schema":1`, `"schema":2`, 1), priv),
	} {
		if _, err := Load(dir, pub); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The signature is over the exact bytes: a manifest edited after signing is refused.
	dir := write(t, manifest(d, ""), priv)
	_ = os.WriteFile(filepath.Join(dir, ManifestFile), []byte(manifest(d, " ")), 0o644)
	if _, err := Load(dir, pub); err == nil {
		t.Error("edited manifest accepted")
	}
	if _, err := Load(write(t, manifest(d, ""), priv), other); err == nil {
		t.Error("verified with the wrong key")
	}
}

// Fields a plugin adds to its manifest (a classification, a grant) are not part of the contract:
// they are ignored, never read.
func TestManifestClaimsBeyondTheContractAreIgnored(t *testing.T) {
	pub, priv := keys(t)
	m, err := Load(write(t, manifest(Digest([]byte("x")), `,"classification":"ANYTHING","writes":true`), priv), pub)
	if err != nil || m.Name != "demo" {
		t.Fatalf("%v %+v", err, m)
	}
}

func TestKeysRoundTrip(t *testing.T) {
	pub, priv := keys(t)
	k, err := ParseKey(base64.StdEncoding.EncodeToString(pub))
	if err != nil || !k.Equal(pub) {
		t.Fatalf("%v", err)
	}
	if _, err := ParseKey("not base64!"); err == nil {
		t.Fatal("bad key accepted")
	}
	if Verify(pub, []byte("m"), Sign(priv, []byte("m"))) != nil || Verify(pub, []byte("n"), Sign(priv, []byte("m"))) == nil {
		t.Fatal("verify")
	}
}
