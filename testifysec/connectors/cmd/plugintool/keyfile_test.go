package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testPass = "a test passphrase 0123"

func TestMain(m *testing.M) {
	os.Setenv("PLUGINTOOL_PASSPHRASE", testPass)
	keyIterations = 1000 // the format is the same; 600000 rounds would make the byte-flip test slow
	os.Exit(m.Run())
}

// An encrypted key file opens with its passphrase and gives back the same key; a wrong passphrase,
// any single changed byte, a header naming another version, or a plaintext key without
// --insecure-plaintext-key is refused.
func TestTheSigningKeyIsEncryptedAtRest(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	file, err := sealKey(priv, []byte(testPass))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(file), string(priv.Seed())) {
		t.Fatal("the seed is in the file")
	}
	got, err := openKey(file, "", false)
	if err != nil || !got.Equal(priv) {
		t.Fatalf("round trip: %v", err)
	}
	t.Setenv("PLUGINTOOL_PASSPHRASE", "another passphrase 0123")
	if _, err := openKey(file, "", false); err == nil {
		t.Fatal("a wrong passphrase opened the key")
	}
	t.Setenv("PLUGINTOOL_PASSPHRASE", testPass)
	for i := range file {
		flipped := append([]byte{}, file...)
		flipped[i] ^= 0x01
		if _, err := openKey(flipped, "", false); err == nil {
			t.Fatalf("byte %d flipped (%q -> %q) still opened", i, file[i], flipped[i])
		}
	}
	other := strings.Replace(string(file), keyMagic+keyVersion, keyMagic+"v2", 1)
	if _, err := openKey([]byte(other), "", false); err == nil || !strings.Contains(err.Error(), "unsupported header") {
		t.Fatalf("version v2: %v", err)
	}
}

// The passphrase never comes from argv: --passphrase-file or PLUGINTOOL_PASSPHRASE, at least 12
// characters. A plaintext key is refused without --insecure-plaintext-key, and keygen writes an
// encrypted file unless that flag is given.
func TestThePassphraseAndPlaintextRules(t *testing.T) {
	dir := t.TempDir()
	pf := filepath.Join(dir, "pass")
	if err := os.WriteFile(pf, []byte(testPass+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if p, err := passphrase(pf); err != nil || string(p) != testPass {
		t.Fatalf("passphrase file: %q %v", p, err)
	}
	t.Setenv("PLUGINTOOL_PASSPHRASE", "short")
	if _, err := passphrase(""); err == nil {
		t.Fatal("a short passphrase was accepted")
	}
	t.Setenv("PLUGINTOOL_PASSPHRASE", "")
	if _, err := passphrase(""); err == nil {
		t.Fatal("no passphrase was accepted")
	}
	t.Setenv("PLUGINTOOL_PASSPHRASE", testPass)
	if err := run([]string{"keygen", "-out", filepath.Join(dir, "enc")}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "enc.key"))
	if !strings.HasPrefix(string(b), keyHeader()+"\n") {
		t.Fatalf("keygen wrote %q", b)
	}
	if err := run([]string{"keygen", "-insecure-plaintext-key", "-out", filepath.Join(dir, "plain")}); err != nil {
		t.Fatal(err)
	}
	plain, _ := os.ReadFile(filepath.Join(dir, "plain.key"))
	if _, err := openKey(plain, "", false); err == nil {
		t.Fatal("a plaintext key was accepted without --insecure-plaintext-key")
	}
	if _, err := openKey(plain, "", true); err != nil {
		t.Fatalf("plaintext with the flag: %v", err)
	}
	if _, err := readPriv(filepath.Join(dir, "enc.key"), pf, false); err != nil {
		t.Fatalf("encrypted key with a passphrase file: %v", err)
	}
}
