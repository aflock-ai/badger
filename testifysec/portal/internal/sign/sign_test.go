package sign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func keyPEM(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func write(t *testing.T, path string, data []byte, mode os.FileMode) string {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// The key comes from a file mounted from the key vault (a secret volume): owner- or
// group-readable, never world-readable or group-writable, one PKCS#8 P-256 PEM block.
func TestKeyFileChecks(t *testing.T) {
	dir := t.TempDir()
	good := keyPEM(t)
	for _, mode := range []os.FileMode{0o400, 0o440, 0o600} {
		p := write(t, filepath.Join(dir, "ok-"+mode.String()), good, mode)
		if _, err := LoadKeyFile(p); err != nil {
			t.Errorf("mode %v: %v", mode, err)
		}
	}
	two := append(append([]byte{}, good...), good...)
	for name, c := range map[string]struct {
		data []byte
		mode os.FileMode
	}{
		"world readable": {good, 0o404},
		"group writable": {good, 0o460},
		"not pem":        {[]byte("not a key"), 0o400},
		"two blocks":     {two, 0o400},
	} {
		p := write(t, filepath.Join(dir, name), c.data, c.mode)
		if _, err := LoadKeyFile(p); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	if _, err := LoadKeyFile("relative/key"); err == nil {
		t.Error("loaded a relative path")
	}
	if _, err := LoadKeyFile(dir); err == nil {
		t.Error("loaded a directory")
	}
	// A secret volume publishes each key as a link into its current data directory.
	data := filepath.Join(dir, "..data")
	os.Mkdir(data, 0o700)
	write(t, filepath.Join(data, "key"), good, 0o400)
	if err := os.Symlink(filepath.Join("..data", "key"), filepath.Join(dir, "key")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyFile(filepath.Join(dir, "key")); err != nil {
		t.Fatalf("secret volume layout: %v", err)
	}
}
