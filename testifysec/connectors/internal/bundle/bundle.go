// Package bundle is the signed description of a connector plugin: a manifest naming the sha256 of
// the plugin executable and its tools, and the plugin signer's signature over the manifest. The
// gateway admits a bundle only when the signature verifies against a signer its signed profile
// trusts and the manifest names the executable digest the profile pins. The vendor's image only
// carries the executable: it is mounted read-only into the platform's plughost container, which
// runs the executable sandboxed only if its digest matches. A bundle says what the executable is;
// it never says what marking it carries or who may use it: those come from the profile.
package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

const (
	ManifestFile = "manifest.json"
	SigFile      = "manifest.sig"

	maxManifest = 1 << 20
)

// Tool is one tool as the signed manifest describes it. Write is the signer's statement that the
// tool changes state in the service.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Write       bool            `json:"write,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// Manifest is the contract between a plugin and the gateway. Fields a plugin adds beyond these are
// ignored.
type Manifest struct {
	Schema  int    `json:"schema"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
	Tools   []Tool `json:"tools"`
}

var (
	toolName  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	digestFmt = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	version   = regexp.MustCompile(`^[A-Za-z0-9.+-]{1,64}$`)
)

// ValidDigest reports whether d is a digest in the form Digest writes.
func ValidDigest(d string) bool { return digestFmt.MatchString(d) }

// Digest is the sha256 digest of b, as manifests and profiles write it.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ParseKey reads a base64 ed25519 public key.
func ParseKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("not a base64 ed25519 public key")
	}
	return ed25519.PublicKey(b), nil
}

// Sign returns the base64 ed25519 signature of msg, as a .sig file holds it.
func Sign(priv ed25519.PrivateKey, msg []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)) + "\n")
}

// Verify checks a .sig file's content against msg.
func Verify(pub ed25519.PublicKey, msg, sig []byte) error {
	raw, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(sig)))
	if err != nil || len(raw) != ed25519.SignatureSize || !ed25519.Verify(pub, msg, raw) {
		return errors.New("signature does not verify")
	}
	return nil
}

// ReadCapped reads a whole file, refusing one larger than limit.
func ReadCapped(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", filepath.Base(path), limit)
	}
	return b, nil
}

// Parse reads and checks a manifest's content (not its signature).
func Parse(b []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("manifest: %w", err)
	}
	if m.Schema != 1 {
		return m, errors.New("manifest: schema must be 1")
	}
	if !toolName.MatchString(m.Name) || !version.MatchString(m.Version) {
		return m, errors.New("manifest: name or version invalid")
	}
	seen := map[string]bool{}
	for _, t := range m.Tools {
		if !toolName.MatchString(t.Name) || seen[t.Name] || t.Description == "" {
			return m, fmt.Errorf("manifest: tool %q needs a unique lower_snake name and a description", t.Name)
		}
		seen[t.Name] = true
		var s struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(t.InputSchema, &s) != nil || s.Type != "object" {
			return m, fmt.Errorf("manifest: tool %q input schema must be a JSON Schema object", t.Name)
		}
	}
	return m, nil
}

// Load verifies a bundle directory against the signer's key and returns its manifest.
func Load(dir string, signer ed25519.PublicKey) (Manifest, error) {
	mb, err := ReadCapped(filepath.Join(dir, ManifestFile), maxManifest)
	if err != nil {
		return Manifest{}, err
	}
	sig, err := ReadCapped(filepath.Join(dir, SigFile), 4<<10)
	if err != nil {
		return Manifest{}, err
	}
	if err := Verify(signer, mb, sig); err != nil {
		return Manifest{}, fmt.Errorf("manifest: %w", err)
	}
	m, err := Parse(mb)
	if err != nil {
		return m, err
	}
	if !ValidDigest(m.Digest) {
		return m, errors.New("manifest: digest must be sha256:<hex>")
	}
	return m, nil
}
