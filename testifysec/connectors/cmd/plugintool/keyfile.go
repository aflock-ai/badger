package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// A signing key file holds the ed25519 seed encrypted under a passphrase: whoever holds the plugin
// signing key can make any code run as a plugin. The format uses the standard library only (the
// module has no dependencies): PBKDF2-HMAC-SHA256 with keyIterations rounds over a 16-byte random
// salt derives an AES-256-GCM key, and the header line, which names the version, the KDF and its
// rounds, is the AEAD's associated data, so it cannot be changed without failing to open.
//
//	badger-plugintool-key/v1 pbkdf2-sha256 600000
//	<base64 of salt(16) | nonce(12) | sealed seed(32+16)>
const (
	keyMagic      = "badger-plugintool-key/"
	keyVersion    = "v1"
	minPassphrase = 12
)

// keyIterations is the PBKDF2 round count new files are written with and files must name (tests
// lower it to stay fast).
var keyIterations = 600000

func keyHeader() string {
	return fmt.Sprintf("%s%s pbkdf2-sha256 %d", keyMagic, keyVersion, keyIterations)
}

// passphrase reads the key passphrase from --passphrase-file or PLUGINTOOL_PASSPHRASE, never from
// the command line. A file's trailing newline is dropped. Empty or shorter than 12 is refused.
func passphrase(file string) ([]byte, error) {
	var p []byte
	switch {
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		p = bytes.TrimRight(b, "\r\n")
	case os.Getenv("PLUGINTOOL_PASSPHRASE") != "":
		p = []byte(os.Getenv("PLUGINTOOL_PASSPHRASE"))
	default:
		return nil, errors.New("the signing key needs a passphrase: --passphrase-file <file> or PLUGINTOOL_PASSPHRASE")
	}
	if len(p) < minPassphrase {
		return nil, fmt.Errorf("the passphrase must be at least %d characters", minPassphrase)
	}
	return p, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func keyAEAD(pass, salt []byte) (cipher.AEAD, error) {
	k, err := pbkdf2.Key(sha256.New, string(pass), salt, keyIterations, 32)
	if err != nil {
		return nil, err
	}
	defer zero(k)
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealKey is the key file content for priv under pass.
func sealKey(priv ed25519.PrivateKey, pass []byte) ([]byte, error) {
	salt, nonce := make([]byte, 16), make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	aead, err := keyAEAD(pass, salt)
	if err != nil {
		return nil, err
	}
	seed := append([]byte{}, priv.Seed()...)
	defer zero(seed)
	body := append(append(append([]byte{}, salt...), nonce...), aead.Seal(nil, nonce, seed, []byte(keyHeader()))...)
	return []byte(keyHeader() + "\n" + base64.StdEncoding.EncodeToString(body) + "\n"), nil
}

// openKey reads a key file. An encrypted one is opened with the passphrase; a header naming
// another version or KDF, a wrong passphrase or any changed byte is refused. A plaintext key (the
// old base64 form) is refused unless insecure is set, which warns.
func openKey(b []byte, passFile string, insecure bool) (ed25519.PrivateKey, error) {
	text := string(b)
	if !strings.HasPrefix(text, keyMagic) {
		if !insecure {
			return nil, errors.New("the signing key file is not encrypted; re-create it with plugintool keygen, or pass --insecure-plaintext-key")
		}
		fmt.Fprintln(os.Stderr, "plugintool: WARNING: using an unencrypted signing key (--insecure-plaintext-key); whoever copies it can sign any plugin")
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
		if err != nil || len(raw) != ed25519.PrivateKeySize {
			return nil, errors.New("not a base64 ed25519 private key")
		}
		return ed25519.PrivateKey(raw), nil
	}
	header, rest, ok := strings.Cut(text, "\n")
	if !ok || header != keyHeader() {
		return nil, errors.New("the signing key file has an unsupported header (version or KDF); refused")
	}
	body, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest))
	if err != nil || len(body) != 16+12+ed25519.SeedSize+16 || rest != base64.StdEncoding.EncodeToString(body)+"\n" {
		return nil, errors.New("the signing key file is damaged; refused")
	}
	pass, err := passphrase(passFile)
	if err != nil {
		return nil, err
	}
	defer zero(pass)
	aead, err := keyAEAD(pass, body[:16])
	if err != nil {
		return nil, err
	}
	seed, err := aead.Open(nil, body[16:28], body[28:], []byte(keyHeader()))
	if err != nil {
		return nil, errors.New("the signing key cannot be opened: wrong passphrase or a changed file")
	}
	defer zero(seed)
	return ed25519.NewKeyFromSeed(seed), nil
}
