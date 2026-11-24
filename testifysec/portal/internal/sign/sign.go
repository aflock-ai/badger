// Package sign produces DSSE envelopes in the form the native Rookery verifier accepts:
// exactly payloadType, payload and signatures[{keyid, sig}], ECDSA P-256 over SHA-256 of the
// DSSE pre-authentication encoding, keyid = hex SHA-256 of the SPKI PEM.
package sign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// Signer holds a key the portal never exports. A file key implements it now; a PKCS#11
// token exposes the same crypto.Signer, so an HSM is a constructor, not a new interface.
type Signer interface {
	KeyID() string
	PublicKeyPEM() []byte
	Sign(message []byte) ([]byte, error)
}

// Envelope is the DSSE JSON. []byte fields encode as standard padded base64, as Rookery's do.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     []byte      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

type Signature struct {
	KeyID string `json:"keyid"`
	Sig   []byte `json:"sig"`
}

// PAE is DSSE v1 pre-authentication encoding.
func PAE(payloadType string, payload []byte) []byte {
	return fmt.Appendf(nil, "DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload)
}

// Envelop signs payload with every signer (two signers give admission a threshold of two).
func Envelop(payloadType string, payload []byte, signers ...Signer) (Envelope, error) {
	if len(signers) == 0 {
		return Envelope{}, errors.New("no signer")
	}
	e := Envelope{PayloadType: payloadType, Payload: payload}
	for _, s := range signers {
		sig, err := s.Sign(PAE(payloadType, payload))
		if err != nil {
			return Envelope{}, err
		}
		e.Signatures = append(e.Signatures, Signature{KeyID: s.KeyID(), Sig: sig})
	}
	return e, nil
}

// Key wraps any ECDSA P-256 crypto.Signer.
type Key struct {
	signer crypto.Signer
	pem    []byte
	id     string
}

func NewKey(s crypto.Signer) (*Key, error) {
	pub, ok := s.Public().(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("signing key must be ECDSA P-256")
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	p := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	sum := sha256.Sum256(p)
	return &Key{signer: s, pem: p, id: hex.EncodeToString(sum[:])}, nil
}

func (k *Key) KeyID() string        { return k.id }
func (k *Key) PublicKeyPEM() []byte { return append([]byte(nil), k.pem...) }
func (k *Key) Sign(message []byte) ([]byte, error) {
	digest := sha256.Sum256(message)
	return k.signer.Sign(rand.Reader, digest[:], crypto.SHA256)
}

// LoadKeyFile loads the signing key from the file the deployment mounts from its key vault (a
// secret volume, read once at start). A secret volume publishes the file as a link into its
// current data directory, so the link is resolved once and the target opened without following
// any further link. Until a vault or HSM signer replaces it, this is the only way a key enters
// the service: the portal never generates or writes one.
func LoadKeyFile(path string) (*Key, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("signing key file must be an absolute path")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	// Check and read the same open file, not a name that could be swapped in between.
	f, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	// A secret volume gives the service's group read access (fsGroup); nobody else may read it
	// and only its owner may write it.
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o027 != 0 {
		return nil, errors.New("signing key must be a regular file that only its owner and group can read")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return nil, errors.New("signing key must be one PKCS#8 PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	s, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("unsupported key")
	}
	return NewKey(s)
}
