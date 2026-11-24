// Command hardened-bundle-verify verifies and optionally stages an offline bundle.
package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
)

const releaseType = "application/vnd.testifysec.hardened-opencode.release.v1+json"
const maximumArchive = int64(2 << 30)

type trust struct {
	Schema                string   `json:"schema"`
	Purpose               string   `json:"purpose"`
	Product               string   `json:"product"`
	Tenant                string   `json:"tenant"`
	Channel               string   `json:"channel"`
	MinimumSequence       int64    `json:"minimumSequence"`
	UpstreamCommit        string   `json:"upstreamCommit"`
	UpstreamTree          string   `json:"upstreamTree"`
	UpstreamLicenseSHA256 string   `json:"upstreamLicenseSha256"`
	PublicKeys            []string `json:"publicKeys"`
	Threshold             int      `json:"threshold"`
}

type artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   int64  `json:"mode"`
}

type manifest struct {
	Schema         string     `json:"schema"`
	Product        string     `json:"product"`
	Tenant         string     `json:"tenant"`
	Channel        string     `json:"channel"`
	Sequence       int64      `json:"sequence"`
	NotBefore      string     `json:"notBefore"`
	ExpiresAt      string     `json:"expiresAt"`
	UpstreamCommit string     `json:"upstreamCommit"`
	UpstreamTree   string     `json:"upstreamTree"`
	ArchiveSHA256  string     `json:"archiveSha256"`
	ArchiveSize    int64      `json:"archiveSize"`
	Artifacts      []artifact `json:"artifacts"`
}

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var gitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var jsonKeys = map[string]bool{}

func init() {
	for _, key := range strings.Fields("schema purpose product tenant channel minimumSequence upstreamCommit upstreamTree upstreamLicenseSha256 publicKeys threshold sequence notBefore expiresAt archiveSha256 archiveSize artifacts path sha256 size mode payloadType payload signatures keyid sig") {
		jsonKeys[key] = true
	}
}

// Canonical spellings prevent encoding/json's case-insensitive aliases; a
// second pass with typed integer fields rejects fractional and overflow values.
func strictDecode(data []byte, output any) error {
	if !utf8.Valid(data) {
		return errors.New("invalid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 16 {
			return errors.New("JSON nesting exceeded")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, composite := token.(json.Delim)
		if !composite {
			return nil
		}
		if delim != '{' && delim != '[' {
			return errors.New("invalid JSON structure")
		}
		seen := map[string]bool{}
		for decoder.More() {
			if delim == '{' {
				token, err = decoder.Token()
				if err != nil {
					return err
				}
				key, ok := token.(string)
				if !ok || !jsonKeys[key] || seen[key] {
					return errors.New("noncanonical or duplicate JSON key")
				}
				seen[key] = true
			}
			if err := visit(depth + 1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	}
	if err := visit(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(output)
}

func boundedFile(filename string, maximum int64) ([]byte, error) {
	f, err := regularFile(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maximum {
		return nil, errors.New("invalid input file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maximum+1))
	if len(data) > int(maximum) {
		return nil, errors.New("input file exceeds limit")
	}
	return data, err
}

// Nonblocking open rejects a FIFO without hanging; no-follow prevents an input
// alias from changing the object selected by the caller. Supported on Linux/Darwin.
func regularFile(filename string) (*os.File, error) {
	fd, err := syscall.Open(filename, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), filename)
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("regular input file required")
	}
	return f, nil
}

func admitted(t trust, m manifest, now time.Time) error {
	if t.Schema != "testifysec.release-trust/v1" || t.Purpose != "release-verification" || t.Product != "hardened-opencode" ||
		!identifier.MatchString(t.Tenant) || !identifier.MatchString(t.Channel) || t.MinimumSequence < 1 ||
		!gitPattern.MatchString(t.UpstreamCommit) || !gitPattern.MatchString(t.UpstreamTree) || !sha256Pattern.MatchString(t.UpstreamLicenseSHA256) {
		return errors.New("invalid release trust")
	}
	if m.Schema != "testifysec.hardened-opencode.release/v1" || m.Product != t.Product || m.Tenant != t.Tenant || m.Channel != t.Channel ||
		m.UpstreamCommit != t.UpstreamCommit || m.UpstreamTree != t.UpstreamTree {
		return errors.New("release assignment mismatch")
	}
	if m.Sequence < t.MinimumSequence {
		return errors.New("release downgrade")
	}
	start, err := time.Parse("2006-01-02T15:04:05Z", m.NotBefore)
	if err != nil || start.Format("2006-01-02T15:04:05Z") != m.NotBefore {
		return errors.New("invalid release time")
	}
	end, err := time.Parse("2006-01-02T15:04:05Z", m.ExpiresAt)
	if err != nil || end.Format("2006-01-02T15:04:05Z") != m.ExpiresAt || !end.After(start) || now.Before(start) || !now.Before(end) {
		return errors.New("release expired or not yet valid")
	}
	if !sha256Pattern.MatchString(m.ArchiveSHA256) || m.ArchiveSize < 1024 || m.ArchiveSize > maximumArchive || len(m.Artifacts) < 1 || len(m.Artifacts) > 4096 {
		return errors.New("invalid release inventory")
	}
	seen := map[string]bool{}
	var size int64
	for _, file := range m.Artifacts {
		if !safePath(file.Path) || seen[file.Path] || !sha256Pattern.MatchString(file.SHA256) || file.Size < 0 || file.Size > maximumArchive ||
			(file.Mode != 0644 && file.Mode != 0755) {
			return errors.New("invalid artifact")
		}
		seen[file.Path] = true
		if file.Path == "LICENSES/OpenCode.LICENSE" && file.SHA256 != t.UpstreamLicenseSHA256 {
			return errors.New("upstream license mismatch")
		}
		size += file.Size
		if size > maximumArchive {
			return errors.New("artifact size limit")
		}
	}
	if !seen["LICENSES/OpenCode.LICENSE"] {
		return errors.New("upstream license missing")
	}
	return nil
}

func safePath(name string) bool {
	if name == "" || len(name) > 512 || path.IsAbs(name) || path.Clean(name) != name || strings.ContainsAny(name, "\\\x00\r\n:") {
		return false
	}
	for _, c := range name {
		if c < 33 || c > 126 {
			return false
		}
	}
	for _, component := range strings.Split(name, "/") {
		if component == "." || component == ".." || component == "" || strings.EqualFold(component, ".git") {
			return false
		}
	}
	return true
}

func verifyManifest(data []byte, t trust, now time.Time) (manifest, error) {
	var m manifest
	if len(t.PublicKeys) < 1 || len(t.PublicKeys) > 16 || t.Threshold < 1 || t.Threshold > len(t.PublicKeys) {
		return m, errors.New("invalid signer threshold")
	}
	verifiers := []cryptoutil.Verifier{}
	for _, text := range t.PublicKeys {
		if len(text) > 16384 {
			return m, errors.New("public key exceeds limit")
		}
		block, rest := pem.Decode([]byte(text))
		if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
			return m, errors.New("invalid public key")
		}
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return m, err
		}
		v, err := cryptoutil.NewVerifier(key)
		if err != nil {
			return m, err
		}
		verifiers = append(verifiers, v)
	}
	var envelope dsse.Envelope
	if err := strictDecode(data, &envelope); err != nil {
		return m, err
	}
	if envelope.PayloadType != releaseType || len(envelope.Payload) > 1<<20 || len(envelope.Signatures) < 1 || len(envelope.Signatures) > 16 {
		return m, errors.New("invalid release envelope")
	}
	checked, err := envelope.Verify(dsse.VerifyWithVerifiers(verifiers...), dsse.VerifyWithThreshold(t.Threshold))
	if err != nil {
		return m, errors.New("release signature failed")
	}
	identities := map[string]bool{}
	for _, result := range checked {
		if result.Error != nil || result.Verifier == nil {
			continue
		}
		id, err := result.Verifier.KeyID()
		if err != nil {
			return m, err
		}
		identities[id] = true
	}
	if len(identities) < t.Threshold {
		return m, errors.New("distinct release signer threshold failed")
	}
	if err := strictDecode(envelope.Payload, &m); err != nil {
		return m, err
	}
	return m, admitted(t, m, now)
}

func verifyArchive(filename string, m manifest) error {
	f, err := regularFile(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return consumeArchive(f, m, nil)
}

// When a destination is supplied, hash exactly the bytes being written. A
// mutable source cannot swap between verification and extraction passes.
func consumeArchive(f *os.File, m manifest, destination *os.Root) error {
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != m.ArchiveSize {
		return errors.New("archive size mismatch")
	}
	whole := sha256.New()
	counted := &countReader{Reader: io.LimitReader(f, maximumArchive+1)}
	reader := io.TeeReader(counted, whole)
	tarReader := tar.NewReader(reader)
	wanted := map[string]artifact{}
	for _, file := range m.Artifacts {
		wanted[file.Path] = file
	}
	seen := map[string]bool{}
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		file, exists := wanted[header.Name]
		if !safePath(header.Name) || !exists || seen[header.Name] || header.Typeflag != tar.TypeReg || header.Format != tar.FormatUSTAR || len(header.PAXRecords) != 0 || header.Linkname != "" ||
			header.Size != file.Size || header.Mode != file.Mode {
			return errors.New("unsafe or unexpected archive entry")
		}
		seen[header.Name] = true
		hash := sha256.New()
		if destination == nil {
			if _, err := io.Copy(hash, tarReader); err != nil {
				return err
			}
		} else {
			if err := destination.MkdirAll(path.Dir(file.Path), 0700); err != nil {
				return err
			}
			output, err := destination.OpenFile(file.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(io.MultiWriter(output, hash), tarReader)
			modeErr := output.Chmod(os.FileMode(file.Mode))
			syncErr := output.Sync()
			closeErr := output.Close()
			if err := errors.Join(copyErr, modeErr, syncErr, closeErr); err != nil {
				return err
			}
		}
		if hex.EncodeToString(hash.Sum(nil)) != file.SHA256 {
			return errors.New("artifact digest mismatch")
		}
	}
	if len(seen) != len(wanted) {
		return errors.New("missing archive artifact")
	}
	// tar.Reader stops at the end marker. Hash and reject any nonzero trailing
	// data too, so an appended second archive cannot hide from the inventory.
	buffer := make([]byte, 65536)
	for {
		n, err := reader.Read(buffer)
		for _, value := range buffer[:n] {
			if value != 0 {
				return errors.New("trailing archive data")
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	if counted.bytes != m.ArchiveSize || hex.EncodeToString(whole.Sum(nil)) != m.ArchiveSHA256 {
		return errors.New("archive digest mismatch")
	}
	return nil
}

type countReader struct {
	io.Reader
	bytes int64
}

func (r *countReader) Read(data []byte) (int, error) {
	n, err := r.Reader.Read(data)
	r.bytes += int64(n)
	return n, err
}

func run() error {
	trustPath := flag.String("trust", "", "Administrator-provisioned release trust JSON; never read from the bundle")
	envelopePath := flag.String("manifest", "", "DSSE-signed release manifest")
	archivePath := flag.String("archive", "", "Uncompressed release tar")
	stageRoot := flag.String("stage-root", "", "Optional existing private directory for a new verified staging directory; never activates or executes")
	flag.Parse()
	if flag.NArg() != 0 || *trustPath == "" || *envelopePath == "" || *archivePath == "" {
		return errors.New("trust, manifest and archive are required")
	}
	data, err := boundedFile(*trustPath, 1<<20)
	if err != nil {
		return err
	}
	var t trust
	if err := strictDecode(data, &t); err != nil {
		return err
	}
	data, err = boundedFile(*envelopePath, 2<<20)
	if err != nil {
		return err
	}
	m, err := verifyManifest(data, t, time.Now().UTC())
	if err != nil {
		return err
	}
	if *stageRoot != "" {
		directory, err := stageArchive(*stageRoot, *archivePath, m)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"verified": true, "scope": "offline-release-staging-only", "activated": false, "stagedDirectory": directory, "sequence": m.Sequence, "archiveSha256": m.ArchiveSHA256, "artifacts": len(m.Artifacts)})
	}
	if err := verifyArchive(*archivePath, m); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"verified": true, "scope": "offline-release-verification-only", "sequence": m.Sequence, "archiveSha256": m.ArchiveSHA256, "artifacts": len(m.Artifacts)})
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "bundle verification failed")
		os.Exit(1)
	}
}
