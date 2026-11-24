// Package vzbackend prepares pinned VZ files and runs one typed local VM job.
// It does not enable the production broker peer path or confer platform identity.
package vzbackend

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"regexp"
	"strings"
)

const backendKind = "darwin-vz/v1"

const ManifestSchema = "testifysec.aflock.vz-backend/v1"
const AssignmentSchema = "testifysec.aflock.vz-backend-assignment/v1"
const Scope = "backend-preparation-only"
const ManifestLimit = 16 << 10
const EnvelopeLimit = 512 << 10

type File struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type Files struct {
	Host       File `json:"host"`
	Kernel     File `json:"kernel"`
	RootDisk   File `json:"rootDisk"`
	Provenance File `json:"provenance"`
}
type Manifest struct {
	Schema        string `json:"schema"`
	Kind          string `json:"kind"`
	HostTarget    string `json:"hostTarget"`
	GuestTarget   string `json:"guestTarget"`
	JobSchema     string `json:"jobSchema"`
	ResultSchema  string `json:"resultSchema"`
	RelayProtocol string `json:"relayProtocol"`
	Files         Files  `json:"files"`
}

// Assignment comes only from the protected service administrator. It is not
// request data, an activation grant, a platform identity, or a signing role.
type Assignment struct {
	Schema                string `json:"schema"`
	InstallationDirectory string `json:"installationDirectory"`
	StagingDirectory      string `json:"stagingDirectory"`
	ManifestSHA256        string `json:"manifestSha256"`
	ProfileSHA256         string `json:"profileSha256"`
	AdmissionExecutable   string `json:"admissionExecutable"`
	AdmissionSHA256       string `json:"admissionSha256"`
	TenantID              string `json:"tenantId"`
	DeploymentID          string `json:"deploymentId"`
	ProfileID             string `json:"profileId"`
}

type Observation struct {
	ManifestSHA256 string `json:"manifestSha256"`
	ProfileSHA256  string `json:"profileSha256"`
	Files          Files  `json:"files"`
}

type refusal struct{ code string }

func (e *refusal) Error() string { return e.code }
func refused(code string) error  { return &refusal{code} }

// Code exposes only a fixed error classification, never native stdout, paths or
// supplied profile bytes. Cleanup uncertainty takes precedence over other errors.
func Code(err error) string {
	if errors.Is(err, errCleanup) {
		return "cleanup_failed"
	}
	var r *refusal
	if errors.As(err, &r) {
		return r.code
	}
	return "preparation_unavailable"
}

var errCleanup = errors.New("backend cleanup incomplete")
var hexDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func hash(raw []byte) string { value := sha256.Sum256(raw); return hex.EncodeToString(value[:]) }
func absolute(value string) bool {
	return len(value) <= 4096 && filepath.IsAbs(value) && filepath.Clean(value) == value && !strings.ContainsRune(value, 0)
}
func beneath(child, parent string) bool {
	return child == parent || (parent == string(filepath.Separator) && filepath.IsAbs(child)) || strings.HasPrefix(child, parent+string(filepath.Separator))
}

func validateAssignment(a Assignment) error {
	if a.Schema != AssignmentSchema || !identifier.MatchString(a.TenantID) || !identifier.MatchString(a.DeploymentID) || !identifier.MatchString(a.ProfileID) {
		return refused("assignment_invalid")
	}
	if !hexDigest.MatchString(a.ManifestSHA256) || !hexDigest.MatchString(a.ProfileSHA256) || !hexDigest.MatchString(a.AdmissionSHA256) {
		return refused("assignment_invalid")
	}
	if !absolute(a.InstallationDirectory) || !absolute(a.StagingDirectory) || !absolute(a.AdmissionExecutable) {
		return refused("assignment_invalid")
	}
	if beneath(a.StagingDirectory, a.InstallationDirectory) || beneath(a.InstallationDirectory, a.StagingDirectory) || beneath(a.AdmissionExecutable, a.StagingDirectory) {
		return refused("assignment_overlap")
	}
	return nil
}

type role struct {
	name       string
	file       File
	limit      int64
	executable bool
}

func roles(files Files) []role {
	return []role{{"hc-vm", files.Host, 64 << 20, true}, {"kernel", files.Kernel, 128 << 20, false}, {"root.ext4", files.RootDisk, 2 << 30, false}, {"build.json", files.Provenance, 256 << 10, false}}
}
func parseManifest(raw []byte) (Manifest, error) {
	var m Manifest
	if len(raw) > ManifestLimit || strict(raw, &m) != nil {
		return m, refused("manifest_invalid")
	}
	if m.Schema != ManifestSchema || m.Kind != backendKind || m.HostTarget != "darwin-arm64" || m.GuestTarget != "linux-arm64" || m.JobSchema != "testifysec.vm-job/v3" || m.ResultSchema != "testifysec.vm-result/v3" || m.RelayProtocol != "HCMDL2" {
		return m, refused("manifest_contract")
	}
	for _, r := range roles(m.Files) {
		if !hexDigest.MatchString(r.file.SHA256) || r.file.Size < 1 || r.file.Size > r.limit {
			return m, refused("manifest_bounds")
		}
	}
	return m, nil
}
