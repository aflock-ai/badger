// Package vzsession runs a developer VZ session using administrator assignments,
// fresh platform identity and signed profile admission. It is not an installed
// privilege boundary or a finalized signing-evidence producer.
package vzsession

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/aflock-ai/badger/testifysec/broker/vzbackend"
	"github.com/aflock-ai/badger/testifysec/platform"
)

const AssignmentSchema = "testifysec.aflock.vz-session-assignment/v1"
const RequestSchema = "testifysec.aflock.vz-session-request/v1"
const ResultSchema = "testifysec.aflock.vz-session-result/v1"

type Assignment struct {
	Schema                  string `json:"schema"`
	BackendAssignmentFile   string `json:"backendAssignmentFile"`
	BackendAssignmentSHA256 string `json:"backendAssignmentSha256"`
	PlatformConfigFile      string `json:"platformConfigFile"`
	PlatformConfigSHA256    string `json:"platformConfigSha256"`
	SignedProfileFile       string `json:"signedProfileFile"`
	GatewayExecutable       string `json:"gatewayExecutable"`
	GatewaySHA256           string `json:"gatewaySha256"`
	GatewayTemplateFile     string `json:"gatewayTemplateFile"`
	GatewayTemplateSHA256   string `json:"gatewayTemplateSha256"`
	WorkspaceID             string `json:"workspaceId"`
	WorkspaceDirectory      string `json:"workspaceDirectory"`
	StateDirectory          string `json:"stateDirectory"`
	AuditDirectory          string `json:"auditDirectory"`
	MaximumTimeoutSeconds   int    `json:"maximumTimeoutSeconds"`
}

type Request struct {
	Schema         string `json:"schema"`
	WorkspaceID    string `json:"workspaceId"`
	Prompt         string `json:"prompt"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
}

type refusal struct{ code string }

func (r *refusal) Error() string { return r.code }
func refused(code string) error  { return &refusal{code} }

var errCleanup = errors.New("session cleanup incomplete")
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func hash(raw []byte) string { value := sha256.Sum256(raw); return hex.EncodeToString(value[:]) }
func absolute(s string) bool {
	return len(s) > 0 && len(s) <= 4096 && filepath.IsAbs(s) && filepath.Clean(s) == s && !strings.ContainsRune(s, 0)
}
func beneath(child, parent string) bool {
	return child == parent || parent == string(filepath.Separator) && filepath.IsAbs(child) || strings.HasPrefix(child, parent+string(filepath.Separator))
}

// Code returns fixed classifications only; it never prints credential contents,
// paths, provider output, profile bytes or the caller's prompt.
func Code(err error) string {
	if errors.Is(err, errCleanup) {
		return "cleanup_failed"
	}
	var r *refusal
	if errors.As(err, &r) {
		return r.code
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "cancelled"
	}
	return "session_unavailable"
}

// ReadInput reads one owned, bounded, private regular file through held parents.
func ReadInput(path string, limit int64) ([]byte, error) {
	if !absolute(path) {
		return nil, refused("input_path")
	}
	c, err := openCustody(filepath.Dir(path), true)
	if err != nil {
		return nil, err
	}
	defer c.close()
	raw, err := readFile(c.root(), filepath.Base(path), limit, false, true)
	if err != nil {
		return nil, err
	}
	if err = c.check(); err != nil {
		return nil, err
	}
	return raw, nil
}

func readFile(root *os.Root, name string, limit int64, executable, private bool) ([]byte, error) {
	f, before, err := openChecked(root, name, executable)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	uid, _, _, ok := fileIdentity(before)
	if before.Size() < 0 || before.Size() > limit || private && (!ok || uid != int64(os.Geteuid()) || before.Mode().Perm()&0077 != 0) {
		return nil, refused("input_bounds")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, refused("input_bounds")
	}
	if err = checkFile(root, name, f, before); err != nil {
		return nil, err
	}
	return raw, nil
}

type configuration struct {
	assignment       Assignment
	assignmentSHA256 string
	backend          vzbackend.Assignment
	platform         platformsession.Config
	profile          []byte
	template         gatewayTemplate
}

func configurationFrom(raw []byte) (configuration, error) {
	var c configuration
	if len(raw) > 16384 || strict(raw, &c.assignment) != nil {
		return c, refused("assignment_invalid")
	}
	a := c.assignment
	if err := a.validate(); err != nil {
		return c, err
	}
	if err := readPinnedJSON(a.BackendAssignmentFile, a.BackendAssignmentSHA256, &c.backend); err != nil {
		return c, err
	}
	if _, err := vzbackend.New(c.backend); err != nil {
		return c, refused("backend_assignment")
	}
	if err := readPinnedJSON(a.PlatformConfigFile, a.PlatformConfigSHA256, &c.platform); err != nil {
		return c, err
	}
	if c.platform.TenantID != c.backend.TenantID {
		return c, refused("tenant_binding")
	}
	if err := readPinnedJSON(a.GatewayTemplateFile, a.GatewayTemplateSHA256, &c.template); err != nil {
		return c, err
	}
	if err := c.template.validate(); err != nil {
		return c, err
	}
	var err error
	c.profile, err = ReadInput(a.SignedProfileFile, vzbackend.EnvelopeLimit)
	if err != nil {
		return c, refused("profile_input")
	}
	if err = c.checkProtectedInputs(); err != nil {
		return c, err
	}
	if err = c.checkAdmissionLocation(); err != nil {
		return c, err
	}
	c.assignmentSHA256 = hash(raw)
	return c, nil
}

func (a Assignment) validate() error {
	if a.Schema != AssignmentSchema || !idPattern.MatchString(a.WorkspaceID) || a.MaximumTimeoutSeconds < 1 || a.MaximumTimeoutSeconds > 45 {
		return refused("assignment_invalid")
	}
	for _, s := range []string{a.BackendAssignmentSHA256, a.PlatformConfigSHA256, a.GatewaySHA256, a.GatewayTemplateSHA256} {
		if !digestPattern.MatchString(s) {
			return refused("assignment_digest")
		}
	}
	paths := []string{a.BackendAssignmentFile, a.PlatformConfigFile, a.SignedProfileFile, a.GatewayExecutable, a.GatewayTemplateFile, a.WorkspaceDirectory, a.StateDirectory, a.AuditDirectory}
	for _, p := range paths {
		if !absolute(p) {
			return refused("assignment_path")
		}
	}
	return checkSeparation(a, paths)
}

func (c configuration) checkProtectedInputs() error {
	a := c.assignment
	device := ""
	if c.template.BrokerSignIn != nil {
		device = c.template.BrokerSignIn.DeviceIDFile
	}
	for _, p := range []string{c.backend.InstallationDirectory, c.backend.StagingDirectory, c.backend.AdmissionExecutable, c.platform.CAFile, c.platform.CredentialFile, c.template.CollectorTokenFile, device} {
		if p != "" && (beneath(p, a.WorkspaceDirectory) || beneath(p, a.StateDirectory) || beneath(p, a.AuditDirectory)) {
			return refused("assignment_overlap")
		}
	}
	for _, p := range []string{c.backend.InstallationDirectory, c.backend.StagingDirectory} {
		for _, q := range []string{a.WorkspaceDirectory, a.StateDirectory, a.AuditDirectory} {
			if beneath(q, p) {
				return refused("assignment_overlap")
			}
		}
	}
	return nil
}

func readPinnedJSON(path, sha string, target any) error {
	raw, err := ReadInput(path, 32768)
	if err != nil || hash(raw) != sha || strict(raw, target) != nil {
		return refused("configuration_digest")
	}
	return nil
}

// The gateway requires a service-owned admission launcher inside a private
// directory. Backend preparation also supports root-owned protected inputs;
// apply the stricter shared-session requirement before any VM can start.
func (c configuration) checkAdmissionLocation() (resultErr error) {
	parent, err := openCustody(filepath.Dir(c.backend.AdmissionExecutable), true)
	if err != nil {
		return refused("admission_location")
	}
	defer func() { resultErr = errors.Join(resultErr, parent.close()) }()
	f, info, err := openChecked(parent.root(), filepath.Base(c.backend.AdmissionExecutable), true)
	if err != nil {
		return refused("admission_location")
	}
	defer func() { resultErr = errors.Join(resultErr, f.Close()) }()
	uid, _, _, ok := fileIdentity(info)
	if !ok || uid != int64(os.Geteuid()) {
		return refused("admission_owner")
	}
	return parent.check()
}

func checkSeparation(a Assignment, paths []string) error {
	roots := []string{a.WorkspaceDirectory, a.StateDirectory, a.AuditDirectory}
	for i, p := range roots {
		for j, q := range roots {
			if i != j && beneath(p, q) {
				return refused("assignment_overlap")
			}
		}
		for _, q := range paths[:5] {
			if beneath(q, p) {
				return refused("assignment_overlap")
			}
		}
	}
	return nil
}

func requestFrom(raw []byte, a Assignment) (Request, error) {
	var r Request
	if len(raw) > 8192 || strict(raw, &r) != nil || r.Schema != RequestSchema || r.WorkspaceID != a.WorkspaceID || len(r.Prompt) == 0 || len(r.Prompt) > 4096 || r.TimeoutSeconds < 1 || r.TimeoutSeconds > a.MaximumTimeoutSeconds {
		return r, refused("request_invalid")
	}
	return r, nil
}

func supported() bool { return runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" }
