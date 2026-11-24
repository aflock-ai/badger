package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"unicode/utf8"
)

const requestSchema = "testifysec.hardened-opencode.exec/v1"
const policySchema = "testifysec.hardened-opencode.broker-policy/v1"
const inputLimit = 128 << 10

type limits struct {
	TimeoutSeconds int   `json:"timeoutSeconds"`
	OutputBytes    int   `json:"outputBytes"`
	WorkspaceBytes int64 `json:"workspaceBytes"`
	WorkspaceFiles int   `json:"workspaceFiles"`
	MemoryMiB      int   `json:"memoryMiB,omitempty"`
	WorkspaceMiB   int   `json:"workspaceMiB,omitempty"`
}
type workspace struct {
	ID     string `json:"id"`
	Source string `json:"source"`
}
type policy struct {
	Schema                  string              `json:"schema"`
	ListenSocket            string              `json:"listenSocket"`
	DockerSocket            string              `json:"dockerSocket"`
	Image                   string              `json:"image"`
	Workspace               workspace           `json:"workspace"`
	Limits                  limits              `json:"limits"`
	AllowedUIDs             []uint32            `json:"allowedUIDs"`
	DevelopmentAllowSameUID bool                `json:"developmentAllowSameUID"`
	Toolpack                string              `json:"toolpack,omitempty"`
	GatewaySocket           string              `json:"gatewaySocket,omitempty"`
	GatewayVolume           string              `json:"gatewayVolume,omitempty"`
	AdmissionExecutable     string              `json:"admissionExecutable,omitempty"`
	AdmissionSHA256         string              `json:"admissionSha256,omitempty"`
	ProfileSHA256           string              `json:"profileSha256,omitempty"`
	TenantID                string              `json:"tenantId,omitempty"`
	DeploymentID            string              `json:"deploymentId,omitempty"`
	ProfileID               string              `json:"profileId,omitempty"`
	Activation              *activationPolicy   `json:"activation,omitempty"`
	ConnectorTokenDir       string              `json:"connectorTokenDir,omitempty"`
	Finalization            *finalizationPolicy `json:"finalization,omitempty"`
	// activatedSequence is the profile sequence the device's latest admitted activation record
	// names, when activation records pin the profile; never read from the policy file.
	activatedSequence uint64
	activated         bool
}
type executionRequest struct {
	Schema          string `json:"schema"`
	Workspace       string `json:"workspace"`
	Command         string `json:"command"`
	Stdin           string `json:"stdin,omitempty"`
	TimeoutSeconds  int    `json:"timeoutSeconds,omitempty"`
	ProfileEnvelope string `json:"profileEnvelope,omitempty"`
	// ActivationEnvelope and ResetEnvelope are signed records from the management backend's pull,
	// applied before the profile is admitted (activation.go).
	ActivationEnvelope string `json:"activationEnvelope,omitempty"`
	ResetEnvelope      string `json:"resetEnvelope,omitempty"`
}
type material struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
	Executable bool   `json:"executable"`
}
type result struct {
	Schema          string            `json:"schema"`
	Status          string            `json:"status"`
	Code            string            `json:"code,omitempty"`
	Message         string            `json:"message,omitempty"`
	ExitCode        int               `json:"exitCode"`
	Output          string            `json:"output,omitempty"`
	OutputSHA256    string            `json:"outputSha256,omitempty"`
	OutputBase64    string            `json:"outputBase64,omitempty"`
	RequestSHA256   string            `json:"requestSha256,omitempty"`
	PolicySHA256    string            `json:"policySha256,omitempty"`
	BinarySHA256    string            `json:"binarySha256,omitempty"`
	BoundarySHA256  string            `json:"boundarySha256,omitempty"`
	Boundary        any               `json:"boundary,omitempty"`
	Materials       []material        `json:"materials"`
	MaterialsSHA256 string            `json:"materialsSha256,omitempty"`
	Runtime         map[string]any    `json:"runtime,omitempty"`
	CallerUID       uint32            `json:"callerUid"`
	Assurance       string            `json:"assurance"`
	Cleanup         bool              `json:"cleanup"`
	ProfileSHA256   string            `json:"profileSha256,omitempty"`
	Artifact        *artifactEnvelope `json:"artifact,omitempty"`
	Execution       any               `json:"execution,omitempty"`
	ExecutionSHA256 string            `json:"executionSha256,omitempty"`
	retainedRun     string            `json:"-"`
}
type refusal struct {
	Code    string
	Message string
}

func (e *refusal) Error() string      { return e.Code + ": " + e.Message }
func deny(code, message string) error { return &refusal{code, message} }
func hash(raw []byte) string          { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func marshal(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}

// encoding/json deliberately replaces invalid surrogate escapes. Admission must
// reject them, rather than silently changing a command or policy path.
func validUnicode(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	inside := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inside = !inside
			continue
		}
		if !inside || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		digits, err := hex.DecodeString(string(raw[i+1 : i+5]))
		if err != nil {
			return false
		}
		code := uint16(digits[0])<<8 | uint16(digits[1])
		i += 4
		if code >= 0xdc00 && code <= 0xdfff {
			return false
		}
		if code >= 0xd800 && code <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, err := hex.DecodeString(string(raw[i+3 : i+7]))
			if err != nil {
				return false
			}
			part := uint16(low[0])<<8 | uint16(low[1])
			if part < 0xdc00 || part > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}
func strict(raw []byte, target any) error {
	if len(raw) > inputLimit || !validUnicode(raw) {
		return deny("invalid_json", "Oversized or invalid Unicode JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 {
			return fmt.Errorf("nesting limit")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return fmt.Errorf("duplicate or invalid key")
				}
				seen[name] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("unexpected delimiter")
		}
		_, err = decoder.Token()
		return err
	}
	if err := walk(0); err != nil {
		return deny("invalid_json", "Malformed or ambiguous JSON")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return deny("invalid_json", "Trailing JSON")
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return deny("invalid_schema", "Unknown or invalid request fields")
	}
	// encoding/json also accepts case-insensitive aliases for struct fields.
	// Exact JSON field spelling is part of this protocol, so reject those aliases.
	var shape any
	if err := json.Unmarshal(raw, &shape); err != nil {
		return deny("invalid_json", "Invalid JSON")
	}
	if !exactFields(shape, reflect.TypeOf(target).Elem()) {
		return deny("invalid_schema", "Unknown or incorrectly cased fields")
	}
	return nil
}
func exactFields(value any, kind reflect.Type) bool {
	if kind.Kind() == reflect.Pointer {
		return exactFields(value, kind.Elem())
	}
	switch kind.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return false
		}
		allowed := map[string]reflect.Type{}
		for i := 0; i < kind.NumField(); i++ {
			field := kind.Field(i)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "" {
				name = field.Name
			}
			if name != "-" {
				allowed[name] = field.Type
			}
		}
		for key, item := range object {
			field, ok := allowed[key]
			if !ok || !exactFields(item, field) {
				return false
			}
		}
	case reflect.Slice:
		if value == nil {
			return true
		}
		array, ok := value.([]any)
		if !ok {
			return false
		}
		for _, item := range array {
			if !exactFields(item, kind.Elem()) {
				return false
			}
		}
	case reflect.String:
		_, ok := value.(string)
		return ok
	case reflect.Bool:
		_, ok := value.(bool)
		return ok
	case reflect.Int, reflect.Int64, reflect.Uint32, reflect.Uint64:
		_, ok := value.(float64)
		return ok
	}
	return true
}
func cleanAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsRune(path, 0)
}
func beneath(path, root string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}
func privateFile(path string) ([]byte, error) {
	if !cleanAbsolute(path) {
		return nil, deny("unsafe_policy", "Policy path must be absolute and clean")
	}
	root, err := secureRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	parent, err := root.Stat(".")
	if err != nil {
		return nil, err
	}
	if !ownedPrivate(parent, false) {
		return nil, deny("unsafe_policy", "Policy directory must be broker-owned and not writable by others")
	}
	before, err := root.Lstat(filepath.Base(path))
	if err != nil {
		return nil, err
	}
	if !ownedPrivate(before, true) {
		return nil, deny("unsafe_policy", "Policy must be a private broker-owned regular file")
	}
	file, err := root.OpenFile(filepath.Base(path), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, deny("unsafe_policy", "Policy changed during opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, inputLimit+1))
	if len(raw) > inputLimit {
		return nil, deny("invalid_json", "Policy exceeds limit")
	}
	return raw, err
}
func ownedPrivate(info os.FileInfo, file bool) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) {
		return false
	}
	if file {
		return info.Mode().IsRegular() && info.Mode().Perm()&0077 == 0 && stat.Nlink == 1
	}
	return info.IsDir() && info.Mode().Perm()&0022 == 0
}

// assignmentID is managed/profile.ts's identifier grammar.
var assignmentID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

func loadPolicy(path string) (policy, string, error) {
	var p policy
	raw, err := privateFile(path)
	if err != nil {
		return p, "", err
	}
	if err = strict(raw, &p); err != nil {
		return p, "", err
	}
	if p.Schema != policySchema || !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(p.Image) {
		return p, "", deny("invalid_policy", "Policy must select an immutable local image ID")
	}
	if !cleanAbsolute(p.ListenSocket) || !cleanAbsolute(p.DockerSocket) || !cleanAbsolute(p.Workspace.Source) || p.Workspace.Source == "/" || !regexp.MustCompile(`^[a-z0-9-]{1,64}$`).MatchString(p.Workspace.ID) {
		return p, "", deny("invalid_policy", "Invalid administrative paths or workspace")
	}
	if beneath(path, p.Workspace.Source) || beneath(p.ListenSocket, p.Workspace.Source) || beneath(p.DockerSocket, p.Workspace.Source) {
		return p, "", deny("unsafe_policy", "Authority paths must be outside the workspace")
	}
	l := p.Limits
	if l.TimeoutSeconds < 1 || l.TimeoutSeconds > 60 || l.OutputBytes < 1024 || l.OutputBytes > 1<<20 || l.WorkspaceBytes < 1 || l.WorkspaceBytes > 64<<20 || l.WorkspaceFiles < 1 || l.WorkspaceFiles > 10000 {
		return p, "", deny("invalid_policy", "Invalid resource limits")
	}
	if p.Limits.MemoryMiB == 0 {
		p.Limits.MemoryMiB = 128
	}
	if p.Limits.WorkspaceMiB == 0 {
		p.Limits.WorkspaceMiB = 64
	}
	if p.Limits.MemoryMiB < 64 || p.Limits.MemoryMiB > 4096 || p.Limits.WorkspaceMiB < 16 || p.Limits.WorkspaceMiB > 2048 || p.Limits.WorkspaceMiB > p.Limits.MemoryMiB/2 {
		return p, "", deny("invalid_policy", "Invalid memory or workspace quota")
	}
	if len(p.AllowedUIDs) == 0 || len(p.AllowedUIDs) > 32 {
		return p, "", deny("invalid_policy", "Explicit caller UID allowlist is required")
	}
	if !p.DevelopmentAllowSameUID && runtime.GOOS != "linux" {
		return p, "", deny("unsupported_platform", "Production peer authentication requires Linux SO_PEERCRED")
	}
	for _, uid := range p.AllowedUIDs {
		if uid == uint32(os.Getuid()) && !p.DevelopmentAllowSameUID {
			return p, "", deny("unsafe_policy", "Production callers must use a separate UID")
		}
	}
	for _, optional := range []string{p.Toolpack, p.GatewaySocket, p.ConnectorTokenDir} {
		if optional != "" && (!cleanAbsolute(optional) || beneath(optional, p.Workspace.Source)) {
			return p, "", deny("unsafe_policy", "Optional mounts must be administrative paths outside the workspace")
		}
	}
	if p.GatewayVolume != "" && (!regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`).MatchString(p.GatewayVolume) || p.GatewaySocket != "") {
		return p, "", deny("unsafe_policy", "Choose a single fixed gateway socket or volume")
	}
	if !developmentNoProfile || !p.DevelopmentAllowSameUID || p.AdmissionExecutable != "" || p.AdmissionSHA256 != "" || p.ProfileSHA256 != "" || p.TenantID != "" || p.DeploymentID != "" || p.ProfileID != "" || p.Activation != nil {
		// With activation records the profile digest comes from the device's activation state,
		// never from this file; without them the administrator pins it here.
		pinned := regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(p.ProfileSHA256)
		if !cleanAbsolute(p.AdmissionExecutable) || beneath(p.AdmissionExecutable, p.Workspace.Source) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(p.AdmissionSHA256) || pinned != (p.Activation == nil) || (p.Activation != nil && p.ProfileSHA256 != "") {
			return p, "", deny("invalid_policy", "Pinned native admission and exactly one profile pin (policy digest or activation records) are required")
		}
		if p.Activation != nil {
			if _, err = activationTrust(p); err != nil || !cleanAbsolute(p.Activation.StateDir) || beneath(p.Activation.StateDir, p.Workspace.Source) {
				return p, "", deny("invalid_policy", "Activation needs a state directory outside the workspace, root CAs, a signer SAN and the device key digest")
			}
		}
		for _, id := range []string{p.TenantID, p.DeploymentID, p.ProfileID} {
			if !assignmentID.MatchString(id) {
				return p, "", deny("invalid_policy", "Tenant, deployment and profile identifiers are required")
			}
		}
	}
	if err = validateFinalization(p); err != nil {
		return p, "", err
	}
	return p, hash(raw), nil
}
func failure(err error) result {
	var refused *refusal
	if errors.As(err, &refused) {
		return result{Schema: "testifysec.hardened-opencode.exec-result/v1", Status: "rejected", Code: refused.Code, Message: refused.Message, Assurance: "not-assessed"}
	}
	return result{Schema: "testifysec.hardened-opencode.exec-result/v1", Status: "rejected", Code: "io_failure", Message: "Broker operation failed; no host fallback", Assurance: "not-assessed"}
}
