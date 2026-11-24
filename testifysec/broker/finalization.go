package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

type finalizationPolicy struct {
	Executable         string `json:"executable"`
	SHA256             string `json:"sha256"`
	AssignmentFile     string `json:"assignmentFile"`
	AssignmentSHA256   string `json:"assignmentSha256"`
	RetentionDirectory string `json:"retentionDirectory"`
}

// Candidate registration binds the admitted worker run. The gateway's static
// audit-session assignment remains separate; this hook does not establish that
// correlation or claim hardware attestation, signing, upload, or push delivery.

type finalizationRun struct {
	Schema             string `json:"schema"`
	SessionID          string `json:"sessionID"`
	WorkspaceDirectory string `json:"workspaceDirectory"`
	WorkspaceID        string `json:"workspaceID"`
	RequestSHA256      string `json:"requestSha256"`
	MaterialsSHA256    string `json:"materialsSha256"`
	BrokerSHA256       string `json:"brokerSha256"`
	BrokerPolicySHA256 string `json:"brokerPolicySha256"`
	ProfileSHA256      string `json:"profileSha256"`
}

type finalizationResponse struct {
	Schema         string `json:"schema"`
	Status         string `json:"status"`
	SessionID      string `json:"sessionID,omitempty"`
	PreparedSHA256 string `json:"preparedSha256,omitempty"`
	RecordSHA256   string `json:"recordSha256,omitempty"`
}

var finalizationDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var finalizationSession = regexp.MustCompile(`^session-[0-9a-f]{32}$`)

// The workspace is untrusted. Only the separate administrative retention and
// executable paths require this custody, including every ancestor component.
func finalizationRoot(path string, private bool) (*os.Root, error) {
	if !cleanAbsolute(path) {
		return nil, deny("unsafe_finalization", "Expected an absolute canonical finalization directory")
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		return nil, err
	}
	info, err := root.Stat(".")
	if err != nil || !finalizationOwner(info) {
		root.Close()
		return nil, deny("unsafe_finalization", "Filesystem root custody could not be established")
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, openErr := finalizationChild(root, part)
		closeErr := root.Close()
		if openErr != nil {
			return nil, errors.Join(openErr, closeErr)
		}
		if closeErr != nil {
			next.Close()
			return nil, closeErr
		}
		root = next
	}
	info, err = root.Stat(".")
	if err != nil || (private && (!ownedPrivate(info, false) || info.Mode().Perm() != 0700)) {
		root.Close()
		return nil, deny("unsafe_finalization", "Finalization state must be a private broker-owned directory")
	}
	return root, nil
}

func finalizationChild(parent *os.Root, name string) (*os.Root, error) {
	before, err := parent.Lstat(name)
	if err != nil || !finalizationOwner(before) {
		return nil, deny("unsafe_finalization", "Finalization directory ancestor is not protected")
	}
	child, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	after, err := child.Stat(".")
	if err != nil || !os.SameFile(before, after) || !finalizationOwner(after) {
		child.Close()
		return nil, deny("unsafe_finalization", "Finalization ancestor changed during opening")
	}
	return child, nil
}

func finalizationOwner(info os.FileInfo) bool {
	if info == nil || !info.IsDir() {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && int64(stat.Uid) != int64(os.Getuid())) {
		return false
	}
	return info.Mode().Perm()&0022 == 0 || (stat.Uid == 0 && info.Mode()&os.ModeSticky != 0)
}

func validateFinalization(p policy) error {
	f := p.Finalization
	if f == nil {
		return nil
	}
	if p.AdmissionExecutable == "" || !finalizationDigest.MatchString(p.ProfileSHA256) || !finalizationDigest.MatchString(f.SHA256) || !finalizationDigest.MatchString(f.AssignmentSHA256) {
		return deny("invalid_finalization", "Finalization requires pinned native admission, producer and assignment")
	}
	for _, path := range []string{f.Executable, f.AssignmentFile, f.RetentionDirectory} {
		if !cleanAbsolute(path) || beneath(path, p.Workspace.Source) {
			return deny("unsafe_finalization", "Finalization authority must be outside the workspace")
		}
	}
	if beneath(p.Workspace.Source, f.RetentionDirectory) || beneath(f.Executable, f.RetentionDirectory) || beneath(f.AssignmentFile, f.RetentionDirectory) {
		return deny("unsafe_finalization", "Retention must not contain the workspace or configured authority")
	}
	root, err := finalizationRoot(f.RetentionDirectory, true)
	if err != nil {
		return err
	}
	if err = root.Close(); err != nil {
		return err
	}
	return verifyFinalizationAuthority(*f)
}

func finalizationFile(path string, limit int64, executable bool) ([]byte, error) {
	root, err := finalizationRoot(filepath.Dir(path), true)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(filepath.Base(path))
	if err != nil || !ownedPrivate(info, true) || (executable && info.Mode().Perm()&0100 == 0) {
		return nil, deny("unsafe_finalization", "Finalization input must be a private broker-owned regular file")
	}
	file, err := root.OpenFile(filepath.Base(path), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !stable(info, opened) {
		return nil, deny("unsafe_finalization", "Finalization input changed during opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	after, statErr := file.Stat()
	if err != nil || statErr != nil || int64(len(raw)) > limit || !stable(opened, after) {
		return nil, deny("unsafe_finalization", "Finalization input changed or exceeded its bound")
	}
	return raw, nil
}

func verifyFinalizationAuthority(f finalizationPolicy) error {
	assignment, err := finalizationFile(f.AssignmentFile, inputLimit, false)
	if err != nil || hash(assignment) != f.AssignmentSHA256 {
		return deny("finalization_assignment_mismatch", "Protected producer assignment differs from its configured digest")
	}
	binary, err := finalizationFile(f.Executable, 64<<20, true)
	if err != nil || hash(binary) != f.SHA256 || len(binary) < 4 {
		return deny("finalization_executable_mismatch", "Protected native producer differs from its configured digest")
	}
	magic := string(binary[:4])
	if magic != "\x7fELF" && magic != "\xcf\xfa\xed\xfe" && magic != "\xfe\xed\xfa\xcf" {
		return deny("finalization_executable_mismatch", "Finalization requires a native executable, not an interpreter script")
	}
	return nil
}

func executionScratch(p policy) (string, bool, error) {
	if p.Finalization == nil {
		directory, err := os.MkdirTemp("", "hc-native-")
		return directory, false, err
	}
	if err := validateFinalization(p); err != nil {
		return "", false, err
	}
	root, err := finalizationRoot(p.Finalization.RetentionDirectory, true)
	if err != nil {
		return "", false, err
	}
	defer root.Close()
	name, err := allocateFinalization(root)
	if err != nil {
		return "", false, err
	}
	return filepath.Join(p.Finalization.RetentionDirectory, name), true, nil
}

func allocateFinalization(root *os.Root) (name string, failure error) {
	lock, err := root.OpenFile(".allocation.lock", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", deny("finalization_busy", "Retained state allocation requires operator review or is busy")
	}
	defer func() { failure = errors.Join(failure, root.Remove(".allocation.lock")) }()
	if err = lock.Close(); err != nil {
		return "", err
	}
	directory, err := root.Open(".")
	if err != nil {
		return "", err
	}
	// Every retained attempt counts, including incomplete or ambiguous runs.
	// Capacity is recovered only through operator review, never automatic replay.
	entries, readErr := directory.ReadDir(66)
	closeErr := directory.Close()
	if (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil || len(entries) >= 65 {
		return "", deny("finalization_retention_full", "Retained runs reached the bound; operator review is required")
	}
	for _, entry := range entries {
		if entry.Name() != ".allocation.lock" && (!entry.IsDir() || !finalizationSession.MatchString(entry.Name())) {
			return "", deny("unsafe_finalization", "Unexpected entry in protected retention directory")
		}
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return "", err
	}
	name = "session-" + hex.EncodeToString(nonce[:])
	if err = root.Mkdir(name, 0700); err != nil {
		return "", err
	}
	return name, nil
}

func writeFinalization(root *os.Root, name string, raw []byte) error {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(raw)
	return errors.Join(writeErr, file.Close())
}

func (b *broker) prepareFinalization(ctx context.Context, directory string, raw []byte, materials []material, profileHash string) error {
	root, err := finalizationRoot(directory, true)
	if err != nil {
		return err
	}
	defer root.Close()
	run := finalizationRun{"testifysec.hardened-code.producer-run/v1", filepath.Base(directory), b.policy.Workspace.Source, b.policy.Workspace.ID, hash(raw), hash(marshal(materials)), b.binaryHash, b.policyHash, profileHash}
	for _, item := range []struct {
		name string
		raw  []byte
	}{{"request.json", raw}, {"materials.json", marshal(materials)}, {"run.json", marshal(run)}} {
		if err = writeFinalization(root, item.name, item.raw); err != nil {
			return err
		}
	}
	if err = root.Chmod("inputs", 0700); err != nil {
		return err
	}
	if err = b.invokeFinalization(ctx, "produce-prepare", directory); err != nil {
		return deny("finalization_prepare_failed", "Protected producer refused the pre-execution snapshot; no worker started")
	}
	return root.Chmod("inputs", 0755)
}

func (b *broker) finalizeExecution(ctx context.Context, answer result) error {
	root, err := finalizationRoot(answer.retainedRun, true)
	if err != nil {
		return err
	}
	defer root.Close()
	// Preserve the completed observation before any helper invocation. A lost
	// acknowledgement may mean registration succeeded; never delete or retry it.
	if err = writeFinalization(root, "result.json", marshal(answer)); err != nil {
		return err
	}
	if err = root.Chmod("inputs", 0700); err != nil {
		return err
	}
	return b.invokeFinalization(ctx, "produce-finalize", answer.retainedRun)
}

func (b *broker) invokeFinalization(ctx context.Context, operation, directory string) error {
	f := b.policy.Finalization
	if f == nil || (operation != "produce-prepare" && operation != "produce-finalize") || filepath.Dir(directory) != f.RetentionDirectory || !finalizationSession.MatchString(filepath.Base(directory)) {
		return deny("unsafe_finalization", "Finalization invocation is not service-assigned")
	}
	if err := verifyFinalizationAuthority(*f); err != nil {
		return err
	}
	run, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	output, diagnostics := &cappedOutput{cancel: cancel}, &cappedOutput{cancel: cancel}
	command := exec.CommandContext(run, f.Executable, operation, f.AssignmentFile, f.AssignmentSHA256, directory)
	command.Dir = directory
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + directory, "TMPDIR=" + directory, "LANG=C"}
	command.Stdout, command.Stderr = output, diagnostics
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = time.Second
	err := command.Run()
	if command.Process != nil {
		err = errors.Join(err, drainFinalizationGroup(command.Process.Pid))
	}
	if err != nil || output.overflow || diagnostics.overflow {
		return deny("finalization_unavailable", "Protected producer failed or exceeded its resource bound")
	}
	if err = verifyFinalizationAuthority(*f); err != nil {
		return err
	}
	return validateFinalizationResponse(operation, directory, output.buffer.Bytes())
}

func drainFinalizationGroup(pid int) error {
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		err := syscall.Kill(-pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		if err != nil && !errors.Is(err, syscall.EPERM) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
	return errors.New("producer group did not drain")
}

func validateFinalizationResponse(operation, directory string, raw []byte) error {
	var response finalizationResponse
	if err := strict(raw, &response); err != nil {
		return err
	}
	status := strings.TrimPrefix(operation, "produce-") + "d"
	if operation == "produce-finalize" {
		status = "finalized"
	}
	if response.Schema != "testifysec.hardened-code.producer-response/v1" || response.Status != status || response.SessionID != filepath.Base(directory) || !finalizationDigest.MatchString(response.PreparedSHA256) {
		return deny("finalization_response_mismatch", "Producer response does not match the assigned operation and session")
	}
	prepared, err := finalizationFile(filepath.Join(directory, "prepared.json"), inputLimit, false)
	if err != nil || hash(prepared) != response.PreparedSHA256 {
		return deny("finalization_response_mismatch", "Prepared state does not match producer acknowledgement")
	}
	if operation == "produce-prepare" {
		if response.RecordSHA256 != "" {
			return deny("finalization_response_mismatch", "Preparation cannot acknowledge a finalized record")
		}
		return nil
	}
	return validateFinalizedRecord(directory, raw, response)
}

func validateFinalizedRecord(directory string, raw []byte, response finalizationResponse) error {
	record, err := finalizationFile(filepath.Join(directory, "registration.json"), inputLimit, false)
	if err != nil || hash(record) != response.RecordSHA256 || !finalizationDigest.MatchString(response.RecordSHA256) {
		return deny("finalization_response_mismatch", "Finalized registration does not match producer acknowledgement")
	}
	acknowledgement, err := finalizationFile(filepath.Join(directory, "finalized.json"), inputLimit, false)
	if err != nil || string(acknowledgement) != string(bytesTrimSpace(raw)) {
		return deny("finalization_response_mismatch", "Retained finalization acknowledgement differs")
	}
	return nil
}

func bytesTrimSpace(raw []byte) []byte { return []byte(strings.TrimSpace(string(raw))) }
