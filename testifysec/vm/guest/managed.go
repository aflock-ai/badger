package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// V3 has independent fixed budgets. V2 fixture limits are unchanged.
const managedJobLimit = 512 << 10
const managedFrameLimit = 768 << 10
const managedResultLimit = 768 << 10
const managedContentLimit = 256 << 10
const managedFileLimit = 64 << 10
const managedOutputLimit = 64 << 10
const managedFilesLimit = 128
const managedEntriesLimit = 256

type managedFile struct {
	Path          string `json:"path"`
	SHA256        string `json:"sha256"`
	Size          int64  `json:"size"`
	Executable    bool   `json:"executable"`
	ContentBase64 string `json:"contentBase64"`
}
type fileDescription struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
	Executable bool   `json:"executable"`
}
type managedRequest struct {
	Prompt         string `json:"prompt"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
}
type managedResult struct {
	Schema                string        `json:"schema"`
	Nonce                 string        `json:"nonce"`
	JobSHA256             string        `json:"jobSha256"`
	Binding               binding       `json:"binding"`
	JobValidated          bool          `json:"jobValidated"`
	Passed                bool          `json:"passed"`
	Error                 string        `json:"error"`
	PID                   int           `json:"pid"`
	WorkerUID             uint32        `json:"workerUid"`
	RootReadonly          bool          `json:"rootReadonly"`
	WorkerStarted         bool          `json:"workerStarted"`
	ExitObserved          bool          `json:"exitObserved"`
	ExitCode              *int          `json:"exitCode"`
	Reaped                bool          `json:"reaped"`
	OutputDrained         bool          `json:"outputDrained"`
	OutputComplete        bool          `json:"outputComplete"`
	OutputBase64          string        `json:"outputBase64"`
	OutputSHA256          string        `json:"outputSha256"`
	CaptureComplete       bool          `json:"captureComplete"`
	InitialManifestSHA256 string        `json:"initialManifestSha256"`
	FinalManifestSHA256   string        `json:"finalManifestSha256"`
	Files                 []managedFile `json:"files"`
	Removed               []string      `json:"removed"`
}

func descriptionHash(files []managedFile) string {
	descriptions := make([]fileDescription, 0, len(files))
	for _, f := range files {
		descriptions = append(descriptions, fileDescription{f.Path, f.SHA256, f.Size, f.Executable})
	}
	raw, _ := json.Marshal(descriptions)
	return sum(raw)
}

// Same portable artifact path rules as broker/artifact.go. Full modes and
// empty directories are deliberately not exported as portable file artifacts.
func managedPath(name string) bool {
	if name == "" || len(name) > 1024 || path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.ContainsAny(name, `\:*?"<>|`) {
		return false
	}
	parts := strings.Split(name, "/")
	if len(parts) > 32 {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > 255 || strings.TrimRight(part, ". ") != part {
			return false
		}
		for _, r := range part {
			if r < 32 || r >= 127 {
				return false
			}
		}
		lower := strings.ToLower(part)
		if lower == ".git" || strings.HasPrefix(lower, "git~") {
			return false
		}
		stem, _, _ := strings.Cut(lower, ".")
		if stem == "con" || stem == "prn" || stem == "aux" || stem == "nul" || len(stem) == 4 && (strings.HasPrefix(stem, "com") || strings.HasPrefix(stem, "lpt")) && stem[3] >= '0' && stem[3] <= '9' {
			return false
		}
	}
	return true
}

type pathSet struct {
	names map[string]string
	files map[string]bool
}

func (p *pathSet) add(name string, file bool) bool {
	if !managedPath(name) {
		return false
	}
	if p.names == nil {
		p.names = map[string]string{}
		p.files = map[string]bool{}
	}
	parts := strings.Split(name, "/")
	for i := range parts {
		prefix := strings.Join(parts[:i+1], "/")
		key := strings.ToLower(prefix)
		if prior, ok := p.names[key]; ok && (prior != prefix || p.files[key] || i == len(parts)-1 && file) {
			return false
		}
		p.names[key] = prefix
		if i == len(parts)-1 && file {
			p.files[key] = true
		}
	}
	return len(p.names) <= managedEntriesLimit
}

func decodeManaged(j *job) error {
	if !managedUnicode(j.Request) || !managedUnicode(j.Materials) {
		return errors.New("managed-json-encoding")
	}
	var req managedRequest
	if strictJob(j.Request, &req) != nil || len(req.Prompt) > 4096 || req.TimeoutSeconds < 1 || req.TimeoutSeconds > 45 {
		return errors.New("managed-request")
	}
	if strictJob(j.Materials, &j.ManagedFiles) != nil || len(j.ManagedFiles) > managedFilesLimit {
		return errors.New("managed-materials")
	}
	var paths pathSet
	total := int64(0)
	previous := ""
	for _, f := range j.ManagedFiles {
		if f.Path <= previous || !paths.add(f.Path, true) || !hexString(f.SHA256, 32) || f.Size < 0 || f.Size > managedFileLimit {
			return errors.New("managed-material-path")
		}
		previous = f.Path
		raw, e := base64.StdEncoding.Strict().DecodeString(f.ContentBase64)
		if e != nil || base64.StdEncoding.EncodeToString(raw) != f.ContentBase64 || int64(len(raw)) != f.Size || sum(raw) != f.SHA256 {
			return errors.New("managed-material-bytes")
		}
		total += f.Size
		if total > managedContentLimit {
			return errors.New("managed-material-limit")
		}
	}
	j.Mode = "worker"
	j.Prompt = req.Prompt
	j.TimeoutSeconds = req.TimeoutSeconds
	return nil
}

func installManaged(j job) error {
	root, err := os.OpenRoot("/workspace")
	if err != nil {
		return err
	}
	defer root.Close()
	for _, f := range j.ManagedFiles {
		parts := strings.Split(f.Path, "/")
		for i := 0; i < len(parts)-1; i++ {
			name := strings.Join(parts[:i+1], "/")
			if e := root.Mkdir(name, 0755); e != nil && !errors.Is(e, os.ErrExist) {
				return errors.New("managed-material-directory")
			}
			if e := root.Chown(name, 65534, 65534); e != nil {
				return e
			}
		}
		mode := os.FileMode(0600)
		if f.Executable {
			mode = 0700
		}
		file, e := root.OpenFile(f.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
		if e != nil {
			return errors.New("managed-material-install")
		}
		raw, _ := base64.StdEncoding.Strict().DecodeString(f.ContentBase64)
		n, we := file.Write(raw)
		ce := file.Chown(65534, 65534)
		ee := file.Close()
		if n != len(raw) || we != nil || ce != nil || ee != nil {
			return errors.New("managed-material-install")
		}
	}
	return nil
}

func runManaged(j job, r *result, relay *guestRelay) error {
	m := r.Managed
	m.InitialManifestSHA256 = descriptionHash(j.ManagedFiles)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(j.TimeoutSeconds)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/toolpack/opencode-worker")
	cmd.Dir = "/workspace"
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/tmp/home", "TMPDIR=/tmp", "LANG=C.UTF-8"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}, Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = time.Second
	cmd.Cancel = func() error { return syscall.Kill(-1, syscall.SIGKILL) }
	raw, _ := json.Marshal(map[string]string{"schema": "testifysec.hardened-opencode.prompt/v1", "prompt": j.Prompt, "profileDigest": j.Binding.ProfileSHA256})
	cmd.Stdin = bytes.NewReader(raw)
	output := &boundedOutput{limit: managedOutputLimit, cancel: cancel}
	// One shared kernel pipe preserves stdout/stderr write order. Observe EOF
	// directly; os/exec.Wait can mask its internal drain error behind ExitError.
	reader, writer, err := os.Pipe()
	if err != nil {
		return errors.New("managed-output-pipe")
	}
	defer reader.Close()
	cmd.Stdout = writer
	cmd.Stderr = writer
	drained := make(chan bool, 1)
	go func() { _, err := io.Copy(output, reader); drained <- err == nil }()
	runErr := cmd.Start()
	writer.Close()
	if runErr == nil {
		m.WorkerStarted = true
		runErr = cmd.Wait()
	}
	if cmd.ProcessState != nil {
		code := cmd.ProcessState.ExitCode()
		m.ExitObserved = true
		m.ExitCode = &code
	}
	// Only PID1 and its workload exist. No capture before every user process is
	// gone; WNOHANG keeps reap bounded even with a stuck task. Host deadline is
	// independent and still stops the entire VM if kernel teardown stalls.
	killErr := syscall.Kill(-1, syscall.SIGKILL)
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, e := syscall.Wait4(-1, nil, syscall.WNOHANG, nil)
		if errors.Is(e, syscall.ECHILD) {
			m.Reaped = killErr == nil || errors.Is(killErr, syscall.ESRCH)
			break
		}
		if e != nil && !errors.Is(e, syscall.EINTR) || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	drainTimer := time.NewTimer(2 * time.Second)
	select {
	case eof := <-drained:
		m.OutputDrained = m.WorkerStarted && eof
	case <-drainTimer.C:
		reader.Close()
		join := time.NewTimer(time.Second)
		select {
		case <-drained:
		case <-join.C:
			return errors.New("managed-output-join")
		}
		join.Stop()
	}
	drainTimer.Stop()
	m.OutputComplete = m.OutputDrained && !output.overflow
	out := []byte(output.String())
	m.OutputBase64 = base64.StdEncoding.EncodeToString(out)
	m.OutputSHA256 = sum(out)
	if relay != nil {
		if e := relay.stop(); e != nil {
			return e
		}
	}
	if !m.Reaped {
		return errors.New("managed-reap-incomplete")
	}
	if output.overflow {
		return errors.New("worker-output-limit")
	}
	if ctx.Err() != nil {
		return errors.New("worker-deadline")
	}
	if !m.OutputDrained {
		return errors.New("worker-drain-deadline")
	}
	if runErr != nil {
		return errors.New("worker-failed")
	}
	files, err := captureManaged("/workspace")
	if err != nil {
		return err
	}
	m.Files = files
	m.FinalManifestSHA256 = descriptionHash(files)
	after := map[string]bool{}
	for _, f := range files {
		after[f.Path] = true
	}
	for _, f := range j.ManagedFiles {
		if !after[f.Path] {
			m.Removed = append(m.Removed, f.Path)
		}
	}
	m.CaptureComplete = true
	return nil
}

func captureManaged(workspace string) ([]managedFile, error) {
	root, err := os.OpenRoot(workspace)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	files := []managedFile{}
	var paths pathSet
	entries, total := 0, int64(0)
	var walk func(string, int) error
	walk = func(directory string, depth int) error {
		if depth > 32 {
			return errors.New("managed-artifact-depth")
		}
		dir, e := root.OpenFile(directory, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if e != nil {
			return errors.New("managed-artifact-directory")
		}
		defer dir.Close()
		// Enumeration allocation is bounded before sorting, including directories.
		items, e := dir.ReadDir(managedEntriesLimit - entries + 1)
		if e != nil && !errors.Is(e, io.EOF) {
			return errors.New("managed-artifact-enumeration")
		}
		entries += len(items)
		if entries > managedEntriesLimit {
			return errors.New("managed-artifact-count")
		}
		sort.Slice(items, func(i, j int) bool { return items[i].Name() < items[j].Name() })
		for _, item := range items {
			name := item.Name()
			if directory != "." {
				name = directory + "/" + name
			}
			info, e := root.Lstat(name)
			if e != nil {
				return errors.New("managed-artifact-stat")
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || (!info.IsDir() && !info.Mode().IsRegular()) || info.Mode().IsRegular() && st.Nlink != 1 {
				return errors.New("managed-artifact-type")
			}
			if !paths.add(name, info.Mode().IsRegular()) {
				return errors.New("managed-artifact-path")
			}
			if info.IsDir() {
				if e := walk(name, depth+1); e != nil {
					return e
				}
				continue
			}
			if len(files) >= managedFilesLimit || info.Size() < 0 || info.Size() > managedFileLimit || total+info.Size() > managedContentLimit {
				return errors.New("managed-artifact-size")
			}
			file, e := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
			if e != nil {
				return errors.New("managed-artifact-open")
			}
			opened, se := file.Stat()
			data, re := io.ReadAll(io.LimitReader(file, managedFileLimit+1))
			after, ae := file.Stat()
			ce := file.Close()
			if se != nil || re != nil || ae != nil || ce != nil || !os.SameFile(info, opened) || !os.SameFile(opened, after) || info.Size() != int64(len(data)) || after.Size() != info.Size() || after.Mode() != info.Mode() || after.ModTime() != info.ModTime() {
				return errors.New("managed-artifact-changed")
			}
			total += int64(len(data))
			files = append(files, managedFile{name, sum(data), int64(len(data)), info.Mode().Perm()&0111 != 0, base64.StdEncoding.EncodeToString(data)})
		}
		return nil
	}
	if err = walk(".", 0); err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func managedUnicode(raw []byte) bool {
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
