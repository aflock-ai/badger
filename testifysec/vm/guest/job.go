package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
	"unsafe"
)

const jobPort = 17001
const jobLimit = 32768
const frameLimit = 65536

type binding struct {
	RequestSHA256   string `json:"requestSha256"`
	ProfileSHA256   string `json:"profileSha256"`
	SessionID       string `json:"sessionId"`
	MaterialsSHA256 string `json:"materialsSha256"`
	BackendSHA256   string `json:"backendSha256"`
}
type job struct {
	Schema         string          `json:"schema"`
	Binding        binding         `json:"binding"`
	Request        json.RawMessage `json:"request"`
	Materials      json.RawMessage `json:"materials"`
	Mode           string          `json:"-"`
	Prompt         string          `json:"-"`
	Files          []material      `json:"-"`
	Digest         string          `json:"-"`
	ManagedFiles   []managedFile   `json:"-"`
	TimeoutSeconds int             `json:"-"`
}
type request struct {
	Mode   string `json:"mode"`
	Prompt string `json:"prompt"`
}
type material struct {
	Path          string `json:"path"`
	ContentBase64 string `json:"contentBase64"`
	SHA256        string `json:"sha256"`
}
type envelope struct {
	Schema    string `json:"schema"`
	Nonce     string `json:"nonce"`
	JobBase64 string `json:"jobBase64"`
}
type expectation struct {
	Nonce, JobSHA256 string
	Protocol         int
	Binding          binding
}

func sum(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func hexString(raw string, size int) bool {
	b, e := hex.DecodeString(raw)
	return e == nil && len(b) == size && hex.EncodeToString(b) == raw
}
func sessionID(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return s != "." && s != ".."
}
func validBinding(b binding) bool {
	return hexString(b.RequestSHA256, 32) && hexString(b.ProfileSHA256, 32) && hexString(b.MaterialsSHA256, 32) && hexString(b.BackendSHA256, 32) && sessionID(b.SessionID)
}

// Reject duplicates, aliases, null scalar coercions, trailing values and invalid
// UTF-8 before typed decoding. All containers and strings are frame-bounded.
func strictJob(raw []byte, target any) error {
	if !utf8.Valid(raw) {
		return errors.New("job-json")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 24 {
			return errors.New("job-json-depth")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				s, ok := key.(string)
				if !ok || seen[s] {
					return errors.New("job-json-duplicate")
				}
				seen[s] = true
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case json.Delim('['):
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case nil:
			return errors.New("job-json-null")
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("job-json-trailing")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	encoded, err := json.Marshal(target)
	if err != nil {
		return err
	}
	var a, b any
	if json.Unmarshal(raw, &a) != nil || json.Unmarshal(encoded, &b) != nil {
		return errors.New("job-json")
	}
	var keys func(any, any) bool
	keys = func(a, b any) bool {
		switch x := a.(type) {
		case map[string]any:
			y, ok := b.(map[string]any)
			if !ok || len(x) != len(y) {
				return false
			}
			for k, v := range x {
				w, ok := y[k]
				if !ok || !keys(v, w) {
					return false
				}
			}
		case []any:
			y, ok := b.([]any)
			if !ok || len(x) != len(y) {
				return false
			}
			for i, v := range x {
				if !keys(v, y[i]) {
					return false
				}
			}
		}
		return true
	}
	if !keys(a, b) {
		return errors.New("job-json-fields")
	}
	return nil
}

func bootExpectation() (expectation, error) {
	var expected expectation
	raw, err := os.ReadFile("/proc/cmdline")
	if err != nil || len(raw) > 4096 {
		return expected, errors.New("boot-expectations")
	}
	values := map[string]string{}
	for _, word := range strings.Fields(string(raw)) {
		if strings.HasPrefix(word, "hc.") {
			key, value, ok := strings.Cut(word, "=")
			if !ok || values[key] != "" {
				return expected, errors.New("boot-expectations")
			}
			values[key] = value
		}
	}
	if values["hc.gateway"] == "1" {
		delete(values, "hc.gateway")
	}
	protocol := 2
	if value, ok := values["hc.protocol"]; ok {
		if value != "3" {
			return expected, errors.New("boot-protocol")
		}
		protocol = 3
		delete(values, "hc.protocol")
	}
	if len(values) != 7 {
		return expected, errors.New("boot-expectations")
	}
	expected = expectation{Protocol: protocol, Nonce: values["hc.nonce"], JobSHA256: values["hc.job"], Binding: binding{RequestSHA256: values["hc.request"], ProfileSHA256: values["hc.profile"], SessionID: values["hc.session"], MaterialsSHA256: values["hc.materials"], BackendSHA256: values["hc.backend"]}}
	if !hexString(expected.Nonce, 16) || !hexString(expected.JobSHA256, 32) || !validBinding(expected.Binding) {
		return expected, errors.New("boot-expectations")
	}
	return expected, nil
}

func decodeJob(reader io.Reader, expected expectation) (job, error) {
	var j job
	var header [12]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return j, errors.New("job-frame-header")
	}
	magic, version, maxFrame, maxJob := "HCJOB2\r\n", "2", frameLimit, jobLimit
	if expected.Protocol == 3 {
		magic, version, maxFrame, maxJob = "HCJOB3\r\n", "3", managedFrameLimit, managedJobLimit
	}
	size := binary.BigEndian.Uint32(header[8:])
	if string(header[:8]) != magic || size < 1 || int(size) > maxFrame {
		return j, errors.New("job-frame-size")
	}
	raw := make([]byte, int(size))
	if _, err := io.ReadFull(reader, raw); err != nil {
		return j, errors.New("job-frame-truncated")
	}
	var extra [1]byte
	if n, err := reader.Read(extra[:]); n != 0 || err != io.EOF {
		return j, errors.New("job-frame-extra-or-no-eof")
	}
	var e envelope
	if strictJob(raw, &e) != nil || e.Schema != "testifysec.vm-envelope/v"+version || e.Nonce != expected.Nonce {
		return j, errors.New("job-envelope-binding")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(e.JobBase64)
	if err != nil || len(data) > maxJob || base64.StdEncoding.EncodeToString(data) != e.JobBase64 || sum(data) != expected.JobSHA256 {
		return j, errors.New("job-bytes-binding")
	}
	if strictJob(data, &j) != nil || j.Schema != "testifysec.vm-job/v"+version || !validBinding(j.Binding) || j.Binding != expected.Binding {
		return j, errors.New("job-assignment-binding")
	}
	if sum(j.Request) != j.Binding.RequestSHA256 || sum(j.Materials) != j.Binding.MaterialsSHA256 {
		return j, errors.New("job-content-binding")
	}
	if expected.Protocol == 3 {
		if err := decodeManaged(&j); err != nil {
			return j, err
		}
		j.Digest = sum(data)
		return j, nil
	}
	var request request
	if strictJob(j.Request, &request) != nil || len(request.Prompt) > 4096 {
		return j, errors.New("job-request")
	}
	switch request.Mode {
	case "edit", "timeout", "overflow", "symlink", "descendant", "worker", "gateway":
	default:
		return j, errors.New("invalid-mode")
	}
	j.Mode, j.Prompt = request.Mode, request.Prompt
	if strictJob(j.Materials, &j.Files) != nil || len(j.Files) > 16 {
		return j, errors.New("job-materials")
	}
	total := 0
	seen := map[string]bool{}
	for _, f := range j.Files {
		if !materialPath(f.Path) || seen[strings.ToLower(f.Path)] || !hexString(f.SHA256, 32) {
			return j, errors.New("job-material-path")
		}
		seen[strings.ToLower(f.Path)] = true
		raw, err := base64.StdEncoding.Strict().DecodeString(f.ContentBase64)
		if err != nil || base64.StdEncoding.EncodeToString(raw) != f.ContentBase64 || len(raw) > 8192 || sum(raw) != f.SHA256 {
			return j, errors.New("job-material-bytes")
		}
		total += len(raw)
		if total > 16384 {
			return j, errors.New("job-material-limit")
		}
	}
	j.Digest = sum(data)
	return j, nil
}
func materialPath(s string) bool {
	if len(s) < 1 || len(s) > 128 || s == "." || s == ".." || strings.EqualFold(s, ".git") || strings.HasSuffix(s, ".") {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// Linux sockaddr_vm UAPI: fixed host CID2/port17001, never an IP network device.
func connectJob() (*os.File, error) { return connectFixedVSock(jobPort) }
func connectFixedVSock(port uint32) (*os.File, error) {
	if port != jobPort && port != 17002 {
		return nil, errors.New("unapproved-vsock-port")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		fd, err := syscall.Socket(afVSOCK, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
		if err != nil {
			return nil, errors.New("job-vsock-unavailable")
		}
		timeout := syscall.Timeval{Sec: 2}
		if syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout) != nil || syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &timeout) != nil {
			_ = syscall.Close(fd)
			return nil, errors.New("job-vsock-deadline")
		}
		address := struct {
			Family   uint16
			Reserved uint16
			Port     uint32
			CID      uint32
			Zero     [4]byte
		}{Family: afVSOCK, Port: port, CID: 2}
		_, _, errno := syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&address)), unsafe.Sizeof(address))
		if errno == 0 {
			return os.NewFile(uintptr(fd), "session-job-vsock"), nil
		}
		_ = syscall.Close(fd)
		if time.Now().After(deadline) {
			return nil, errors.New("job-vsock-connect-deadline")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
func readJob(r *result) (job, error) {
	expected, err := bootExpectation()
	if err != nil {
		return job{}, err
	}
	r.Nonce, r.JobSHA256, r.Binding = expected.Nonce, expected.JobSHA256, expected.Binding
	if expected.Protocol == 3 {
		r.Managed = &managedResult{Schema: "testifysec.vm-result/v3", Files: []managedFile{}, Removed: []string{}, OutputSHA256: sum(nil)}
	}
	file, err := connectJob()
	if err != nil {
		return job{}, err
	}
	defer file.Close()
	deadlineDone := make(chan struct{})
	timer := time.AfterFunc(5*time.Second, func() { _ = syscall.Shutdown(int(file.Fd()), syscall.SHUT_RDWR); close(deadlineDone) })
	defer func() {
		if !timer.Stop() {
			<-deadlineDone
		}
	}()
	j, err := decodeJob(file, expected)
	if err == nil {
		r.JobSHA256 = j.Digest
		r.JobValidated = true
	}
	return j, err
}
func installMaterials(j job) error {
	if j.Schema == "testifysec.vm-job/v3" {
		return installManaged(j)
	}
	for _, f := range j.Files {
		raw, err := base64.StdEncoding.Strict().DecodeString(f.ContentBase64)
		if err != nil {
			return errors.New("job-material-bytes")
		}
		path := "/workspace/" + f.Path
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
		if err != nil {
			return errors.New("job-material-install")
		}
		n, writeErr := file.Write(raw)
		ownerErr := file.Chown(65534, 65534)
		closeErr := file.Close()
		if writeErr != nil || n != len(raw) || ownerErr != nil || closeErr != nil {
			return errors.New("job-material-install")
		}
	}
	return nil
}
