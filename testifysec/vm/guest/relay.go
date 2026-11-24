package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const gatewaySocket = "/run/hardened-gateway/gateway.sock"

// afVSOCK is AF_VSOCK (40 on every Linux architecture, include/linux/socket.h).
// The frozen syscall package defines it for linux/arm64 but not linux/amd64,
// so naming it here keeps the guest building and testable on either.
const afVSOCK = 40
const modelRequestLimit = 1024 * 1024

type modelEnvelope struct {
	Schema     string  `json:"schema"`
	Nonce      string  `json:"nonce"`
	JobSHA256  string  `json:"jobSha256"`
	Binding    binding `json:"binding"`
	Sequence   int     `json:"sequence"`
	Path       string  `json:"path"`
	BodyBase64 string  `json:"bodyBase64"`
}
type guestRelay struct {
	mu       sync.Mutex
	closed   bool
	sequence int
	inflight int
	ctx      context.Context
	cancel   context.CancelFunc
	active   map[*os.File]bool
	workers  sync.WaitGroup
	server   *http.Server
	listener net.Listener
	expected expectation
}

func startGuestRelay(j job, nonce string) (*guestRelay, error) {
	if err := mount("tmpfs", "/run", "tmpfs", "size=1048576,mode=0755", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC); err != nil {
		return nil, err
	}
	if err := os.Mkdir("/run/hardened-gateway", 0755); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", gatewaySocket)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(gatewaySocket, 0666); err != nil {
		listener.Close()
		return nil, err
	}
	g := &guestRelay{listener: listener, active: map[*os.File]bool{}, expected: expectation{Nonce: nonce, JobSHA256: j.Digest, Binding: j.Binding}}
	g.ctx, g.cancel = context.WithCancel(context.Background())
	g.server = &http.Server{Handler: g, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 8192}
	g.workers.Add(1)
	go func() { defer g.workers.Done(); _ = g.server.Serve(listener) }()
	return g, nil
}
func (g *guestRelay) stop() error {
	g.mu.Lock()
	g.closed = true
	g.cancel()
	for file := range g.active {
		_ = syscall.Shutdown(int(file.Fd()), syscall.SHUT_RDWR)
	}
	g.mu.Unlock()
	_ = g.server.Close()
	done := make(chan struct{})
	go func() { g.workers.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-time.After(4 * time.Second):
		return errors.New("guest-relay-drain-deadline")
	}
}
func (g *guestRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	if g.closed || g.inflight >= 2 || g.sequence >= 32 {
		g.mu.Unlock()
		http.Error(w, "relay unavailable", 503)
		return
	}
	// Register before body reads so closing cannot race an initially empty Wait.
	g.workers.Add(1)
	g.inflight++
	g.sequence++
	sequence := g.sequence
	g.mu.Unlock()
	defer func() { g.mu.Lock(); g.inflight--; g.mu.Unlock(); g.workers.Done() }()
	if r.Method != "POST" || (r.URL.Path != "/v1/chat/completions" && r.URL.Path != "/v1/responses") || r.URL.IsAbs() || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.Header.Get("Content-Encoding") != "" {
		http.Error(w, "unapproved model route", 400)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, modelRequestLimit))
	if err != nil {
		http.Error(w, "model request too large", 413)
		return
	}
	file, err := connectModel(g.ctx)
	if err != nil {
		http.Error(w, "model relay unavailable", 502)
		return
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		file.Close()
		http.Error(w, "relay closed", 503)
		return
	}
	g.active[file] = true
	g.mu.Unlock()
	defer func() { g.mu.Lock(); delete(g.active, file); g.mu.Unlock(); file.Close() }()
	deadlineDone := make(chan struct{})
	timer := time.AfterFunc(30*time.Second, func() { _ = syscall.Shutdown(int(file.Fd()), syscall.SHUT_RDWR); close(deadlineDone) })
	defer func() {
		if !timer.Stop() {
			<-deadlineDone
		}
	}()
	envelope := modelEnvelope{Schema: "testifysec.vm-model-request/v1", Nonce: g.expected.Nonce, JobSHA256: g.expected.JobSHA256, Binding: g.expected.Binding, Sequence: sequence, Path: r.URL.Path, BodyBase64: base64.StdEncoding.EncodeToString(body)}
	frame, err := modelFrame(envelope)
	if err != nil || writeModelFrame(file, frame) != nil {
		http.Error(w, "model relay unavailable", 502)
		return
	}
	// ReadResponse supplies framing/truncation checks; the host forwards the
	// gateway's HTTP bytes unchanged, including incomplete chunked responses.
	response, err := http.ReadResponse(bufio.NewReaderSize(io.LimitReader(file, 16*1024*1024+65536+1), 8192), r)
	if err != nil {
		http.Error(w, "model relay unavailable", 502)
		return
	}
	defer response.Body.Close()
	for _, key := range []string{"Content-Type", "Cache-Control", "X-Hardened-Request-ID"} {
		if value := response.Header.Get(key); value != "" {
			w.Header().Set(key, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	buffer := make([]byte, 32768)
	total := 0
	for {
		n, readErr := response.Body.Read(buffer)
		total += n
		if total > 16*1024*1024 {
			panic(http.ErrAbortHandler)
		}
		if n > 0 {
			if _, err = w.Write(buffer[:n]); err != nil {
				return
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		if readErr == io.EOF {
			return
		}
		if readErr != nil {
			panic(http.ErrAbortHandler)
		}
	}
}

// Pending connects are nonblocking and owned by this function until transfer
// into g.active. Cancellation is observed within one 50ms poll; an unpublished
// descriptor cannot outlive the four-second handler drain.
func connectModel(ctx context.Context) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := syscall.Socket(afVSOCK, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	owned := true
	defer func() {
		if owned {
			_ = syscall.Close(fd)
		}
	}()
	address := struct {
		Family, Reserved uint16
		Port, CID        uint32
		Zero             [4]byte
	}{Family: afVSOCK, Port: 17002, CID: 2}
	_, _, errno := syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&address)), unsafe.Sizeof(address))
	if errno != 0 && errno != syscall.EINPROGRESS {
		return nil, errno
	}
	deadline := time.Now().Add(2500 * time.Millisecond)
	for errno != 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !time.Now().Before(deadline) {
			return nil, errors.New("model-connect-deadline")
		}
		ready := struct {
			FD               int32
			Events, Returned int16
		}{FD: int32(fd), Events: 4}
		interval := syscall.NsecToTimespec((50 * time.Millisecond).Nanoseconds())
		count, _, pollErr := syscall.Syscall6(syscall.SYS_PPOLL, uintptr(unsafe.Pointer(&ready)), 1, uintptr(unsafe.Pointer(&interval)), 0, 0, 0)
		if pollErr == syscall.EINTR {
			continue
		}
		if pollErr != 0 {
			return nil, pollErr
		}
		if count == 0 {
			continue
		}
		if ready.Returned&4 == 0 {
			return nil, errors.New("model-connect-refused")
		}
		value, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
		if err != nil {
			return nil, err
		}
		if value != 0 {
			return nil, syscall.Errno(value)
		}
		errno = 0
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := syscall.SetNonblock(fd, false); err != nil {
		return nil, err
	}
	timeout := syscall.Timeval{Sec: 2}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout); err != nil {
		return nil, err
	}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &timeout); err != nil {
		return nil, err
	}
	owned = false
	return os.NewFile(uintptr(fd), "model-vsock"), nil
}
func modelFrame(value modelEnvelope) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(raw) > 1400000 {
		return nil, errors.New("relay frame too large")
	}
	frame := append([]byte("HCMDL2\r\n"), make([]byte, 4)...)
	binary.BigEndian.PutUint32(frame[8:12], uint32(len(raw)))
	return append(frame, raw...), nil
}
func writeModelBytes(file *os.File, raw []byte) error {
	for len(raw) > 0 {
		n, err := file.Write(raw)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		raw = raw[n:]
	}
	return nil
}

func readModelReceipt(file *os.File, frame []byte) ([]byte, error) {
	expectedDigest := sha256.Sum256(frame)
	receipt := make([]byte, 40)
	if _, err := io.ReadFull(file, receipt); err != nil {
		return nil, err
	}
	if !bytes.Equal(receipt[:8], []byte("HCRCP2\r\n")) || !bytes.Equal(receipt[8:], expectedDigest[:]) {
		return nil, errors.New("relay frame receipt mismatch")
	}
	return receipt, nil
}

func modelConfirmation(receipt []byte) []byte {
	acceptedDigest := sha256.Sum256(receipt)
	return append([]byte("HCCMT2\r\n"), acceptedDigest[:]...)
}

func writeModelFrame(file *os.File, frame []byte) error {
	if err := writeModelBytes(file, frame); err != nil {
		return err
	}
	receipt, err := readModelReceipt(file, frame)
	if err != nil {
		return err
	}
	// A close after receipt refusal is not acceptance of the request.
	if err := writeModelBytes(file, modelConfirmation(receipt)); err != nil {
		return err
	}
	return syscall.Shutdown(int(file.Fd()), syscall.SHUT_WR)
}

// Fixed synthetic request workload, executed as the ordinary untrusted UID.
// It exists to exercise real native HTTP/VSock/gateway transports offline.
type relayFixture struct {
	PaddingBytes int             `json:"paddingBytes,omitempty"`
	Path         string          `json:"path"`
	Body         json.RawMessage `json:"body"`
	Status       int             `json:"status"`
	Contains     string          `json:"contains"`
	Attack       string          `json:"attack"`
}

func fixtureGateway() int {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4097))
	var fixture relayFixture
	if err != nil || len(raw) > 4096 || json.Unmarshal(raw, &fixture) != nil {
		return 4
	}
	// Fixed request-size fixture, not a new executable or arbitrary generator.
	if fixture.PaddingBytes != 0 {
		if fixture.PaddingBytes != 20480 || fixture.Path != "/v1/chat/completions" {
			return 4
		}
		var body map[string]any
		if json.Unmarshal(fixture.Body, &body) != nil || body == nil {
			return 4
		}
		body["messages"] = []map[string]string{{"role": "user", "content": strings.Repeat("x", 20480)}}
		fixture.Body, err = json.Marshal(body)
		if err != nil {
			return 4
		}
	}
	if fixture.Attack != "" {
		if fixture.Attack == "slow-body" {
			return slowBodyFixture()
		}
		return attackRelay(fixture)
	}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", gatewaySocket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 32 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequest("POST", "http://hardened-gateway"+fixture.Path, bytes.NewReader(fixture.Body))
	if err != nil {
		return 4
	}
	request.Header.Set("Authorization", "Bearer guest-forged-token")
	request.Header.Set("X-Agent-ID", "guest-forged-agent")
	request.Header.Set("X-Provider-URL", "http://unapproved.invalid")
	response, err := client.Do(request)
	if err != nil {
		return 4
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 17*1024*1024))
	if readErr != nil {
		fmt.Println("GATEWAY_STREAM_REFUSED")
		return 4
	}
	if response.StatusCode != fixture.Status || !bytes.Contains(body, []byte(fixture.Contains)) {
		return 4
	}
	if bytes.Contains(body, []byte("synthetic-provider-credential")) || response.Header.Get("Set-Cookie") != "" {
		return 4
	}
	if os.WriteFile("/workspace/result.txt", []byte("vm-fixture-verified\n"), 0600) != nil {
		return 4
	}
	fmt.Printf("GATEWAY_STATUS=%d WORKER_UID=65534 HARNESS_TEST_PASSED\n", response.StatusCode)
	return 0
}

func slowBodyFixture() int {
	for i := 0; i < 2; i++ {
		connection, err := net.DialTimeout("unix", gatewaySocket, time.Second)
		if err != nil {
			return 4
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(4 * time.Second))
		_, err = io.WriteString(connection, "POST /v1/chat/completions HTTP/1.1\r\nHost: fixture\r\nContent-Type: application/json\r\nContent-Length: 100\r\nExpect: 100-continue\r\n\r\n")
		if err != nil {
			return 4
		}
		// 100 Continue is emitted when the admitted handler begins its body
		// read, proving both reservations exist before the third request.
		response, err := http.ReadResponse(bufio.NewReader(connection), nil)
		if err != nil || response.StatusCode != 100 {
			return 4
		}
	}
	connection, err := net.DialTimeout("unix", gatewaySocket, time.Second)
	if err != nil {
		return 4
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = io.WriteString(connection, "POST /v1/chat/completions HTTP/1.1\r\nHost: fixture\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
	if err != nil {
		return 4
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		return 4
	}
	defer response.Body.Close()
	_, err = io.ReadAll(response.Body)
	if err != nil || response.StatusCode != 503 {
		return 4
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	file, err := connectModel(cancelled)
	if file != nil {
		file.Close()
		return 4
	}
	if !errors.Is(err, context.Canceled) {
		return 4
	}
	if os.WriteFile("/workspace/result.txt", []byte("vm-fixture-verified\n"), 0600) != nil {
		return 4
	}
	fmt.Println("THIRD_SLOW_BODY_REFUSED CONNECT_CANCELLED WORKER_UID=65534 HARNESS_TEST_PASSED")
	return 0
}
func attackRelay(fixture relayFixture) int {
	if fixture.Attack == "busy" {
		for i := 0; i < 3; i++ {
			file, err := connectFixedVSock(17002)
			if err != nil {
				return 4
			}
			defer file.Close()
		}
		time.Sleep(6 * time.Second)
		return 4
	}
	expected, err := bootExpectation()
	if err != nil {
		return 4
	}
	envelope := modelEnvelope{Schema: "testifysec.vm-model-request/v1", Nonce: expected.Nonce, JobSHA256: expected.JobSHA256, Binding: expected.Binding, Sequence: 1, Path: fixture.Path, BodyBase64: base64.StdEncoding.EncodeToString(fixture.Body)}
	switch fixture.Attack {
	case "nonce":
		envelope.Nonce = strings.Repeat("0", 32)
	case "job":
		envelope.JobSHA256 = strings.Repeat("0", 64)
	case "request":
		envelope.Binding.RequestSHA256 = strings.Repeat("0", 64)
	case "profile":
		envelope.Binding.ProfileSHA256 = strings.Repeat("0", 64)
	case "session":
		envelope.Binding.SessionID = "wrong-session"
	case "materials":
		envelope.Binding.MaterialsSHA256 = strings.Repeat("0", 64)
	case "backend":
		envelope.Binding.BackendSHA256 = strings.Repeat("0", 64)
	case "path":
		envelope.Path = "/v1/files"
	case "sequence":
		envelope.Sequence = 0
	case "body-limit":
		envelope.BodyBase64 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), modelRequestLimit+1))
	case "body-encoding":
		envelope.BodyBase64 = "eA==\n"
	}
	frame, err := modelFrame(envelope)
	if err != nil {
		return 4
	}
	switch fixture.Attack {
	case "oversize":
		binary.BigEndian.PutUint32(frame[8:12], 1400001)
		frame = frame[:12]
	case "old-magic":
		copy(frame[:8], []byte("HCMDL1\r\n"))
	case "truncated":
		frame = frame[:len(frame)-1]
	case "duplicate", "unknown", "null-sequence":
		raw := frame[12:]
		if fixture.Attack == "duplicate" {
			raw = bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"other","schema":`), 1)
		}
		if fixture.Attack == "unknown" {
			raw = bytes.Replace(raw, []byte(`"schema":`), []byte(`"socket":"/host/secret","schema":`), 1)
		}
		if fixture.Attack == "null-sequence" {
			raw = bytes.Replace(raw, []byte(`"sequence":1`), []byte(`"sequence":null`), 1)
		}
		frame = append(frame[:12], raw...)
		binary.BigEndian.PutUint32(frame[8:12], uint32(len(raw)))
	}
	count := 1
	if fixture.Attack == "replay" {
		count = 2
	}
	for i := 0; i < count; i++ {
		file, err := connectFixedVSock(17002)
		if err != nil {
			return 4
		}
		err = writeAttackFrame(file, frame, fixture.Attack)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(file, 17*1024*1024))
		}
		file.Close()
	}
	return 4
}

// Late-stage attacks complete the receipt handshake before changing acceptance
// or EOF, so refusal does not accidentally prove only a missing marker.
func writeAttackFrame(file *os.File, frame []byte, attack string) error {
	if err := writeModelBytes(file, frame); err != nil {
		return err
	}
	if attack == "oversize" || attack == "truncated" || attack == "old-magic" {
		return syscall.Shutdown(int(file.Fd()), syscall.SHUT_WR)
	}
	receipt, err := readModelReceipt(file, frame)
	if err != nil {
		return err
	}
	confirmation := modelConfirmation(receipt)
	switch attack {
	case "acceptance-missing":
		confirmation = nil
	case "acceptance-short":
		confirmation = confirmation[:12]
	case "acceptance-magic":
		confirmation[0] ^= 1
	case "acceptance-digest":
		confirmation[39] ^= 1
	}
	if err := writeModelBytes(file, confirmation); err != nil {
		return err
	}
	if attack == "extra" {
		if err := writeModelBytes(file, []byte{0}); err != nil {
			return err
		}
	}
	if attack == "no-eof" {
		// Hold beyond the host's three-second EOF deadline. Reading with the
		// guest's two-second timeout would close early and accidentally supply EOF.
		time.Sleep(6 * time.Second)
		return nil
	}
	return syscall.Shutdown(int(file.Fd()), syscall.SHUT_WR)
}
