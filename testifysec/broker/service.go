package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type peer struct {
	uid uint32
	err error
}
type peerKey struct{}
type broker struct {
	policy         policy
	policyHash     string
	binaryHash     string
	engine         *engine
	admission      chan struct{}
	lifecycle      sync.Mutex
	closing        bool
	handlers       sync.WaitGroup
	cleanupFailure error
	// admit is verifyAdmission; a test replaces it to reach the lifecycle without a verifier.
	admit func(context.Context, policy, string) (string, error)
}

func newBroker(p policy, digest string) *broker {
	executable, _ := os.Executable()
	raw, _ := os.ReadFile(executable)
	return &broker{policy: p, policyHash: digest, binaryHash: hash(raw), engine: newEngine(p.DockerSocket), admission: make(chan struct{}, 1), admit: verifyAdmission}
}
func (b *broker) beginHandler() bool {
	b.lifecycle.Lock()
	defer b.lifecycle.Unlock()
	if b.closing {
		return false
	}
	b.handlers.Add(1)
	return true
}
func (b *broker) beginDrain() { b.lifecycle.Lock(); b.closing = true; b.lifecycle.Unlock() }
func (b *broker) failedCleanup(err error) {
	b.lifecycle.Lock()
	b.closing = true
	if b.cleanupFailure == nil {
		b.cleanupFailure = err
	}
	b.lifecycle.Unlock()
}
func (b *broker) waitHandlers(ctx context.Context) error {
	done := make(chan struct{})
	go func() { b.handlers.Wait(); close(done) }()
	select {
	case <-done:
		b.lifecycle.Lock()
		defer b.lifecycle.Unlock()
		return b.cleanupFailure
	case <-ctx.Done():
		return deny("shutdown_incomplete", "Worker cleanup exceeded shutdown deadline")
	}
}
func (b *broker) execute(ctx context.Context, raw []byte, uid uint32) (answer result, err error) {
	answer, err = b.executeWorker(ctx, raw, uid)
	return b.completeExecution(ctx, answer, err)
}

func (b *broker) completeExecution(ctx context.Context, answer result, err error) (result, error) {
	if err != nil || answer.retainedRun == "" || answer.Status != "completed" || answer.ExitCode != 0 || !answer.Cleanup || answer.Artifact == nil {
		return answer, err
	}
	if err = b.finalizeExecution(ctx, answer); err != nil {
		return answer, deny("finalization_failed", "Worker completed and was cleaned up; protected finalization failed; review protected state before retrying")
	}
	return answer, nil
}

func (b *broker) executeWorker(ctx context.Context, raw []byte, uid uint32) (answer result, err error) {
	var request executionRequest
	if err = strict(raw, &request); err != nil {
		return answer, err
	}
	if request.Schema != requestSchema || request.Workspace != b.policy.Workspace.ID {
		return answer, deny("workspace_denied", "Request must use the assigned workspace and schema")
	}
	if request.Command == "" || len(request.Command) > 8192 || len(request.Stdin) > 65536 || containsNUL(request.Command) {
		return answer, deny("invalid_schema", "Command or stdin exceeds the permitted shape")
	}
	timeout := request.TimeoutSeconds
	if timeout == 0 {
		timeout = b.policy.Limits.TimeoutSeconds
	}
	if timeout < 1 || timeout > b.policy.Limits.TimeoutSeconds {
		return answer, deny("invalid_schema", "Request timeout exceeds policy")
	}
	operation, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	admitted := b.policy
	if admitted.Activation != nil {
		if admitted, err = activate(admitted, request, time.Now()); err != nil {
			return answer, err
		}
	}
	profileHash, err := b.admit(operation, admitted, request.ProfileEnvelope)
	if err != nil {
		return answer, err
	}
	observed, err := b.engine.preflight(operation, b.policy.Image)
	if err != nil {
		return answer, err
	}
	if b.policy.GatewayVolume != "" {
		if err = b.engine.call(operation, "GET", "/volumes/"+b.policy.GatewayVolume, nil, nil); err != nil {
			return answer, deny("gateway_unavailable", "Approved session gateway volume does not exist")
		}
	}
	scratch, retained, err := executionScratch(b.policy)
	if err != nil {
		return answer, err
	}
	if retained {
		defer func() { answer.retainedRun = scratch }()
	} else {
		defer os.RemoveAll(scratch)
	}
	scratch, err = filepath.EvalSymlinks(scratch)
	if err != nil {
		return answer, err
	}
	if beneath(scratch, b.policy.Workspace.Source) {
		return answer, deny("unsafe_policy", "Private broker scratch must be outside the workspace")
	}
	materials, err := snapshot(operation, b.policy.Workspace.Source, filepath.Join(scratch, "inputs"), b.policy.Limits)
	if err != nil {
		return answer, err
	}
	if retained {
		if err = b.prepareFinalization(operation, scratch, raw, materials, profileHash); err != nil {
			return answer, err
		}
	}
	requestDirectory := filepath.Join(scratch, "request")
	if err = os.Mkdir(requestDirectory, 0755); err != nil {
		return answer, err
	}
	if err = os.WriteFile(filepath.Join(requestDirectory, "stdin"), []byte(request.Stdin), 0444); err != nil {
		return answer, err
	}
	// Registered before provisioning, so tokens copied before a refusal are removed too; a
	// retained run keeps no tokens.
	defer os.RemoveAll(filepath.Join(scratch, "run", runTokensFolder))
	run, err := provisionRun(b.policy, scratch, request.ProfileEnvelope, uid)
	if err != nil {
		return answer, err
	}
	configuration, err := configFor(b.policy, filepath.Join(scratch, "inputs"), requestDirectory, run, b.policyHash)
	if err != nil {
		return answer, err
	}
	for _, key := range observed["clearedImageEnvironment"].([]string) {
		configuration.Env = append(configuration.Env, key+"=")
	}
	configuration.Entrypoint = []string{"/bin/sleep"}
	configuration.Cmd = []string{"3600"}
	invocation := execConfig{User: "65534:65534", WorkingDir: "/workspace", AttachStdout: true, AttachStderr: true, Cmd: []string{"/bin/sh", "-c", `cp -R /inputs/. /workspace/ && exec /bin/sh -c "$1" < /request/stdin`, "hc-worker", request.Command}}
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return answer, err
	}
	name := "hc-native-" + hex.EncodeToString(nonce)
	volumeName := name + "-workspace"
	configuration.Labels["io.testifysec.hardened.operation"] = name
	defer func() {
		if cleanupErr := b.engine.cleanupOwned(name, volumeName, b.policyHash); cleanupErr != nil {
			err = deny("cleanup_failed", "Owned worker and volume cleanup could not be confirmed")
			b.failedCleanup(err)
			answer = result{}
		} else {
			answer.Cleanup = true
		}
	}()
	if err = b.engine.createWorkspaceVolume(operation, volumeName, b.policyHash, b.policy.Limits.WorkspaceMiB); err != nil {
		return answer, err
	}
	delete(configuration.HostConfig.Tmpfs, "/workspace")
	configuration.HostConfig.Mounts = append(configuration.HostConfig.Mounts, mount{Type: "volume", Source: volumeName, Target: "/workspace", ReadOnly: false})
	var created struct {
		ID string `json:"Id"`
	}
	if err = b.engine.call(operation, "POST", "/containers/create?name="+name, configuration, &created); err != nil {
		return answer, err
	}
	if !validID(created.ID) {
		return answer, deny("engine_unavailable", "Invalid container ID")
	}
	actual, err := b.engine.inspect(operation, created.ID)
	if err != nil {
		return answer, err
	}
	if err = verifyBoundary(actual, configuration); err != nil {
		return answer, err
	}
	execution, cancelExecution := context.WithTimeout(operation, time.Duration(timeout)*time.Second)
	defer cancelExecution()
	if err = b.engine.call(execution, "POST", "/containers/"+created.ID+"/start", nil, nil); err != nil {
		return answer, err
	}
	execID, connection, reader, err := b.engine.startExec(execution, created.ID, invocation)
	if err != nil {
		return answer, err
	}
	defer connection.Close()
	output, err := streamOutput(execution, connection, reader, b.policy.Limits.OutputBytes)
	var networkError net.Error
	if execution.Err() != nil || (errors.As(err, &networkError) && networkError.Timeout()) {
		return answer, deny("execution_timeout", "Execution deadline or caller cancellation terminated worker")
	}
	if err != nil {
		return answer, err
	}
	exitCode, err := b.engine.waitExec(execution, execID, created.ID)
	if err != nil {
		return answer, err
	}
	cancelExecution()
	// Freeze all remaining descendants, retaining tmpfs. Stopping the keeper
	// would unmount and discard the workspace before the daemon could export it.
	if err = b.engine.call(operation, "POST", "/containers/"+created.ID+"/pause", nil, nil); err != nil {
		return answer, err
	}
	actual, err = b.engine.inspect(operation, created.ID)
	if err != nil {
		return answer, err
	}
	if !actual.State.Running || !actual.State.Paused || actual.State.OOMKilled || actual.State.Error != "" {
		return answer, deny("execution_failed", "Worker freeze could not be established")
	}
	if err = verifyBoundary(actual, configuration); err != nil {
		return answer, err
	}
	capture, cancelCapture := context.WithTimeout(operation, 10*time.Second)
	defer cancelCapture()
	archive, err := b.engine.archive(capture, created.ID)
	if err != nil {
		return answer, err
	}
	artifact, err := captureArtifact(capture, archive, materials, b.policy.Limits)
	archive.Close()
	if err != nil {
		return answer, err
	}
	normalized := configuration
	normalized.Cmd = append([]string(nil), configuration.Cmd...)
	normalizedInvocation := invocation
	normalizedInvocation.Cmd = append([]string(nil), invocation.Cmd...)
	normalizedInvocation.Cmd[len(normalizedInvocation.Cmd)-1] = "<request-command>"
	normalized.HostConfig.Mounts = append([]mount(nil), configuration.HostConfig.Mounts...)
	normalized.HostConfig.Mounts[0].Source = "<private-inputs>"
	normalized.HostConfig.Mounts[1].Source = "<private-stdin>"
	normalized.HostConfig.Mounts[len(normalized.HostConfig.Mounts)-1].Source = "<private-workspace-tmpfs>"
	observed["workspaceStorage"] = map[string]any{"driver": "local", "type": "tmpfs", "sizeMiB": b.policy.Limits.WorkspaceMiB, "capture": "paused-container-docker-archive"}
	assurance := "linux-kernel-peer-uid; not-assessed"
	if b.policy.DevelopmentAllowSameUID {
		assurance = "same-uid-development-fixture; not-assessed"
	}
	answer = result{Schema: "testifysec.hardened-opencode.exec-result/v1", Status: "completed", ExitCode: exitCode, Output: string(output), OutputBase64: base64.StdEncoding.EncodeToString(output), OutputSHA256: hash(output), RequestSHA256: hash(raw), PolicySHA256: b.policyHash, BinarySHA256: b.binaryHash, BoundarySHA256: hash(marshal(normalized)), Boundary: normalized, Materials: materials, MaterialsSHA256: hash(marshal(materials)), Runtime: observed, CallerUID: uid, Assurance: assurance, ProfileSHA256: profileHash, Artifact: artifact, Execution: normalizedInvocation, ExecutionSHA256: hash(marshal(normalizedInvocation))}
	if len(marshal(answer)) > responseLimit {
		return result{}, deny("response_limit", "Exact bounded result exceeds IPC response budget")
	}
	return answer, nil
}
func containsNUL(text string) bool {
	for _, r := range text {
		if r == 0 {
			return true
		}
	}
	return false
}
func (b *broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	identity, ok := r.Context().Value(peerKey{}).(peer)
	allowed := false
	if ok && identity.err == nil {
		for _, uid := range b.policy.AllowedUIDs {
			if identity.uid == uid {
				allowed = true
			}
		}
	}
	if !allowed {
		w.WriteHeader(http.StatusForbidden)
		w.Write(marshal(failure(deny("unauthorized_peer", "Kernel peer UID is not assigned to this broker"))))
		return
	}
	if r.Method != "POST" || r.URL.Path != "/v1/execute" || r.URL.RawQuery != "" {
		w.WriteHeader(http.StatusNotFound)
		w.Write(marshal(failure(deny("unsupported_operation", "Only POST /v1/execute is supported"))))
		return
	}
	if !b.beginHandler() {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write(marshal(failure(deny("broker_draining", "Broker is shutting down"))))
		return
	}
	defer b.handlers.Done()
	select {
	case b.admission <- struct{}{}:
		defer func() { <-b.admission }()
	default:
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write(marshal(failure(deny("broker_busy", "One execution is already active"))))
		return
	}
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, inputLimit+1))
	if err != nil || len(raw) > inputLimit {
		w.WriteHeader(http.StatusBadRequest)
		w.Write(marshal(failure(deny("invalid_json", "IPC body exceeds limit"))))
		return
	}
	answer, err := b.execute(r.Context(), raw, identity.uid)
	b.respondExecution(w, raw, identity.uid, answer, err)
}

func (b *broker) respondExecution(w http.ResponseWriter, raw []byte, uid uint32, answer result, err error) {
	if err != nil {
		cleaned := answer.Cleanup
		answer = failure(err)
		answer.Cleanup = cleaned
		answer.RequestSHA256 = hash(raw)
		answer.PolicySHA256 = b.policyHash
		answer.BinarySHA256 = b.binaryHash
		if b.policy.DevelopmentAllowSameUID {
			answer.Message = err.Error()
		}
		answer.CallerUID = uid
		w.WriteHeader(http.StatusBadRequest)
	}
	w.Write(marshal(answer))
}

type limitedListener struct {
	net.Listener
	slots chan struct{}
}
type limitedConnection struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConnection) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (l *limitedListener) Accept() (net.Conn, error) {
	l.slots <- struct{}{}
	connection, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitedConnection{Conn: connection, release: func() { <-l.slots }}, nil
}
func serve(ctx context.Context, path string) error {
	p, digest, err := loadPolicy(path)
	if err != nil {
		return err
	}
	root, err := secureRoot(filepath.Dir(p.ListenSocket))
	if err != nil {
		return err
	}
	info, err := root.Stat(".")
	root.Close()
	if err != nil || !ownedPrivate(info, false) {
		return deny("unsafe_policy", "IPC directory must be broker-owned and not writable by others")
	}
	if _, err = os.Lstat(p.ListenSocket); !os.IsNotExist(err) {
		return deny("unsafe_policy", "IPC socket path already exists")
	}
	listener, err := net.Listen("unix", p.ListenSocket)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(p.ListenSocket)
	mode := os.FileMode(0666)
	if p.DevelopmentAllowSameUID {
		mode = 0600
	}
	if err = os.Chmod(p.ListenSocket, mode); err != nil {
		return err
	}
	b := newBroker(p, digest)
	requests, cancelRequests := context.WithCancel(context.Background())
	defer cancelRequests()
	server := &http.Server{Handler: b, BaseContext: func(net.Listener) context.Context { return requests }, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 100 * time.Second, IdleTimeout: 2 * time.Second, MaxHeaderBytes: 4096, ConnContext: func(ctx context.Context, c net.Conn) context.Context {
		underlying := c
		if limited, ok := c.(*limitedConnection); ok {
			underlying = limited.Conn
		}
		uid, err := peerUID(underlying)
		return context.WithValue(ctx, peerKey{}, peer{uid, err})
	}}
	stop := context.AfterFunc(ctx, func() { b.beginDrain(); cancelRequests(); server.Close() })
	defer stop()
	fmt.Println("ready")
	err = server.Serve(&limitedListener{Listener: listener, slots: make(chan struct{}, 16)})
	b.beginDrain()
	cancelRequests()
	server.Close()
	drain, cancelDrain := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancelDrain()
	if cleanupErr := b.waitHandlers(drain); cleanupErr != nil {
		return cleanupErr
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
