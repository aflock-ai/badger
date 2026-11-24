package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

type engine struct {
	socket string
	client *http.Client
}

type engineHTTPError struct {
	status int
	reason *refusal
}

func (e *engineHTTPError) Error() string { return e.reason.Error() }
func (e *engineHTTPError) Unwrap() error { return e.reason }
func engineAbsent(err error) bool {
	var status *engineHTTPError
	return errors.As(err, &status) && status.status == http.StatusNotFound
}

func unixClient(socket string) *http.Client {
	return &http.Client{Transport: &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}, ResponseHeaderTimeout: 15 * time.Second, MaxConnsPerHost: 8}, Timeout: 0}
}
func newEngine(socket string) *engine { return &engine{socket, unixClient(socket)} }
func (e *engine) call(ctx context.Context, method, path string, body any, target any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(marshal(body))
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://docker/v1.47"+path, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := e.client.Do(request)
	if err != nil {
		return deny("engine_unavailable", "Local Docker API unavailable; no host fallback")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(raw) > 1<<20 {
		return deny("engine_unavailable", "Invalid Docker API response")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &engineHTTPError{response.StatusCode, &refusal{"engine_unavailable", fmt.Sprintf("Local Docker API refused operation (%d)", response.StatusCode)}}
	}
	if target != nil && json.Unmarshal(raw, target) != nil {
		return deny("engine_unavailable", "Malformed Docker response")
	}
	return nil
}

type imageInfo struct {
	ID           string `json:"Id"`
	OS           string `json:"Os"`
	Architecture string
	Config       struct {
		Env     []string
		Volumes map[string]json.RawMessage
	}
}

func (e *engine) preflight(ctx context.Context, image string) (map[string]any, error) {
	var info struct {
		OSType, ServerVersion, KernelVersion string
		SecurityOptions                      []string
	}
	if err := e.call(ctx, "GET", "/info", nil, &info); err != nil {
		return nil, err
	}
	var item imageInfo
	if err := e.call(ctx, "GET", "/images/"+url.PathEscape(image)+"/json", nil, &item); err != nil {
		return nil, err
	}
	seccomp := false
	for _, option := range info.SecurityOptions {
		if option == "name=seccomp,profile=builtin" {
			seccomp = true
		}
	}
	if info.OSType != "linux" || item.OS != "linux" || item.ID != image || !seccomp {
		return nil, deny("unsupported_runtime", "Exact Linux image and built-in seccomp are required")
	}
	if len(item.Config.Volumes) > 0 {
		return nil, deny("unapproved_image", "Image-declared volumes are prohibited")
	}
	var cleared []string
	if len(item.Config.Env) > 128 {
		return nil, deny("unapproved_image", "Image environment exceeds limit")
	}
	for _, variable := range item.Config.Env {
		key, _, _ := strings.Cut(variable, "=")
		if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(key) {
			return nil, deny("unapproved_image", "Invalid image environment key")
		}
		if key != "PATH" && key != "HOME" && key != "TMPDIR" && key != "LANG" {
			cleared = append(cleared, key)
		}
	}
	return map[string]any{"serverVersion": info.ServerVersion, "kernel": info.KernelVersion, "os": info.OSType, "architecture": item.Architecture, "image": item.ID, "securityOptions": info.SecurityOptions, "clearedImageEnvironment": cleared}, nil
}

type mount struct {
	Type        string
	Source      string
	Target      string
	ReadOnly    bool
	BindOptions *struct{ Propagation string } `json:",omitempty"`
}
type hostConfig struct {
	ReadonlyRootfs bool
	NetworkMode    string
	CapDrop        []string
	CapAdd         []string `json:",omitempty"`
	SecurityOpt    []string
	PidsLimit      int64
	Memory         int64
	MemorySwap     int64
	NanoCpus       int64
	IpcMode        string
	LogConfig      struct {
		Type   string
		Config map[string]string
	}
	Tmpfs   map[string]string
	Mounts  []mount
	Ulimits []struct {
		Name string
		Soft int64
		Hard int64
	}
	Privileged    bool
	PidMode       string
	Devices       []json.RawMessage
	RestartPolicy struct {
		Name              string
		MaximumRetryCount int
	}
}
type containerConfig struct {
	Image        string
	User         string
	Env          []string
	Cmd          []string
	Entrypoint   []string
	WorkingDir   string
	Labels       map[string]string
	AttachStdout bool
	AttachStderr bool
	Tty          bool
	OpenStdin    bool
	HostConfig   hostConfig
}

func configFor(p policy, inputs, requestDirectory, run, policyHash string) (containerConfig, error) {
	config := containerConfig{Image: p.Image, User: "65534:65534", Env: []string{"HOME=/tmp/home", "PATH=/usr/bin:/bin", "TMPDIR=/tmp", "LANG=C"}, Entrypoint: []string{"/bin/sh"}, WorkingDir: "/workspace", AttachStdout: true, AttachStderr: true, Labels: map[string]string{"io.testifysec.hardened.policy": policyHash}}
	host := &config.HostConfig
	host.ReadonlyRootfs = true
	host.NetworkMode = "none"
	host.CapDrop = []string{"ALL"}
	host.SecurityOpt = []string{"no-new-privileges=true"}
	host.PidsLimit = 64
	host.Memory = int64(p.Limits.MemoryMiB) << 20
	host.MemorySwap = host.Memory
	host.NanoCpus = 1_000_000_000
	host.IpcMode = "private"
	host.LogConfig.Type = "none"
	host.LogConfig.Config = map[string]string{}
	host.RestartPolicy.Name = "no"
	host.Tmpfs = map[string]string{"/tmp": "rw,noexec,nosuid,nodev,size=16m,mode=1777", "/workspace": fmt.Sprintf("rw,nosuid,nodev,size=%dm,mode=1777", p.Limits.WorkspaceMiB)}
	host.Ulimits = []struct {
		Name string
		Soft int64
		Hard int64
	}{{"nofile", 256, 256}, {"core", 0, 0}}
	bind := func(source, target string) {
		host.Mounts = append(host.Mounts, mount{Type: "bind", Source: source, Target: target, ReadOnly: true, BindOptions: &struct{ Propagation string }{"rprivate"}})
	}
	bind(inputs, "/inputs")
	bind(requestDirectory, "/request")
	if run != "" {
		bind(run, runMount)
	}
	if p.Toolpack != "" {
		root, err := secureRoot(p.Toolpack)
		if err != nil {
			return config, err
		}
		info, err := root.Stat(".")
		root.Close()
		if err != nil || !ownedPrivate(info, false) {
			return config, deny("unsafe_toolpack", "Toolpack must be broker-owned and not writable by others")
		}
		bind(p.Toolpack, "/toolpack")
	}
	if p.GatewaySocket != "" {
		info, err := os.Lstat(p.GatewaySocket)
		if err != nil || info.Mode()&os.ModeSocket == 0 {
			return config, deny("gateway_unavailable", "Approved gateway socket is unavailable")
		}
		bind(p.GatewaySocket, "/run/hardened-gateway/gateway.sock")
	}
	if p.GatewayVolume != "" {
		host.Mounts = append(host.Mounts, mount{Type: "volume", Source: p.GatewayVolume, Target: "/run/hardened-gateway", ReadOnly: true})
	}
	return config, nil
}

type inspected struct {
	ID         string `json:"Id"`
	Name       string
	Config     containerConfig
	HostConfig hostConfig
	Mounts     []struct {
		Type, Source, Destination, Name string
		RW                              bool
	}
	State struct {
		Running   bool
		Paused    bool
		ExitCode  int
		OOMKilled bool
		Error     string
	}
}

type execConfig struct {
	User         string
	WorkingDir   string
	AttachStdout bool
	AttachStderr bool
	Tty          bool
	Cmd          []string
}
type execInspection struct {
	ID          string `json:"ID"`
	ContainerID string
	Running     bool
	ExitCode    int
}

// A keeper keeps the tmpfs mounted after the requested process exits. Docker's
// exec inspection supplies its exit status; no worker-written marker is trusted.
func (e *engine) startExec(ctx context.Context, id string, config execConfig) (string, net.Conn, io.Reader, error) {
	var created struct {
		ID string `json:"Id"`
	}
	if err := e.call(ctx, "POST", "/containers/"+id+"/exec", config, &created); err != nil {
		return "", nil, nil, err
	}
	if !validID(created.ID) {
		return "", nil, nil, deny("engine_unavailable", "Invalid exec ID")
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", e.socket)
	if err != nil {
		return "", nil, nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		connection.SetDeadline(deadline)
	}
	request, err := http.NewRequest("POST", "http://docker/v1.47/exec/"+created.ID+"/start", bytes.NewReader([]byte(`{"Detach":false,"Tty":false}`)))
	if err != nil {
		connection.Close()
		return "", nil, nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "tcp")
	if err = request.Write(connection); err != nil {
		connection.Close()
		return "", nil, nil, err
	}
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		connection.Close()
		return "", nil, nil, err
	}
	if response.StatusCode == 101 {
		return created.ID, connection, reader, nil
	}
	if response.StatusCode == 200 {
		return created.ID, connection, response.Body, nil
	}
	response.Body.Close()
	connection.Close()
	return "", nil, nil, deny("engine_unavailable", "Docker refused attached exec")
}

func (e *engine) waitExec(ctx context.Context, id, container string) (int, error) {
	for {
		var actual execInspection
		if err := e.call(ctx, "GET", "/exec/"+id+"/json", nil, &actual); err != nil {
			return 0, err
		}
		if actual.ID != id || actual.ContainerID != container {
			return 0, deny("execution_failed", "Exec identity mismatch")
		}
		if !actual.Running {
			return actual.ExitCode, nil
		}
		select {
		case <-ctx.Done():
			return 0, deny("execution_timeout", "Requested process did not exit")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (e *engine) archive(ctx context.Context, id string) (io.ReadCloser, error) {
	request, err := http.NewRequestWithContext(ctx, "GET", "http://docker/v1.47/containers/"+id+"/archive?path=%2Fworkspace", nil)
	if err != nil {
		return nil, err
	}
	response, err := e.client.Do(request)
	if err != nil {
		return nil, deny("artifact_unavailable", "Docker archive unavailable")
	}
	if response.StatusCode != 200 {
		response.Body.Close()
		return nil, deny("artifact_unavailable", "Docker refused frozen workspace archive")
	}
	return response.Body, nil
}

func (e *engine) inspect(ctx context.Context, id string) (inspected, error) {
	var value inspected
	err := e.call(ctx, "GET", "/containers/"+id+"/json", nil, &value)
	return value, err
}
func verifyBoundary(actual inspected, expected containerConfig) error {
	a := actual.HostConfig
	b := expected.HostConfig
	if !a.ReadonlyRootfs || a.NetworkMode != "none" || len(a.CapDrop) != 1 || a.CapDrop[0] != "ALL" || len(a.CapAdd) > 0 || a.Privileged || a.PidMode != "" || len(a.Devices) > 0 || a.PidsLimit != 64 || a.Memory != b.Memory || a.MemorySwap != b.MemorySwap || a.NanoCpus != 1_000_000_000 || a.IpcMode != "private" || a.LogConfig.Type != "none" || actual.Config.User != "65534:65534" || string(marshal(a.Tmpfs)) != string(marshal(b.Tmpfs)) {
		return deny("boundary_mismatch", "Engine did not establish the required boundary")
	}
	found := false
	for _, option := range a.SecurityOpt {
		if option == "no-new-privileges=true" {
			found = true
		}
	}
	if !found || len(actual.Mounts) != len(b.Mounts) {
		return deny("boundary_mismatch", "Unexpected privileges or mounts")
	}
	for _, expectedMount := range b.Mounts {
		ok := false
		for _, observed := range actual.Mounts {
			source := observed.Source
			if observed.Type == "volume" {
				source = observed.Name
			}
			if source == expectedMount.Source && observed.Destination == expectedMount.Target && observed.Type == expectedMount.Type && observed.RW == !expectedMount.ReadOnly {
				ok = true
			}
		}
		if !ok {
			return deny("boundary_mismatch", "Unexpected writable or substituted mount")
		}
	}
	return nil
}

// Docker's archive API does not expose HostConfig.Tmpfs contents. A uniquely
// named local-driver tmpfs volume retains the same RAM/storage boundary and is
// mounted by the daemon's archive path as well as the isolated worker.
func (e *engine) createWorkspaceVolume(ctx context.Context, name, policyHash string, size int) error {
	options := map[string]string{"type": "tmpfs", "device": "tmpfs", "o": fmt.Sprintf("size=%dm,uid=65534,gid=65534,mode=0700,nosuid,nodev", size)}
	labels := map[string]string{"io.testifysec.hardened.policy": policyHash, "io.testifysec.hardened.workspace": name}
	var actual struct {
		Name, Driver, Scope string
		Options, Labels     map[string]string
	}
	if err := e.call(ctx, "POST", "/volumes/create", map[string]any{"Name": name, "Driver": "local", "DriverOpts": options, "Labels": labels}, &actual); err != nil {
		return err
	}
	if actual.Name != name || actual.Driver != "local" || actual.Scope != "local" || string(marshal(actual.Options)) != string(marshal(options)) || string(marshal(actual.Labels)) != string(marshal(labels)) {
		return deny("boundary_mismatch", "Workspace volume options or ownership mismatch")
	}
	return nil
}
func (e *engine) removeVolume(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return e.call(ctx, "DELETE", "/volumes/"+name, nil, nil)
}

// Attach before start so even a very short command cannot lose output. Docker's
// non-TTY stream carries eight-byte headers; cap each frame before allocation.
func (e *engine) attach(ctx context.Context, id string) (net.Conn, *bufio.Reader, error) {
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", e.socket)
	if err != nil {
		return nil, nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		connection.SetDeadline(deadline)
	}
	request, err := http.NewRequest("POST", "http://docker/v1.47/containers/"+id+"/attach?stream=1&stdout=1&stderr=1", nil)
	if err != nil {
		connection.Close()
		return nil, nil, err
	}
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "tcp")
	if err = request.Write(connection); err != nil {
		connection.Close()
		return nil, nil, err
	}
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		connection.Close()
		return nil, nil, err
	}
	if response.StatusCode != 101 {
		response.Body.Close()
		connection.Close()
		return nil, nil, deny("engine_unavailable", "Docker did not establish live output attachment")
	}
	return connection, reader, nil
}
func streamOutput(ctx context.Context, connection net.Conn, reader io.Reader, limit int) ([]byte, error) {
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	defer stop()
	var output bytes.Buffer
	for {
		var header [8]byte
		_, err := io.ReadFull(reader, header[:])
		if err == io.EOF {
			return output.Bytes(), nil
		}
		if err != nil {
			return nil, err
		}
		if (header[0] != 1 && header[0] != 2) || header[1] != 0 || header[2] != 0 || header[3] != 0 {
			return nil, deny("engine_unavailable", "Invalid Docker stream frame")
		}
		size := int64(binary.BigEndian.Uint32(header[4:]))
		if size > int64(limit-output.Len()) {
			return nil, deny("output_limit", "Execution exceeded captured-output limit")
		}
		if _, err = io.CopyN(&output, reader, size); err != nil {
			return nil, err
		}
	}
}
func (e *engine) remove(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return e.call(ctx, "DELETE", "/containers/"+id+"?force=1&v=1", nil, nil)
}
func validID(id string) bool { return regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(id) }
