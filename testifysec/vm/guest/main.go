// A development-only PID1 for a disposable VM, not an admission authority.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type result struct {
	Managed      *managedResult    `json:"-"`
	Schema       string            `json:"schema"`
	Nonce        string            `json:"nonce"`
	JobSHA256    string            `json:"jobSha256"`
	Binding      binding           `json:"binding"`
	JobValidated bool              `json:"jobValidated"`
	Passed       bool              `json:"passed"`
	Error        string            `json:"error,omitempty"`
	PID          int               `json:"pid"`
	WorkerUID    uint32            `json:"workerUid"`
	RootReadonly bool              `json:"rootReadonly"`
	Interfaces   []string          `json:"interfaces"`
	Output       string            `json:"output"`
	Files        map[string][]byte `json:"files"`
}

// Neither a worker's output nor a filename is copied into the control channel.
// The complete bounded result is encoded as one JSON frame by PID1.
func emit(r result) {
	if r.Managed != nil {
		m := r.Managed
		m.Nonce = r.Nonce
		m.JobSHA256 = r.JobSHA256
		m.Binding = r.Binding
		m.JobValidated = r.JobValidated
		m.Passed = r.Passed
		m.Error = r.Error
		m.PID = r.PID
		m.WorkerUID = r.WorkerUID
		m.RootReadonly = r.RootReadonly
		b, e := json.Marshal(m)
		if e != nil || len(b) > managedResultLimit {
			m.Passed = false
			m.CaptureComplete = false
			m.Files = []managedFile{}
			m.Removed = []string{}
			m.FinalManifestSHA256 = ""
			m.Error = "managed-result-overflow"
			b, _ = json.Marshal(m)
		}
		fmt.Printf("\nHCVM3 %08x %s\n", len(b), b)
		return
	}
	b, err := json.Marshal(r)
	if err != nil || len(b) > 65536 {
		b = []byte(`{"schema":"testifysec.vm-result/v2","passed":false,"error":"result-overflow"}`)
	}
	fmt.Printf("\nHCVM1 %08x %s\n", len(b), b)
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "fixture-worker" {
		os.Exit(fixtureWorker(os.Args[2]))
	}
	if os.Getpid() != 1 {
		fmt.Fprintln(os.Stderr, "guest init requires PID1")
		os.Exit(2)
	}
	r := result{Schema: "testifysec.vm-result/v2", PID: os.Getpid(), WorkerUID: 65534, Files: map[string][]byte{}}
	if err := run(&r); err != nil {
		r.Error = err.Error()
	} else {
		r.Passed = true
	}
	emit(r)
	syscall.Sync()
	_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	for {
		time.Sleep(time.Second)
	}
}

func mount(source, target, kind, options string, flags uintptr) error {
	if err := os.MkdirAll(target, 0755); err != nil {
		return err
	}
	err := syscall.Mount(source, target, kind, flags, options)
	// CONFIG_DEVTMPFS_MOUNT may already have mounted /dev before PID1.
	if errors.Is(err, syscall.EBUSY) && target == "/dev" && kind == "devtmpfs" {
		b, readErr := os.ReadFile("/proc/mounts")
		if readErr != nil {
			return readErr
		}
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[1] == target && fields[2] == kind {
				return nil
			}
		}
	}
	return err
}

func run(r *result) error {
	for _, m := range []struct {
		source, target, kind, options string
		flags                         uintptr
	}{
		{"proc", "/proc", "proc", "", syscall.MS_NOSUID | syscall.MS_NOEXEC | syscall.MS_NODEV},
		{"sysfs", "/sys", "sysfs", "", syscall.MS_NOSUID | syscall.MS_NOEXEC | syscall.MS_NODEV | syscall.MS_RDONLY},
		{"devtmpfs", "/dev", "devtmpfs", "mode=0755", syscall.MS_NOSUID},
		{"tmpfs", "/tmp", "tmpfs", "size=268435456,mode=1777", syscall.MS_NOSUID | syscall.MS_NODEV},
		{"tmpfs", "/workspace", "tmpfs", "size=67108864,mode=0755", syscall.MS_NOSUID | syscall.MS_NODEV},
	} {
		if err := mount(m.source, m.target, m.kind, m.options, m.flags); err != nil {
			return fmt.Errorf("mount %s: %w", m.target, err)
		}
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs("/", &fs); err != nil {
		return err
	}
	r.RootReadonly = fs.Flags&1 != 0
	if !r.RootReadonly {
		return errors.New("root-is-writable")
	}
	j, err := readJob(r)
	if err != nil {
		return err
	}
	boot, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return err
	}
	var relay *guestRelay
	if strings.Contains(" "+strings.TrimSpace(string(boot))+" ", " hc.gateway=1 ") {
		relay, err = startGuestRelay(j, r.Nonce)
		if err != nil {
			return errors.New("guest-gateway-start")
		}
		defer relay.stop()
	}
	if err = installMaterials(j); err != nil {
		return err
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, item := range interfaces {
		r.Interfaces = append(r.Interfaces, item.Name)
		resolved, resolveErr := filepath.EvalSymlinks("/sys/class/net/" + item.Name)
		// Built-in bonding/dummy drivers can create dormant virtual interfaces
		// without any VZ NIC. Reject a hardware device or any active interface.
		if resolveErr != nil || !strings.HasPrefix(resolved, "/sys/devices/virtual/net/") || item.Flags&net.FlagUp != 0 {
			return errors.New("active-or-hardware-network-interface")
		}
	}
	if err = os.Chown("/workspace", 65534, 65534); err != nil {
		return err
	}
	if j.Schema == "testifysec.vm-job/v3" {
		return runManaged(j, r, relay)
	}
	duration := 5 * time.Second
	args := []string{"/init", "fixture-worker", j.Mode}
	if j.Mode == "timeout" {
		duration = 2 * time.Second
	}
	if j.Mode == "worker" {
		duration = 45 * time.Second
		args = []string{"/toolpack/opencode-worker"}
	}
	if j.Mode == "gateway" {
		duration = 35 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.WaitDelay = time.Second
	cmd.Cancel = func() error { return syscall.Kill(-1, syscall.SIGKILL) }
	cmd.Dir = "/workspace"
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/tmp/home", "TMPDIR=/tmp", "LANG=C.UTF-8"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}, Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if j.Mode == "worker" {
		raw, _ := json.Marshal(map[string]string{"schema": "testifysec.hardened-opencode.prompt/v1", "prompt": j.Prompt, "profileDigest": j.Binding.ProfileSHA256})
		cmd.Stdin = bytes.NewReader(raw)
	}
	if j.Mode == "gateway" {
		cmd.Stdin = strings.NewReader(j.Prompt)
	}
	output := &boundedOutput{limit: 32768, cancel: cancel}
	cmd.Stdout = output
	cmd.Stderr = output
	runErr := cmd.Run()
	// This VM has only PID1 and its workload. Kill every remaining userspace
	// process, including descendants that changed their process group, and reap.
	_ = syscall.Kill(-1, syscall.SIGKILL)
	for {
		_, e := syscall.Wait4(-1, nil, 0, nil)
		if errors.Is(e, syscall.ECHILD) {
			break
		}
		if e != nil && !errors.Is(e, syscall.EINTR) {
			return errors.New("guest-reap-failed")
		}
	}
	r.Output = output.String()
	if relay != nil {
		if err := relay.stop(); err != nil {
			return err
		}
		relay = nil
	}
	if output.overflow {
		return errors.New("worker-output-limit")
	}
	if ctx.Err() != nil {
		return errors.New("worker-deadline")
	}
	if errors.Is(runErr, exec.ErrWaitDelay) {
		return errors.New("worker-drain-deadline")
	}
	if runErr != nil {
		return errors.New("worker-failed")
	}
	if err := capture(r); err != nil {
		return err
	}
	expected := "vm-fixture-verified\n"
	if j.Mode == "worker" {
		expected = "hardened-worker-verified\n"
	}
	if string(r.Files["result.txt"]) != expected || !strings.Contains(r.Output, "HARNESS_TEST_PASSED") {
		return errors.New("artifact-or-test-mismatch")
	}
	return nil
}

func capture(r *result) error {
	root, err := os.OpenRoot("/workspace")
	if err != nil {
		return err
	}
	defer root.Close()
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	entries, err := directory.ReadDir(17)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(entries) > 16 {
		return errors.New("artifact-count-limit")
	}
	total := int64(0)
	for _, entry := range entries {
		name := entry.Name()
		if filepath.Base(name) != name || name == "." || name == ".." {
			return errors.New("invalid-artifact-path")
		}
		info, err := root.Lstat(name)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || !ok || stat.Nlink != 1 {
			return errors.New("nonregular-artifact")
		}
		total += info.Size()
		if info.Size() > 8192 || total > 16384 {
			return errors.New("artifact-size-limit")
		}
		b, err := root.ReadFile(name)
		if err != nil || int64(len(b)) != info.Size() {
			return errors.New("artifact-read-failed")
		}
		r.Files[name] = b
	}
	return nil
}

type boundedOutput struct {
	mu       sync.Mutex
	data     bytes.Buffer
	limit    int
	overflow bool
	cancel   context.CancelFunc
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	remaining := b.limit - b.data.Len()
	if n > remaining {
		b.overflow = true
		b.cancel()
		p = p[:remaining]
	}
	_, _ = b.data.Write(p)
	return n, nil
}
func (b *boundedOutput) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.data.String() }

func fixtureWorker(mode string) int {
	if os.Getuid() != 65534 || os.Getgid() != 65534 {
		return 3
	}
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})
	_ = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: 65536, Max: 65536})
	switch mode {
	case "gateway":
		return fixtureGateway()
	case "pipe-child":
		time.Sleep(time.Minute)
		return 4
	case "descendant":
		child := exec.Command("/init", "fixture-worker", "pipe-child")
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if child.Start() != nil {
			return 4
		}
		fmt.Println("DESCENDANT_STARTED")
		return 0
	case "timeout":
		time.Sleep(time.Minute)
		return 4
	case "overflow":
		fmt.Print(strings.Repeat("x", 65536))
		return 4
	case "symlink":
		if os.Symlink("/init", "/workspace/result.txt") != nil {
			return 4
		}
		return 0
	case "edit":
		if os.WriteFile("/workspace/result.txt", []byte("vm-fixture-verified\n"), 0600) != nil {
			return 4
		}
		b, e := os.ReadFile("/workspace/result.txt")
		if e != nil || string(b) != "vm-fixture-verified\n" {
			return 4
		}
		fmt.Println("WORKER_UID=65534 HARNESS_TEST_PASSED")
		return 0
	default:
		return 2
	}
}
