//go:build darwin || linux

// jade:ring local
package vzsession

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This subprocess fixture uses the exact fixed production argv and process
// supervisor. It runs only in the test binary; no production injection hook.
func TestMain(m *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == "--config" {
		var config struct {
			Mode string `json:"mode"`
		}
		raw, err := os.ReadFile(os.Args[2])
		if err != nil || json.Unmarshal(raw, &config) != nil {
			os.Exit(2)
		}
		if config.Mode == "early-exit" {
			os.Exit(3)
		}
		if config.Mode == "token" {
			// Report what the gateway received: the token on descriptor 3, and its argv and environment.
			line := make([]byte, 128)
			n, _ := os.NewFile(3, "token").Read(line)
			// Outside the owned session directory, whose inventory must stay exact.
			dir := filepath.Dir(filepath.Dir(os.Args[2]))
			_ = os.WriteFile(filepath.Join(dir, "received"), line[:n], 0600)
			_ = os.WriteFile(filepath.Join(dir, "environ"), []byte(strings.Join(append(os.Args, os.Environ()...), "\n")), 0600)
		}
		signals := make(chan os.Signal, 1)
		if config.Mode == "ignore-signal" {
			signal.Ignore(syscall.SIGTERM)
		} else {
			signal.Notify(signals, syscall.SIGTERM)
		}
		listener, err := net.Listen("unix", filepath.Join(filepath.Dir(os.Args[2]), "gateway.sock"))
		if err != nil {
			os.Exit(4)
		}
		defer listener.Close()
		if config.Mode == "overflow" {
			_, _ = os.Stdout.Write(make([]byte, 16385))
		}
		if config.Mode == "ignore-signal" {
			for {
				time.Sleep(time.Second)
			}
		}
		<-signals
		_ = listener.Close()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func fixtureGateway(t *testing.T, mode string) (*child, *ownedDirectory) {
	t.Helper()
	// Keep Unix-socket names below the platform limit even when Go's parent
	// test name and TMPDIR are long. Cleanup belongs only to this fixture.
	base := os.TempDir()
	if runtime.GOOS == "darwin" {
		base = "/private/tmp"
	}
	parent, err := os.MkdirTemp(base, "avs-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
	d, err := newDirectory(parent, "s")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.close() })
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.write("gateway", raw, 0700); err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(map[string]string{"mode": mode})
	if err = d.write("gateway.json", raw, 0400); err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	if _, err = w.WriteString(fixtureToken + "\n"); err != nil {
		t.Fatal(err)
	}
	c, err := startGateway(context.Background(), d, r)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.stop() })
	return c, d
}

const fixtureToken = "bbt_Zml4dHVyZS10b2tlbi1maXh0dXJlLXRva2VuLWZpeHR1cmU"

// The gateway gets its provider token on descriptor 3 and nowhere else: not in argv, not in the
// environment.
func TestGatewayGetsTheTokenOnItsDescriptorOnly(t *testing.T) {
	c, d := fixtureGateway(t, "token")
	if err := c.ready(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	reports := filepath.Dir(d.path)
	got, err := os.ReadFile(filepath.Join(reports, "received"))
	if err != nil || string(got) != fixtureToken+"\n" {
		t.Fatalf("gateway received %q (%v)", got, err)
	}
	env, err := os.ReadFile(filepath.Join(reports, "environ"))
	if err != nil || strings.Contains(string(env), "bbt_") || !strings.Contains(string(env), "--config") {
		t.Fatalf("argv/environment: %q (%v)", env, err)
	}
	if !c.stop() {
		t.Fatal("gateway did not stop")
	}
}

func TestGatewayActualProcessDrainsAndStops(t *testing.T) {
	c, d := fixtureGateway(t, "normal")
	if err := c.ready(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if !c.stop() {
		t.Fatal("graceful process did not produce exit, EOF and absent group")
	}
	if !c.stop() {
		t.Fatal("stop was not idempotent")
	}
	if err := d.remove(); err != nil {
		t.Fatal(err)
	}
}

func TestGatewayFailureCannotCountAsCleanSuccess(t *testing.T) {
	for _, mode := range []string{"early-exit", "overflow", "ignore-signal"} {
		t.Run(mode, func(t *testing.T) {
			c, d := fixtureGateway(t, mode)
			err := c.ready(context.Background(), d)
			if mode == "early-exit" && err == nil {
				t.Fatal("dead gateway became ready")
			}
			if mode != "early-exit" && err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			if c.stop() {
				t.Fatal("failed gateway became successful cleanup")
			}
			if time.Since(started) > 11*time.Second {
				t.Fatal("gateway stop exceeded bound")
			}
			if !groupAbsent(c.cmd.Process.Pid) {
				t.Fatal("fixture process group remains")
			}
		})
	}
}

func TestSnapshotFIFORefusedWithoutBlocking(t *testing.T) {
	dir := privateTestDir(t)
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := snapshot(context.Background(), dir); err == nil {
		t.Fatal("FIFO accepted")
	}
	if time.Since(start) > time.Second {
		t.Fatal("FIFO blocked snapshot")
	}
}
