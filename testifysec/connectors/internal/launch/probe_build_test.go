//go:build linux

package launch

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

// probeCanary is the service token the probe is given; no hello's output may carry it.
const probeCanary = "conngw-test-token-7613470213-AbCdEf"

var (
	probeOnce sync.Once
	probePath string
	probeErr  error
)

// probeExe builds testdata/probe once and returns its path: a real Go plugin for the sandbox tests.
// A build failure fails the test: testdata/probe is its own module, so nothing else compiles it,
// and a skip would let every live sandbox test vanish while go test still passed.
func probeExe(t *testing.T) string {
	t.Helper()
	probeOnce.Do(func() {
		gobin := filepath.Join(runtime.GOROOT(), "bin", "go")
		if _, err := os.Stat(gobin); err != nil {
			probeErr = err
			return
		}
		dir, err := os.MkdirTemp(diskTmp, "probe")
		if err != nil {
			probeErr = err
			return
		}
		out := filepath.Join(dir, "probe")
		cmd := exec.Command(gobin, "build", "-o", out, ".")
		cmd.Dir = "testdata/probe"
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOPROXY=off", "GOWORK=off", "GOFLAGS=-mod=mod", "TMPDIR="+diskTmp)
		if b, err := cmd.CombinedOutput(); err != nil {
			probeErr = fmt.Errorf("%w: %s", err, b)
			return
		}
		probePath = out
		b, err := os.ReadFile(out)
		if err != nil {
			probeErr = err
			return
		}
		// Every hello the tests send names the probe's digest, as the profile names the plugin's.
		good.PluginDigest = fmt.Sprintf("sha256:%x", sha256.Sum256(b))
		// And the token file every hello names: the host reads it to refuse it in plugin output.
		tok := filepath.Join(dir, "token")
		if probeErr = os.WriteFile(tok, []byte(probeCanary+"\n"), 0o600); probeErr != nil {
			return
		}
		good.TokenPath = tok
	})
	if probeErr != nil {
		t.Fatalf("cannot build the probe: %v", probeErr)
	}
	return probePath
}
