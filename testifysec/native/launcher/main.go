// Command launcher starts the compiled Bun component with a fixed environment.
// The installation and loader environment remain the deployment's responsibility.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

var runtimeName string
var runtimeDigest string
var helpBase64 string
var versionBase64 string

func main() {
	if err := launch(); err != nil {
		fmt.Fprintln(os.Stderr, "native verification unavailable")
		os.Exit(2)
	}
}

func launch() error {
	// Only the customer launcher embeds informational text. These exact flags
	// return before locating/loading the runtime; internal verifiers stay stdin-only.
	if len(os.Args) == 2 {
		text := ""
		switch os.Args[1] {
		case "--help":
			text = helpBase64
		case "--version":
			text = versionBase64
		}
		if text != "" {
			data, err := base64.StdEncoding.DecodeString(text)
			if err != nil {
				return err
			}
			_, err = os.Stdout.Write(data)
			return err
		}
	}
	// Execution CLIs accept only stdin; never forward Bun runtime flags.
	if len(os.Args) != 1 || filepath.Base(runtimeName) != runtimeName || runtimeName == "" {
		return fmt.Errorf("invalid invocation")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return err
	}
	path := filepath.Join(filepath.Dir(executable), runtimeName)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("invalid runtime")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != runtimeDigest {
		return fmt.Errorf("runtime digest mismatch")
	}
	// BUN_OPTIONS/preload, NODE_OPTIONS, dynamic-loader and inherited credentials
	// must not reach Bun initialization. No agent-provided variable is forwarded.
	return syscall.Exec(path, []string{path}, []string{"PATH=/usr/bin:/bin", "LANG=C", "TMPDIR=/tmp"})
}
