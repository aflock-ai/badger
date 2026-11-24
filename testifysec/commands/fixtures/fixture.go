// jade:ring local
// Synthetic native backend; never reads platform credentials or opens a browser.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "fixture-child" {
		time.Sleep(time.Minute)
		return
	}
	if len(os.Args) != 2 || (os.Args[1] != "enroll" && os.Args[1] != "attest") {
		os.Exit(2)
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 16385))
	if err != nil || len(raw) > 16384 {
		os.Exit(2)
	}
	var request map[string]any
	if json.Unmarshal(raw, &request) != nil {
		os.Exit(2)
	}
	directory, _ := request["stateDirectory"].(string)
	mode, _ := request["name"].(string)
	executable, _ := os.Executable()
	cwd, _ := os.Getwd()
	marker := map[string]any{"pid": os.Getpid(), "executable": executable, "cwd": cwd, "args": os.Args[1:], "environment": os.Environ()}
	writeMarker := func() {
		data, _ := json.Marshal(marker)
		if os.WriteFile(filepath.Join(directory, "started.json"), data, 0600) != nil {
			os.Exit(3)
		}
	}
	writeMarker()
	event := func(kind string) {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": "testifysec.hardened-code.command-event/v1", "event": kind, "trustMode": request["trustMode"], "identityReference": "synthetic-fixture"})
	}
	terminal := "enrolled"
	if os.Args[1] == "attest" {
		terminal = "attested"
	}
	switch mode {
	case "invalid-utf8":
		_, _ = os.Stdout.Write([]byte{255, 10})
		return
	case "duplicate":
		fmt.Println(`{"schema":"other","schema":"testifysec.hardened-code.command-event/v1","event":"enrolled"}`)
		return
	case "unknown-event":
		event("secret")
		return
	case "wrong-role":
		event("attested")
		return
	case "truncated":
		fmt.Print(`{"schema":"testifysec.hardened-code.command-event/v1","event":"enrolled"}`)
		return
	case "overflow":
		fmt.Print(strings.Repeat("x", 256*1024))
		return
	case "stderr":
		fmt.Fprint(os.Stderr, strings.Repeat("fixture-secret-must-never-print", 2048))
		time.Sleep(time.Second)
		return
	case "hang", "cancel", "signal":
		event("progress")
		time.Sleep(time.Minute)
		return
	case "nonzero":
		event("error")
		os.Exit(7)
	case "descendant":
		child := exec.Command(executable, "fixture-child")
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if child.Start() != nil {
			os.Exit(4)
		}
		marker["childPid"] = child.Process.Pid
		writeMarker()
	}
	event(terminal)
}
