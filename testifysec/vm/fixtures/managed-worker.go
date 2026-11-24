// jade:ring local
// A test-only Linux worker/toolpack utility. It never ships as the product worker.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

func main() {
	if os.Getuid() != 65534 {
		os.Exit(91)
	}
	mode := ""
	if len(os.Args) == 2 {
		mode = os.Args[1]
	} else {
		var request struct {
			Prompt string `json:"prompt"`
		}
		if json.NewDecoder(os.Stdin).Decode(&request) != nil {
			os.Exit(92)
		}
		mode = request.Prompt
	}
	if mode == "child" {
		time.Sleep(time.Minute)
		return
	}
	if mode == "nonzero-descendant" {
		child := exec.Command(os.Args[0], "child")
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if child.Start() != nil {
			os.Exit(93)
		}
		fmt.Println("DESCENDANT_STARTED")
		os.Exit(7)
	}
	switch mode {
	case "edit":
		must(os.MkdirAll("nested/a&b", 0755))
		must(os.WriteFile("nested/a&b/result.bin", []byte{0, 255, 128, 10}, 0600))
		must(os.WriteFile("nested/run.sh", []byte("#!/bin/sh\nexit 0\n"), 0700))
		must(os.Chmod("nested/run.sh", 0700))
		must(os.Remove("delete.txt"))
		must(os.WriteFile("keep.txt", []byte("changed\n"), 0600))
		_, _ = os.Stdout.Write([]byte{255, 0, 128})
		_, _ = os.Stderr.Write([]byte("stderr-tail\n"))
	case "symlink":
		must(os.Symlink("/init", "link"))
	case "hardlink":
		must(os.Link("keep.txt", "alias"))
	case "special":
		must(syscall.Mkfifo("fifo", 0600))
	case "case-collision":
		must(os.Mkdir("A", 0755))
		must(os.Mkdir("a", 0755))
	case "git":
		must(os.Mkdir(".GiT", 0755))
	case "overflow":
		must(os.WriteFile("huge", make([]byte, 65537), 0600))
	case "wide":
		for i := 0; i < 257; i++ {
			must(os.Mkdir(fmt.Sprintf("d%03d", i), 0755))
		}
	case "output-overflow":
		fmt.Print(strings.Repeat("x", 65537))
	case "timeout":
		time.Sleep(time.Minute)
	case "no-marker":
		fmt.Println("ordinary successful output")
	default:
		os.Exit(94)
	}
}
func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "fixture operation failed")
		os.Exit(95)
	}
}
