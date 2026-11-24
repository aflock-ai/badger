package main

import (
	"encoding/json"
	"io"
	"os"

	"github.com/aflock-ai/badger/testifysec/execution"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || (args[0] != "preflight" && args[0] != "inspect" && args[0] != "matrix") {
		io.WriteString(stderr, "usage: hardened-execution inspect|preflight|matrix; execution is not available\n")
		return 2
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if args[0] == "matrix" {
		if encoder.Encode(struct {
			Schema  string             `json:"schema"`
			Targets []execution.Target `json:"proposedTargets"`
		}{"testifysec.hardened-opencode.execution-targets/v1", execution.Targets()}) != nil {
			return 1
		}
		return 0
	}
	if encoder.Encode(execution.Preflight()) != nil {
		return 1
	}
	if args[0] == "preflight" && execution.RequireExecution() != nil {
		return 3
	}
	return 0
}
