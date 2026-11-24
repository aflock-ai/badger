package main

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/aflock-ai/badger/testifysec/broker/vzsession"
)

func main() {
	flags := flag.NewFlagSet("vz-session", flag.ContinueOnError)
	assignment := flags.String("assignment", "", "private administrator assignment file")
	request := flags.String("request", "", "private request file: workspaceId, prompt and timeout")
	if flags.Parse(os.Args[1:]) != nil || flags.NArg() != 0 || *assignment == "" || *request == "" {
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	result, err := vzsession.ExecuteFiles(ctx, *assignment, *request)
	if result.Schema == "" {
		result.Schema = vzsession.ResultSchema
		result.Qualification = "developer-only-unqualified"
	}
	if err != nil {
		result.Completed = false
		result.Code = vzsession.Code(err)
	}
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		os.Exit(1)
	}
	if err != nil {
		os.Exit(1)
	}
}
