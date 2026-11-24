package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	platformsession "github.com/aflock-ai/badger/testifysec/platform"
)

func main() {
	path := flag.String("config", "", "private administrator-provisioned configuration")
	flag.Parse()
	if *path == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: hardened-session-check --config /protected/config.json")
		os.Exit(2)
	}
	config, err := platformsession.LoadConfig(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid session configuration")
		os.Exit(2)
	}
	client, err := platformsession.New(config)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer client.Close()
	identity, err := client.Check(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(identity)
}
