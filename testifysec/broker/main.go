package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: hardened-broker <serve|execute|uat>")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		flags := flag.NewFlagSet("serve", flag.ExitOnError)
		configuration := flags.String("config", "", "private administrative policy JSON")
		flags.Parse(os.Args[2:])
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		err = serve(ctx, *configuration)
	case "execute":
		flags := flag.NewFlagSet("execute", flag.ExitOnError)
		socket := flags.String("socket", "", "broker Unix socket")
		input := flags.String("request", "", "bounded request JSON file")
		flags.Parse(os.Args[2:])
		file, e := os.Open(*input)
		if e != nil {
			err = e
			break
		}
		raw, e := io.ReadAll(io.LimitReader(file, inputLimit+1))
		file.Close()
		if e != nil {
			err = e
			break
		}
		if len(raw) > inputLimit {
			err = deny("invalid_json", "Request exceeds limit")
			break
		}
		request, _ := http.NewRequest("POST", "http://broker/v1/execute", bytes.NewReader(raw))
		request.Header.Set("Content-Type", "application/json")
		response, e := unixClient(*socket).Do(request)
		if e != nil {
			err = e
			break
		}
		defer response.Body.Close()
		_, err = io.Copy(os.Stdout, io.LimitReader(response.Body, 8<<20))
		if err == nil && response.StatusCode != 200 {
			os.Exit(1)
		}
	case "uat":
		err = runUAT(os.Args[2:])
	case "peer-uat":
		err = peerUAT()
	case "artifact-socket-uat":
		err = artifactSocketUAT()
	default:
		err = fmt.Errorf("unknown command")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, string(marshal(failure(err))))
		os.Exit(1)
	}
}
