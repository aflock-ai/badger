// Command vz-backend-check is a developer diagnostic, never a VM launcher.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aflock-ai/badger/testifysec/broker/vzbackend"
)

type result struct {
	Schema           string           `json:"schema"`
	Scope            string           `json:"scope"`
	Prepared         bool             `json:"prepared"`
	Cleaned          bool             `json:"cleaned"`
	ExecutionEnabled bool             `json:"executionEnabled"`
	Code             string           `json:"code,omitempty"`
	ManifestSHA256   string           `json:"manifestSha256,omitempty"`
	ProfileSHA256    string           `json:"profileSha256,omitempty"`
	Files            *vzbackend.Files `json:"files,omitempty"`
}

func check(ctx context.Context, args []string, input io.Reader) (vzbackend.Observation, error) {
	if len(args) != 2 || args[0] != "--assignment" {
		return vzbackend.Observation{}, errors.New("invalid arguments")
	}
	assignment, err := vzbackend.LoadAssignment(args[1])
	if err != nil {
		return vzbackend.Observation{}, err
	}
	envelope, err := io.ReadAll(io.LimitReader(input, vzbackend.EnvelopeLimit+1))
	if err != nil {
		return vzbackend.Observation{}, err
	}
	verifier, err := vzbackend.New(assignment)
	if err != nil {
		return vzbackend.Observation{}, err
	}
	prepared, err := verifier.Prepare(ctx, envelope)
	if err != nil {
		return vzbackend.Observation{}, err
	}
	observation, err := prepared.Inspect(ctx)
	err = errors.Join(err, prepared.Close())
	return observation, err
}
func run() int {
	interrupted, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(interrupted, 90*time.Second)
	defer cancel()
	observation, err := checkOwned(ctx, os.Args[1:], os.Stdin)
	output := result{Schema: "testifysec.aflock.vz-backend-check/v1", Scope: vzbackend.Scope}
	if err != nil {
		output.Code = vzbackend.Code(err)
	} else {
		output.Prepared = true
		output.Cleaned = true
		output.ManifestSHA256 = observation.ManifestSHA256
		output.ProfileSHA256 = observation.ProfileSHA256
		output.Files = &observation.Files
	}
	if json.NewEncoder(os.Stdout).Encode(output) != nil {
		return 1
	}
	if err != nil {
		return 1
	}
	return 0
}

func checkOwned(ctx context.Context, args []string, original *os.File) (vzbackend.Observation, error) {
	input, release, err := ownedInput(original)
	if err != nil {
		return vzbackend.Observation{}, err
	}
	finish := closeInputOnCancel(ctx, input)
	observation, err := check(ctx, args, input)
	finish()
	return observation, errors.Join(err, release())
}

func closeInputOnCancel(ctx context.Context, input *os.File) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = input.Close(); close(done) })
	return func() {
		if !stop() {
			<-done
		}
	}
}
func main() { os.Exit(run()) }
