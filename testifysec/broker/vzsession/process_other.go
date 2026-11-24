//go:build !darwin && !linux

package vzsession

import (
	"context"
	"os"
)

type child struct{}

func startGateway(context.Context, *ownedDirectory, *os.File) (*child, error) {
	return nil, refused("unsupported_platform")
}
func (*child) ready(context.Context, *ownedDirectory) error { return refused("unsupported_platform") }
func (*child) stop() bool                                   { return false }
