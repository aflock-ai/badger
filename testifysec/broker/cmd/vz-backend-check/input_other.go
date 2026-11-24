//go:build !darwin && !linux

package main

import (
	"errors"
	"os"
)

func ownedInput(*os.File) (*os.File, func() error, error) {
	return nil, nil, errors.New("unsupported input platform")
}
