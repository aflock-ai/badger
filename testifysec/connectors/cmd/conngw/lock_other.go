//go:build !unix

package main

import (
	"errors"
	"os"
)

// lockFile is unsupported here: conngw runs only on unix, where the labels file can be locked.
func lockFile(*os.File) error { return errors.New("labels file locking needs a unix system") }
