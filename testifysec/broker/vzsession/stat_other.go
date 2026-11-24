//go:build !darwin && !linux

package vzsession

import "os"

func fileIdentity(os.FileInfo) (int64, uint64, int64, bool) { return 0, 0, 0, false }
func readFlags() int                                        { return os.O_RDONLY }
