package vzbackend

import (
	"os"
	"syscall"
)

func fileIdentity(info os.FileInfo) (int64, uint64, syscall.Timespec, bool) {
	if info == nil {
		return 0, 0, syscall.Timespec{}, false
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, syscall.Timespec{}, false
	}
	return int64(s.Uid), uint64(s.Nlink), s.Ctimespec, true
}
func readFlags() int { return os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK }
