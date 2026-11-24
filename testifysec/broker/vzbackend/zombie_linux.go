//go:build linux

package vzbackend

// Linux signals zombies and exiting processes without EPERM, so on Linux EPERM always means a live member this user
// may not signal.
func zombieGroup(int) bool { return false }
