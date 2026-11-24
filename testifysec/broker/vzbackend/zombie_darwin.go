//go:build darwin

package vzbackend

import "golang.org/x/sys/unix"

// From xnu sys/proc.h: p_stat for an exited, unreaped process, and the p_flag set once a
// process has begun exiting. Neither can run user code again.
const (
	szomb  = 5
	pWexit = 0x2000
)

func zombieGroup(group int) bool {
	members, err := unix.SysctlKinfoProcSlice("kern.proc.pgrp", group)
	if err != nil {
		return false
	}
	// No members left: the group is already gone and the next probe reports ESRCH.
	for _, member := range members {
		if member.Proc.P_stat != szomb && member.Proc.P_flag&pWexit == 0 {
			return false
		}
	}
	return true
}
