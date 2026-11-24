//go:build !linux

package main

// protectMemory relies on the platform elsewhere: on macOS a hardened-runtime binary without the
// get-task-allow entitlement already refuses task_for_pid from other processes of the same user.
func protectMemory() error { return nil }
