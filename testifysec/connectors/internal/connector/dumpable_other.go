//go:build !linux

package connector

// noCoreDumps is Linux-only; elsewhere connectors run outside the plugin host.
var noCoreDumps = func() error { return nil }
