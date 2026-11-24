//go:build !linux

package main

// hardenGateway is Linux-only; the gateway serves plugins only on Linux.
func hardenGateway() error { return nil }
