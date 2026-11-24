//go:build !unix

package launch

import "net"

// Off unix there is no plugin host: unix sockets, descriptor passing and core limits are missing,
// and plugins cannot be sandboxed (CheckSandbox). Every entry point refuses, so plughost exits
// before anything runs.

// CheckCores refuses: see CheckSandbox.
func CheckCores() error { return CheckSandbox() }

// Listen refuses: see CheckSandbox.
func Listen(string) (net.Listener, error) { return nil, CheckSandbox() }

// Serve refuses: see CheckSandbox.
func Serve(net.Listener, string, int, int) error { return CheckSandbox() }

// ServeVendor refuses: see CheckSandbox.
func ServeVendor(net.Listener, string, string, int, int) error { return CheckSandbox() }

// CheckVendorMount refuses: see CheckSandbox.
func CheckVendorMount(string) error { return CheckSandbox() }
