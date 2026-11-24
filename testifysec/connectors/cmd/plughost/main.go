// Command plughost runs in a connector plugin's own container, as the plugin's own user, beside the
// plugin executable. It listens on a unix socket on a volume only the gateway's container shares
// and starts the plugin once per stream, with the settings the gateway's hello names from the
// administrator's signed profile (internal/launch), sandboxed so it cannot write the filesystem
// (Landlock). It refuses to run as root, where Landlock is not available, or where a core dump
// could carry a plugin's memory off the node (kernel.core_pattern).
//
//	plughost -socket /run/conngw/<connector>/plugin.sock -vendor /vendor -plugin /vendor/plugin -gateway-uid 65532 [-max 8]
//
// -vendor is the vendor image volume's mountPath: the plugin runs from plughost's verified copy and
// cannot read anything beneath it.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aflock-ai/badger/testifysec/connectors/internal/launch"
)

func main() {
	launch.Shim() // when started to run one plugin, this runs it sandboxed and never returns
	sock := flag.String("socket", "", "absolute path of the socket the gateway connects to")
	plugin := flag.String("plugin", "", "absolute path of the plugin executable, inside -vendor")
	vendor := flag.String("vendor", "", "the vendor image volume's mount point, hidden from the plugin")
	max := flag.Int("max", 8, "streams at once; more are closed at once")
	gateway := flag.Int("gateway-uid", 0, "the gateway's uid: the only user served")
	flag.Parse()
	if err := run(*sock, *plugin, *vendor, *max, *gateway); err != nil {
		fmt.Fprintln(os.Stderr, "plughost:", err)
		os.Exit(2)
	}
}

func run(sock, plugin, vendor string, max, gateway int) error {
	if err := launch.CheckUser(os.Geteuid()); err != nil {
		return err
	}
	if err := launch.CheckSandbox(); err != nil {
		return err
	}
	if err := launch.CheckCores(); err != nil {
		return err
	}
	if !filepath.IsAbs(sock) || !filepath.IsAbs(plugin) || !filepath.IsAbs(vendor) || max < 1 || gateway <= 0 || gateway == os.Geteuid() {
		return fmt.Errorf("-socket, -vendor and -plugin must be absolute, -max positive, and -gateway-uid the gateway's (not root, not this host's)")
	}
	if err := launch.CheckVendorMount(vendor); err != nil {
		return err
	}
	l, err := launch.Listen(sock)
	if err != nil {
		return err
	}
	return launch.ServeVendor(l, plugin, vendor, max, gateway)
}
