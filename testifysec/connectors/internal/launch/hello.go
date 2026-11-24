// Package launch is the protocol between the connector gateway (cmd/conngw) and a plugin's own
// container (cmd/plughost). Each plugin runs in a container of its own, as its own user, with only
// its own token mounted; the gateway reaches it over a unix socket on a volume the two share and
// nothing else mounts. Per stream the gateway connects, sends one hello line naming the plugin's
// settings from the administrator's signed profile, and then carries MCP over the connection,
// having made every label, grant and refusal check itself first. The host starts the plugin with
// exactly those settings, an empty environment and its stderr discarded.
package launch

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Hello is the first line of a stream: what the plugin is started with.
type Hello struct {
	Version        int               `json:"conngw"` // 1
	BaseURL        string            `json:"baseUrl"`
	TokenPath      string            `json:"tokenPath"` // in the plugin's container
	CAPath         string            `json:"caPath,omitempty"`
	Classification string            `json:"classification"`
	Writes         bool              `json:"writes"`
	Flags          map[string]string `json:"flags,omitempty"`
	// PluginDigest is the sha256 of the plugin executable the profile pins (and the plugin signer's
	// manifest names). The host runs nothing else.
	PluginDigest string `json:"pluginDigest"`
}

// pluginDigest is the form of Hello.PluginDigest (internal/bundle's digest form).
var pluginDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// FlagName is a plugin-specific flag's name.
var FlagName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// Reserved are the shared connector flags the hello's own fields set (internal/connector); a flag
// of the same name would override them, since the last occurrence wins.
var Reserved = map[string]bool{"base-url": true, "token-file": true, "classification": true, "ca-file": true,
	"enable-writes": true, "insecure-loopback-http": true, "manifest": true}

// Args is the plugin's command line for this hello, or why the hello is refused.
func (h Hello) Args(exe string) ([]string, error) {
	switch {
	case h.Version != 1:
		return nil, errors.New("hello: unknown version")
	case !pluginDigest.MatchString(h.PluginDigest):
		return nil, errors.New("hello: pluginDigest must be sha256:<hex>")
	case h.BaseURL == "" || h.Classification == "" || !filepath.IsAbs(h.TokenPath) || (h.CAPath != "" && !filepath.IsAbs(h.CAPath)):
		return nil, errors.New("hello: baseUrl, an absolute tokenPath and a classification are required, and caPath must be absolute")
	}
	args := []string{exe, "--base-url=" + h.BaseURL, "--token-file=" + h.TokenPath, "--classification=" + h.Classification}
	if h.CAPath != "" {
		args = append(args, "--ca-file="+h.CAPath)
	}
	if h.Writes {
		args = append(args, "--enable-writes")
	}
	keys := make([]string, 0, len(h.Flags))
	for k := range h.Flags {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		v := h.Flags[k]
		if !FlagName.MatchString(k) || Reserved[k] || strings.ContainsAny(v, "\x00\r\n") {
			return nil, fmt.Errorf("hello: flag %q is invalid", k)
		}
		args = append(args, "--"+k+"="+v)
	}
	return args, nil
}

// CheckUser refuses root: the host and every plugin it starts run as the container's own user.
func CheckUser(uid int) error {
	if uid == 0 {
		return errors.New("the plugin host must not run as root")
	}
	return nil
}
