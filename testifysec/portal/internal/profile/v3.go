package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/aflock-ai/badger/testifysec/connectors/marking"
)

// PayloadTypeV3 is the DSSE payload type admission v3 requires (testifysec/managed/profile-v3.ts).
const PayloadTypeV3 = "application/vnd.testifysec.hardened-opencode.profile.v3+json"

// Gateway is the marking the model gateway is accredited for.
type Gateway struct {
	Classification string `json:"classification"`
}

// Connector is one admitted connector, field for field as profile-v3.ts and gateway v3 read it.
// CAPath is always encoded (null when unset); Notice is left out when unset, never null.
type Connector struct {
	Name           string            `json:"name"`
	BinarySHA256   string            `json:"binarySha256"`
	BaseURL        string            `json:"baseUrl"`
	TokenPath      string            `json:"tokenPath"`
	CAPath         *string           `json:"caPath"`
	Writes         bool              `json:"writes"`
	Classification string            `json:"classification"`
	Notice         *string           `json:"notice,omitempty"`
	Flags          map[string]string `json:"flags"`
	Permissions    map[string]string `json:"permissions"`
}

// V3 is the signed v3 payload: the v1 fields, then gateway and connectors.
type V3 struct {
	SchemaVersion int         `json:"schemaVersion"`
	ProfileID     string      `json:"profileId"`
	TenantID      string      `json:"tenantId"`
	DeploymentID  string      `json:"deploymentId"`
	Sequence      uint64      `json:"sequence"`
	NotBefore     string      `json:"notBefore"`
	ExpiresAt     string      `json:"expiresAt"`
	Controls      Controls    `json:"controls"`
	Gateway       Gateway     `json:"gateway"`
	Connectors    []Connector `json:"connectors"`
}

// Catalog is profile-v3.ts catalog: the connectors a release ships, and for each the flags it
// accepts beyond the shared ones, with the fixed values a flag is limited to (nil: any value). A
// catalog connector takes only these flags; any other name is a plugin (below).
var Catalog = map[string]map[string][]string{
	"jira":       {"marking-field": nil, "marking-label-prefix": nil},
	"confluence": {"label-prefix": nil},
	"gitlab":     {"auth": {"private-token", "bearer"}, "marking-prefix": nil},
}

// A connector outside the Catalog is a plugin served by the connector pod (cmd/conngw), signed under
// any name the pod accepts for a connector (its name rule), with flags the pod would pass to the
// plugin (internal/launch FlagName, not Reserved) other than notice, which the managed command line
// sets itself. connectors/cmd/conngw/testdata/connector-names.json is the corpus the pod, admission
// v3 and this package all test.
var (
	pluginName    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	pluginFlag    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	reservedFlags = map[string]bool{"base-url": true, "token-file": true, "classification": true, "ca-file": true,
		"enable-writes": true, "insecure-loopback-http": true, "manifest": true, "notice": true}
)

// MaxConnectors is admission's bound on the connectors array.
const MaxConnectors = 16

var (
	pin            = regexp.MustCompile(`^[0-9a-f]{64}$`)
	flagValue      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.:/-]{0,127}$`)
	permissionTool = regexp.MustCompile(`^[a-z0-9_]*\*?$`) // after "<connector>_"
	noticeText     = regexp.MustCompile(`^[A-Za-z0-9 .,;:()'/-]{1,160}$`)
	// A DNS name in plain ASCII: nothing a WHATWG parser would rewrite or refuse (IDN, escapes).
	dnsName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$`)
	// A last label a WHATWG parser reads as a number, which makes the whole host an IPv4 address.
	numeric = regexp.MustCompile(`(?i)(^|\.)(0x[0-9a-f]*|[0-9]+)$`)
)

// Validate applies every rule admission v3 applies to the payload alone, plus the gateway ceiling
// that admission's consumers (managed-connectors.ts, gateway v3) apply: no connector marked above
// the gateway. Assignment, rollback floor and the current time are the caller's, as for v1.
func (p V3) Validate() error {
	if p.SchemaVersion != 3 {
		return errors.New("schemaVersion must be 3")
	}
	common := V1{SchemaVersion: 1, ProfileID: p.ProfileID, TenantID: p.TenantID, DeploymentID: p.DeploymentID,
		Sequence: p.Sequence, NotBefore: p.NotBefore, ExpiresAt: p.ExpiresAt, Controls: p.Controls}
	if err := common.Validate(); err != nil {
		return err
	}
	accredited, err := marking.Parse(p.Gateway.Classification)
	if err != nil {
		return errors.New("gateway classification is not a marking")
	}
	if p.Connectors == nil || len(p.Connectors) > MaxConnectors {
		return fmt.Errorf("connectors must be a list of at most %d", MaxConnectors)
	}
	seen := map[string]bool{}
	for _, c := range p.Connectors {
		if err := c.validate(accredited); err != nil {
			return fmt.Errorf("connector %q: %w", c.Name, err)
		}
		if seen[c.Name] {
			return fmt.Errorf("connector %q is listed twice", c.Name)
		}
		seen[c.Name] = true
	}
	return nil
}

func (c Connector) validate(accredited marking.Marking) error {
	if !pluginName.MatchString(c.Name) {
		return errors.New("not a connector name: a lowercase letter, then up to 31 lowercase letters, digits or hyphens")
	}
	flags, listed := Catalog[c.Name]
	if !pin.MatchString(c.BinarySHA256) {
		return errors.New("binarySha256 must be 64 lowercase hex")
	}
	if err := baseURL(c.BaseURL); err != nil {
		return err
	}
	if !absolute(c.TokenPath) || (c.CAPath != nil && !absolute(*c.CAPath)) {
		return errors.New("tokenPath and caPath must be absolute paths with no relative segment")
	}
	m, err := marking.Parse(c.Classification)
	if err != nil {
		return errors.New("classification is not a marking")
	}
	if !marking.Dominates(accredited, m) {
		return errors.New("marked above the gateway's accreditation")
	}
	if c.Notice != nil && !noticeText.MatchString(*c.Notice) {
		return errors.New("notice must be one line of plain text, 1 to 160 characters")
	}
	if c.Flags == nil || c.Permissions == nil {
		return errors.New("flags and permissions are required ({} for none)")
	}
	for flag, value := range c.Flags {
		values, known := flags[flag]
		if !listed {
			known = pluginFlag.MatchString(flag) && !reservedFlags[flag]
		}
		if !known || !flagValue.MatchString(value) || (values != nil && !contains(values, value)) {
			return fmt.Errorf("flag %q is not one this connector accepts with that value", flag)
		}
	}
	for tool, effect := range c.Permissions {
		if !strings.HasPrefix(tool, c.Name+"_") || len(tool) > 128 || !permissionTool.MatchString(tool[len(c.Name)+1:]) ||
			(effect != "allow" && effect != "ask" && effect != "deny") {
			return fmt.Errorf("permission %q must name this connector's tools and be allow, ask or deny", tool)
		}
	}
	return nil
}

func contains(values []string, v string) bool {
	for _, x := range values {
		if x == v {
			return true
		}
	}
	return false
}

// absolute is profile-v3.ts absolute(): at most 1024 bytes, rooted, no trailing slash, control
// character, backslash, or empty, "." or ".." segment.
func absolute(s string) bool {
	if len(s) > 1024 || !strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") || strings.ContainsAny(s, "\\\x7f") {
		return false
	}
	for _, r := range s {
		if r < 0x20 {
			return false
		}
	}
	for _, part := range strings.Split(s, "/")[1:] {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

// baseURL is profile-v3.ts baseURL(), stricter where Go's parser and a WHATWG parser could read
// a URL differently: an https URL with a plain host, an optional port, and no credentials, query
// or fragment.
func baseURL(s string) error {
	bad := errors.New("baseUrl must be an https URL with a host and no credentials, query or fragment")
	if len(s) > 2048 || strings.ContainsAny(s, "?#\\") {
		return bad
	}
	for _, r := range s {
		if r <= 0x20 || r >= 0x7f {
			return bad
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || !strings.HasPrefix(s[len("https:"):], "//") {
		return bad
	}
	if authority, _, _ := strings.Cut(s[len("https://"):], "/"); strings.Contains(authority, "%") {
		return bad // an escaped host or port: both parsers decode it, but nothing should need to
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	// Hostname drops the brackets, so whether the host was bracketed is read from u.Host: brackets
	// hold an IPv6 literal and nothing else, which is all a WHATWG parser accepts in them.
	switch bracketed := strings.HasPrefix(u.Host, "["); {
	case bracketed || strings.Contains(host, ":"):
		if !bracketed || ip == nil || ip.To4() != nil {
			return bad
		}
	case numeric.MatchString(host): // only a plain dotted-quad IPv4 address
		if ip == nil || strings.Count(host, ".") != 3 {
			return bad
		}
	case !dnsName.MatchString(host):
		return bad
	case strings.HasPrefix(strings.ToLower(host), "xn--") || strings.Contains(strings.ToLower(host), ".xn--"):
		return bad // a punycode label: a WHATWG parser decodes and may refuse it; Go cannot check it here
	}
	if port := u.Port(); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return bad
		}
	}
	return nil
}

// Payload returns the exact bytes to sign.
func (p V3) Payload() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(p)
}
