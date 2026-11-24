package profile

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The URLs admission's WHATWG parser reads as written are signed; the issue package's tests cover
// the refusals.
func TestBaseURLAccepts(t *testing.T) {
	for _, u := range []string{"https://jira.example.invalid", "HTTPS://Jira.Example.Invalid/", "https://conngw.example.invalid:8443/connectors/gitlab",
		"https://192.0.2.10:443/api", "https://[2001:db8::1]:8443/connectors/jira", "https://host-1.example.invalid:"} {
		if err := baseURL(u); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
}

// Hosts Go's parser accepts and a WHATWG parser refuses (bracketed non-IPv6; punycode, which it
// decodes and may find invalid), checked here directly so they hold whatever the toolchain accepts.
func TestBaseURLRefusesWhatWHATWGWould(t *testing.T) {
	for _, u := range []string{"https://[jira.example.invalid]", "https://[192.0.2.10]:443", "https://[::ffff:c000:20a]", "https://[2001:db8::1%25en0]",
		"https://xn--a.example", "https://a.XN--a.example"} {
		if baseURL(u) == nil {
			t.Errorf("%s accepted", u)
		}
	}
}

// The connector pod's naming rules, shared with cmd/conngw and admission v3 through one corpus: a
// plugin outside the catalog is signed under any name the pod accepts, with any flag it would pass.
func TestPluginNamingCorpus(t *testing.T) {
	raw, err := os.ReadFile("../../../connectors/cmd/conngw/testdata/connector-names.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Names, Flags struct{ Accept, Refuse []string }
	}
	if err := json.Unmarshal(raw, &corpus); err != nil || len(corpus.Names.Accept) == 0 || len(corpus.Flags.Refuse) == 0 {
		t.Fatal("corpus unreadable or empty", err)
	}
	p := func(c Connector) V3 {
		return V3{SchemaVersion: 3, ProfileID: "p", TenantID: "t", DeploymentID: "d", Sequence: 1, NotBefore: "2026-01-01T00:00:00Z",
			ExpiresAt: "2026-01-02T00:00:00Z", Controls: Fixed, Gateway: Gateway{Classification: "SECRET"}, Connectors: []Connector{c}}
	}
	plugin := Connector{Name: "servicenow-1", BinarySHA256: strings.Repeat("a", 64), BaseURL: "https://conngw.example.invalid:8443/connectors/servicenow-1",
		TokenPath: "/var/run/secrets/tokens/workspace", Classification: "CONFIDENTIAL", Flags: map[string]string{"region": "us-1"},
		Permissions: map[string]string{"servicenow-1_*": "ask", "servicenow-1_search_records": "allow"}}
	if err := p(plugin).Validate(); err != nil {
		t.Fatal("plugin refused:", err)
	}
	for _, n := range corpus.Names.Accept {
		c := plugin
		c.Name, c.Flags, c.Permissions = n, map[string]string{}, map[string]string{n + "_*": "allow"}
		if err := p(c).Validate(); err != nil {
			t.Errorf("name %q refused: %v", n, err)
		}
	}
	for _, n := range corpus.Names.Refuse {
		c := plugin
		c.Name, c.Flags, c.Permissions = n, map[string]string{}, map[string]string{}
		if p(c).Validate() == nil {
			t.Errorf("name %q accepted", n)
		}
	}
	for _, f := range corpus.Flags.Accept {
		c := plugin
		c.Flags = map[string]string{f: "x"}
		if err := p(c).Validate(); err != nil {
			t.Errorf("flag %q refused: %v", f, err)
		}
	}
	for _, f := range append(corpus.Flags.Refuse, "notice") {
		c := plugin
		c.Flags = map[string]string{f: "x"}
		if p(c).Validate() == nil {
			t.Errorf("flag %q accepted", f)
		}
	}
	// Every other entry check still holds for a plugin, and a catalog connector keeps its own flags.
	for name, edit := range map[string]func(*Connector){
		"pin":             func(c *Connector) { c.BinarySHA256 = "a" },
		"url":             func(c *Connector) { c.BaseURL = "http://conngw.example.invalid" },
		"path":            func(c *Connector) { c.TokenPath = "relative" },
		"marking":         func(c *Connector) { c.Classification = "SECRETISH" },
		"above-gateway":   func(c *Connector) { c.Classification = "TOP SECRET" },
		"flag-value":      func(c *Connector) { c.Flags = map[string]string{"region": "--enable-writes"} },
		"foreign-perm":    func(c *Connector) { c.Permissions = map[string]string{"jira_*": "allow"} },
		"perm-grammar":    func(c *Connector) { c.Permissions = map[string]string{"servicenow-1_X": "allow"} },
		"perm-star":       func(c *Connector) { c.Permissions = map[string]string{"servicenow-1_*_x": "allow"} },
		"perm-effect":     func(c *Connector) { c.Permissions = map[string]string{"servicenow-1_a": "always"} },
		"catalog-flags":   func(c *Connector) { c.Name, c.Permissions = "jira", map[string]string{} },
		"flags-missing":   func(c *Connector) { c.Flags = nil },
		"notice-grammar":  func(c *Connector) { n := "<b>"; c.Notice = &n },
		"permissions-nil": func(c *Connector) { c.Permissions = nil },
	} {
		c := plugin
		edit(&c)
		if p(c).Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	twice := p(plugin)
	twice.Connectors = append(twice.Connectors, plugin)
	if twice.Validate() == nil {
		t.Error("repeated plugin accepted")
	}
}
