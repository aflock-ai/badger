package main

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aflock-ai/badger/testifysec/connectors/internal/bundle"
)

// grant gives a connector to workspaces. A subject is "<namespace>/<account>" (one workspace) or
// "<namespace>/*" (every workspace in the namespace). Tools is the read allowlist: left out, every
// read tool in the signed manifest; empty, none. WriteTools are opt-in and need the connector's Writes.
type grant struct {
	Workspaces []string `json:"workspaces"`
	Tools      []string `json:"tools"`
	WriteTools []string `json:"writeTools"`
}

// permit is what one workspace may do with one connector: the tools it may call, from the signed
// manifest, and whether the plugin starts with writes.
type permit struct {
	tools  map[string]bundle.Tool
	writes bool
}

func (p *permit) allows(tool string) bool {
	if p == nil {
		return false
	}
	_, ok := p.tools[tool]
	return ok
}

// list is the tools/list answer the caller gets: the permitted tools as the manifest signs them.
func (p *permit) list() []map[string]any {
	out := []map[string]any{}
	if p == nil {
		return out
	}
	names := make([]string, 0, len(p.tools))
	for n := range p.tools {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		t := p.tools[n]
		out = append(out, map[string]any{"name": t.Name, "description": t.Description, "inputSchema": t.InputSchema,
			"annotations": map[string]bool{"readOnlyHint": !t.Write, "openWorldHint": true}})
	}
	return out
}

// checkGrants validates the grants' shape against the configured namespaces. Tool names are checked
// against the manifest at admission.
func checkGrants(s source, namespaces map[string]bool) error {
	if len(s.Grants) == 0 {
		return errors.New("grants must name the workspaces granted it")
	}
	subjects := map[string]bool{}
	for _, g := range s.Grants {
		if len(g.Workspaces) == 0 {
			return errors.New("a grant must name workspaces")
		}
		for _, w := range g.Workspaces {
			ns, account, ok := strings.Cut(w, "/")
			if !ok || !namespaces[ns] || (account != "*" && !dnsLabel.MatchString(account)) {
				return fmt.Errorf("grant subject %q is not <configured namespace>/<account> or <configured namespace>/*", w)
			}
			if subjects[w] {
				return fmt.Errorf("grant subject %q appears twice", w)
			}
			subjects[w] = true
		}
		if len(g.WriteTools) > 0 && !s.Writes {
			return errors.New("writeTools need writes: true on the connector")
		}
	}
	return nil
}

// grantFor is the grant that names the workspace exactly, else the one for its namespace.
func (s source) grantFor(ws string) (grant, bool) {
	ns, _, ok := strings.Cut(ws, "/")
	if !ok {
		return grant{}, false
	}
	var wild *grant
	for i, g := range s.Grants {
		if slices.Contains(g.Workspaces, ws) {
			return g, true
		}
		if wild == nil && slices.Contains(g.Workspaces, ns+"/*") {
			wild = &s.Grants[i]
		}
	}
	if wild != nil {
		return *wild, true
	}
	return grant{}, false
}

// permitFor is the workspace's permit for this connector; false when it is not granted. A write
// tool is permitted only when the profile allows writes and the grant names it.
func (s source) permitFor(ws string) (*permit, bool) {
	g, ok := s.grantFor(ws)
	if !ok {
		return nil, false
	}
	p := &permit{tools: map[string]bundle.Tool{}}
	if s.manifest == nil {
		return p, true
	}
	for _, t := range s.manifest.Tools {
		switch {
		case !t.Write && (g.Tools == nil || slices.Contains(g.Tools, t.Name)):
			p.tools[t.Name] = t
		case t.Write && s.Writes && slices.Contains(g.WriteTools, t.Name):
			p.tools[t.Name] = t
			p.writes = true
		}
	}
	return p, true
}

// admit verifies each connector's bundle against the profile: signed by the profile's signer for it,
// naming the executable digest the profile pins, and listing every tool the grants name. Any failure
// refuses start.
func admit(c *config) error {
	for i := range c.Sources {
		s := &c.Sources[i]
		m, err := bundle.Load(s.Bundle, c.signers[s.Signer])
		if err != nil {
			return fmt.Errorf("plugin %s: %w", s.Name, err)
		}
		if m.Digest != s.Digest {
			return fmt.Errorf("plugin %s: its executable is not the one the profile pins", s.Name)
		}
		tools := map[string]bundle.Tool{}
		for _, t := range m.Tools {
			tools[t.Name] = t
		}
		for _, g := range s.Grants {
			for _, n := range g.Tools {
				if t, ok := tools[n]; !ok || t.Write {
					return fmt.Errorf("plugin %s: grant tool %q is not a read tool in its manifest", s.Name, n)
				}
			}
			for _, n := range g.WriteTools {
				if t, ok := tools[n]; !ok || !t.Write {
					return fmt.Errorf("plugin %s: grant write tool %q is not a write tool in its manifest", s.Name, n)
				}
			}
		}
		s.manifest = &m
		if c.policy != nil {
			if err := s.classify(c.policy); err != nil {
				return fmt.Errorf("plugin %s: %w", s.Name, err)
			}
		}
	}
	return nil
}
