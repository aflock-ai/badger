// Command badger-docs serves the Badger documentation of the build it ships with to an agent, as
// a read-only MCP server on standard input and output.
//
//	badger-docs mcp [--overlay <dir>]...   serve the docs over MCP (stdio)
//	badger-docs version                    print the badger version and commit the docs are from
//
// The docs are embedded at build time from docs/tools/generate.ts --bundle, so they describe the
// commit the binary was built from; a binary whose bundle names another commit refuses to start.
// An overlay is a directory holding a bundle.json built by the same generator over a private page
// tree; its topics are added under overlay/<dir name>/ and never replace a public one. The server
// opens no network connection and reads no file but the overlays named on its command line.
package main

import (
	"bufio"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"slices"
)

//go:embed bundle
var embedded embed.FS

var protocolVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

func stringArg(name, description string) map[string]any {
	return map[string]any{"type": "object", "properties": map[string]any{name: map[string]string{"type": "string", "description": description}}, "additionalProperties": false}
}

var tools = []map[string]any{
	{"name": "list_topics", "description": "List every documentation topic (id, title, description). Optional section: concepts, admin, developer, walkthroughs, reference, security, or overlay/<name>.",
		"inputSchema": stringArg("section", "Only topics in this section")},
	{"name": "search", "description": "Search the documentation sections and the configuration reference. Returns topic#section ids to read and matching config keys.",
		"inputSchema": withRequired(stringArg("query", "Words to look for, such as a config key or a refusal reason"), "query")},
	{"name": "read", "description": "Read a topic, or one section of it as topic#section, in Markdown. Every answer starts with the badger version and commit it describes.",
		"inputSchema": withRequired(stringArg("topic", "Topic id from list_topics or search, optionally with #section"), "topic")},
	{"name": "get_config_reference", "description": "Every key in a component's JSON configuration, with type, stated default, comment and source file:line at the docs' commit. Components: gateway, platform, badger-broker, conngw.",
		"inputSchema": withRequired(stringArg("component", "Component name"), "component")},
	{"name": "version", "description": "The badger version, commit and date these docs were generated from, the binary's own build stamp, and any overlays.",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}},
}

func withRequired(schema map[string]any, name string) map[string]any {
	schema["required"] = []string{name}
	return schema
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// serve answers newline-delimited JSON-RPC 2.0 requests, one at a time, until r ends.
func serve(d *Docs, r io.Reader, w io.Writer) error {
	in := bufio.NewScanner(r)
	in.Buffer(make([]byte, 64<<10), 1<<20)
	out := json.NewEncoder(w)
	for in.Scan() {
		if len(in.Bytes()) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(in.Bytes(), &req); err != nil || req.JSONRPC != "2.0" || req.Method == "" {
			if err := out.Encode(rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}}); err != nil {
				return err
			}
			continue
		}
		if len(req.ID) == 0 || string(req.ID) == "null" {
			continue // a notification
		}
		result, rerr := handle(d, req)
		if err := out.Encode(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result, Error: rerr}); err != nil {
			return err
		}
	}
	return in.Err()
}

func handle(d *Docs, req rpcRequest) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		json.Unmarshal(req.Params, &p)
		v := protocolVersions[0]
		if slices.Contains(protocolVersions, p.ProtocolVersion) {
			v = p.ProtocolVersion
		}
		return map[string]any{
			"protocolVersion": v,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]string{"name": "badger-docs", "version": d.base.Roots[0].Version},
			"instructions":    "Badger documentation for " + d.stamp() + ". Use get_config_reference for exact configuration keys and search before guessing a setting.",
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		for _, t := range tools {
			t["annotations"] = map[string]bool{"readOnlyHint": true, "openWorldHint": false}
		}
		return map[string]any{"tools": tools}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
			return nil, &rpcError{-32602, "tools/call needs a tool name"}
		}
		text, isErr := d.call(p.Name, p.Arguments)
		return map[string]any{"content": []map[string]string{{"type": "text", "text": text}}, "isError": isErr}, nil
	}
	return nil, &rpcError{-32601, "method not found"}
}

// buildStamp is the commit the Go toolchain recorded for this binary, when it was built in a git
// checkout.
func buildStamp() map[string]any {
	stamp := map[string]any{"revision": "", "modified": false}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				stamp["revision"] = s.Value
			case "vcs.modified":
				stamp["modified"] = s.Value == "true"
			}
		}
	}
	return stamp
}

// checkBuild refuses docs generated from another commit than the binary. A binary built without a
// VCS stamp (from an archive, or with -buildvcs=false) has nothing to compare and is allowed; its
// version output says so.
func checkBuild(b *Bundle, revision string, modified bool) error {
	if revision == "" || revision == b.Roots[0].Commit {
		return nil
	}
	return fmt.Errorf("the embedded docs are from badger commit %s but this binary was built from %s; regenerate the bundle (bun docs/tools/bundle.ts testifysec/docsmcp/bundle/docs.json) and rebuild", b.Roots[0].Commit, revision)
}

func load() (*Bundle, error) {
	raw, err := embedded.ReadFile("bundle/docs.json")
	if err != nil {
		return nil, fmt.Errorf("this binary was built without a docs bundle; run bun docs/tools/bundle.ts testifysec/docsmcp/bundle/docs.json before go build")
	}
	b, err := parseBundle(raw)
	if err != nil {
		return nil, err
	}
	stamp := buildStamp()
	return b, checkBuild(b, stamp["revision"].(string), stamp["modified"].(bool))
}

func main() {
	fail := func(err error) {
		fmt.Fprintln(os.Stderr, "badger-docs:", err)
		os.Exit(1)
	}
	usage := "usage: badger-docs mcp [--overlay <dir>]... | badger-docs version"
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	b, err := load()
	if err != nil {
		fail(err)
	}
	switch os.Args[1] {
	case "version":
		if len(os.Args) != 2 {
			fmt.Fprintln(os.Stderr, usage)
			os.Exit(2)
		}
		r := b.Roots[0]
		stamp := buildStamp()
		built := "no VCS stamp in this binary"
		if rev := stamp["revision"].(string); rev != "" {
			built = "binary built from " + rev
			if stamp["modified"].(bool) {
				built += " with uncommitted changes"
			}
		}
		dirty := ""
		if r.Dirty {
			dirty = " (docs from a tree with uncommitted changes)"
		}
		fmt.Printf("badger-docs: badger %s at %s, docs of %s%s; %s\n", r.Version, r.Commit, b.Date, dirty, built)
	case "mcp":
		var overlays []Overlay
		args := os.Args[2:]
		for len(args) > 0 {
			if args[0] != "--overlay" || len(args) < 2 {
				fmt.Fprintln(os.Stderr, usage)
				os.Exit(2)
			}
			o, err := loadOverlay(args[1])
			if err != nil {
				fail(err)
			}
			overlays = append(overlays, o)
			args = args[2:]
		}
		d, err := newDocs(b, overlays)
		if err != nil {
			fail(err)
		}
		if err := serve(d, os.Stdin, os.Stdout); err != nil {
			fail(err)
		}
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
}
