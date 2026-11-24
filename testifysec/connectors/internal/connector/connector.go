// Package connector is the shared runtime for Badger's enclave-service connectors. A connector
// is a static binary that speaks MCP over stdio; it supplies a Spec (its name, auth scheme and
// tools) and calls Main. Everything a connector must not get wrong is here: flags come only from
// the administrator's profile, write tools are not even registered unless writes are enabled,
// every result is size-capped and labelled as untrusted external content, and the credential is
// scrubbed from output and logs.
package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/aflock-ai/badger/testifysec/connectors/internal/egress"
	"github.com/aflock-ai/badger/testifysec/connectors/internal/marking"
)

// Spec describes one connector.
type Spec struct {
	Name    string            // short service name, e.g. "jira"; tool names should start with it
	Version string            // connector version reported in initialize
	Scheme  egress.AuthScheme // how the service wants the credential
	// Tools returns every tool, read and write. It is called once, after flags are parsed and the
	// client is built.
	Tools func(c *egress.Client) []Tool
	// Flags, if set, registers connector-specific settings on the shared flag set (use Env for the
	// environment fallback). The function it returns, if not nil, runs after parsing: it validates
	// the settings and may adjust the spec, for example choose Scheme.
	Flags func(fs *flag.FlagSet) func(*Spec) error
}

// Tool is one MCP tool. Write must be true for anything that changes state in the service;
// write tools are left out entirely unless the profile enables writes.
type Tool struct {
	Name        string          // ^[a-z][a-z0-9_]{0,63}$, e.g. jira_get_issue
	Description string          // shown to the model
	Write       bool            // changes state in the service
	InputSchema json.RawMessage // JSON Schema object; see ObjectSchema
	Handler     func(ctx context.Context, args json.RawMessage) (Result, error)
}

// Result is what a handler returns: plain text or markdown for the model. The server wraps,
// caps and scrubs it; handlers never format the wrapper themselves.
type Result struct {
	Text string
}

// Config is the connector's whole configuration. Main fills it from flags and environment the
// administrator's profile sets; tests fill it directly.
type Config struct {
	BaseURL              string
	TokenFile            string
	Classification       string // system-high banner of the service, e.g. SECRET
	Notice               string // optional line printed under the top banner and over the bottom one
	CAFile               string
	EnableWrites         bool
	InsecureLoopbackHTTP bool         // tests against a loopback fake only
	MaxOutputBytes       int          // tool result cap before wrapping; default 48 KiB
	Logger               *slog.Logger // default: text to stderr
}

// Server holds the registered tools and serves them.
type Server struct {
	spec    Spec
	cfg     Config
	tools   map[string]Tool
	require map[string][]string // each tool's required arguments, from its input schema
	marking marking.Marking
	redact  func(string) string
	hasCred func(string) bool
	log     *slog.Logger
	timeout time.Duration
}

var toolName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// notice is what a notice line may hold. It is printed outside the untrusted-content block, so it
// can carry no markup.
var notice = regexp.MustCompile(`^[A-Za-z0-9 .,;:()'/-]{1,160}$`)

// New builds the egress client and registers the spec's tools.
func New(spec Spec, cfg Config) (*Server, error) {
	if cfg.MaxOutputBytes <= 0 {
		cfg.MaxOutputBytes = 48 << 10
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	if cfg.TokenFile == "" {
		return nil, errors.New("no token file configured")
	}
	if cfg.Classification == "" {
		return nil, errors.New("no classification marking configured")
	}
	mark, err := marking.Parse(cfg.Classification)
	if err != nil {
		return nil, fmt.Errorf("classification marking %q: %v", cfg.Classification, err)
	}
	if cfg.Notice != "" && !notice.MatchString(cfg.Notice) {
		return nil, errors.New("notice must be one line of at most 160 letters, digits, spaces and . , ; : ( ) ' / -")
	}
	client, err := egress.New(egress.Config{BaseURL: cfg.BaseURL, EgressFD: egressFD(), Token: egress.FileToken(cfg.TokenFile), Scheme: spec.Scheme,
		CAFile: cfg.CAFile, InsecureLoopbackHTTP: cfg.InsecureLoopbackHTTP, UserAgent: "badger-connector-" + spec.Name + "/" + spec.Version})
	if err != nil {
		return nil, err
	}
	s := &Server{spec: spec, cfg: cfg, marking: mark, tools: map[string]Tool{}, redact: client.Redact, hasCred: client.ContainsCredential, log: cfg.Logger, timeout: 2 * time.Minute}
	for _, t := range spec.Tools(client) {
		if err := s.add(t, cfg.EnableWrites); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Server) add(t Tool, writes bool) error {
	if !toolName.MatchString(t.Name) || t.Description == "" || t.Handler == nil {
		return fmt.Errorf("tool %q: needs a lower_snake name, a description and a handler", t.Name)
	}
	if _, dup := s.tools[t.Name]; dup {
		return fmt.Errorf("tool %q registered twice", t.Name)
	}
	if t.Write && !writes {
		return nil
	}
	if t.InputSchema == nil {
		t.InputSchema = ObjectSchema(nil)
	}
	var schema struct {
		Type     string   `json:"type"`
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(t.InputSchema, &schema); err != nil || schema.Type != "object" {
		return fmt.Errorf("tool %q: input schema must be a JSON Schema object", t.Name)
	}
	if s.require == nil {
		s.require = map[string][]string{}
	}
	s.require[t.Name] = schema.Required
	s.tools[t.Name] = t
	return nil
}

// checkRequired refuses a call that leaves out, or sets to null, an argument the tool's schema
// requires, before the handler runs: a write tool must never act on a zero value it was not given.
func checkRequired(args json.RawMessage, required []string) error {
	if len(required) == 0 {
		return nil
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(args, &got); err != nil {
		return errors.New("invalid arguments: expected a JSON object")
	}
	for _, k := range required {
		if v, ok := got[k]; !ok || string(bytes.TrimSpace(v)) == "null" {
			return fmt.Errorf("invalid arguments: %q is required", k)
		}
	}
	return nil
}

// ToolNames lists the registered tools, sorted.
func (s *Server) ToolNames() []string {
	names := make([]string, 0, len(s.tools))
	for n := range s.tools {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// CallResult is one finished tool call: the wrapped, capped, scrubbed text, whose first and
// last lines are Banner.
type CallResult struct {
	Text    string
	IsError bool
	Banner  string
}

// Call runs one tool. It is what tools/call uses, and what connector tests call directly.
func (s *Server) Call(ctx context.Context, name string, args json.RawMessage) CallResult {
	t, ok := s.tools[name]
	if !ok {
		// The name came from the client: shown only if it is a valid tool name, never in the
		// wrapper's attribute.
		msg := "unknown tool"
		if toolName.MatchString(name) {
			msg += " " + name
		}
		return s.result("unknown", Result{Text: msg}, true)
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	start := time.Now()
	res, err := Result{}, checkRequired(args, s.require[name])
	if err == nil {
		res, err = t.Handler(ctx, args)
	}
	attrs := []any{"tool", name, "write", t.Write, "ms", time.Since(start).Milliseconds()}
	if err != nil {
		// The error text can carry service content (a response body excerpt), which may be marked
		// above what the log may hold, so the log gets only the HTTP status, never the text.
		var he *egress.HTTPError
		if errors.As(err, &he) {
			attrs = append(attrs, "status", he.Status)
		}
		s.log.Warn("tool failed", attrs...)
		return s.result(name, Result{Text: "error: " + err.Error()}, true)
	}
	s.log.Info("tool ok", append(attrs, "bytes", len(res.Text))...)
	return s.result(name, res, false)
}

// Decode unmarshals tool arguments strictly: unknown fields and wrong types are errors the
// model sees and can correct.
func Decode(args json.RawMessage, v any) error {
	if len(bytes.TrimSpace(args)) == 0 {
		args = json.RawMessage("{}")
	}
	d := json.NewDecoder(bytes.NewReader(args))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("invalid arguments: %v", err)
	}
	return nil
}

// ObjectSchema builds a flat JSON Schema object. props maps a property name to its JSON type
// ("string", "integer", "boolean"); required names the required ones. Connectors needing
// descriptions, enums or nesting write the schema as a json.RawMessage literal instead.
func ObjectSchema(props map[string]string, required ...string) json.RawMessage {
	p := map[string]any{}
	for k, typ := range props {
		p[k] = map[string]string{"type": typ}
	}
	if required == nil {
		required = []string{}
	}
	b, _ := json.Marshal(map[string]any{"type": "object", "properties": p, "required": required, "additionalProperties": false})
	return b
}

// Env returns the environment variable name, or def when it is unset or empty. Connectors use it
// as a flag default so flags win over the environment.
func Env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// Parse reads the shared and connector-specific flags from args (os.Args[1:] in Main). Shared
// settings fall back to BADGER_CONNECTOR_* environment variables; both are set by the
// administrator's signed profile, never by the model, user config or repository config.
func Parse(spec Spec, args []string) (Spec, Config, error) {
	fs := flag.NewFlagSet(spec.Name, flag.ContinueOnError)
	var cfg Config
	fs.StringVar(&cfg.BaseURL, "base-url", Env("BADGER_CONNECTOR_BASE_URL", ""), "service base URL (https)")
	fs.StringVar(&cfg.TokenFile, "token-file", Env("BADGER_CONNECTOR_TOKEN_FILE", ""), "file the broker writes the user's credential to")
	fs.StringVar(&cfg.Classification, "classification", Env("BADGER_CONNECTOR_CLASSIFICATION", ""), "system-high marking of the service (banner)")
	fs.StringVar(&cfg.Notice, "notice", Env("BADGER_CONNECTOR_NOTICE", ""), "a line stating the content's real status, printed inside the banners, never part of them")
	fs.StringVar(&cfg.CAFile, "ca-file", Env("BADGER_CONNECTOR_CA_FILE", ""), "PEM roots for the service's CA (default: system roots)")
	fs.BoolVar(&cfg.EnableWrites, "enable-writes", os.Getenv("BADGER_CONNECTOR_ENABLE_WRITES") == "1", "register write tools")
	fs.BoolVar(&cfg.InsecureLoopbackHTTP, "insecure-loopback-http", false, "allow http:// to a loopback host (tests only)")
	var after func(*Spec) error
	if spec.Flags != nil {
		after = spec.Flags(fs)
	}
	if err := fs.Parse(args); err != nil {
		return spec, cfg, err
	}
	if fs.NArg() > 0 {
		return spec, cfg, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if after != nil {
		if err := after(&spec); err != nil {
			return spec, cfg, err
		}
	}
	return spec, cfg, nil
}

// Main is a connector binary's whole main function. Run with --manifest as its only argument, it
// prints the plugin manifest (see Manifest) and exits.
func Main(spec Spec) {
	if err := noCoreDumps(); err != nil {
		fmt.Fprintf(os.Stderr, "%s connector: cannot disable core dumps, so the token is not read: %v\n", spec.Name, err)
		os.Exit(2)
	}
	if len(os.Args) == 2 && os.Args[1] == "--manifest" {
		b, err := Manifest(spec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s connector: %v\n", spec.Name, err)
			os.Exit(2)
		}
		os.Stdout.Write(append(b, '\n'))
		return
	}
	spec, cfg, err := Parse(spec, os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s connector: %v\n", spec.Name, err)
		os.Exit(2)
	}
	s, err := New(spec, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s connector: %v\n", spec.Name, err)
		os.Exit(2)
	}
	if err := s.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "%s connector: %v\n", spec.Name, s.redact(err.Error()))
		os.Exit(1)
	}
}

// egressFD is the plugin host's egress descriptor from BADGER_EGRESS_FD (internal/launch), or 0
// outside a plugin host.
func egressFD() int {
	fd, err := strconv.Atoi(os.Getenv("BADGER_EGRESS_FD"))
	if err != nil || fd < 3 {
		return 0
	}
	return fd
}
