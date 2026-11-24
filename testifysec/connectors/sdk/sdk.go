// Package sdk is the public interface for building a connector plugin, in this repository or
// outside it. A plugin is a binary whose main function is sdk.Main(spec): it speaks MCP over stdio,
// takes its settings only from the flags the connector gateway passes (base URL, token file,
// classification, CA, writes), and prints its manifest with --manifest so it can be packed and
// signed (cmd/plugintool). The gateway admits it by digest and decides its marking and who may use
// which tool; nothing a plugin says changes either. See testifysec/CONNECTORS.md, "Plugins".
//
// Everything a plugin must not get wrong (the egress lock to the base URL, the credential scrubbed
// from output and logs, the result size cap, the untrusted-content wrapper and the banner lines) is
// in the runtime behind these names, so a plugin built against this package gets it unchanged.
package sdk

import (
	"github.com/aflock-ai/badger/testifysec/connectors/internal/connector"
	"github.com/aflock-ai/badger/testifysec/connectors/internal/egress"
)

type (
	// Spec describes one plugin: name, version, auth scheme, tools and optional extra flags.
	Spec = connector.Spec
	// Tool is one MCP tool; Write marks a tool that changes state in the service.
	Tool = connector.Tool
	// Result is a handler's text for the model.
	Result = connector.Result
	// Config is the runtime configuration Main fills from flags; tests fill it directly.
	Config = connector.Config
	// Server is a running plugin, for tests that call tools directly.
	Server = connector.Server
	// CallResult is one finished tool call, wrapped and capped.
	CallResult = connector.CallResult
	// Client is the egress client a plugin's tools call the service with.
	Client = egress.Client
	// AuthScheme is how the service wants the credential.
	AuthScheme = egress.AuthScheme
	// HTTPError is a service answer outside 2xx.
	HTTPError = egress.HTTPError
)

const (
	Bearer       = egress.Bearer
	PrivateToken = egress.PrivateToken
)

// Main is a plugin binary's whole main function.
func Main(spec Spec) { connector.Main(spec) }

// New builds a server from a spec and a configuration (tests).
func New(spec Spec, cfg Config) (*Server, error) { return connector.New(spec, cfg) }

// Parse reads the shared and plugin-specific flags (tests).
func Parse(spec Spec, args []string) (Spec, Config, error) { return connector.Parse(spec, args) }

// Manifest is what --manifest prints.
func Manifest(spec Spec) ([]byte, error) { return connector.Manifest(spec) }

// Decode unmarshals tool arguments strictly.
var Decode = connector.Decode

// ObjectSchema builds a flat JSON Schema object.
var ObjectSchema = connector.ObjectSchema

// Env returns an environment variable or a default, for flag defaults.
var Env = connector.Env
