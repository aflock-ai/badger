package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aflock-ai/badger/testifysec/connectors/internal/launch"
	"github.com/aflock-ai/badger/testifysec/connectors/marking"
)

// contentFree are the requests whose answers carry no service content: they are forwarded so the
// plugin stays a correct MCP server, but the caller gets the gateway's own answer (synthesize).
// Every other request with an id is checked against the grant and raises the label.
var contentFree = map[string]bool{"initialize": true, "ping": true, "tools/list": true}

// message is how the gateway reads a line. What reaches the plugin is re-encoded from it (forward),
// so a plugin that parses differently (duplicate keys read first-wins) sees only what was checked.
// Result and Error tell a response from a request on the plugin's side.
type message struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  json.RawMessage `json:"error,omitempty"`
}

// usGovDigest is the default scheme's digest: what a declaration without a scheme means.
var usGovDigest = func() string {
	s, err := marking.Preset("us-gov")
	if err != nil {
		panic("conngw: us-gov preset: " + err.Error())
	}
	return s.Digest()
}()

// metaKey names the machine-readable classification in each tools/call result's _meta
// (internal/connector). The gateway writes it from the profile.
const metaKey = "com.testifysec/classification"

// canonical is how the connector library writes an id back (encoding/json, HTML escaping on), so a
// request and its answer meet under one key however the caller escaped the id: "<" and "\u003c" are
// the same id, and the second one is refused while the first is pending.
func canonical(id json.RawMessage) string {
	var v any
	if json.Unmarshal(id, &v) != nil {
		return string(id)
	}
	if str, ok := v.(string); ok {
		b, _ := json.Marshal(str)
		return string(b)
	}
	var compact bytes.Buffer
	if json.Compact(&compact, id) != nil {
		return string(id)
	}
	return compact.String()
}

// stream carries one caller's MCP stream to one connector process and back, applying the
// no-write-down rule under the caller's workspace.
type stream struct {
	ws     string
	conn   source
	labels *labels
	log    *slog.Logger

	// writeTimeout bounds each write to the caller, when its connection takes deadlines: a caller
	// that stops reading fails the write and ends the stream instead of holding it open.
	writeTimeout time.Duration

	last atomic.Int64 // unix nanoseconds of the stream's last activity, for the idle timeout

	// Lines logged about the plugin's output are logged once per stream (and the high-water when
	// it changes): how many there are and when is the plugin's choice, a signal into the log.
	logged   map[string]bool
	loggedHW string
	loggedMu sync.Mutex

	// perm is what this workspace may call on this connector; nil permits no tool.
	perm *permit

	// Every request reaches the plugin under an id of the gateway's own (a counter), never the
	// caller's: an id is caller text, and it would otherwise pass to the plugin unchecked.
	mu      sync.Mutex
	next    int64
	inUse   map[string]string          // the caller's id (canonical) -> the gateway's, while pending
	pending map[string]bool            // the gateway's id -> whether its answer carries content
	ids     map[string]json.RawMessage // the gateway's id -> the caller's own spelling of its id
	methods map[string]string          // the gateway's id -> method (initialize: "initialize\n<version>"), for pending content-free requests
	tools   map[string]string          // the gateway's id -> the tool a pending tools/call names
	out     sync.Mutex                 // serializes writes to the caller
}

func (s *stream) touch() { s.last.Store(time.Now().UnixNano()) }

// once reports whether key is logged for the first time on this stream.
func (s *stream) once(key string) bool {
	s.loggedMu.Lock()
	defer s.loggedMu.Unlock()
	if s.logged[key] {
		return false
	}
	if s.logged == nil {
		s.logged = map[string]bool{}
	}
	s.logged[key] = true
	return true
}

// firstHighWater reports whether this stream has not yet logged the label banner b.
func (s *stream) firstHighWater(b string) bool {
	s.loggedMu.Lock()
	defer s.loggedMu.Unlock()
	if s.loggedHW == b {
		return false
	}
	s.loggedHW = b
	return true
}

func (s *stream) write(w io.Writer, b []byte) error {
	s.out.Lock()
	defer s.out.Unlock()
	if d, ok := w.(interface{ SetWriteDeadline(time.Time) error }); ok && s.writeTimeout > 0 {
		_ = d.SetWriteDeadline(time.Now().Add(s.writeTimeout))
	}
	_, err := w.Write(b)
	return err
}

// refuse answers a request without forwarding it.
func (s *stream) refuse(w io.Writer, id json.RawMessage, method, text string) error {
	var answer any
	if method == "tools/call" {
		answer = map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{
			"isError": true, "content": []any{map[string]any{"type": "text", "text": text}}}}
	} else {
		answer = map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32001, "message": text}}
	}
	b, _ := json.Marshal(answer)
	return s.write(w, append(b, '\n'))
}

// requests reads the caller's lines and forwards the ones the rule allows to the connector. A line
// the connector would not read as one JSON-RPC object is dropped, so nothing reaches the connector
// unchecked.
func (s *stream) requests(caller io.Reader, reply io.Writer, connector io.Writer) error {
	in := bufio.NewScanner(caller)
	in.Buffer(make([]byte, 64<<10), 4<<20)
	for in.Scan() {
		s.touch()
		line := in.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var msg message
		if err := json.Unmarshal(line, &msg); err != nil || msg.Method == "" {
			s.log.Warn("dropped a line that is not one JSON-RPC request", "workspace", s.ws, "connector", s.conn.Name)
			continue
		}
		notification := len(msg.ID) == 0 || string(msg.ID) == "null"
		// The connector library ignores a request without an id, but only a notifications/ method
		// may go without one here, so a call cannot skip the check below by dropping its id.
		if notification && !strings.HasPrefix(msg.Method, "notifications/") {
			// The method is the caller's text, so it is never logged: the log holds only fixed
			// reasons, the reviewed workspace and the configured connector name.
			s.log.Warn("dropped a request without an id", "workspace", s.ws, "connector", s.conn.Name)
			continue
		}
		if !notification {
			if c := msg.ID[0]; c != '"' && c != '-' && (c < '0' || c > '9') {
				if err := s.refuse(reply, json.RawMessage("null"), msg.Method, "refused by the connector gateway: a request id must be a string or a number"); err != nil {
					return err
				}
				continue
			}
			content := !contentFree[msg.Method]
			var tool string
			if content {
				var text string
				msg, tool, text = s.permitted(msg)
				if text != "" {
					s.log.Warn("refused: not permitted", "workspace", s.ws, "connector", s.conn.Name)
					if err := s.refuse(reply, msg.ID, msg.Method, "refused by the connector gateway: "+text); err != nil {
						return err
					}
					continue
				}
				// Each tool is checked at its own marking (the connector's, without a marking policy).
				m, what := s.conn.markingOf(tool), s.conn.Name
				if s.conn.policy != nil {
					what = tool + " on " + s.conn.Name
				}
				if label, ok := s.labels.allows(s.ws, m); !ok {
					s.log.Warn("refused", "workspace", s.ws, "connector", s.conn.Name, "marking", marking.Banner(m), "label", marking.Banner(label))
					text := fmt.Sprintf("refused by the connector gateway: this workspace has read %s content, and %s is marked %s, so the call could carry that content down. Ask your administrator to reset it.",
						marking.Banner(label), what, marking.Banner(m))
					if err := s.refuse(reply, msg.ID, msg.Method, text); err != nil {
						return err
					}
					continue
				}
				// A registered workspace goes above its ceiling only in a copy (admin.go): the call
				// never reaches the connector and the label does not move.
				if ceiling, ok := s.labels.withinCeiling(s.ws, m); !ok {
					s.log.Warn("refused: above the ceiling", "workspace", s.ws, "connector", s.conn.Name, "marking", marking.Banner(m), "ceiling", marking.Banner(ceiling))
					text := fmt.Sprintf("refused by the connector gateway: %s is marked %s, and reading it would raise this workspace above %s. To read it, continue in a copy of this workspace at %s.",
						what, marking.Banner(m), marking.Banner(ceiling), marking.Banner(m))
					if err := s.refuse(reply, msg.ID, msg.Method, text); err != nil {
						return err
					}
					continue
				}
				// The policy's flow rules refuse what dominance allowed; they never allow anything.
				if why, denied := s.denied(tool); denied {
					s.log.Warn("refused: a flow rule", "workspace", s.ws, "connector", s.conn.Name, "source", s.conn.sourceName(tool))
					if err := s.refuse(reply, msg.ID, msg.Method, "refused by the connector gateway: "+why); err != nil {
						return err
					}
					continue
				}
			}
			s.mu.Lock()
			key := canonical(msg.ID)
			_, taken := s.inUse[key]
			if !taken {
				if s.inUse == nil {
					s.inUse, s.ids, s.methods, s.tools = map[string]string{}, map[string]json.RawMessage{}, map[string]string{}, map[string]string{}
				}
				s.next++
				own := strconv.FormatInt(s.next, 10)
				s.inUse[key] = own
				s.pending[own] = content
				s.ids[own] = append(json.RawMessage{}, msg.ID...)
				if tool != "" {
					s.tools[own] = tool
				}
				if !content {
					s.methods[own] = msg.Method
					if msg.Method == "initialize" {
						s.methods[own] += "\n" + requestedProtocol(msg.Params)
					}
				}
				msg.ID = json.RawMessage(own)
			}
			s.mu.Unlock()
			if taken {
				if err := s.refuse(reply, msg.ID, msg.Method, "refused by the connector gateway: this request id is already in use"); err != nil {
					return err
				}
				continue
			}
		}
		if contentFree[msg.Method] || notification {
			var ok bool
			if line, ok = control(msg); !ok {
				s.log.Warn("dropped a notification the gateway does not carry", "workspace", s.ws, "connector", s.conn.Name)
				continue
			}
		} else {
			line = forward(msg)
		}
		if _, err := connector.Write(append(append([]byte{}, line...), '\n')); err != nil {
			return err
		}
	}
	return in.Err()
}

// forward re-encodes a request from what the gateway parsed.
func forward(msg message) []byte {
	m := map[string]any{"jsonrpc": "2.0", "method": msg.Method}
	if len(msg.ID) > 0 && string(msg.ID) != "null" {
		m["id"] = msg.ID
	}
	if len(msg.Params) > 0 && string(msg.Params) != "null" {
		m["params"] = msg.Params
	}
	b, _ := json.Marshal(m)
	return b
}

// control is what reaches the plugin for a request that passes without the high-water check: the
// gateway's own fixed request, never the caller's params, so a workspace that has read higher content
// cannot send it to a lower plugin there. initialize keeps only the protocol version the gateway
// speaks; the only notification carried is notifications/initialized.
func control(msg message) ([]byte, bool) {
	out := message{ID: msg.ID, Method: msg.Method}
	switch msg.Method {
	case "initialize":
		out.Params, _ = json.Marshal(map[string]any{"protocolVersion": requestedProtocol(msg.Params), "capabilities": map[string]any{},
			"clientInfo": map[string]string{"name": "badger-conngw", "version": "1"}})
	case "ping", "tools/list":
	case "notifications/initialized":
		out.ID = nil
	default:
		return nil, false
	}
	return forward(out), true
}

// denied reports the policy's flow rule that refuses a call to tool from this workspace, with its
// message. A workspace that has read nothing carries nothing a rule could refuse.
func (s *stream) denied(tool string) (string, bool) {
	if s.conn.policy == nil {
		return "", false
	}
	label, labelled, _, _, _ := s.labels.describe(s.ws)
	if !labelled {
		return "", false
	}
	return s.conn.policy.Denied(label, s.conn.sourceName(tool))
}

// permitted checks a request that may carry content: only tools/call, for a tool this workspace's
// grant names. It returns the request to forward, with only the checked params, and the tool, or
// the reason it is refused.
func (s *stream) permitted(msg message) (message, string, string) {
	if msg.Method != "tools/call" {
		return msg, "", "this connector carries only initialize, ping, tools/list and tools/call"
	}
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if json.Unmarshal(msg.Params, &p) != nil || !s.perm.allows(p.Name) {
		return msg, "", "this workspace is not permitted that tool on " + s.conn.Name
	}
	if len(p.Arguments) == 0 || string(p.Arguments) == "null" {
		p.Arguments = json.RawMessage("{}")
	}
	msg.Params, _ = json.Marshal(map[string]any{"name": p.Name, "arguments": p.Arguments})
	return msg, p.Name, ""
}

// errRefusedFrame ends a stream whose connector wrote a frame with a repeated JSON key or nesting
// over launch.MaxJSONDepth.
var errRefusedFrame = errors.New("a connector answer is a refused JSON frame")

// answers passes the connector's lines to the caller. The label rises before any line that may
// carry content is passed on: everything except the answer to a content-free request.
func (s *stream) answers(connector io.Reader, caller io.Writer) error {
	in := bufio.NewScanner(connector)
	in.Buffer(make([]byte, 64<<10), 16<<20)
	for in.Scan() {
		line := in.Bytes()
		s.touch()
		// A frame with a repeated key at any depth, or nested over launch.MaxJSONDepth, ends the
		// stream: this parser and the plugin host's scrub could read different values from it, and
		// unbounded nesting costs memory (launch.JSONStrings).
		if valid, refuse := launch.JSONStrings(line, func(string) {}); valid && refuse != nil {
			s.log.Warn("ending the stream: a connector answer is a refused JSON frame", "workspace", s.ws, "connector", s.conn.Name, "reason", refuse.Error())
			return errRefusedFrame
		}
		var msg message
		var tool string // the tool a response answers, when it answers a pending tools/call
		content, response := true, false
		// Only a response (an id, a result or an error, and no method) to a pending request answers
		// it; a request the connector sends under a pending id, or a response to an id nobody is
		// waiting for, is output like any other: it raises the label and is not passed on.
		if json.Unmarshal(line, &msg) == nil && len(msg.ID) > 0 && msg.Method == "" && (msg.Result != nil || msg.Error != nil) {
			s.mu.Lock()
			key := canonical(msg.ID)
			c, ok := s.pending[key]
			method := s.methods[key]
			tool = s.tools[key]
			if id, known := s.ids[key]; known {
				// The answer goes back under the caller's spelling of its id, not the gateway's.
				msg.ID = id
				delete(s.inUse, canonical(id))
			}
			delete(s.pending, key)
			delete(s.methods, key)
			delete(s.tools, key)
			delete(s.ids, key)
			s.mu.Unlock()
			response, content = ok, !ok || c
			if !content {
				// The caller gets the gateway's answer, never the plugin's text: nothing a plugin
				// says passes as content-free.
				method, protocol, _ := strings.Cut(method, "\n")
				line = s.synthesize(msg, method, protocol)
			}
		}
		if content {
			// The answer to a tool call raises to that tool's marking; any other output to the
			// connector's, the join of all its tools'.
			m := s.conn.markingOf(tool)
			label, prior, err := s.labels.raised(s.ws, m)
			if err != nil {
				// The raise is not durable, so the answer is not passed on.
				s.log.Error("could not record the high-water; ending the stream", "workspace", s.ws, "connector", s.conn.Name, "err", err)
				return err
			}
			if b := marking.Banner(label); b != prior {
				// Each raise is on record: it is durable in the labels file already, and this is
				// its audit event.
				s.log.Info("label raised", "event", "label.raised", "workspace", s.ws, "source", s.conn.sourceName(tool),
					"from", prior, "to", b, "scheme", s.conn.scheme.Digest())
			}
			if b := marking.Banner(label); s.firstHighWater(b) {
				s.log.Info("high-water", "workspace", s.ws, "connector", s.conn.Name, "label", b)
			}
			switch {
			case !response:
				// Output that answers no request (a notification, a request, a line that is not
				// JSON) carries no marking the gateway can put on it, so it is not passed on.
				if s.once("dropped") {
					s.log.Warn("dropped connector output that answers no request (logged once per stream)", "workspace", s.ws, "connector", s.conn.Name)
				}
				continue
			case msg.Error != nil:
				line = s.failed(msg, m)
			default:
				line = s.stamp(msg, m)
			}
		}
		if err := s.write(caller, append(append([]byte{}, line...), '\n')); err != nil {
			return err
		}
	}
	return in.Err()
}

// synthesize is the gateway's own answer to a content-free request the plugin has answered. Nothing
// in it comes from the plugin's answer, not even whether it was an error: initialize's protocol
// version is the one the caller asked for (one the gateway speaks), set when the request passed.
func (s *stream) synthesize(msg message, method, protocol string) []byte {
	answer := map[string]any{"jsonrpc": "2.0", "id": msg.ID}
	switch method {
	case "tools/list":
		answer["result"] = map[string]any{"tools": s.perm.list()}
	case "initialize":
		version := "0"
		if s.conn.manifest != nil {
			version = s.conn.manifest.Version
		}
		answer["result"] = map[string]any{"protocolVersion": protocol,
			"capabilities": map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":   map[string]string{"name": "badger-" + s.conn.Name, "version": version}}
	default:
		answer["result"] = map[string]any{}
	}
	b, _ := json.Marshal(answer)
	return b
}

// requestedProtocol is the revision the caller asked for, when the gateway speaks it, else the
// gateway's first.
func requestedProtocol(params json.RawMessage) string {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &p)
	if slices.Contains(protocolVersions, p.ProtocolVersion) {
		return p.ProtocolVersion
	}
	return protocolVersions[0]
}

// protocolVersions are the MCP revisions the gateway answers initialize with (internal/connector's);
// the first is offered when the caller asks for another.
var protocolVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

// failed is the caller's answer for a connector's error response: a fixed code and message, and
// the profile's marking in data. Nothing of the plugin's error passes on: its code, message and data
// carry no marking. Whether a call failed is the plugin's choice, so the answer is marked like a
// result.
func (s *stream) failed(msg message, m marking.Marking) []byte {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "error": map[string]any{
		"code": -32603, "message": "the connector answered with an error", "data": map[string]any{"_meta": s.meta(m)}}})
	return b
}

// meta is the gateway's _meta for an answer marked m (from the profile), machine-readable.
func (s *stream) meta(m marking.Marking) map[string]any {
	meta := map[string]any{"schema": 1, "banner": marking.Banner(m)}
	// The scheme the banner is read under; left out for us-gov, so its answers are as they were.
	if !s.conn.scheme.IsDefault() {
		meta["scheme"] = s.conn.scheme.Digest()
	}
	return map[string]any{metaKey: meta}
}

// stamp puts the profile's marking m on a result. The caller gets only content, isError and the
// gateway's _meta: every content item must be text framed by the banner the plugin was started with
// (first and last line), or the result is replaced by a refusal; anything else the plugin put in the
// result (structured content, other _meta keys) carries no marking and is dropped. A tool the policy
// marks below the connector's join is reframed with its own banner: the plugin knows only the join.
func (s *stream) stamp(msg message, m marking.Marking) []byte {
	started, banner := marking.Banner(s.conn.marking), marking.Banner(m)
	var result map[string]json.RawMessage
	// A null result decodes without error to a nil map; it starts empty instead.
	if json.Unmarshal(msg.Result, &result) != nil || result == nil {
		result = map[string]json.RawMessage{}
	}
	var items []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	framed := true
	if c, ok := result["content"]; ok {
		framed = json.Unmarshal(c, &items) == nil
		for _, it := range items {
			if it.Type != "text" || !strings.HasPrefix(it.Text, started+"\n") || !strings.HasSuffix(it.Text, "\n"+started) {
				framed = false
			}
		}
	}
	if !framed {
		if s.once("unmarked") {
			s.log.Warn("refused: an answer without this connector's marking (logged once per stream)", "workspace", s.ws, "connector", s.conn.Name)
		}
		text := banner + "\nrefused by the connector gateway: the connector's answer did not carry this connector's marking\n" + banner
		result = map[string]json.RawMessage{"isError": json.RawMessage("true")}
		result["content"], _ = json.Marshal([]any{map[string]string{"type": "text", "text": text}})
	}
	out := map[string]json.RawMessage{}
	if _, ok := result["content"]; ok {
		// Re-encoded from what was checked: an item's other fields are not passed on.
		_ = json.Unmarshal(result["content"], &items)
		clean := make([]map[string]string, 0, len(items))
		for _, it := range items {
			if framed && banner != started {
				// Framed, so at least started+"\n"+started: the two banners never overlap.
				it.Text = banner + it.Text[len(started):len(it.Text)-len(started)] + banner
			}
			clean = append(clean, map[string]string{"type": it.Type, "text": it.Text})
		}
		out["content"], _ = json.Marshal(clean)
	}
	var isErr bool
	if json.Unmarshal(result["isError"], &isErr) == nil && isErr {
		out["isError"] = json.RawMessage("true")
	}
	out["_meta"], _ = json.Marshal(s.meta(m))
	result = out
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": result})
	return b
}

// declared is what the caller's signed profile says about a connector, sent by the bridge. It must
// match this pod's configuration, so the workspace's own high-water check and this one agree.
type declared struct {
	Classification string            `json:"classification"`
	Writes         bool              `json:"writes"`
	Flags          map[string]string `json:"flags"`
	// Scheme is the digest of the scheme the caller's profile reads the classification under;
	// absent is us-gov.
	Scheme string `json:"scheme,omitempty"`
}

// gateway is the connector pod's HTTP handler: one upgrade per stream, on /connectors/<name>.
type gateway struct {
	sources map[string]source
	review  interface {
		workspace(ctx context.Context, token string) (string, error)
		admin(ctx context.Context, token string) (string, error)
	}
	labels *labels
	// namespaces are the workspace namespaces this pod serves; floor, when set, turns on the admin
	// API (admin.go) and is the level every registered workspace may reach; inbox, when set, turns
	// on send-up (sendup.go).
	namespaces []string
	floor      *marking.Marking
	inbox      *inbox
	// adminRead bounds reading an admin or send-up request's body; zero takes 5 seconds.
	adminRead time.Duration
	log       *slog.Logger
	start     func(source) (*process, error)

	// Streams are bounded before a connector starts: at most maxStreams in the pod and
	// maxPerWorkspace for one workspace. A stream idle for `idle` is closed; zero never closes one.
	maxStreams, maxPerWorkspace int
	idle                        time.Duration
	active                      sync.Mutex
	open                        map[string]int
	total                       int
}

func (g *gateway) acquire(ws string) bool {
	g.active.Lock()
	defer g.active.Unlock()
	if g.total >= g.maxStreams || g.open[ws] >= g.maxPerWorkspace {
		return false
	}
	if g.open == nil {
		g.open = map[string]int{}
	}
	g.open[ws]++
	g.total++
	return true
}

func (g *gateway) release(ws string) {
	g.active.Lock()
	defer g.active.Unlock()
	g.total--
	if g.open[ws]--; g.open[ws] <= 0 {
		delete(g.open, ws)
	}
}

// process is one running connector: its stdin, its stdout, and how to stop it. stop may be called
// more than once; it kills the process and closes both pipes.
type process struct {
	in   io.WriteCloser
	out  io.Reader
	stop func()
}

// dial reaches one connector's plugin for one stream, refusing before a byte is sent unless the
// pod's status says the plugin's container runs the plughost image the profile pins, the socket is answered
// by the plugin's own uid and gid (not a socket linked in from another plugin's volume), and the
// container is the same one after connecting as before, and the socket's listener is in exactly
// that container (inContainer, by cgroup: status can lag an image replacement). Then it sends the
// hello. stop closes the
// connection, which ends the plugin's process in its container.
func dial(ctx context.Context, s source, pins func(ctx context.Context, name, digest string) (container, error)) (*process, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	before, err := pins(ctx, s.Name, s.host)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", s.Socket)
	if err != nil {
		return nil, err
	}
	uc := c.(*net.UnixConn)
	fail := func(err error) (*process, error) { _ = uc.Close(); return nil, err }
	uid, gid, pr, err := peer(uc)
	if err != nil || uid != s.UID || gid != s.GID {
		pr.close()
		return fail(errors.Join(errors.New("the plugin socket is not answered by the plugin's user"), err))
	}
	defer pr.close()
	if err := inContainer(procRoot, pr, before.id); err != nil {
		return fail(err)
	}
	if after, err := pins(ctx, s.Name, s.host); err != nil || after.id != before.id {
		return fail(errors.Join(errors.New("the plugin container changed while connecting"), err))
	}
	b, _ := json.Marshal(s.hello())
	_ = uc.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := uc.Write(append(b, '\n')); err != nil {
		return fail(err)
	}
	_ = uc.SetWriteDeadline(time.Time{})
	var once sync.Once
	return &process{in: halfCloser{uc}, out: uc, stop: func() { once.Do(func() { _ = uc.Close() }) }}, nil
}

// procRoot is where process cgroups are read (tests replace it).
var procRoot = "/proc"

// halfCloser ends the plugin's input without closing its output, so it can finish its answers.
type halfCloser struct{ *net.UnixConn }

func (h halfCloser) Close() error { return h.CloseWrite() }

const upgradeProtocol = "badger-mcp"

func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasPrefix(r.URL.Path, "/admin/"):
		g.serveAdmin(w, r)
		return
	case r.URL.Path == "/sendup" || r.URL.Path == "/inbox" || strings.HasPrefix(r.URL.Path, "/inbox/"):
		g.serveSendUp(w, r)
		return
	}
	// An upgrade request has no body. One that declares one is refused before anything more is
	// read, so a body that never arrives cannot hold the handler.
	// The connection is taken over and closed after a fixed answer: net/http would otherwise keep
	// it open waiting to drain the body.
	if r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
		conn, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			w.Header().Set("Connection", "close")
			http.Error(w, "a stream request has no body", http.StatusBadRequest)
			return
		}
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		_ = conn.Close()
		return
	}
	name, ok := strings.CutPrefix(r.URL.Path, "/connectors/")
	src, known := g.sources[name]
	if r.Method != http.MethodGet || !ok || !known || !strings.EqualFold(r.Header.Get("Upgrade"), upgradeProtocol) {
		http.NotFound(w, r)
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" || len(token) > 16<<10 {
		http.Error(w, "workspace token required", http.StatusUnauthorized)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	ws, err := g.review.workspace(ctx, token)
	cancel()
	switch {
	case errors.Is(err, errUnauthenticated):
		http.Error(w, "workspace token not accepted", http.StatusUnauthorized)
		return
	case errors.Is(err, errNotWorkspace):
		http.Error(w, "not a workspace", http.StatusForbidden)
		return
	case err != nil:
		g.log.Error("token review failed", "err", err)
		http.Error(w, "token review unavailable", http.StatusServiceUnavailable)
		return
	}
	// Authorization is the pod's own: the connector's grants name the workspaces that may use it and
	// what they may call. The declaration below only checks that their profile and this
	// configuration agree.
	perm, granted := src.permitFor(ws)
	if !granted {
		g.log.Warn("refused: workspace not granted this connector", "workspace", ws, "connector", name)
		http.Error(w, "this workspace is not granted this connector", http.StatusForbidden)
		return
	}
	// The plugin starts with writes only for a workspace whose grant has write tools.
	src.Writes = perm.writes
	var d declared
	if json.Unmarshal([]byte(r.Header.Get("Badger-Connector")), &d) != nil || !src.matches(d) {
		g.log.Warn("refused: the caller's profile does not match this connector", "workspace", ws, "connector", name)
		http.Error(w, "the workspace profile and the connector pod disagree about this connector", http.StatusConflict)
		return
	}
	if !g.acquire(ws) {
		g.log.Warn("refused: too many streams", "workspace", ws, "connector", name)
		http.Error(w, "too many open connector streams", http.StatusTooManyRequests)
		return
	}
	defer g.release(ws)
	p, err := g.start(src)
	if err != nil {
		g.log.Error("connector did not start", "connector", name, "err", err)
		http.Error(w, "connector unavailable", http.StatusServiceUnavailable)
		return
	}
	defer p.stop()
	conn, buf, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Time{})
	if _, err := conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: " + upgradeProtocol + "\r\nConnection: Upgrade\r\n\r\n")); err != nil {
		return
	}
	g.log.Info("stream", "workspace", ws, "connector", name)
	s := &stream{ws: ws, conn: src, labels: g.labels, log: g.log, pending: map[string]bool{}, perm: perm, writeTimeout: 30 * time.Second}
	s.relay(buf, conn, p, 2*time.Minute, g.idle)
}

// relay runs both directions of one stream until it ends, or until it has been idle for `idle`. When the connector side ends, the
// connector is stopped and its pipes closed at once, so a request blocked writing to it returns.
// When the caller stops sending, the connector gets end of input and `grace` to finish its answers
// (a connector call is bounded at two minutes); then it and the caller's connection are closed.
func (s *stream) relay(caller io.Reader, reply io.WriteCloser, p *process, grace, idle time.Duration) {
	done := make(chan struct{})
	// A stream with no traffic either way for `idle` is closed, connector and caller both; an idle of
	// zero never closes one (idleMinutes: 0). The stream bounds still hold.
	s.touch()
	quiet := make(chan struct{})
	defer close(quiet)
	go func() {
		if idle <= 0 {
			return
		}
		tick := time.NewTicker(idle / 4)
		defer tick.Stop()
		for {
			select {
			case <-quiet:
				return
			case now := <-tick.C:
				if now.Sub(time.Unix(0, s.last.Load())) > idle {
					s.log.Warn("closing an idle stream", "workspace", s.ws, "connector", s.conn.Name)
					p.stop()
					_ = reply.Close()
					return
				}
			}
		}
	}()
	go func() {
		_ = s.answers(p.out, reply)
		p.stop()
		_ = reply.Close()
		close(done)
	}()
	_ = s.requests(caller, reply, p.in)
	_ = p.in.Close()
	select {
	case <-done:
	case <-time.After(grace):
		// Closing the caller's connection too unblocks an answer stuck writing to a caller that
		// stopped reading.
		p.stop()
		_ = reply.Close()
		<-done
	}
}

// matches reports whether the caller's declaration is this source's configuration.
func (s source) matches(d declared) bool {
	// An omitted scheme is us-gov, as it always was; an explicit digest must be this one.
	declared := d.Scheme
	if declared == "" {
		declared = usGovDigest
	}
	if declared != s.scheme.Digest() {
		return false // a classification read under another scheme is never compared
	}
	m, err := s.scheme.Parse(d.Classification)
	if err != nil || marking.Banner(m) != marking.Banner(s.marking) || d.Writes != s.Writes {
		return false
	}
	if d.Flags == nil {
		d.Flags = map[string]string{}
	}
	flags := s.Flags
	if flags == nil {
		flags = map[string]string{}
	}
	return maps.Equal(d.Flags, flags)
}
