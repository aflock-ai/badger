package connector

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"slices"
)

// The MCP subset a tools-only stdio server needs (newline-delimited JSON-RPC 2.0): initialize,
// ping, tools/list and tools/call. Notifications (no id) are accepted and ignored. Requests are
// handled one at a time, in order.

// protocolVersions are the MCP revisions this server answers; the first is offered when the
// client asks for one it does not know.
// metaKey names the machine-readable classification in each tools/call result's _meta. OpenCode
// reads it to keep the session high-water mark (see testifysec/CONNECTORS.md).
const metaKey = "com.testifysec/classification"

var protocolVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

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

// Serve reads requests from r and writes responses to w until r ends.
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	in := bufio.NewScanner(r)
	in.Buffer(make([]byte, 64<<10), 4<<20)
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
			continue // notification
		}
		result, rerr := s.handle(ctx, req)
		if err := out.Encode(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result, Error: rerr}); err != nil {
			return err
		}
	}
	return in.Err()
}

func (s *Server) handle(ctx context.Context, req rpcRequest) (any, *rpcError) {
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
			"serverInfo":      map[string]string{"name": "badger-" + s.spec.Name, "version": s.spec.Version},
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		tools := []map[string]any{}
		for _, n := range s.ToolNames() {
			t := s.tools[n]
			tools = append(tools, map[string]any{"name": t.Name, "description": t.Description, "inputSchema": t.InputSchema,
				"annotations": map[string]bool{"readOnlyHint": !t.Write, "openWorldHint": true}})
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
		r := s.Call(ctx, p.Name, p.Arguments)
		return map[string]any{"content": []map[string]string{{"type": "text", "text": r.Text}}, "isError": r.IsError,
			"_meta": map[string]any{metaKey: map[string]any{"schema": 1, "banner": r.Banner}}}, nil
	default:
		return nil, &rpcError{-32601, "method not found"}
	}
}
