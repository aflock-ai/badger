//go:build ignore

// Local UAT fixture only. No production credentials or external model calls.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sync"
)

func main() {
	var mu sync.Mutex
	calls := 0
	var events []json.RawMessage
	var credentials []bool
	persist := func() {
		data, _ := json.Marshal(map[string]any{"providerRequests": calls, "credentialIsolated": credentials, "auditBatches": events})
		_ = os.WriteFile("/private/observations.json", data, 0600)
	}
	server := &http.Server{Addr: "127.0.0.1:8090", Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		defer persist()
		data, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		if err != nil {
			http.Error(w, "fixture failed", 400)
			return
		}
		if r.URL.Path == "/v1/logs" {
			events = append(events, json.RawMessage(data))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{}"))
			return
		}
		if r.URL.Path != "/v1/chat/completions" {
			http.Error(w, "unsupported", 404)
			return
		}
		calls++
		credentials = append(credentials, r.Header.Get("Authorization") == "Bearer synthetic-provider-credential")
		var body struct {
			Model    string
			Messages []struct{ Role string }
			Tools    []struct {
				Function struct {
					Name       string
					Parameters struct{ Properties map[string]json.RawMessage }
				}
			}
		}
		if json.Unmarshal(data, &body) != nil || body.Model != "approved" {
			http.Error(w, "bad fixture model", 400)
			return
		}
		names := map[string]bool{}
		// OpenCode 2.0's write tool names its target `path`, 1.x's `filePath`: follow the advertised one.
		target := "filePath"
		for _, tool := range body.Tools {
			names[tool.Function.Name] = true
			if _, ok := tool.Function.Parameters.Properties["path"]; ok && tool.Function.Name == "write" {
				target = "path"
			}
		}
		for _, name := range []string{"task", "webfetch", "websearch", "lsp", "skill", "question"} {
			if names[name] {
				http.Error(w, "forbidden tool", 400)
				return
			}
		}
		results := 0
		for _, message := range body.Messages {
			if message.Role == "tool" {
				results++
			}
		}
		operation := ""
		var arguments any
		if names["write"] && results == 0 {
			operation = "write"
			arguments = map[string]any{target: "/workspace/result.txt", "content": "hardened-worker-verified\n"}
		}
		if (names["bash"] || names["shell"]) && results == 1 {
			operation = "shell"
			if names["bash"] {
				operation = "bash"
			}
			arguments = map[string]any{"command": "test \"$(cat result.txt)\" = hardened-worker-verified && printf 'HARNESS_TEST_PASSED\\n'", "description": "Check generated file", "timeout": 10000}
		}
		chunk := func(delta any, finish any) map[string]any {
			return map[string]any{"id": fmt.Sprint("fixture-", calls), "object": "chat.completion.chunk", "created": 1, "model": "approved", "choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}}}
		}
		var first, last map[string]any
		if operation != "" {
			arg, _ := json.Marshal(arguments)
			first = chunk(map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"index": 0, "id": fmt.Sprint("call-", calls), "type": "function", "function": map[string]any{"name": operation, "arguments": string(arg)}}}}, nil)
			last = chunk(map[string]any{}, "tool_calls")
		} else {
			first = chunk(map[string]any{"role": "assistant", "content": "Managed file and test journey completed."}, nil)
			last = chunk(map[string]any{}, "stop")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		for _, event := range []any{first, last} {
			raw, _ := json.Marshal(event)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", raw)
		}
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
	})}
	go func() {
		if err := server.ListenAndServe(); err != nil {
			fmt.Fprintln(os.Stderr, "fixture service stopped")
		}
	}()
	command := exec.Command("/tools/hardened-gateway", "--config", "/private/config.json")
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/private", "TMPDIR=/tmp"}
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		os.Exit(1)
	}
}
