package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

type jsonObject map[string]json.RawMessage

func fields(value jsonObject, allowed ...string) bool {
	if value == nil {
		return false
	}
	set := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		set[name] = true
	}
	for name := range value {
		if !set[name] {
			return false
		}
	}
	return true
}

func object(raw json.RawMessage) jsonObject {
	var value jsonObject
	if json.Unmarshal(raw, &value) != nil {
		return nil
	}
	return value
}

func text(raw json.RawMessage) (string, bool) {
	var value string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	return value, true
}

func oneOf(raw json.RawMessage, choices ...string) bool {
	s, ok := text(raw)
	if !ok {
		return false
	}
	for _, choice := range choices {
		if s == choice {
			return true
		}
	}
	return false
}

func optionalString(value jsonObject, key string) bool {
	raw, exists := value[key]
	if !exists {
		return true
	}
	_, ok := text(raw)
	return ok
}

func optionalBool(value jsonObject, key string) bool {
	raw, exists := value[key]
	return !exists || bytes.Equal(raw, []byte("true")) || bytes.Equal(raw, []byte("false"))
}

func array(raw json.RawMessage, limit int) ([]json.RawMessage, bool) {
	var values []json.RawMessage
	if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &values) != nil || len(values) > limit {
		return nil, false
	}
	return values, true
}

// This is a deliberately bounded stateless text/function subset. Hosted tools,
// remote files/images, stored item/conversation references and background jobs
// cannot create effects outside this gateway's one admitted HTTP request.
func validateResponsesRequest(body jsonObject) error {
	bad := errors.New("unsupported Responses schema")
	if !fields(body, "model", "input", "instructions", "stream", "store", "background", "tools", "tool_choice", "parallel_tool_calls", "temperature", "top_p", "max_output_tokens", "reasoning", "text", "include") || !bytes.Equal(body["store"], []byte("false")) {
		return bad
	}
	if raw, ok := body["background"]; ok && !bytes.Equal(raw, []byte("false")) {
		return bad
	}
	if !optionalString(body, "instructions") || !optionalBool(body, "stream") || !optionalBool(body, "parallel_tool_calls") {
		return bad
	}
	for _, key := range []string{"temperature", "top_p", "max_output_tokens"} {
		if raw, ok := body[key]; ok {
			if oneOf(body["model"], "gpt-6-astra") && key != "max_output_tokens" {
				return bad
			}
			var value float64
			if bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, &value) != nil || value < 0 || value > 32768 {
				return bad
			}
			if key == "max_output_tokens" && (value < 1 || value != float64(int64(value))) {
				return bad
			}
			if key == "temperature" && value > 2 || key == "top_p" && value > 1 {
				return bad
			}
		}
	}
	if input, ok := text(body["input"]); ok {
		if input == "" {
			return bad
		}
	} else {
		input, ok := array(body["input"], 4096)
		if !ok || len(input) == 0 {
			return bad
		}
		for _, raw := range input {
			if !responsesInput(object(raw)) {
				return bad
			}
		}
	}
	if raw, exists := body["include"]; exists {
		include, ok := array(raw, 1)
		if !ok {
			return bad
		}
		for _, value := range include {
			if !oneOf(value, "reasoning.encrypted_content") {
				return bad
			}
		}
	}
	if raw, exists := body["tools"]; exists {
		tools, ok := array(raw, 128)
		if !ok {
			return bad
		}
		seen := map[string]bool{}
		for _, raw := range tools {
			tool := object(raw)
			name, named := text(tool["name"])
			if !fields(tool, "type", "name", "description", "parameters", "strict") || !oneOf(tool["type"], "function") || !named || name == "" || len(name) > 128 || seen[name] || !optionalString(tool, "description") || !optionalBool(tool, "strict") || object(tool["parameters"]) == nil {
				return bad
			}
			seen[name] = true
		}
	}
	if raw, exists := body["tool_choice"]; exists && !oneOf(raw, "none", "auto", "required") {
		choice := object(raw)
		name, ok := text(choice["name"])
		if !fields(choice, "type", "name") || !oneOf(choice["type"], "function") || !ok || name == "" {
			return bad
		}
	}
	if raw, exists := body["reasoning"]; exists {
		reasoning := object(raw)
		if !fields(reasoning, "effort", "summary") {
			return bad
		}
		if v, ok := reasoning["effort"]; ok {
			// Exact reviewed model contract; a prefix or alias cannot opt another
			// model into max. The caller's model already matched the admin pin.
			efforts := []string{"none", "minimal", "low", "medium", "high", "xhigh"}
			if oneOf(body["model"], "gpt-6-astra") {
				efforts = []string{"low", "medium", "high", "xhigh", "max"}
			}
			if !oneOf(v, efforts...) {
				return bad
			}
		}
		if v, ok := reasoning["summary"]; ok && !oneOf(v, "auto", "concise", "detailed") {
			return bad
		}
	}
	if raw, exists := body["text"]; exists {
		format := object(raw)
		if !fields(format, "format", "verbosity") {
			return bad
		}
		if v, ok := format["verbosity"]; ok && !oneOf(v, "low", "medium", "high") {
			return bad
		}
		if v, ok := format["format"]; ok {
			f := object(v)
			if !fields(f, "type", "name", "description", "schema", "strict") || !oneOf(f["type"], "text", "json_object", "json_schema") || !optionalString(f, "name") || !optionalString(f, "description") || !optionalBool(f, "strict") {
				return bad
			}
			if oneOf(f["type"], "json_schema") && object(f["schema"]) == nil {
				return bad
			}
		}
	}
	return nil
}

func responsesInput(item jsonObject) bool {
	switch {
	case len(item["type"]) == 0 || oneOf(item["type"], "message"):
		if !fields(item, "type", "role", "content", "id", "status") || !oneOf(item["role"], "system", "developer", "user", "assistant") || !optionalString(item, "id") || !optionalString(item, "status") {
			return false
		}
		if _, ok := text(item["content"]); ok {
			return true
		}
		parts, ok := array(item["content"], 4096)
		if !ok || len(parts) == 0 {
			return false
		}
		for _, raw := range parts {
			part := object(raw)
			if oneOf(part["type"], "refusal") {
				if !fields(part, "type", "refusal") || !optionalString(part, "refusal") || part["refusal"] == nil {
					return false
				}
				continue
			}
			if !fields(part, "type", "text", "annotations") || !oneOf(part["type"], "input_text", "output_text") {
				return false
			}
			if _, ok := text(part["text"]); !ok {
				return false
			}
			if annotations, exists := part["annotations"]; exists {
				if values, ok := array(annotations, 0); !ok || len(values) != 0 {
					return false
				}
			}
		}
		return true
	case oneOf(item["type"], "function_call"):
		return fields(item, "type", "id", "call_id", "name", "arguments", "status") && requiredStrings(item, "call_id", "name", "arguments") && optionalString(item, "id") && optionalString(item, "status")
	case oneOf(item["type"], "function_call_output"):
		return fields(item, "type", "id", "call_id", "output", "status") && requiredStrings(item, "call_id", "output") && optionalString(item, "id") && optionalString(item, "status")
	case oneOf(item["type"], "reasoning"):
		if !fields(item, "type", "id", "summary", "encrypted_content") || !optionalString(item, "id") || !optionalString(item, "encrypted_content") {
			return false
		}
		parts, ok := array(item["summary"], 4096)
		if !ok {
			return false
		}
		for _, raw := range parts {
			part := object(raw)
			if !fields(part, "type", "text") || !oneOf(part["type"], "summary_text") || !requiredStrings(part, "text") {
				return false
			}
		}
		return len(parts) > 0 || requiredStrings(item, "encrypted_content")
	}
	return false
}

func requiredStrings(item jsonObject, names ...string) bool {
	for _, name := range names {
		if _, ok := text(item[name]); !ok {
			return false
		}
	}
	return true
}

func identifier(raw json.RawMessage) bool {
	value, ok := text(raw)
	return ok && len(value) > 0 && len(value) <= 256
}
func index(raw json.RawMessage) bool {
	var value int
	return !bytes.Equal(raw, []byte("null")) && json.Unmarshal(raw, &value) == nil && value >= 0 && value < 4096
}
func responsePart(part jsonObject) bool {
	switch {
	case oneOf(part["type"], "output_text"):
		if !fields(part, "type", "text", "annotations", "logprobs") || !requiredStrings(part, "text") {
			return false
		}
		for _, key := range []string{"annotations", "logprobs"} {
			if raw, ok := part[key]; ok {
				if _, ok := array(raw, 0); !ok {
					return false
				}
			}
		}
		return true
	case oneOf(part["type"], "refusal"):
		return fields(part, "type", "refusal") && requiredStrings(part, "refusal")
	case oneOf(part["type"], "summary_text", "reasoning_text"):
		return fields(part, "type", "text") && requiredStrings(part, "text")
	}
	return false
}
func responsesOutput(item jsonObject) bool {
	// Responses metadata fields are not interpreted as authority. Output item
	// types are limited to the admitted text/reasoning/function protocol.
	switch {
	case oneOf(item["type"], "message"):
		if !fields(item, "type", "id", "role", "status", "content", "phase") || !oneOf(item["role"], "assistant") || !oneOf(item["status"], "in_progress", "completed", "incomplete") {
			return false
		}
		parts, ok := array(item["content"], 4096)
		if !ok {
			return false
		}
		for _, raw := range parts {
			if !responsePart(object(raw)) {
				return false
			}
		}
		if raw, ok := item["phase"]; ok && !bytes.Equal(raw, []byte("null")) && !oneOf(raw, "commentary", "final_answer") {
			return false
		}
	case oneOf(item["type"], "function_call"):
		if !fields(item, "type", "id", "call_id", "name", "arguments", "status") || !identifier(item["call_id"]) || !identifier(item["name"]) || !requiredStrings(item, "arguments") {
			return false
		}
	case oneOf(item["type"], "reasoning"):
		if !fields(item, "type", "id", "summary", "encrypted_content", "content", "status") {
			return false
		}
		for _, key := range []string{"summary", "content"} {
			if raw, ok := item[key]; ok {
				parts, ok := array(raw, 4096)
				if !ok {
					return false
				}
				for _, raw := range parts {
					if !responsePart(object(raw)) {
						return false
					}
				}
			}
		}
		if raw, ok := item["encrypted_content"]; ok && !bytes.Equal(raw, []byte("null")) {
			if _, ok := text(raw); !ok {
				return false
			}
		}
	default:
		return false
	}
	if raw, ok := item["id"]; ok && !identifier(raw) {
		return false
	}
	if raw, ok := item["status"]; ok && !oneOf(raw, "in_progress", "completed", "incomplete") {
		return false
	}
	return true
}

func responseOutcome(value jsonObject, model string) (string, string, error) {
	bad := errors.New("invalid Responses result")
	id, ok := text(value["id"])
	if !ok || id == "" || len(id) > 256 || !oneOf(value["object"], "response") || !oneOf(value["model"], model) {
		return "", "", bad
	}
	output, valid := array(value["output"], 4096)
	if valid {
		for _, raw := range output {
			if !responsesOutput(object(raw)) {
				valid = false
				break
			}
		}
	}
	if !valid {
		return "", "", bad
	}
	status, _ := text(value["status"])
	switch status {
	case "completed":
		for _, key := range []string{"error", "incomplete_details"} {
			if raw, exists := value[key]; exists && !bytes.Equal(raw, []byte("null")) {
				return "", "", bad
			}
		}
		for _, raw := range output {
			item := object(raw)
			if oneOf(item["type"], "message") {
				parts, valid := array(item["content"], 4096)
				if !valid {
					return "", "", bad
				}
				for _, part := range parts {
					if oneOf(object(part)["type"], "refusal") {
						return id, "provider-response-refused", nil
					}
				}
			}
		}
		return id, "provider-response-completed", nil
	case "failed":
		return id, "provider-response-failed", nil
	case "incomplete":
		return id, "provider-response-incomplete", nil
	default:
		return "", "", bad
	}
}

// Complete frames are parsed before forwarding. Terminal bytes are retained
// until clean EOF, so a later duplicate/truncated event cannot expose a false
// success marker to the caller before the gateway detects it.
type responsesSSE struct {
	line, frame, data  []byte
	event              string
	sequence           int64
	started            bool
	id, model, outcome string
	terminal           []byte
	refusal            bool
}

func (s *responsesSSE) observe(chunk []byte) ([]byte, error) {
	var forward []byte
	for _, ch := range chunk {
		s.frame = append(s.frame, ch)
		if len(s.frame) > 64*1024 {
			return nil, errors.New("Responses event limit")
		}
		if ch != '\n' {
			s.line = append(s.line, ch)
			continue
		}
		line := bytes.TrimSuffix(s.line, []byte("\r"))
		s.line = nil
		if len(line) == 0 {
			if len(s.data) > 0 {
				if s.outcome != "" {
					return nil, errors.New("event after Responses terminal")
				}
				if err := s.accept(); err != nil {
					return nil, err
				}
				if s.outcome != "" {
					s.terminal = append([]byte(nil), s.frame...)
				} else {
					forward = append(forward, s.frame...)
				}
			}
			s.frame, s.data, s.event = nil, nil, ""
			continue
		}
		if line[0] == ':' {
			continue
		}
		key, value, found := bytes.Cut(line, []byte(":"))
		if !found {
			return nil, errors.New("invalid SSE field")
		}
		value = bytes.TrimPrefix(value, []byte(" "))
		switch string(key) {
		case "event":
			if s.event != "" {
				return nil, errors.New("duplicate SSE event")
			}
			s.event = string(value)
		case "data":
			s.data = append(s.data, value...)
			s.data = append(s.data, '\n')
		default:
			return nil, errors.New("unsupported SSE field")
		}
	}
	return forward, nil
}

func (s *responsesSSE) accept() error {
	var event jsonObject
	if err := strictJSON(s.data, &event); err != nil || event == nil {
		return errors.New("invalid Responses event JSON")
	}
	typeName, ok := text(event["type"])
	var seq int64
	if !ok || s.event != "" && s.event != typeName || bytes.Equal(event["sequence_number"], []byte("null")) || json.Unmarshal(event["sequence_number"], &seq) != nil || seq < 0 || s.started && seq <= s.sequence {
		return errors.New("invalid Responses event identity")
	}
	s.sequence = seq
	response := object(event["response"])
	switch typeName {
	case "response.created":
		if !fields(event, "type", "sequence_number", "response") {
			return errors.New("invalid Responses creation fields")
		}
		id, ok := text(response["id"])
		if s.started || !ok || id == "" || len(id) > 256 || !oneOf(response["object"], "response") || !oneOf(response["model"], s.model) || !oneOf(response["status"], "in_progress", "queued") {
			return errors.New("invalid Responses creation")
		}
		s.started, s.id = true, id
	case "response.completed", "response.failed", "response.incomplete":
		if !fields(event, "type", "sequence_number", "response") {
			return errors.New("invalid Responses terminal fields")
		}
		id, outcome, err := responseOutcome(response, s.model)
		if err != nil || !s.started || id != s.id || !oneOf(response["status"], strings.TrimPrefix(typeName, "response.")) {
			return errors.New("invalid Responses terminal")
		}
		if s.refusal && outcome == "provider-response-completed" {
			outcome = "provider-response-refused"
		}
		s.outcome = outcome
	case "response.in_progress":
		if !fields(event, "type", "sequence_number", "response") {
			return errors.New("invalid Responses progress fields")
		}
		if !s.started || !oneOf(response["id"], s.id) || !oneOf(response["model"], s.model) || !oneOf(response["status"], "in_progress") {
			return errors.New("invalid Responses progress")
		}
	case "response.output_item.added", "response.output_item.done":
		if !s.started || !fields(event, "type", "sequence_number", "output_index", "item") || !index(event["output_index"]) || !responsesOutput(object(event["item"])) {
			return errors.New("invalid Responses output item")
		}
	case "response.content_part.added", "response.content_part.done", "response.reasoning_summary_part.added", "response.reasoning_summary_part.done":
		if !s.started || !fields(event, "type", "sequence_number", "output_index", "item_id", "content_index", "summary_index", "part") || !index(event["output_index"]) || !identifier(event["item_id"]) || !responsePart(object(event["part"])) {
			return errors.New("invalid Responses part")
		}
		key := "content_index"
		if strings.Contains(typeName, "reasoning_summary") {
			key = "summary_index"
		}
		if !index(event[key]) {
			return errors.New("invalid Responses part index")
		}
	case "response.output_text.delta", "response.output_text.done", "response.refusal.delta", "response.refusal.done", "response.function_call_arguments.delta", "response.function_call_arguments.done", "response.reasoning_summary_text.delta", "response.reasoning_summary_text.done", "response.reasoning_text.delta", "response.reasoning_text.done":
		if !s.started || !fields(event, "type", "sequence_number", "output_index", "item_id", "content_index", "summary_index", "delta", "text", "refusal", "arguments", "name", "obfuscation", "logprobs") || !index(event["output_index"]) || !identifier(event["item_id"]) {
			return errors.New("invalid Responses content")
		}
		key := "text"
		if strings.Contains(typeName, "function_call_arguments") {
			key = "arguments"
		} else if strings.Contains(typeName, "refusal") {
			key = "refusal"
		}
		if strings.HasSuffix(typeName, ".delta") {
			key = "delta"
		}
		if !requiredStrings(event, key) || !optionalString(event, "name") {
			return errors.New("invalid Responses text")
		}
		if !strings.Contains(typeName, "function_call_arguments") {
			key = "content_index"
			if strings.Contains(typeName, "reasoning_summary") {
				key = "summary_index"
			}
			if !index(event[key]) {
				return errors.New("invalid Responses text index")
			}
		}
		if raw, ok := event["obfuscation"]; ok && !bytes.Equal(raw, []byte("null")) {
			if _, ok := text(raw); !ok {
				return errors.New("invalid obfuscation")
			}
		}
		if raw, ok := event["logprobs"]; ok && !bytes.Equal(raw, []byte("null")) {
			if _, ok := array(raw, 0); !ok {
				return errors.New("log probabilities not supported")
			}
		}
		if strings.HasPrefix(typeName, "response.refusal.") {
			s.refusal = true
		}

	default:
		return errors.New("unsupported Responses event type")
	}
	return nil
}

func forwardResponses(w http.ResponseWriter, body io.Reader, streaming bool, model string, count *int64) (string, bool) {
	const limit = 16 * 1024 * 1024
	write := func(raw []byte) bool { n, err := w.Write(raw); *count += int64(n); return err == nil }
	if !streaming {
		raw, err := io.ReadAll(io.LimitReader(body, limit+1))
		if err != nil || len(raw) > limit {
			http.Error(w, "invalid provider response", 502)
			return "response-interrupted", false
		}
		var response jsonObject
		if strictJSON(raw, &response) != nil {
			http.Error(w, "invalid provider response", 502)
			return "response-interrupted", false
		}
		_, outcome, err := responseOutcome(response, model)
		if err != nil {
			http.Error(w, "invalid provider response", 502)
			return "response-interrupted", false
		}
		if !write(raw) {
			return "cancelled", false
		}
		return outcome, false
	}
	stream := responsesSSE{model: model}
	buffer := make([]byte, 32768)
	total := 0
	for {
		n, err := body.Read(buffer)
		total += n
		if total > limit {
			return "response-limit", true
		}
		if n > 0 {
			ready, parseErr := stream.observe(buffer[:n])
			if parseErr != nil {
				return "response-interrupted", true
			}
			if len(ready) > 0 {
				if !write(ready) {
					return "cancelled", false
				}
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
		}
		if err == io.EOF {
			if stream.outcome == "" || len(stream.frame) > 0 || len(stream.line) > 0 {
				return "response-interrupted", true
			}
			if !write(stream.terminal) {
				return "cancelled", false
			}
			return stream.outcome, false
		}
		if err != nil {
			return "response-interrupted", true
		}
	}
}
