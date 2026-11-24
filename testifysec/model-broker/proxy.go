package broker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
)

// secret reads a mounted credential file on each use so key rotation needs no restart.
func secret(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || len(b) > 64<<10 {
		return ""
	}
	s := strings.TrimSpace(string(b))
	for _, c := range s {
		if c < 0x21 || c > 0x7e {
			return ""
		}
	}
	return s
}

// auditSafe passes identifiers made of [A-Za-z0-9._/:@-] and suppresses anything else, so a
// value can never forge or split a log line.
func auditSafe(s string) string {
	if s == "" || len(s) > 256 {
		return "suppressed"
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._/:@-", c)) {
			return "suppressed"
		}
	}
	return s
}

func failure(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	io.WriteString(w, `{"error":{"message":"Request unavailable","type":"broker_error"}}`)
}

type flushWriter struct{ http.ResponseWriter }

func (w flushWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if err == nil {
		err = http.NewResponseController(w.ResponseWriter).Flush()
	}
	return n, err
}

// chatRequest is a parsed chat completion body. model is nil when the body named none.
type chatRequest struct {
	payload map[string]json.RawMessage
	model   *string
}

// readChat reads and parses the body. It returns an HTTP status on failure.
func readChat(w http.ResponseWriter, r *http.Request) (*chatRequest, int) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		var limit *http.MaxBytesError
		if errors.As(err, &limit) {
			return nil, http.StatusRequestEntityTooLarge
		}
		return nil, http.StatusBadRequest
	}
	var payload map[string]json.RawMessage
	if !utf8.Valid(body) || json.Unmarshal(body, &payload) != nil || payload == nil {
		return nil, http.StatusBadRequest
	}
	c := &chatRequest{payload: payload}
	if raw, ok := payload["model"]; ok {
		var m string
		if json.Unmarshal(raw, &m) != nil {
			return nil, http.StatusBadRequest
		}
		c.model = &m
	}
	return c, 0
}

// upstream forwards chat completions to the configured routes.
type upstream struct {
	routes    map[string]*RouteConfig
	order     []*RouteConfig
	client    http.Client
	active    chan struct{}
	usage     *usageBook
	modelList string
}

func newUpstream(routes []RouteConfig, concurrency int, client *http.Client, limits UpstreamConfig) *upstream {
	u := &upstream{routes: map[string]*RouteConfig{}, active: make(chan struct{}, concurrency), usage: &usageBook{prices: map[string]Price{}, window: callWindow(limits)}}
	u.usage.prices = map[string]Price{}
	var list strings.Builder
	list.WriteString(`{"object":"list","data":[`)
	for i := range routes {
		r := &routes[i]
		u.routes[r.Model], u.order = r, append(u.order, r)
		if r.Price != nil {
			u.usage.prices[r.Model] = *r.Price
		}
		if i > 0 {
			list.WriteString(",")
		}
		b, _ := json.Marshal(map[string]any{"id": r.Model, "object": "model", "created": 0, "owned_by": "badger-broker"})
		list.Write(b)
	}
	list.WriteString("]}")
	u.modelList = list.String()
	if client != nil {
		u.client = *client
	}
	if u.client.Transport == nil {
		u.client.Transport = &http.Transport{
			Proxy:                  nil,
			DialContext:            (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:    10 * time.Second,
			ResponseHeaderTimeout:  time.Duration(limits.ResponseHeaderSeconds) * time.Second,
			IdleConnTimeout:        90 * time.Second,
			MaxIdleConns:           concurrency,
			MaxIdleConnsPerHost:    concurrency,
			MaxConnsPerHost:        concurrency,
			MaxResponseHeaderBytes: 64 << 10,
			DisableCompression:     true,
		}
	}
	u.client.Timeout = time.Duration(limits.RequestSeconds) * time.Second
	u.client.Jar = nil
	u.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return u
}

func (u *upstream) ready() bool {
	for _, r := range u.order {
		if secret(r.KeyFile) == "" {
			return false
		}
	}
	return true
}

// forward sends one chat completion for principal to route rt and relays the answer. a is what the
// principal's call is held to: its output cap, and its limits, checked again as the call is admitted
// to the ledger.
func (u *upstream) forward(w http.ResponseWriter, r *http.Request, principal string, label pgdb.Label, attr usageAttr, rt *RouteConfig, c *chatRequest, a admission) {
	payload := c.payload
	w.Header().Set("X-Broker-Usage-Principal", principal)
	payload["model"] = json.RawMessage(strconv.Quote(rt.Model))
	effort := ""
	if raw, ok := payload["reasoning_effort"]; ok {
		if json.Unmarshal(raw, &effort) != nil {
			failure(w, http.StatusBadRequest)
			return
		}
		if mapped, ok := rt.ReasoningMap[effort]; ok {
			effort = mapped
			payload["reasoning_effort"] = json.RawMessage(strconv.Quote(mapped))
		}
		if _, tools := payload["tools"]; tools && rt.NoReasoningWithTools {
			effort = ""
			delete(payload, "reasoning_effort")
		}
	}
	key := secret(rt.KeyFile)
	if key == "" {
		failure(w, http.StatusServiceUnavailable)
		return
	}
	// Reasoning models reject max_tokens; send the replacement field instead.
	if limit, ok := payload["max_tokens"]; ok {
		if _, duplicate := payload["max_completion_tokens"]; duplicate {
			failure(w, http.StatusBadRequest)
			return
		}
		payload["max_completion_tokens"] = limit
		delete(payload, "max_tokens")
	}
	// The output the principal may ask for, whatever the caller sent; the provider enforces it.
	u.usage.mu.Lock()
	price, priced := u.usage.prices[rt.Model]
	u.usage.mu.Unlock()
	if !priced {
		price.Output = 0
	}
	if most := a.outputCap(&price); most > 0 {
		var asked int
		if json.Unmarshal(payload["max_completion_tokens"], &asked) != nil || asked < 1 || asked > most {
			payload["max_completion_tokens"] = json.RawMessage(strconv.Itoa(most))
		}
	}
	// Ask for the final usage chunk so usage can be counted for streamed answers.
	var stream bool
	if raw, ok := payload["stream"]; ok && json.Unmarshal(raw, &stream) == nil && stream {
		options := map[string]json.RawMessage{}
		if raw, ok := payload["stream_options"]; ok && json.Unmarshal(raw, &options) != nil {
			failure(w, http.StatusBadRequest)
			return
		}
		if options == nil { // "stream_options": null
			options = map[string]json.RawMessage{}
		}
		options["include_usage"] = json.RawMessage("true")
		payload["stream_options"], _ = json.Marshal(options)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		failure(w, http.StatusBadRequest)
		return
	}
	select {
	case u.active <- struct{}{}:
		defer func() { <-u.active }()
	default:
		failure(w, http.StatusTooManyRequests)
		return
	}
	req, err := http.NewRequestWithContext(context.WithoutCancel(r.Context()), http.MethodPost, rt.target.String(), strings.NewReader(string(body)))
	if err != nil {
		failure(w, http.StatusBadGateway)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if rt.AuthHeader == "Authorization" {
		req.Header.Set("Authorization", "Bearer "+key)
	} else {
		req.Header.Set(rt.AuthHeader, key)
	}
	req.Header["User-Agent"] = nil
	// Write the call to the ledger before it reaches the model; every path below finishes it, and
	// any path that does not say otherwise records its usage as unknown.
	call, err := u.usage.admit(label, principal, rt.Model, time.Now(), &a)
	switch {
	case errors.Is(err, errOverQuota):
		writeErr(w, http.StatusTooManyRequests, apiError{Code: "quota_exceeded",
			Message: "the monthly quota is reached, counting calls still running; try again when they finish"})
		return
	case errors.Is(err, errSpendUnknown):
		writeErr(w, http.StatusServiceUnavailable, apiError{Code: "quota_unavailable",
			Message: "this month's spend cannot be rebuilt from the usage ledger; an admin must repair it"})
		return
	case err != nil:
		failure(w, http.StatusServiceUnavailable)
		return
	}
	finished := false
	finish := func(t tokens) {
		finished = true
		u.usage.finish(call, principal, rt.Model, attr, t, time.Now())
	}
	defer func() {
		if !finished {
			finish(tokens{Unknown: true})
		}
	}()
	resp, err := u.client.Do(req)
	if err != nil {
		failure(w, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Log only constrained diagnostic identifiers, never the response body or prompt.
		var diagnostic struct {
			Error struct {
				Code  string `json:"code"`
				Param string `json:"param"`
			} `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 16384)).Decode(&diagnostic)
		safe := func(s string) string {
			if len(s) > 64 {
				return "suppressed"
			}
			for _, c := range s {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
					return "suppressed"
				}
			}
			return s
		}
		keys := make([]string, 0, len(payload))
		for k := range payload {
			keys = append(keys, safe(k))
		}
		log.Printf("upstream status=%d code=%s parameter=%s model=%s reasoning=%s keys=%s", resp.StatusCode,
			safe(diagnostic.Error.Code), safe(diagnostic.Error.Param), rt.Model, safe(effort), strings.Join(keys, ","))
		status := resp.StatusCode
		if status < 400 || status > 599 {
			status = http.StatusBadGateway
		}
		if retry := resp.Header.Get("Retry-After"); retry != "" && strings.IndexFunc(retry, func(c rune) bool { return c < '0' || c > '9' }) == -1 {
			if _, err := strconv.ParseUint(retry, 10, 32); err == nil {
				w.Header().Set("Retry-After", retry)
			}
		}
		finish(tokens{}) // the model refused the call; nothing is billed
		failure(w, status)
		return
	}
	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || (contentType != "application/json" && contentType != "text/event-stream") {
		failure(w, http.StatusBadGateway)
		return
	}
	if contentType == "text/event-stream" {
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(resp.StatusCode)
		// The model is already working and billing; if the client has gone, keep reading so the
		// usage at the end of the stream is still counted.
		tee := &usageTee{w: flushWriter{w}, werr: http.NewResponseController(w).Flush()}
		// A read that fails partway may have dropped the final usage after a running total.
		_, rerr := io.Copy(tee, resp.Body)
		tee.used.Unknown = rerr != nil || !tee.complete()
		finish(tee.used)
		return
	}
	response, err := io.ReadAll(io.LimitReader(resp.Body, (8<<20)+1))
	if err != nil || len(response) > 8<<20 {
		// The model may have done (and billed) the work; what it cost is unknown.
		failure(w, http.StatusBadGateway)
		return
	}
	used, _, valid := usageOf(response)
	used.Unknown = !valid
	finish(used)
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(resp.StatusCode)
	w.Write(response)
}
