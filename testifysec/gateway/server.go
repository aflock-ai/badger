package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aflock-ai/badger/testifysec/connectors/marking"
	"github.com/aflock-ai/badger/testifysec/platform"
)

type Gateway struct {
	config    Config
	spool     *Spool
	client    *http.Client // provider requests only (it carries the provider pin)
	collector *http.Client // collector exports; nil in tests that share one client
	provider  credential
	active    chan struct{}
	identity  *platformsession.Client
	// models is the unsigned profile's allowlist, read at start; its bytes are pinned by digest, so
	// it cannot change while the gateway runs. Nil: only config.Model (allowed, models.go).
	models []ModelEntry
}

func newGateway(c Config) (*Gateway, error) {
	if c.requestPath() == "" {
		return nil, errors.New("unsupported provider protocol")
	}
	if err := profileConfiguration(c); err != nil {
		return nil, err
	}
	if err := identityConfiguration(c); err != nil {
		return nil, err
	}
	var identity *platformsession.Client
	if c.PlatformConfigFile != "" {
		binding, err := platformsession.LoadConfig(c.PlatformConfigFile)
		if err != nil {
			return nil, err
		}
		if binding.TenantID != c.Tenant || "spiffe://"+binding.TrustDomain+"/tenant/"+binding.TenantID+"/agent/"+binding.AgentID != c.Agent {
			return nil, errors.New("platform identity assignment mismatch")
		}
		identity, err = platformsession.New(binding)
		if err != nil {
			return nil, err
		}
	}
	p, err := token(c.ProviderTokenFile)
	if err != nil {
		return nil, err
	}
	// Checked at start; read again for each export (exportOne), so a renewed token is used.
	if _, err = token(c.CollectorTokenFile); err != nil {
		return nil, err
	}
	s, err := openSpool(c)
	if err != nil {
		return nil, err
	}
	var models []ModelEntry
	if c.ProfileFile != "" {
		// Checked now so a bad profile stops the gateway before it listens; checked again per request.
		if _, models, err = readUnsignedProfile(c, time.Now()); err != nil {
			return nil, err
		}
	}
	g := &Gateway{config: c, spool: s, active: make(chan struct{}, 1), identity: identity, client: providerClient(c), collector: collectorClient(c), models: models}
	g.provider.set(p)
	if c.ProviderTokenFD > 0 {
		// Inherited descriptors are not close-on-exec; keep this one out of every child.
		syscall.CloseOnExec(c.ProviderTokenFD)
		go g.provider.follow(os.NewFile(uintptr(c.ProviderTokenFD), "provider-token"))
	}
	return g, nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	record, err := g.spool.begin(0)
	if err != nil {
		http.Error(w, "required audit unavailable", 503)
		return
	}
	outcome, status := "request-denied", 400
	var responseBytes int64
	defer func() {
		if g.spool.finish(record, outcome, status, responseBytes) != nil {
			fmt.Println("audit terminal write failed; new actions blocked")
		}
	}()
	// The one other route: the provider's limits for this workspace (the model broker's GET
	// /v1/limits), read by the managed agent at start. It takes no input and not the model's slot.
	if r.Method == "GET" && r.URL.Path == "/v1/limits" && r.URL.RawPath == "" && r.URL.RawQuery == "" && !r.URL.IsAbs() {
		outcome, status = g.limits(w, r)
		return
	}
	// And the profile's models (models.go), which the gateway answers itself.
	if r.Method == "GET" && r.URL.Path == "/v1/models" && r.URL.RawPath == "" && r.URL.RawQuery == "" && !r.URL.IsAbs() {
		outcome, status = g.listModels(w)
		return
	}
	// The mounted socket itself is a session capability. Caller-supplied identity,
	// destinations, authorization, tracing headers and query strings have no authority.
	if r.Method != "POST" || r.URL.Path != g.config.requestPath() || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.IsAbs() || r.Header.Get("Content-Encoding") != "" {
		http.Error(w, "unsupported request", http.StatusBadRequest)
		return
	}
	select {
	case g.active <- struct{}{}:
		defer func() { <-g.active }()
	default:
		status = 429
		http.Error(w, "session busy", http.StatusTooManyRequests)
		return
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024*1024))
	if err != nil {
		status = 413
		http.Error(w, "request too large", 413)
		return
	}
	record.RequestBytes = len(b)
	var body map[string]json.RawMessage
	if err = strictJSON(b, &body); err != nil || body == nil {
		http.Error(w, "invalid request", 400)
		return
	}
	var model string
	err = json.Unmarshal(body["model"], &model)
	// The audit names the model the request asked for, if it is a well-formed ID (else the default).
	if err == nil && reModelID.MatchString(model) {
		record.Model = model
	}
	if err != nil || !g.allowed(model) {
		status = 403
		http.Error(w, "model not approved", 403)
		return
	}
	if g.config.Protocol == "responses" {
		if err = validateResponsesRequest(body); err != nil {
			http.Error(w, "unsupported Responses request", 400)
			return
		}
	} else {
		for key := range body {
			switch key {
			case "model", "messages", "stream", "stream_options", "tools", "tool_choice", "parallel_tool_calls", "temperature", "top_p", "max_tokens", "max_completion_tokens", "stop", "frequency_penalty", "presence_penalty", "seed", "response_format", "reasoning_effort":
			case "store":
				// Only the no-retention value; anything else could ask the provider to keep the conversation.
				if !bytes.Equal(body["store"], []byte("false")) {
					http.Error(w, "unsupported request field", 400)
					return
				}
			default:
				http.Error(w, "unsupported request field", 400)
				return
			}
		}
		var messages []json.RawMessage
		if err = json.Unmarshal(body["messages"], &messages); err != nil || len(messages) == 0 || len(messages) > 4096 {
			http.Error(w, "invalid messages", 400)
			return
		}
	}
	var streaming bool
	if value, ok := body["stream"]; ok {
		if bytes.Equal(value, []byte("null")) || json.Unmarshal(value, &streaming) != nil {
			http.Error(w, "invalid stream", 400)
			return
		}
	}
	profile, err := checkProfile(r.Context(), g.config)
	if err != nil {
		outcome, status = "profile-refused", 403
		http.Error(w, "signed profile unavailable or refused", status)
		return
	}
	profileExpiry := profile.expires
	// Gateway v3: every admitted connector must sit within this gateway's accredited marking, since
	// the worker could have read any of them. A connector's classification is the one its
	// administrator set, so within that ceiling nothing is read from the request body.
	if profile.accredited != nil {
		for _, m := range profile.connectors {
			if !marking.Dominates(*profile.accredited, m) {
				outcome, status = "classification-refused", 403
				http.Error(w, fmt.Sprintf("the signed profile admits a connector marked %s and this gateway is accredited for %s, so no request is sent", marking.Banner(m), marking.Banner(*profile.accredited)), status)
				return
			}
		}
	}
	if g.identity != nil {
		checked, err := g.identity.Check(r.Context())
		if err != nil {
			outcome, status = "identity-unavailable", 503
			if errors.Is(err, platformsession.ErrRefused) {
				outcome, status = "identity-refused", 403
			}
			http.Error(w, "platform identity unavailable", status)
			return
		}
		record.IdentitySource = "platform-online-check"
		record.IdentityCheckedAt = checked.CheckedAt
		record.RepositoryID = checked.RepositoryID
		record.DelegatingUserID = checked.Delegation.UserID
		record.EnrollmentAAL = checked.Delegation.EnrollmentAAL
		if err = g.spool.attribute(record); err != nil {
			outcome, status = "audit-unavailable", 503
			http.Error(w, "required audit unavailable", status)
			return
		}
	}
	if !profileExpiry.IsZero() && !time.Now().Before(profileExpiry) {
		outcome, status = "profile-refused", 403
		http.Error(w, "signed profile expired", status)
		return
	}
	// The start record on disk names the model actually sent before the provider sees it.
	if record.Model != g.config.Model {
		if err = g.spool.attribute(record); err != nil {
			outcome, status = "audit-unavailable", 503
			http.Error(w, "required audit unavailable", status)
			return
		}
	}
	outcome, status = "provider-unavailable", 0
	req, err := http.NewRequestWithContext(r.Context(), "POST", g.config.ProviderURL, bytes.NewReader(b))
	if err != nil {
		http.Error(w, "provider unavailable", 502)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	token := g.provider.get()
	if token == "" && g.config.ProviderTokenFD > 0 {
		outcome, status = "credential-unavailable", 503
		http.Error(w, "provider credential unavailable", status)
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := g.client.Do(req)
	if err != nil {
		if r.Context().Err() != nil {
			outcome = "cancelled"
		}
		http.Error(w, "provider unavailable", 502)
		return
	}
	defer res.Body.Close()
	status = res.StatusCode
	if status < 200 || status >= 300 {
		// A model broker's monthly quota refusal is final. The worker gets a fixed answer the
		// gateway writes itself (the provider's body is never reflected), marked not retryable,
		// so the session stops instead of retrying against a spent quota.
		if status == http.StatusTooManyRequests && providerQuotaExceeded(res.Body) {
			outcome = "provider-quota-exceeded"
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Should-Retry", "false")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"error":{"code":"quota_exceeded","message":"Model quota exceeded for this workspace. Ask your administrator to raise the limit."}}`+"\n")
			return
		}
		outcome = "provider-refused"
		http.Error(w, "provider refused request", 502)
		return
	}
	// Never reflect upstream error bodies, cookies, server headers or request IDs.
	if streaming {
		w.Header().Set("Content-Type", "text/event-stream")
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	w.Header().Set("X-Hardened-Request-ID", record.ID)
	if g.config.Protocol == "responses" {
		var abort bool
		outcome, abort = forwardResponses(w, res.Body, streaming, model, &responseBytes)
		if abort {
			panic(http.ErrAbortHandler)
		}
		return
	}
	const limit = 16 * 1024 * 1024
	buf := make([]byte, 32*1024)
	var stream sseTerminal
	for {
		n, readErr := res.Body.Read(buf)
		if responseBytes+int64(n) > limit {
			outcome = "response-limit"
			panic(http.ErrAbortHandler)
		}
		if n > 0 {
			if streaming && !stream.observe(buf[:n]) {
				outcome = "response-interrupted"
				panic(http.ErrAbortHandler)
			}
			written, writeErr := w.Write(buf[:n])
			responseBytes += int64(written)
			if writeErr != nil {
				outcome = "cancelled"
				return
			}
			if streaming {
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
		}
		if readErr == io.EOF {
			if streaming {
				if !stream.done {
					outcome = "response-interrupted"
					panic(http.ErrAbortHandler)
				}
				outcome = "provider-stream-ended"
				return
			}
			outcome = "completed"
			return
		}
		if readErr != nil {
			outcome = "response-interrupted"
			panic(http.ErrAbortHandler)
		}
	}
}

// Only a complete SSE event containing exactly data: [DONE] establishes the
// provider's declared stream ending. TCP EOF alone is not model completion.
type sseTerminal struct {
	line      []byte
	candidate bool
	done      bool
}

func (s *sseTerminal) observe(chunk []byte) bool {
	for _, b := range chunk {
		if b != '\n' {
			s.line = append(s.line, b)
			if len(s.line) > 64*1024 {
				return false
			}
			continue
		}
		line := bytes.TrimSuffix(s.line, []byte("\r"))
		s.line = nil
		if len(line) == 0 {
			if s.candidate {
				s.done = true
			}
			s.candidate = false
			continue
		}
		if bytes.HasPrefix(line, []byte("data:")) {
			s.candidate = bytes.Equal(bytes.TrimSpace(line[5:]), []byte("[DONE]"))
		}
	}
	return true
}

// otlp is the record as OTLP logs; profile is profileSignature of the gateway's configuration.
func otlp(r Record, profile string) []byte {
	attribute := func(k, v string) map[string]any {
		return map[string]any{"key": k, "value": map[string]string{"stringValue": v}}
	}
	attrs := []map[string]any{attribute("request.id", r.ID), attribute("tenant.id", r.Tenant), attribute("session.id", r.Session), attribute("agent.spiffe_id", r.Agent), attribute("identity.source", r.IdentitySource), attribute("profile.sha256", r.ProfileDigest), attribute("profile.signature", profile), attribute("gen_ai.request.model", r.Model)}
	if r.IdentitySource == "platform-online-check" {
		attrs = append(attrs, attribute("identity.checked_at", r.IdentityCheckedAt.Format(time.RFC3339Nano)), attribute("repository.id", r.RepositoryID), attribute("delegation.user_id", r.DelegatingUserID), attribute("delegation.enrollment_aal", r.EnrollmentAAL), attribute("delegation.human_presence", "not-currently-established"))
	}
	entry := func(at time.Time, outcome string) map[string]any {
		phase := "terminal"
		fields := append([]map[string]any{}, attrs...)
		if outcome == "started" {
			phase = "start"
		} else {
			fields = append(fields, attribute("response.status_code", strconv.Itoa(r.Status)), attribute("request.bytes", strconv.Itoa(r.RequestBytes)), attribute("response.bytes", strconv.FormatInt(r.ResponseBytes, 10)))
		}
		fields = append(fields, attribute("event.id", r.ID+"/"+phase))
		return map[string]any{"timeUnixNano": strconv.FormatInt(at.UnixNano(), 10), "severityNumber": 9, "severityText": "INFO", "body": map[string]string{"stringValue": outcome}, "attributes": fields}
	}
	payload := map[string]any{"resourceLogs": []any{map[string]any{"resource": map[string]any{"attributes": []any{attribute("service.name", "hardened-opencode-gateway")}}, "scopeLogs": []any{map[string]any{"scope": map[string]string{"name": "testifysec.hardened-opencode.audit", "version": "1"}, "logRecords": []any{entry(r.Started, "started"), entry(r.Finished, r.Outcome)}}}}}}
	b, _ := json.Marshal(payload)
	return b
}

func (g *Gateway) exportOne(ctx context.Context) error {
	r, ok := g.spool.next()
	if !ok {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, "POST", g.config.CollectorURL, bytes.NewReader(otlp(r, profileSignature(g.config))))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	collectorToken, err := token(g.config.CollectorTokenFile)
	if err != nil {
		return errors.New("collector credential unavailable")
	}
	if collectorToken != "" {
		req.Header.Set("Authorization", "Bearer "+collectorToken)
	}
	res, err := g.collectorClient().Do(req)
	if err != nil {
		return errors.New("collector unavailable")
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 65537))
	if err != nil || len(b) > 65536 || res.StatusCode != 200 {
		return errors.New("collector rejected")
	}
	var response struct {
		PartialSuccess *struct {
			RejectedLogRecords string `json:"rejectedLogRecords"`
			ErrorMessage       string `json:"errorMessage"`
		} `json:"partialSuccess"`
	}
	if err = strictJSON(b, &response); err != nil {
		return errors.New("invalid collector response")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil || fields == nil {
		return errors.New("invalid collector object")
	}
	for key, value := range fields {
		if key != "partialSuccess" || bytes.Equal(value, []byte("null")) {
			return errors.New("invalid collector field")
		}
		var partial map[string]json.RawMessage
		if json.Unmarshal(value, &partial) != nil || partial == nil {
			return errors.New("invalid collector partial result")
		}
		for name := range partial {
			if name != "rejectedLogRecords" && name != "errorMessage" {
				return errors.New("invalid collector partial field")
			}
		}
	}
	if response.PartialSuccess != nil && (response.PartialSuccess.RejectedLogRecords != "" && response.PartialSuccess.RejectedLogRecords != "0" || response.PartialSuccess.ErrorMessage != "") {
		return errors.New("collector partial refusal")
	}
	return g.spool.acknowledge(r.ID)
}

func (g *Gateway) exportLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for i := 0; i < g.config.MaxRecords; i++ {
				if _, ok := g.spool.next(); !ok {
					break
				}
				if err := g.exportOne(ctx); err != nil {
					fmt.Println("audit exporter: retry pending")
					break
				}
			}
		}
	}
}

// collectorClient never carries the provider pin: the collector is always verified against the
// system roots, even on the provider's host.
func collectorClient(c Config) *http.Client {
	c.ProviderCertSHA256 = ""
	return providerClient(c)
}

func (g *Gateway) collectorClient() *http.Client {
	if g.collector != nil {
		return g.collector
	}
	return g.client
}

// limits asks the provider for this workspace's limits at the provider's origin and path prefix,
// with the provisioned credential, and passes back a JSON object of at most 1 KiB. Anything else
// is a fixed 404, so the managed agent keeps its compiled values; the provider's answer is never
// reflected otherwise.
func (g *Gateway) limits(w http.ResponseWriter, r *http.Request) (string, int) {
	unavailable := func() (string, int) {
		http.Error(w, "limits unavailable", http.StatusNotFound)
		return "limits-unavailable", http.StatusNotFound
	}
	req, err := http.NewRequestWithContext(r.Context(), "GET", strings.TrimSuffix(g.config.ProviderURL, g.config.requestPath())+"/v1/limits", nil)
	token := g.provider.get()
	if err != nil || (token == "" && g.config.ProviderTokenFD > 0) {
		return unavailable()
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := g.client.Do(req)
	if err != nil {
		return unavailable()
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 1025))
	var body map[string]json.RawMessage
	if res.StatusCode != http.StatusOK || err != nil || len(b) > 1024 || strictJSON(b, &body) != nil || body == nil {
		return unavailable()
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
	return "limits-served", http.StatusOK
}

// providerClient is the gateway's HTTP client for provider requests. With a provider pin, the provider host must
// present exactly that key (no CA involved); every other host (the collector) is verified against
// the system roots as usual.
func providerClient(c Config) *http.Client {
	base := &tls.Config{MinVersion: tls.VersionTLS12}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: base, DisableCompression: true, MaxIdleConns: 2, MaxConnsPerHost: 2, ResponseHeaderTimeout: time.Duration(c.TimeoutSeconds) * time.Second}
	if c.ProviderCertSHA256 != "" {
		// The pin applies to the provider's exact host and port; readConfig requires an ASCII host
		// with a pin, so it compares equal to the address the transport dials.
		pinned := ""
		if u, err := url.Parse(c.ProviderURL); err == nil {
			port := u.Port()
			if port == "" {
				port = "443"
			}
			pinned = net.JoinHostPort(strings.ToLower(u.Hostname()), port)
		}
		dialer := &net.Dialer{Timeout: time.Duration(c.TimeoutSeconds) * time.Second}
		transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			cfg := base.Clone()
			cfg.ServerName = host
			if net.JoinHostPort(strings.ToLower(host), port) == pinned {
				cfg.InsecureSkipVerify = true // the pin below replaces CA verification, it is never skipped
				cfg.VerifyConnection = func(cs tls.ConnectionState) error {
					if len(cs.PeerCertificates) == 0 {
						return errors.New("no provider certificate")
					}
					sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
					if hex.EncodeToString(sum[:]) != c.ProviderCertSHA256 {
						return errors.New("provider certificate does not match its pin")
					}
					return nil
				}
			}
			raw, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			conn := tls.Client(raw, cfg)
			if err = conn.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			return conn, nil
		}
	}
	return &http.Client{
		Timeout:       time.Duration(c.TimeoutSeconds) * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     transport,
	}
}

// providerQuotaExceeded reports whether a provider refusal is the model broker's quota answer,
// `{"error":{"code":"quota_exceeded",...}}`, reading at most 4 KiB of it.
func providerQuotaExceeded(body io.Reader) bool {
	var refusal struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	b, err := io.ReadAll(io.LimitReader(body, 4096))
	return err == nil && json.Unmarshal(b, &refusal) == nil && refusal.Error.Code == "quota_exceeded"
}
