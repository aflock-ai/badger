// Package egress is the only way a connector reaches its service: one base URL from the
// administrator's profile, a credential read from a broker-managed file on every request, and
// nothing else. It refuses other schemes, hosts, ports and paths outside the base, refuses
// redirects that leave the base, caps response bodies, and never puts the credential in an error.
package egress

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// AuthScheme is how the credential is presented. Each connector picks one.
type AuthScheme int

const (
	Bearer       AuthScheme = iota // Authorization: Bearer <token> (Atlassian DC PATs, GitLab OAuth)
	PrivateToken                   // PRIVATE-TOKEN: <token> (GitLab personal/project access tokens)
)

// TokenSource yields the current credential. It is called once per request so the broker can
// rotate the credential underneath a running connector. A later OIDC token exchange implements it.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// FileToken reads the credential from a file the broker writes. The error never carries content.
type FileToken string

func (f FileToken) Token(context.Context) (string, error) {
	fh, err := os.Open(string(f))
	if err != nil {
		return "", fmt.Errorf("token file: %w", errors.Unwrap(err))
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, 64<<10))
	if err != nil {
		return "", errors.New("token file: read failed")
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" || strings.ContainsFunc(tok, func(r rune) bool { return r < 0x21 || r == 0x7f }) {
		return "", errors.New("token file: empty or malformed")
	}
	return tok, nil
}

// Config is set from the administrator's profile, never by the model or by user or repo config.
type Config struct {
	BaseURL              string // e.g. https://jira.example.invalid/rest/api/2
	Token                TokenSource
	Scheme               AuthScheme
	CAFile               string        // PEM roots for an enclave CA; empty uses the system roots
	InsecureLoopbackHTTP bool          // tests only: allow http:// to a loopback host
	Timeout              time.Duration // whole request; default 30s
	MaxResponseBytes     int64         // default 8 MiB
	UserAgent            string
	// EgressFD, when not 0, is the descriptor every connection comes from, whatever host the request
	// names: a plugin host's egress descriptor (BADGER_EGRESS_FD). One byte asks for a connection;
	// the host passes back one it dialled to the base URL's host and port. TLS still runs here, to
	// the base URL's host name.
	EgressFD int
}

// Client is an HTTP client locked to Config.BaseURL.
type Client struct {
	base   *url.URL
	cfg    Config
	http   *http.Client
	mu     sync.Mutex
	recent []string // credentials this client has sent, for Redact
}

func New(cfg Config) (*Client, error) {
	base, err := url.Parse(cfg.BaseURL)
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("egress: base URL must be an absolute URL with no userinfo, query or fragment")
	}
	switch {
	case base.Scheme == "https":
	case base.Scheme == "http" && cfg.InsecureLoopbackHTTP && isLoopback(base.Hostname()):
	default:
		return nil, fmt.Errorf("egress: base URL scheme %q refused (https only)", base.Scheme)
	}
	if cfg.Token == nil {
		return nil, errors.New("egress: no token source")
	}
	base.Path = strings.TrimRight(base.Path, "/")
	base.RawPath = ""
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.MaxResponseBytes == 0 {
		cfg.MaxResponseBytes = 8 << 20
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		pool := x509.NewCertPool()
		if err != nil || !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("egress: CA file unreadable or holds no certificates")
		}
		tlsCfg.RootCAs = pool
	}
	dial := (&net.Dialer{Timeout: 10 * time.Second}).DialContext
	if cfg.EgressFD != 0 {
		d, err := newFDDialer(cfg.EgressFD)
		if err != nil {
			return nil, fmt.Errorf("egress: descriptor %d: %w", cfg.EgressFD, err)
		}
		dial = func(ctx context.Context, _, _ string) (net.Conn, error) { return d.dial(ctx) }
	}
	c := &Client{base: base, cfg: cfg}
	c.http = &http.Client{
		Timeout: cfg.Timeout,
		// No proxy from the environment: the profile names the one destination.
		// No keep-alive: an idle connection is where net/http logs bytes a server sends unasked
		// (an echoed credential after a zero-length body) through the global logger, past any
		// redaction. A connector makes few requests, so a fresh connection each time costs little.
		Transport: &http.Transport{Proxy: nil, TLSClientConfig: tlsCfg, ForceAttemptHTTP2: true, DisableKeepAlives: true,
			DialContext: dial, ResponseHeaderTimeout: cfg.Timeout},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("egress: too many redirects")
			}
			if !c.inside(req.URL) {
				return errors.New("egress: redirect outside the configured base URL refused")
			}
			return nil
		},
	}
	return c, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// inside reports whether u is the base origin and its path stays under the base path.
func (c *Client) inside(u *url.URL) bool {
	if u.Scheme != c.base.Scheme || u.Host != c.base.Host || u.User != nil {
		return false
	}
	p := u.Path
	if p != c.base.Path && !strings.HasPrefix(p, c.base.Path+"/") {
		return false
	}
	// Dot segments, and anything a server might normalize into one: Tomcat (Jira, Confluence)
	// drops ";params" before resolving "..", so "/jira/..;/x" reaches "/x"; some servers treat a
	// backslash as a separator. Both are refused, escaped or not (Path is decoded).
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == "." || strings.ContainsAny(seg, ";\\") {
			return false
		}
	}
	return true
}

// Get fetches path (relative to the base, starting with "/", segments already escaped).
func (c *Client) Get(ctx context.Context, path string, query url.Values) ([]byte, error) {
	return c.Do(ctx, http.MethodGet, path, query, "", nil)
}

// Do sends one request. body may be nil; contentType applies when it is not.
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, contentType string, body []byte) ([]byte, error) {
	b, _, err := c.DoWithHeaders(ctx, method, path, query, contentType, body)
	return b, err
}

// GetWithHeaders is Get that also returns the paging headers (PagingHeaders) of the response.
func (c *Client) GetWithHeaders(ctx context.Context, path string, query url.Values) ([]byte, http.Header, error) {
	return c.DoWithHeaders(ctx, http.MethodGet, path, query, "", nil)
}

// PagingHeaders are the only response headers a connector sees. Nothing else is copied, so a
// header a service reflects (a cookie, the credential) cannot reach a tool result.
var PagingHeaders = []string{"Link", "X-Next-Page", "X-Page", "X-Per-Page", "X-Prev-Page", "X-Total", "X-Total-Pages"}

// DoWithHeaders is Do that also returns the paging headers of a successful response.
func (c *Client) DoWithHeaders(ctx context.Context, method, path string, query url.Values, contentType string, body []byte) ([]byte, http.Header, error) {
	resp, err := c.send(ctx, method, path, query, contentType, body, nil)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, c.cfg.MaxResponseBytes+1))
	if err != nil {
		return nil, nil, errors.New("reading the service response failed")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body := c.Redact(string(b))
		if int64(len(b)) > c.cfg.MaxResponseBytes {
			body = c.redactCut(string(b))
		}
		return nil, nil, newHTTPError(resp, body)
	}
	if int64(len(b)) > c.cfg.MaxResponseBytes {
		return nil, nil, fmt.Errorf("the service response exceeded %d bytes; narrow the request", c.cfg.MaxResponseBytes)
	}
	h := http.Header{}
	for _, k := range PagingHeaders {
		if v := resp.Header.Get(k); v != "" {
			h.Set(k, v)
		}
	}
	return b, h, nil
}

// Tail returns the last n bytes of a GET (n at most the response cap), for bodies such as job
// logs that can exceed the cap. It asks for a suffix Range and, when the service ignores it,
// streams the body keeping the last n bytes. dropped reports that earlier bytes were left out.
func (c *Client) Tail(ctx context.Context, path string, query url.Values, n int64) (tail []byte, dropped bool, err error) {
	if n <= 0 || n > c.cfg.MaxResponseBytes {
		return nil, false, fmt.Errorf("egress: tail of %d bytes refused (1 to %d)", n, c.cfg.MaxResponseBytes)
	}
	// identity: a suffix range of a transparently compressed body is not a suffix of the text.
	resp, err := c.send(ctx, http.MethodGet, path, query, "", nil,
		http.Header{"Range": {fmt.Sprintf("bytes=-%d", n)}, "Accept": {"*/*"}, "Accept-Encoding": {"identity"}})
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusRequestedRangeNotSatisfiable:
		return nil, false, nil // empty body
	case resp.StatusCode == http.StatusPartialContent:
		b, err := io.ReadAll(io.LimitReader(resp.Body, n+1))
		if err != nil {
			return nil, false, errors.New("reading the service response failed")
		}
		if int64(len(b)) > n {
			// A range answer longer than the range: cutting it could split a credential.
			return nil, false, errors.New("the service answered a range request with more than the range")
		}
		dropped := !strings.HasPrefix(resp.Header.Get("Content-Range"), "bytes 0-")
		return c.redactTail(b, dropped), dropped, nil
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		// Read past the cap and redact before newHTTPError cuts to it, so the cut never splits a
		// credential; a credential at the read limit is caught by redactCut.
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2*maxErrorBody))
		return nil, false, newHTTPError(resp, c.redactCut(string(b)))
	}
	buf := make([]byte, 0, 2*n)
	chunk := make([]byte, 32<<10)
	for {
		k, rerr := resp.Body.Read(chunk)
		buf = append(buf, chunk[:k]...)
		if int64(len(buf)) > 2*n { // keep memory at most 2n
			buf, dropped = append(buf[:0], buf[int64(len(buf))-n:]...), true
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return nil, false, errors.New("reading the service response failed")
		}
	}
	if int64(len(buf)) > n {
		buf, dropped = buf[int64(len(buf))-n:], true
	}
	return c.redactTail(buf, dropped), dropped, nil
}

// redactTail scrubs a tail: whole credentials, and, when the cut fell inside one, the piece of a
// credential the tail starts with (any suffix of a recent credential), which Redact alone would
// miss. A tail that happens to start with a credential's last bytes loses those bytes too.
func (c *Client) redactTail(b []byte, cut bool) []byte {
	return []byte(c.redact(string(b), cut, false))
}

// send validates path, attaches the credential and the extra headers, and sends one request.
func (c *Client) send(ctx context.Context, method, path string, query url.Values, contentType string, body []byte, extra http.Header) (*http.Response, error) {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("egress: path %q refused", path)
	}
	u, err := url.Parse(c.base.Scheme + "://" + c.base.Host + c.base.EscapedPath() + path)
	if err != nil || !c.inside(u) {
		return nil, fmt.Errorf("egress: path %q refused", path)
	}
	u.RawQuery = query.Encode()
	tok, err := c.cfg.Token.Token(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.remember(tok); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("egress: could not build request")
	}
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	if c.cfg.UserAgent != "" {
		req.Header.Set("User-Agent", c.cfg.UserAgent)
	}
	for k, v := range extra {
		req.Header[k] = v
	}
	if c.cfg.Scheme == PrivateToken {
		req.Header.Set("PRIVATE-TOKEN", tok)
	} else {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		// url.Error carries the method and URL (no credential); keep only the cause.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("request to the service failed: %s", c.Redact(err.Error()))
	}
	return resp, nil
}

// maxCredentials bounds the credentials one connector process remembers. A connector lives for
// one session and keeps every credential it has sent, so anything it later returns is scrubbed
// of all of them; past the bound it refuses to send rather than forget one.
const maxCredentials = 4096

func (c *Client) remember(tok string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if slices.Contains(c.recent, tok) {
		return nil
	}
	if len(c.recent) >= maxCredentials {
		return errors.New("egress: too many credential rotations for one connector session; restart the connector")
	}
	c.recent = append(c.recent, tok)
	return nil
}

// redactCut is Redact for text that was cut at its end: a credential the cut went through
// leaves a prefix that Redact cannot match, so that prefix is replaced too.
func (c *Client) redactCut(s string) string {
	return c.redact(s, false, true)
}

// Redact replaces every credential this client has recently sent with "[redacted]". The server
// applies it to all tool output and logs as a second line of defence.
//
// Every match of every credential is found in the original text first and overlapping matches
// are merged, so a credential that contains another (abc123 and abc123XYZ) is replaced whole.
func (c *Client) Redact(s string) string {
	return c.redact(s, false, false)
}

// redact finds, in the original text, every whole credential and, where the text was cut, the
// piece of a credential at the cut: a credential suffix it starts with (cutStart) or a credential
// prefix it ends with (cutEnd). Overlapping spans are merged before anything is replaced, so no
// replacement hides a match another credential would have made.
func (c *Client) redact(s string, cutStart, cutEnd bool) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var spans [][2]int
	for _, t := range c.recent {
		for i := 0; ; {
			k := strings.Index(s[i:], t)
			if k < 0 {
				break
			}
			spans = append(spans, [2]int{i + k, i + k + len(t)})
			i += k + 1
		}
		for k := len(t) - 1; k > 0; k-- {
			if cutStart && strings.HasPrefix(s, t[len(t)-k:]) {
				spans = append(spans, [2]int{0, k})
				break
			}
		}
		for k := len(t) - 1; k > 0; k-- {
			if cutEnd && strings.HasSuffix(s, t[:k]) {
				spans = append(spans, [2]int{len(s) - k, len(s)})
				break
			}
		}
	}
	if len(spans) == 0 {
		return s
	}
	slices.SortFunc(spans, func(a, b [2]int) int { return a[0] - b[0] })
	var out strings.Builder
	at := 0
	for i := 0; i < len(spans); {
		start, end := spans[i][0], spans[i][1]
		for i++; i < len(spans) && spans[i][0] <= end; i++ {
			end = max(end, spans[i][1])
		}
		out.WriteString(s[at:start])
		out.WriteString("[redacted]")
		at = end
	}
	out.WriteString(s[at:])
	return out.String()
}

// ContainsCredential reports whether s holds a credential this client has sent, compared
// without regard to case (a marking parser upper-cases what it reads).
func (c *Client) ContainsCredential(s string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	u := strings.ToUpper(s)
	for _, t := range c.recent {
		if strings.Contains(u, strings.ToUpper(t)) {
			return true
		}
	}
	return false
}

// HTTPError is a non-2xx response, reduced to a message that is safe to show the model. Headers
// are never copied; a short body excerpt is kept only for client errors whose body explains a
// mistake the model can fix (bad JQL, missing field).
type HTTPError struct {
	Status     int
	RetryAfter string
	Detail     string // one line, 300 bytes, for 400/409/422 only; shown in Error()
	// Body is the response body, credential scrubbed and capped at 16 KiB, for a connector to
	// parse (Jira's errorMessages, Confluence's message). It is not in Error(); a connector that
	// shows any of it to the model must cap it again.
	Body string
}

const maxErrorBody = 16 << 10

func newHTTPError(resp *http.Response, body string) *HTTPError {
	if len(body) > maxErrorBody {
		body = body[:maxErrorBody]
	}
	e := &HTTPError{Status: resp.StatusCode, Body: body}
	if ra := resp.Header.Get("Retry-After"); ra != "" && strings.Trim(ra, "0123456789") == "" && len(ra) < 7 {
		e.RetryAfter = ra
	}
	if s := resp.StatusCode; s == 400 || s == 409 || s == 422 {
		d := strings.Join(strings.Fields(body), " ")
		if len(d) > 300 {
			d = d[:300] + "..."
		}
		e.Detail = d
	}
	return e
}

func (e *HTTPError) Error() string {
	switch {
	case e.Status == 401 || e.Status == 403:
		return fmt.Sprintf("the connector's credential was rejected or lacks permission (HTTP %d)", e.Status)
	case e.Status == 404:
		return "not found, or not visible to you (HTTP 404)"
	case e.Status == 429:
		if e.RetryAfter != "" {
			return "the service is rate limiting requests (HTTP 429); retry after " + e.RetryAfter + " seconds"
		}
		return "the service is rate limiting requests (HTTP 429); retry later"
	case e.Status >= 500:
		return fmt.Sprintf("the service failed (HTTP %d); try again later", e.Status)
	case e.Detail != "":
		return fmt.Sprintf("the service rejected the request (HTTP %d): %s", e.Status, e.Detail)
	default:
		return fmt.Sprintf("the service rejected the request (HTTP %d)", e.Status)
	}
}
