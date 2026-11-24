// Command mcp-bridge stands in for a connector in a hosted workspace whose connectors run in a
// separate connector pod (cmd/conngw). The workspace's signed profile pins this binary under the
// connector's name, and the managed build starts it with that entry's flags, as it would start the
// connector itself. It holds no service token and no route to the service: it carries the MCP
// stdio stream over TLS to the connector pod, which does.
//
// The profile entry's fields mean, for a bridged connector:
//
//   - --base-url: the connector pod's stream URL, https://<pod service>:<port>/connectors/<name>.
//   - --ca-file: the CA that issued the connector pod's certificate. Required: the stream carries
//     the workspace's identity token.
//   - --token-file: the workspace pod's projected service-account token, whose audience the
//     connector pod checks. It is the workspace's identity there, not a service token.
//   - --classification, --enable-writes and every other flag: sent to the connector pod, which
//     refuses the stream unless its own configuration says the same.
//   - --marking-scheme: the digest of the classification scheme the workspace's profile reads the
//     classification under; absent is us-gov. The connector pod refuses a stream whose scheme is
//     not its own.
//
// It speaks to the connector pod in workspace mode only: there is no laptop path.
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const upgradeProtocol = "badger-mcp"

var schemeDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// settings are the flags the managed build passes, as internal/connector would read them.
type settings struct {
	url            *url.URL
	caFile         string
	tokenFile      string
	classification string
	scheme         string
	writes         bool
	flags          map[string]string
}

func parse(args []string) (settings, error) {
	s := settings{flags: map[string]string{}}
	var base string
	for _, arg := range args {
		k, v, hasValue := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
		if !strings.HasPrefix(arg, "--") || k == "" {
			return s, fmt.Errorf("unexpected argument %q", arg)
		}
		switch {
		case k == "enable-writes" && !hasValue:
			s.writes = true
		case !hasValue:
			return s, fmt.Errorf("flag --%s needs a value", k)
		case k == "base-url":
			base = v
		case k == "ca-file":
			s.caFile = v
		case k == "token-file":
			s.tokenFile = v
		case k == "classification":
			s.classification = v
		case k == "marking-scheme":
			if !schemeDigest.MatchString(v) {
				return s, errors.New("--marking-scheme must be a scheme digest, sha256:<64 hex>")
			}
			s.scheme = v
		default:
			if _, dup := s.flags[k]; dup {
				return s, fmt.Errorf("flag --%s given twice", k)
			}
			s.flags[k] = v
		}
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || !strings.HasPrefix(u.Path, "/connectors/") || u.RawQuery != "" || u.User != nil {
		return s, errors.New("--base-url must be the connector pod's https://<host>:<port>/connectors/<name>")
	}
	s.url = u
	if s.caFile == "" || s.tokenFile == "" || s.classification == "" {
		return s, errors.New("--ca-file, --token-file and --classification are required")
	}
	return s, nil
}

// dial opens the stream: TLS to the connector pod, then an HTTP upgrade carrying the workspace's
// token and its declaration of the connector. It returns the connection and its reader, which may
// already hold the start of the stream.
func dial(s settings) (net.Conn, *bufio.Reader, error) {
	pem, err := os.ReadFile(s.caFile)
	pool := x509.NewCertPool()
	if err != nil || !pool.AppendCertsFromPEM(pem) {
		return nil, nil, errors.New("cannot read the connector pod's CA from --ca-file")
	}
	token, err := os.ReadFile(s.tokenFile)
	if err != nil || len(strings.TrimSpace(string(token))) == 0 {
		return nil, nil, errors.New("cannot read the workspace token from --token-file")
	}
	decl := map[string]any{"classification": s.classification, "writes": s.writes, "flags": s.flags}
	if s.scheme != "" {
		decl["scheme"] = s.scheme
	}
	declared, _ := json.Marshal(decl)
	host := s.url.Host
	if s.url.Port() == "" {
		host = net.JoinHostPort(s.url.Hostname(), "443")
	}
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config: &tls.Config{RootCAs: pool, ServerName: s.url.Hostname(), MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}}
	conn, err := d.Dial("tcp", host)
	if err != nil {
		return nil, nil, errors.New("connector pod unavailable")
	}
	req, _ := http.NewRequest(http.MethodGet, s.url.String(), nil)
	req.Header.Set("Upgrade", upgradeProtocol)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Badger-Connector", string(declared))
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, nil, errors.New("connector pod unavailable")
	}
	r := bufio.NewReader(conn)
	res, err := http.ReadResponse(r, req)
	if err != nil {
		conn.Close()
		return nil, nil, errors.New("connector pod gave no answer")
	}
	if res.StatusCode != http.StatusSwitchingProtocols || !strings.EqualFold(res.Header.Get("Upgrade"), upgradeProtocol) {
		reason, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		conn.Close()
		return nil, nil, fmt.Errorf("connector pod refused the stream: %d %s", res.StatusCode, strings.TrimSpace(string(reason)))
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, r, nil
}

// run is main with its inputs passed in.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	s, err := parse(args)
	if err != nil {
		fmt.Fprintln(stderr, "mcp-bridge:", err)
		return 2
	}
	conn, r, err := dial(s)
	if err != nil {
		fmt.Fprintln(stderr, "mcp-bridge:", err)
		return 1
	}
	defer conn.Close()
	// The stream ends when the connector pod closes it. When the client closes stdin first, the
	// pod sees end of input, lets the connector finish, and then closes.
	go func() {
		_, _ = io.Copy(conn, stdin)
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	_, _ = io.Copy(stdout, r)
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }
