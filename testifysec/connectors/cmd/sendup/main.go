// Command sendup is a hosted workspace's client for the connector pod's send-up endpoints
// (cmd/conngw/sendup.go). It runs in the workspace, as its owner's tool or the agent's, and
// identifies the workspace with its pod's projected service-account token, the same identity the
// connector streams use. Whether a send is allowed is decided by the connector pod alone.
//
// Where it connects, which CA it trusts and which token it sends come only from the
// administrator's configuration, mounted read-only at /etc/badger/sendup.json
// ({"url":"https://<pod>:<port>","caFile":"...","tokenFile":"..."}); nothing on the command line
// can point the client, or the token it carries, anywhere else.
//
//	sendup send --to=<ns>/<account> --name=<file name> <path|->
//	sendup list               id, sender, sender's label, name
//	sendup get <id>           the item's bytes on stdout; fails if they cannot all be written
//	sendup ack <id>           removes it from this workspace's inbox
//
// send prints "delivered" or "refused" and nothing else: no answer carries anything of the receiver.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var itemID = regexp.MustCompile(`^[0-9]{20}$`)

type client struct {
	base      string
	tokenFile string
	http      *http.Client
}

func (c *client) do(method, path string, body []byte) (int, []byte, error) {
	token, err := os.ReadFile(c.tokenFile)
	if err != nil || len(bytes.TrimSpace(token)) == 0 {
		return 0, nil, errors.New("cannot read the workspace token")
	}
	req, err := http.NewRequest(method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return 0, nil, errors.New("connector pod unavailable")
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	return res.StatusCode, b, err
}

// configPath is the administrator's configuration, mounted read-only into the workspace.
const configPath = "/etc/badger/sendup.json"

type config struct {
	URL       string `json:"url"`
	CAFile    string `json:"caFile"`
	TokenFile string `json:"tokenFile"`
}

func readConfig(path string) (config, *url.URL, error) {
	var c config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, nil, fmt.Errorf("no configuration at %s", path)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, nil, errors.New("configuration unreadable")
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.User != nil || u.RawQuery != "" ||
		c.CAFile == "" || c.TokenFile == "" {
		return c, nil, errors.New("configuration needs url https://<host>:<port>, caFile and tokenFile")
	}
	return c, u, nil
}

func run(configFile string, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(stderr, "sendup: send, list, get or ack (the destination is the administrator's configuration)")
		return 2
	}
	cfg, u, err := readConfig(configFile)
	if err != nil {
		fmt.Fprintln(stderr, "sendup:", err)
		return 2
	}
	pem, err := os.ReadFile(cfg.CAFile)
	pool := x509.NewCertPool()
	if err != nil || !pool.AppendCertsFromPEM(pem) {
		fmt.Fprintln(stderr, "sendup: cannot read the connector pod's CA")
		return 2
	}
	c := &client{base: "https://" + u.Host, tokenFile: cfg.TokenFile, http: &http.Client{Timeout: 60 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	rest := args
	switch rest[0] {
	case "send":
		return send(c, rest[1:], stdin, stdout, stderr)
	case "list":
		status, b, err := c.do(http.MethodGet, "/inbox", nil)
		var l struct {
			Items []struct{ ID, From, FromLabel, Name string }
		}
		if err != nil || status != http.StatusOK || json.Unmarshal(b, &l) != nil {
			fmt.Fprintln(stderr, "sendup: inbox unavailable")
			return 1
		}
		for _, it := range l.Items {
			fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\n", shown(it.ID), shown(it.From), shown(it.FromLabel), shown(it.Name))
		}
		return 0
	case "get", "ack":
		if len(rest) != 2 || !itemID.MatchString(rest[1]) {
			fmt.Fprintln(stderr, "sendup: an item id is 20 digits")
			return 2
		}
		method := http.MethodGet
		if rest[0] == "ack" {
			method = http.MethodDelete
		}
		status, b, err := c.do(method, "/inbox/"+rest[1], nil)
		if err != nil || status != http.StatusOK {
			fmt.Fprintln(stderr, "sendup: no such item")
			return 1
		}
		if rest[0] == "get" {
			var it struct{ Data []byte }
			if json.Unmarshal(b, &it) != nil {
				fmt.Fprintln(stderr, "sendup: unreadable item")
				return 1
			}
			if _, err := stdout.Write(it.Data); err != nil {
				fmt.Fprintln(stderr, "sendup: the item could not be written out; it stays in the inbox")
				return 1
			}
		}
		return 0
	}
	fmt.Fprintln(stderr, "sendup: send, list, get or ack")
	return 2
}

func send(c *client, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	fs.SetOutput(stderr)
	to := fs.String("to", "", "the receiving workspace, <namespace>/<account>")
	name := fs.String("name", "", "the file name it is delivered under")
	if fs.Parse(args) != nil || *to == "" || *name == "" || fs.NArg() != 1 {
		fmt.Fprintln(stderr, "sendup: send --to=<ns>/<account> --name=<name> <path|->")
		return 2
	}
	// Read at most one byte past the limit, from a file or stdin, so a large input is refused
	// without being held in memory.
	in := stdin
	if fs.Arg(0) != "-" {
		f, err := os.Open(fs.Arg(0))
		if err != nil {
			fmt.Fprintln(stderr, "sendup: cannot read the file")
			return 2
		}
		defer f.Close()
		in = f
	}
	data, err := io.ReadAll(io.LimitReader(in, 4<<20+1))
	if err != nil || len(data) > 4<<20 {
		fmt.Fprintln(stderr, "sendup: cannot read the file, or it is over 4 MiB")
		return 2
	}
	body, _ := json.Marshal(map[string]any{"to": *to, "name": *name, "data": data})
	status, b, err := c.do(http.MethodPost, "/sendup", body)
	if err != nil {
		fmt.Fprintln(stderr, "sendup:", err)
		return 1
	}
	var answer struct{ Status string }
	_ = json.Unmarshal(b, &answer)
	if status == http.StatusOK && answer.Status == "delivered" {
		fmt.Fprintln(stdout, "delivered")
		return 0
	}
	fmt.Fprintln(stdout, "refused")
	return 1
}

func main() { os.Exit(run(configPath, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

// shown is a listing field as it may be printed: as it is when every character is graphic and not a
// tab, otherwise quoted with escapes, so a field from the pod can neither break the one-line,
// tab-separated row nor reach the terminal as a control or format character.
func shown(s string) string {
	for _, r := range s {
		if r == '\t' || r == utf8.RuneError || !unicode.IsGraphic(r) {
			return strconv.QuoteToGraphic(s)
		}
	}
	return s
}
