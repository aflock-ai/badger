// Command conngw is the connector gateway: it runs in a connector pod, in front of the connector
// plugins, for hosted workspaces whose connectors are reached through cmd/mcp-bridge. The pod
// alone holds the service tokens and the network route to each service. conngw is the pod's side
// of the no-write-down rule, keyed by workspace, so a shell command that speaks MCP to the pod
// directly gets the same answer as the agent:
//
//   - Its configuration is the administrator's signed profile: it starts only if the pinned admin
//     key verifies it. Each connector is a plugin in a container of its own, as its own user, with
//     only its own token; its bundle is a manifest signed by a signer the profile trusts, admitted
//     only when it names the executable digest the profile pins. Every plugin container runs the
//     platform's plughost image (hostDigest), never the vendor's: the vendor's image is mounted
//     read-only and plughost checks the executable's digest before running it sandboxed. A stream
//     reaches the plugin only while the pod's status says that container runs the plughost image
//     and the socket's owner is the plugin's user. The marking, the grants and the write setting come from the profile alone. The
//     gateway does not run as root and holds no connector token.
//   - A caller opens one TLS connection per stream: GET /connectors/<name> with
//     "Upgrade: badger-mcp", its pod's projected service-account token as a bearer, and a
//     Badger-Connector header saying what its signed profile admits for that connector
//     (classification, writes, flags). The API server reviews the token (TokenReview) for the
//     configured audience; the service account, in one of the configured namespaces, is the
//     workspace ("<namespace>/<account>").
//   - Each connector's grants name workspaces or whole namespaces and the tools each may call;
//     write tools are opt-in. Any other workspace is refused (403); a tool outside the grant is
//     answered by the gateway and never reaches the plugin. The declaration only has to match
//     this pod's configuration, so the workspace's own high-water check and this one use one
//     marking.
//   - Each workspace has one label: the join of the markings of every connector whose answer it
//     has received. A request to a connector whose marking does not dominate the label is refused
//     before it reaches the connector, since its arguments could carry the higher content there.
//     The label rises before an answer is passed on, and every answer carries the profile's
//     marking, whatever the plugin claimed.
//   - The profile pins the deployment's classification scheme by digest (markingScheme; absent is
//     us-gov). The process uses it for every label; the labels file, each caller's declaration and
//     each answer's _meta name it, and a label from another scheme is refused, never converted.
//   - With a marking policy (markingPolicy) each tool has its own marking, from the policy's
//     classify globs (connector:<name>/<tool>), and every tool must have one before the gateway
//     starts. A call is checked, and its answer raises the label and is marked, at the tool's
//     marking; the connector's marking is the join of its tools'. The policy's flow rules refuse
//     calls dominance would allow, never the reverse. Each raise is logged as an audit event.
//
// Labels are kept in a labels file on a persistent volume and read back on start; a pod without
// the file refuses to start. Per workspace is coarser than the managed build's
// per-session check, which still runs inside the workspace. See testifysec/CONNECTORS.md.
package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	stdlog "log"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aflock-ai/badger/testifysec/connectors/internal/bundle"
	"github.com/aflock-ai/badger/testifysec/connectors/internal/launch"
	"github.com/aflock-ai/badger/testifysec/connectors/marking"
)

// source is one connector plugin the pod runs. Every field but the runtime ones comes from the
// administrator's signed profile; the plugin's own bundle supplies only the signed list of its tools.
type source struct {
	Name           string            `json:"name"`   // also the name of the plugin's container in the pod
	Bundle         string            `json:"bundle"` // directory holding manifest.json and manifest.sig
	Digest         string            `json:"digest"` // the plugin executable's sha256, pinned by the profile and named by its manifest
	Signer         string            `json:"signer"` // key in the profile's signers that signs the manifest
	Socket         string            `json:"socket"` // the plugin host's socket, on a volume only it and the gateway mount
	BaseURL        string            `json:"baseUrl"`
	TokenPath      string            `json:"tokenPath"` // in the plugin's container
	CAPath         string            `json:"caPath"`    // in the plugin's container
	Writes         bool              `json:"writes"`    // whether any grant may give write tools
	Classification string            `json:"classification"`
	Flags          map[string]string `json:"flags"`
	Grants         []grant           `json:"grants"`
	// UID and GID of the plugin's container: its own, not root, not another connector's and not the
	// gateway's. The socket must be answered by them.
	UID int `json:"uid"`
	GID int `json:"gid"`

	marking marking.Marking
	scheme  *marking.Scheme // the deployment's scheme, which the marking was read under
	// tools are the markings of the connector's tools when the profile has a marking policy; marking
	// is then their join. Without a policy every tool has the connector's marking.
	tools    map[string]marking.Marking
	policy   *marking.Policy
	manifest *bundle.Manifest // set by admit
	host     string           // the profile's hostDigest: the image the plugin's container must run
}

// hello is what the plugin's host starts it with: the profile's settings, the profile's marking and
// the workspace's write setting.
func (s source) hello() launch.Hello {
	return launch.Hello{Version: 1, BaseURL: s.BaseURL, TokenPath: s.TokenPath, CAPath: s.CAPath,
		Classification: s.Classification, Writes: s.Writes, Flags: s.Flags, PluginDigest: s.Digest}
}

type config struct {
	Listen   string `json:"listen"`   // e.g. ":8443"
	CertFile string `json:"certFile"` // the TLS certificate workspaces pin with --ca-file
	KeyFile  string `json:"keyFile"`  //
	Audience string `json:"audience"` // the projected token's audience
	// Namespaces hold the workspaces' service accounts; one gateway serves all of them, and a
	// workspace is "<namespace>/<account>".
	Namespaces []string `json:"namespaces"`
	// LabelsFile keeps each workspace's high-water across restarts. It must be on a persistent
	// volume; it is created once with --init-labels and the pod refuses to start without it.
	LabelsFile string `json:"labelsFile"`
	// Stream bounds; zero takes the default.
	MaxStreams             int  `json:"maxStreams"`             // default 64
	MaxStreamsPerWorkspace int  `json:"maxStreamsPerWorkspace"` // default 8
	IdleMinutes            *int `json:"idleMinutes"`            // absent: 30; 0: never close an idle stream
	// Floor turns on the admin API for a workspace controller (admin.go): the level every
	// workspace it registers may reach without a copy. Admins are the controllers' identities,
	// "<namespace>/<account>". InboxDir turns on send-up (sendup.go); it belongs on the labels volume.
	Floor    string   `json:"floor"`
	Admins   []string `json:"admins"`
	InboxDir string   `json:"inboxDir"`
	// HostDigest is the image every plugin container runs: the platform's plughost, built from
	// reviewed code. A vendor's image is never run; its executable is mounted into this one and
	// copied and checked against the connector's digest before it starts (internal/launch.Stage).
	HostDigest string `json:"hostDigest"`
	// Signers are the plugin signers this profile trusts: name -> base64 ed25519 public key.
	Signers map[string]string `json:"signers"`
	Sources []source          `json:"connectors"`
	// MarkingScheme is the deployment's classification scheme, pinned by digest: a preset, or a
	// scheme file at an absolute path. Absent is the us-gov preset, the scheme of every existing
	// deployment. The labels file and every caller's declaration must name the same scheme.
	MarkingScheme *schemeRef `json:"markingScheme"`
	// MarkingPolicy is a badger.marking-policy/v1 document on the profile's scheme. Its classify
	// globs give each tool its own marking, as connector:<name>/<tool>; every tool a connector's
	// manifest lists must have one at start, and its flowRules refuse calls. With a policy, no
	// connector sets classification: its marking is the join of its tools'.
	MarkingPolicy json.RawMessage `json:"markingPolicy"`

	signers map[string]ed25519.PublicKey
	floor   *marking.Marking
	scheme  *marking.Scheme
	policy  *marking.Policy
}

// loadPolicy reads the profile's marking policy, which must be on the profile's scheme. A scheme
// file it names must be the profile's own.
func (c *config) loadPolicy() error {
	file := func(f string) ([]byte, error) {
		if c.MarkingScheme == nil || f != c.MarkingScheme.File {
			return nil, errors.New("a policy's scheme file must be the profile's markingScheme file")
		}
		return bundle.ReadCapped(f, 256<<10)
	}
	p, err := marking.LoadPolicy("markingPolicy", c.MarkingPolicy, file)
	if err != nil {
		return err
	}
	if p.Scheme.Digest() != c.scheme.Digest() {
		return fmt.Errorf("markingPolicy: it is on the %s scheme (%s) and the profile pins %s (%s)", p.Scheme.Name, p.Scheme.Digest(), c.scheme.Name, c.scheme.Digest())
	}
	c.policy = p
	return nil
}

// classify reads each tool's marking from the policy, as connector:<name>/<tool>. Every tool the
// signed manifest lists must have one, or the gateway does not start: no refusal waits for a call.
// The connector's marking, which callers declare and the plugin is started with, is their join.
func (s *source) classify(p *marking.Policy) error {
	names := make([]string, 0, len(s.manifest.Tools))
	for _, t := range s.manifest.Tools {
		names = append(names, s.sourceName(t.Name))
	}
	if missing := p.Uncovered(names); len(missing) > 0 {
		return fmt.Errorf("the marking policy gives no marking for %s; classify every tool the manifest lists, or set a top-level default", strings.Join(missing, ", "))
	}
	if len(names) == 0 {
		return errors.New("the manifest lists no tool for the marking policy to classify")
	}
	s.tools = map[string]marking.Marking{}
	for i, t := range s.manifest.Tools {
		m, err := p.Classify(names[i])
		if err != nil {
			return err
		}
		s.tools[t.Name] = m
		if i > 0 {
			if m, err = p.Scheme.Join(s.marking, m); err != nil {
				return fmt.Errorf("the markings of its tools join to no banner: %w", err)
			}
		}
		s.marking = m
	}
	s.Classification, s.policy = marking.Banner(s.marking), p
	return nil
}

// markingOf is a tool's marking; the connector's when the profile has no policy, or for output
// that answers no known tool call.
func (s source) markingOf(tool string) marking.Marking {
	if m, ok := s.tools[tool]; ok {
		return m
	}
	return s.marking
}

// sourceName is a tool's name in the marking policy and the audit log; connector:<name> for output
// that answers no known tool call.
func (s source) sourceName(tool string) string {
	if tool == "" {
		return "connector:" + s.Name
	}
	return "connector:" + s.Name + "/" + tool
}

type schemeRef struct {
	Preset string `json:"preset"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

// resolve loads the scheme a configuration names and checks its digest.
func (r *schemeRef) resolve() (*marking.Scheme, error) {
	if r == nil {
		return marking.Preset("us-gov")
	}
	var s *marking.Scheme
	var err error
	switch {
	case (r.Preset == "") == (r.File == ""):
		return nil, errors.New("markingScheme names a preset or a file, not both")
	case r.Preset != "":
		s, err = marking.Preset(r.Preset)
	case !filepath.IsAbs(r.File):
		return nil, errors.New("markingScheme file must be an absolute path")
	default:
		var b []byte
		if b, err = bundle.ReadCapped(r.File, 256<<10); err == nil {
			s, err = marking.LoadScheme(filepath.Base(r.File), b)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("markingScheme: %w", err)
	}
	if s.Digest() != r.SHA256 {
		return nil, fmt.Errorf("markingScheme: the %s scheme's digest is %s, the profile pins %s", s.Name, s.Digest(), r.SHA256)
	}
	return s, nil
}

// name is a connector, signer or flag name.
var name = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// dnsLabel is a namespace or service-account name a workspace may have (RFC 1123 label).
var dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// loadProfile reads the configuration only if the administrator's key verifies its signature over
// the file's exact bytes. The key is pinned outside the profile.
func loadProfile(path, sigPath, keyPath string) (config, error) {
	kb, err := bundle.ReadCapped(keyPath, 4<<10)
	if err != nil {
		return config{}, fmt.Errorf("admin key: %w", err)
	}
	key, err := bundle.ParseKey(strings.TrimSpace(string(kb)))
	if err != nil {
		return config{}, fmt.Errorf("admin key: %w", err)
	}
	b, err := bundle.ReadCapped(path, 4<<20)
	if err != nil {
		return config{}, err
	}
	sig, err := bundle.ReadCapped(sigPath, 4<<10)
	if err != nil {
		return config{}, fmt.Errorf("profile signature: %w", err)
	}
	if err := bundle.Verify(key, b, sig); err != nil {
		return config{}, fmt.Errorf("profile: %w", err)
	}
	return parse(b)
}

// load reads and checks a configuration file without its signature (tests, and loadProfile's
// second half).
func load(path string) (config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return config{}, err
	}
	return parse(b)
}

// parse checks a configuration; any invalid entry refuses the whole file.
func parse(b []byte) (config, error) {
	var c config
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, fmt.Errorf("config: %w", err)
	}
	if c.Listen == "" || c.CertFile == "" || c.KeyFile == "" || c.Audience == "" || len(c.Namespaces) == 0 || !filepath.IsAbs(c.LabelsFile) {
		return c, errors.New("config: listen, certFile, keyFile, audience, namespaces and an absolute labelsFile are required")
	}
	namespaces := map[string]bool{}
	for _, ns := range c.Namespaces {
		if !dnsLabel.MatchString(ns) || namespaces[ns] {
			return c, fmt.Errorf("config: namespace %q is invalid or repeated", ns)
		}
		namespaces[ns] = true
	}
	if c.IdleMinutes == nil {
		c.IdleMinutes = new(int)
		*c.IdleMinutes = 30
	}
	for _, v := range []*int{&c.MaxStreams, &c.MaxStreamsPerWorkspace, c.IdleMinutes} {
		if *v < 0 {
			return c, errors.New("config: stream bounds must not be negative")
		}
	}
	c.MaxStreams = cmp.Or(c.MaxStreams, 64)
	c.MaxStreamsPerWorkspace = cmp.Or(c.MaxStreamsPerWorkspace, 8)
	var err error
	if c.scheme, err = c.MarkingScheme.resolve(); err != nil {
		return c, fmt.Errorf("config: %w", err)
	}
	if c.MarkingPolicy != nil {
		if err := c.loadPolicy(); err != nil {
			return c, fmt.Errorf("config: %w", err)
		}
	}
	if (c.Floor == "") != (len(c.Admins) == 0) || (c.InboxDir != "" && (c.Floor == "" || !filepath.IsAbs(c.InboxDir))) {
		return c, errors.New("config: floor and admins go together, and an absolute inboxDir needs them")
	}
	if c.Floor != "" {
		floor, err := c.scheme.Parse(c.Floor)
		if err != nil {
			return c, fmt.Errorf("config: floor: %v", err)
		}
		c.floor = &floor
	}
	for _, a := range c.Admins {
		ns, account, ok := strings.Cut(a, "/")
		if !ok || !dnsLabel.MatchString(ns) || !dnsLabel.MatchString(account) || slices.Contains(c.Namespaces, ns) {
			return c, fmt.Errorf("config: admin %q is not a service account outside the workspace namespaces", a)
		}
	}
	c.signers = map[string]ed25519.PublicKey{}
	for n, k := range c.Signers {
		key, err := bundle.ParseKey(k)
		if !name.MatchString(n) || err != nil {
			return c, fmt.Errorf("config: signer %q is invalid", n)
		}
		c.signers[n] = key
	}
	if !bundle.ValidDigest(c.HostDigest) {
		return c, errors.New("config: hostDigest must be the plugin host image's sha256:<hex>")
	}
	seen, uids, sockets := map[string]bool{}, map[int]bool{}, map[string]bool{}
	for i := range c.Sources {
		s := &c.Sources[i]
		if !name.MatchString(s.Name) || seen[s.Name] {
			return c, fmt.Errorf("config: connector name %q is invalid or repeated", s.Name)
		}
		seen[s.Name] = true
		if !filepath.IsAbs(s.Bundle) || !filepath.IsAbs(s.TokenPath) || (s.CAPath != "" && !filepath.IsAbs(s.CAPath)) ||
			!filepath.IsAbs(s.Socket) || sockets[s.Socket] {
			return c, fmt.Errorf("config: %s: bundle, socket, tokenPath and caPath must be absolute, and the socket its own", s.Name)
		}
		sockets[s.Socket] = true
		if !bundle.ValidDigest(s.Digest) || s.Digest == c.HostDigest {
			return c, fmt.Errorf("config: %s: digest must be the plugin executable's sha256:<hex>", s.Name)
		}
		s.host = c.HostDigest
		if _, ok := c.signers[s.Signer]; !ok {
			return c, fmt.Errorf("config: %s: signer is not one the profile trusts", s.Name)
		}
		for k := range s.Flags {
			if !launch.FlagName.MatchString(k) || launch.Reserved[k] {
				return c, fmt.Errorf("config: %s: flag %q is invalid", s.Name, k)
			}
		}
		if !validID(s.UID) || !validID(s.GID) || uids[s.UID] {
			return c, fmt.Errorf("config: %s: uid and gid must be set, between 1 and 2147483647, and the uid not another connector's", s.Name)
		}
		uids[s.UID] = true
		if err := checkGrants(*s, namespaces); err != nil {
			return c, fmt.Errorf("config: %s: %v", s.Name, err)
		}
		s.scheme = c.scheme
		if c.policy != nil {
			// One place sets a marking: with a policy it is the policy, read at admission (classify).
			if s.Classification != "" {
				return c, fmt.Errorf("config: %s: classification and markingPolicy both set its marking, and a marking is set in one place: the policy", s.Name)
			}
			continue
		}
		if s.marking, err = c.scheme.Parse(s.Classification); err != nil {
			return c, fmt.Errorf("config: %s: classification: %v", s.Name, err)
		}
	}
	return c, nil
}

// validID is a uid or gid other than root that every platform holds without wrapping.
func validID(id int) bool { return id > 0 && id <= math.MaxInt32 }

// checkGatewayUser refuses a gateway running as root (user or group) or as a plugin's user: it holds
// the labels file and the TLS key, which no plugin may open.
func checkGatewayUser(uid, gid int, sources []source) error {
	if uid == 0 || gid == 0 {
		return errors.New("the gateway must not run as root")
	}
	for _, s := range sources {
		if s.UID == uid {
			return fmt.Errorf("connector %s's plugin user is the gateway's", s.Name)
		}
	}
	return nil
}

// limits bound the phase before a stream is upgraded, when the caller is not yet authenticated.
type limits struct {
	header, read, write, idle time.Duration
	preAuth                   int // connections not yet upgraded; more are closed at once
}

var defaultLimits = limits{header: 10 * time.Second, read: 15 * time.Second, write: 30 * time.Second, idle: 30 * time.Second, preAuth: 128}

// server is the pod's listener. HTTP/1.1 only: a stream is an upgraded connection, which HTTP/2
// cannot hijack. Before the upgrade every connection is bounded: header size and read, write and
// idle time, and how many may be open at once; the handler clears the deadlines only on a stream it
// has authenticated and taken over. Its own error log (TLS handshake failures, which name the
// caller's ALPN protocols and server name, and recovered handler panics) writes one fixed line and
// nothing from the error.
func server(addr string, h http.Handler, log *slog.Logger, lim limits) *http.Server {
	var mu sync.Mutex
	open := map[net.Conn]bool{}
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: lim.header,
		ReadTimeout:       lim.read,
		WriteTimeout:      lim.write,
		IdleTimeout:       lim.idle,
		MaxHeaderBytes:    16 << 10,
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		ErrorLog:          stdlog.New(fixed{log}, "", 0),
		ConnState: func(c net.Conn, state http.ConnState) {
			mu.Lock()
			defer mu.Unlock()
			switch state {
			case http.StateNew:
				if len(open) >= lim.preAuth {
					_ = c.Close() // refused at once; its StateClosed finds nothing to remove
					return
				}
				open[c] = true
			case http.StateHijacked, http.StateClosed:
				delete(open, c)
			}
		},
	}
}

// fixed is a writer that logs a constant for whatever it is given.
type fixed struct{ log *slog.Logger }

func (f fixed) Write(b []byte) (int, error) {
	f.log.Warn("tls/http server error")
	return len(b), nil
}

func main() {
	path := flag.String("config", "", "path to the connector gateway's signed profile (JSON)")
	sigPath := flag.String("config-sig", "", "the profile's detached signature (default: <config>.sig)")
	adminKey := flag.String("admin-key", "", "the administrator's base64 ed25519 public key, pinned outside the profile")
	initialize := flag.String("init-labels", "", "create an empty labels file at this path and exit (first install, or an administrator's reset after removing the old one); with --config, for the profile's scheme")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := hardenGateway(); err != nil {
		log.Error("refusing to start: cannot disable core dumps", "err", err)
		os.Exit(2)
	}
	if *initialize != "" {
		scheme := marking.Current()
		if *path != "" {
			c, err := loadProfile(*path, cmp.Or(*sigPath, *path+".sig"), *adminKey)
			if err != nil {
				log.Error("could not create the labels file", "err", err)
				os.Exit(2)
			}
			scheme = c.scheme
		}
		if err := initLabels(*initialize, scheme); err != nil {
			log.Error("could not create the labels file", "err", err)
			os.Exit(2)
		}
		return
	}
	c, err := loadProfile(*path, cmp.Or(*sigPath, *path+".sig"), *adminKey)
	if err != nil {
		log.Error("refusing to start", "err", err)
		os.Exit(2)
	}
	// One scheme for the life of the process: every label is read, compared and printed under it.
	if err := marking.Configure(c.scheme); err != nil {
		log.Error("refusing to start", "err", err)
		os.Exit(2)
	}
	if err := checkGatewayUser(os.Geteuid(), os.Getegid(), c.Sources); err != nil {
		log.Error("refusing to start", "err", err)
		os.Exit(2)
	}
	if err := admit(&c); err != nil {
		log.Error("refusing to start", "err", err)
		os.Exit(2)
	}
	// The API server, reached the way every in-cluster client reaches it.
	const sa = "/var/run/secrets/kubernetes.io/serviceaccount/"
	ca, err := os.ReadFile(sa + "ca.crt")
	pool := x509.NewCertPool()
	if err != nil || !pool.AppendCertsFromPEM(ca) {
		log.Error("refusing to start: no API server CA")
		os.Exit(2)
	}
	l, err := openLabels(c.LabelsFile, c.scheme)
	if err != nil {
		log.Error("refusing to start", "err", err)
		os.Exit(2)
	}
	var in *inbox
	if c.InboxDir != "" {
		if in, err = openInbox(c.InboxDir); err != nil {
			log.Error("refusing to start", "err", err)
			os.Exit(2)
		}
	}
	sources := map[string]source{}
	for _, s := range c.Sources {
		sources[s.Name] = s
		log.Info("connector", "name", s.Name, "plugin", s.manifest.Name, "version", s.manifest.Version, "digest", s.Digest, "marking", marking.Banner(s.marking), "writes", s.Writes)
	}
	// The pod's own status, for the image each plugin container runs.
	podAt, err := podURL(os.Getenv)
	if err != nil {
		log.Error("refusing to start", "err", err)
		os.Exit(2)
	}
	// The API server is reached at fixed URLs only: no redirect is followed, so the token goes nowhere else.
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	pods := &podStatus{url: podAt, client: client, tokenFile: sa + "token"}
	g := &gateway{
		sources: sources,
		review: &reviewer{
			url:        "https://kubernetes.default.svc/apis/authentication.k8s.io/v1/tokenreviews",
			client:     client,
			tokenFile:  sa + "token",
			audience:   c.Audience,
			namespaces: c.Namespaces,
			admins:     c.Admins,
		},
		labels:          l,
		namespaces:      c.Namespaces,
		floor:           c.floor,
		inbox:           in,
		log:             log,
		start:           func(s source) (*process, error) { return dial(context.Background(), s, pods.check) },
		maxStreams:      c.MaxStreams,
		maxPerWorkspace: c.MaxStreamsPerWorkspace,
		idle:            time.Duration(*c.IdleMinutes) * time.Minute,
	}
	srv := server(c.Listen, g, log, defaultLimits)
	log.Info("listening", "addr", c.Listen)
	log.Error("stopped", "err", srv.ListenAndServeTLS(c.CertFile, c.KeyFile))
	os.Exit(1)
}
