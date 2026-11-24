package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unicode/utf8"
)

type Config struct {
	Schema            string `json:"schema"`
	Socket            string `json:"socket"`
	Spool             string `json:"spool"`
	ProviderURL       string `json:"providerURL"`
	Protocol          string `json:"protocol,omitempty"`
	ProviderTokenFile string `json:"providerTokenFile,omitempty"`
	ProviderTokenFD   int    `json:"providerTokenFd,omitempty"`
	// ProviderCertSHA256 pins the provider's certificate key (SHA-256 of its SubjectPublicKeyInfo,
	// lowercase hex), for a provider whose certificate no system root signs.
	ProviderCertSHA256  string `json:"providerCertSha256,omitempty"`
	CollectorURL        string `json:"collectorURL"`
	CollectorTokenFile  string `json:"collectorTokenFile"`
	Model               string `json:"model"`
	Tenant              string `json:"tenant"`
	Session             string `json:"session"`
	Agent               string `json:"agent"`
	ProfileDigest       string `json:"profileDigest"`
	MaxRecords          int    `json:"maxRecords"`
	MaxOfflineSeconds   int    `json:"maxOfflineSeconds"`
	TimeoutSeconds      int    `json:"timeoutSeconds"`
	DevelopmentLoopback bool   `json:"developmentLoopback"`
	// AdministratorIdentity runs a v3 gateway with no platform: the agent is who the administrator
	// provisioned (the signed profile it admits and the provider credential it holds), and every
	// endpoint is HTTPS. For a network that cannot reach the TestifySec platform.
	AdministratorIdentity bool   `json:"administratorIdentity,omitempty"`
	PlatformConfigFile    string `json:"platformConfigFile,omitempty"`
	SignedProfileFile     string `json:"signedProfileFile,omitempty"`
	// ProfileFile is an unsigned profile (models.go): read by the gateway itself, pinned by
	// profileDigest, with no admission executable. Gateway v3 only, instead of signedProfileFile.
	ProfileFile         string             `json:"profileFile,omitempty"`
	AdmissionExecutable string             `json:"admissionExecutable,omitempty"`
	AdmissionSHA256     string             `json:"admissionSha256,omitempty"`
	Backend             *BackendAssignment `json:"backend,omitempty"`
}

// Omitted protocol preserves the original v1 Chat Completions configuration.
// Responses is an explicit administrator choice, never selected by a worker.
func (c Config) requestPath() string {
	switch c.Protocol {
	case "", "chat-completions":
		return "/v1/chat/completions"
	case "responses":
		return "/v1/responses"
	default:
		return ""
	}
}

// Reject duplicate keys before decoding; encoding/json otherwise accepts the
// last value and case-insensitive struct aliases. Depth is independently bounded.
func strictJSON(data []byte, target any) error {
	if !utf8.Valid(data) {
		return errors.New("invalid JSON encoding")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 {
			return errors.New("JSON depth exceeded")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch t {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return errors.New("duplicate JSON key")
				}
				seen[s] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case json.Delim('['):
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case json.Delim('}'), json.Delim(']'):
			return errors.New("invalid JSON delimiter")
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(target)
}

func privateFile(path string, max int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("absolute clean private file path required")
	}
	if err := privateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	s, err := os.Lstat(path)
	if err != nil || !s.Mode().IsRegular() || s.Mode().Perm()&0077 != 0 || s.Size() > max {
		return nil, errors.New("private regular file required")
	}
	stat, ok := s.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 {
		return nil, errors.New("service-owned file required")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(s, actual) {
		return nil, errors.New("file changed")
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if int64(len(b)) > max {
		return nil, errors.New("file too large")
	}
	return b, err
}

func privateDirectory(path string) error {
	s, err := os.Lstat(path)
	if err != nil || !s.IsDir() || s.Mode().Perm() != 0700 {
		return errors.New("private directory required")
	}
	stat, ok := s.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) {
		return errors.New("service-owned directory required")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("symlink directory rejected")
	}
	return nil
}

// rePathPrefix is a clean path prefix: segments of letters, digits, '-' and '_', no dots.
var rePathPrefix = regexp.MustCompile(`^(/[A-Za-z0-9_-]+)*$`)

// endpoint accepts the protocol path itself, or under a clean prefix (a provider behind an edge
// that routes, say, /broker/v1/...). The administrator still selects the exact URL.
func endpoint(raw string, dev bool, path string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" ||
		!strings.HasSuffix(u.Path, path) || !rePathPrefix.MatchString(strings.TrimSuffix(u.Path, path)) {
		return errors.New("invalid endpoint")
	}
	if u.Scheme == "https" {
		return nil
	}
	ip := net.ParseIP(u.Hostname())
	if dev && u.Scheme == "http" && ip != nil && ip.IsLoopback() {
		return nil
	}
	return errors.New("HTTPS required")
}

func readConfig(path string) (Config, error) {
	var c Config
	b, err := privateFile(path, 32768)
	if err != nil {
		return c, err
	}
	if err = strictJSON(b, &c); err != nil {
		return c, err
	}
	if c.Schema == gatewayV2 || c.Schema == gatewayV3 {
		if err = strictV2(b, &c); err != nil {
			return c, err
		}
	}
	// Marshal's canonical field list also disallows Go's case aliases.
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(b, &fields)
	canonical, _ := json.Marshal(c)
	var allowed map[string]json.RawMessage
	_ = json.Unmarshal(canonical, &allowed)
	if len(fields) != len(allowed) {
		return c, errors.New("all config fields required")
	}
	for key := range fields {
		if _, ok := allowed[key]; !ok {
			return c, errors.New("unknown config field")
		}
	}
	id := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	if (c.Schema != "testifysec.hardened-opencode.gateway/v1" && c.Schema != gatewayV2 && c.Schema != gatewayV3) || !id.MatchString(c.Tenant) || !id.MatchString(c.Session) || len(c.Model) == 0 || len(c.Model) > 128 || strings.ContainsAny(c.Model, "\r\n") || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(c.ProfileDigest) {
		return c, errors.New("invalid config binding")
	}
	u, err := url.Parse(c.Agent)
	if err != nil || u.Scheme != "spiffe" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(c.Agent) > 256 {
		return c, errors.New("invalid agent identifier")
	}
	if c.MaxRecords < 2 || c.MaxRecords > 10000 || c.MaxOfflineSeconds < 1 || c.MaxOfflineSeconds > 86400 || c.TimeoutSeconds < 1 || c.TimeoutSeconds > 600 {
		return c, errors.New("invalid limits")
	}
	for _, p := range []string{c.Socket, c.Spool} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return c, errors.New("absolute clean paths required")
		}
	}
	// The provider token comes from exactly one place: a private file, or an inherited pipe.
	if (c.ProviderTokenFile == "") == (c.ProviderTokenFD == 0) || c.ProviderTokenFD < 0 || (c.ProviderTokenFD > 0 && c.ProviderTokenFD < 3) {
		return c, errors.New("exactly one provider token source required")
	}
	if c.ProviderTokenFile != "" && (!filepath.IsAbs(c.ProviderTokenFile) || filepath.Clean(c.ProviderTokenFile) != c.ProviderTokenFile) {
		return c, errors.New("absolute clean paths required")
	}
	if c.CollectorTokenFile != "" && (!filepath.IsAbs(c.CollectorTokenFile) || filepath.Clean(c.CollectorTokenFile) != c.CollectorTokenFile) {
		return c, errors.New("absolute collector token path required")
	}
	if err = identityConfiguration(c); err != nil {
		return c, err
	}
	if c.PlatformConfigFile != "" && (!filepath.IsAbs(c.PlatformConfigFile) || filepath.Clean(c.PlatformConfigFile) != c.PlatformConfigFile) {
		return c, errors.New("absolute platform config path required")
	}
	if err := profileConfiguration(c); err != nil {
		return c, err
	}
	if c.requestPath() == "" {
		return c, errors.New("unsupported provider protocol")
	}
	if err = validPin(c.ProviderCertSHA256, c.ProviderURL); err != nil {
		return c, err
	}
	if err = endpoint(c.ProviderURL, c.DevelopmentLoopback, c.requestPath()); err != nil {
		return c, err
	}
	if err = endpoint(c.CollectorURL, c.DevelopmentLoopback, "/v1/logs"); err != nil {
		return c, err
	}
	return c, nil
}

// identityConfiguration: the platform's live check, or the development loopback harness, or (alone)
// the administrator's provisioning: v3, a profile (signed, or unsigned and pinned by digest), a
// collector token, HTTPS endpoints (endpoint refuses cleartext unless developmentLoopback, which
// administrator identity excludes).
func identityConfiguration(c Config) error {
	if !c.AdministratorIdentity {
		if !c.DevelopmentLoopback && c.PlatformConfigFile == "" {
			return errors.New("live platform identity required")
		}
		return nil
	}
	if c.DevelopmentLoopback || c.PlatformConfigFile != "" {
		return errors.New("exactly one identity source required")
	}
	if c.Schema != gatewayV3 || c.SignedProfileFile == "" && c.ProfileFile == "" {
		return errors.New("administrator identity requires gateway v3 and a profile")
	}
	// With no platform, the collector's only way to know the sender is this token.
	if c.CollectorTokenFile == "" {
		return errors.New("administrator identity requires a collector token")
	}
	return nil
}

func token(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	b, err := privateFile(path, 8192)
	if err != nil {
		return "", err
	}
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" || strings.ContainsAny(s, "\r\n\x00") {
		return "", errors.New("invalid token")
	}
	return s, nil
}

var rePin = regexp.MustCompile(`^[0-9a-f]{64}$`)

var reASCIIHost = regexp.MustCompile(`^[A-Za-z0-9.:\[\]-]+$`)

// validPin checks a provider pin, and that a pinned provider's host is plain ASCII: an
// internationalized name is dialed in its punycode form and would never compare equal.
func validPin(pin, providerURL string) error {
	if pin == "" {
		return nil
	}
	u, err := url.Parse(providerURL)
	if !rePin.MatchString(pin) || err != nil || !reASCIIHost.MatchString(u.Hostname()) {
		return errors.New("invalid provider certificate pin")
	}
	return nil
}
