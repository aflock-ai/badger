package broker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
)

// FileConfig is the operator's configuration file (see README "Configuration" and
// examples/config.json). It is read once at start. Nothing in it can be changed through the
// admin API: issuers, upstreams and credentials stay operator-only.
type FileConfig struct {
	Listen struct {
		Internal  string `json:"internal"`
		Edge      string `json:"edge"`
		Provision string `json:"provision"`
		// Admin serves the admin API and anything mounted beside it, and no model route.
		Admin string `json:"admin"`
	} `json:"listen"`
	// Issuers are the OIDC issuers whose workload tokens the edge verifies (federation.go).
	Issuers          []IssuerConfig `json:"issuers"`
	ClockSkewSeconds int            `json:"clock_skew_seconds"`
	Sources          []string       `json:"sources"`
	Headers          struct {
		Principal string `json:"principal"`
		AdminID   string `json:"admin_id"`
		AdminName string `json:"admin_name"`
		AdminRole string `json:"admin_role"`
	} `json:"headers"`
	HumanPrincipals        []string `json:"human_principals"`
	AdminRoles             []string `json:"admin_roles"`
	TwoPersonRule          *bool    `json:"two_person_rule"`
	MaxNamedBranchTTLHours int      `json:"max_named_branch_ttl_hours"`
	AllowedOrigins         []string `json:"allowed_origins"`
	// Database is where every piece of the service's state lives (README "State").
	Database DatabaseConfig `json:"database"`
	// CeilingMarking is the deployment's accreditation ceiling, a banner the marking package
	// parses. Admin sessions, pipelines and the provisioner run at it; a workspace runs at its own
	// label, never above it.
	CeilingMarking string `json:"ceiling_marking"`
	// ImportStateDir is a broker state directory from before the database (policy versions, audit
	// log, owners, quotas, tokens, usage ledger), imported once into an empty database at start.
	ImportStateDir        string `json:"import_state_dir,omitempty"`
	SeedPolicyFile        string `json:"seed_policy_file"`
	MaxConcurrentUpstream int    `json:"max_concurrent_upstream"`
	// Upstream timeouts. Reasoning models can think for minutes before the first byte.
	Upstream UpstreamConfig `json:"upstream"`
	// Workspace tokens (tokens.go): the provisioner's key file and each token's lifetime.
	ProvisionerKeyFile     string `json:"provisioner_key_file"`
	WorkspaceTokenTTLHours int    `json:"workspace_token_ttl_hours"`
	// Device sign-in (device.go): off unless enabled. A person approves a device at the edge and
	// the device gets its own token for DeviceTokenTTLHours, at most MaxDeviceTokens per person.
	DeviceLogin         bool          `json:"device_login"`
	DeviceTokenTTLHours int           `json:"device_token_ttl_hours"`
	MaxDeviceTokens     int           `json:"max_device_tokens"`
	Routes              []RouteConfig `json:"routes"`
	// SeedLimits are the first defaults for the limits an admin sets in the portal (quota.go):
	// each field is applied once, when the broker first sees it, and never over an admin's value.
	SeedLimits *SeedLimits `json:"seed_limits,omitempty"`

	// AdminUI is display-only chrome for the admin console: the product name in its header
	// and links to sibling admin pages (each href a same-origin path). It grants nothing.
	AdminUI struct {
		Brand string    `json:"brand"`
		Nav   []NavLink `json:"nav"`
	} `json:"admin_ui"`

	// Portal configures the management portal the command mounts on the admin listener. The
	// broker does not read it; the command parses it strictly.
	Portal json.RawMessage `json:"portal,omitempty"`

	issuers []*Issuer
	ceiling pgdb.Label
}

// DatabaseConfig names the files holding the connection strings (mounted secrets, never inline)
// and the service role the migrations grant to.
type DatabaseConfig struct {
	// DSNFile holds the service role's connection string: grants only, no superuser, no BYPASSRLS.
	DSNFile string `json:"dsn_file"`
	// OwnerDSNFile holds the owner role's connection string. When set, the service migrates the
	// schema at start with it; when empty, migrations are run separately before start.
	OwnerDSNFile string `json:"owner_dsn_file,omitempty"`
	ServiceRole  string `json:"service_role"`
}

var reRole = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// Ceiling is the deployment's ceiling label.
func (c *FileConfig) Ceiling() pgdb.Label { return c.ceiling }

// UpstreamConfig bounds one model call: the first response byte within ResponseHeaderSeconds,
// the whole call within RequestSeconds, and the listeners' write deadline above both so the broker
// answers (502 or the model's reply) before its own server cuts the connection.
type NavLink struct {
	Label string `json:"label"`
	Href  string `json:"href"`
}

type UpstreamConfig struct {
	ResponseHeaderSeconds int `json:"response_header_seconds"`
	RequestSeconds        int `json:"request_seconds"`
	ServerWriteSeconds    int `json:"server_write_seconds"`
}

// Defaults sized for reasoning models (a 30 s header timeout made slow answers 502s).
var defaultUpstream = UpstreamConfig{ResponseHeaderSeconds: 180, RequestSeconds: 240, ServerWriteSeconds: 250}

func (u *UpstreamConfig) check() error {
	if *u == (UpstreamConfig{}) {
		*u = defaultUpstream
	}
	if u.ResponseHeaderSeconds <= 0 || u.ResponseHeaderSeconds > u.RequestSeconds ||
		u.RequestSeconds >= u.ServerWriteSeconds || u.ServerWriteSeconds > 900 {
		return errors.New("config: upstream needs 0 < response_header_seconds <= request_seconds < server_write_seconds <= 900")
	}
	return nil
}

// ServerWriteTimeout is every listener's write deadline.
func (c *FileConfig) ServerWriteTimeout() time.Duration {
	return time.Duration(c.Upstream.ServerWriteSeconds) * time.Second
}

// RouteConfig binds one client-visible model name to one upstream and one credential file.
type RouteConfig struct {
	Model       string `json:"model"`
	UpstreamURL string `json:"upstream_url"`
	// AuthHeader carries the key: "api-key" (Azure OpenAI), "Ocp-Apim-Subscription-Key" (Azure
	// API Management) or "Authorization" (sent as "Bearer <key>").
	AuthHeader string `json:"auth_header"`
	KeyFile    string `json:"key_file"`
	APIVersion string `json:"api_version"`
	// ReasoningMap rewrites reasoning_effort values the deployment rejects.
	ReasoningMap map[string]string `json:"reasoning_map"`
	// NoReasoningWithTools drops reasoning_effort when the request carries tools.
	NoReasoningWithTools bool `json:"no_reasoning_with_tools"`
	// Price is what the provider bills for this model. Without it usage is counted in tokens only.
	Price *Price `json:"price_usd_per_million,omitempty"`
	// MaxCallUSD is the most one call can cost. A call in flight is counted at it against a quota,
	// so calls running at once cannot pass a limit together; without it a call in flight counts
	// as unbounded and a limited principal's next call is refused while it runs.
	MaxCallUSD *float64 `json:"max_call_usd,omitempty"`
	target     *url.URL
}

// Price is USD per million tokens: uncached input, input served from the prompt cache, and output.
type Price struct {
	Input       float64 `json:"input"`
	CachedInput float64 `json:"cached_input"`
	Output      float64 `json:"output"`
}

func (p Price) valid() bool {
	for _, v := range []float64{p.Input, p.CachedInput, p.Output} {
		if v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
			return false
		}
	}
	return true
}

var reHeader = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

var authHeaders = []string{"api-key", "Ocp-Apim-Subscription-Key", "Authorization"}

// LoadConfig reads and checks the operator file. Unknown fields are refused so a typo cannot
// silently drop a setting.
func LoadConfig(path string) (*FileConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("cannot read config file")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var c FileConfig
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return &c, c.check()
}

func (c *FileConfig) check() error {
	l := c.Listen
	addrs := []string{l.Internal, l.Edge, l.Provision, l.Admin}
	if slices.Contains(addrs, "") || len(slices.Compact(slices.Sorted(slices.Values(addrs)))) != len(addrs) {
		return errors.New("config: listen.internal, listen.edge, listen.provision and listen.admin must be set and differ")
	}
	if c.ProvisionerKeyFile == "" || c.WorkspaceTokenTTLHours <= 0 || c.WorkspaceTokenTTLHours > 24*31 {
		return errors.New("config: provisioner_key_file and workspace_token_ttl_hours (1-744) are required")
	}
	if c.DeviceLogin {
		if c.DeviceTokenTTLHours == 0 {
			c.DeviceTokenTTLHours = 8
		}
		if c.MaxDeviceTokens == 0 {
			c.MaxDeviceTokens = 5
		}
		if c.DeviceTokenTTLHours < 1 || c.DeviceTokenTTLHours > 24 || c.MaxDeviceTokens < 1 || c.MaxDeviceTokens > 50 {
			return errors.New("config: device_token_ttl_hours (1-24) and max_device_tokens (1-50)")
		}
	}
	issuers, err := compileIssuers(c.Issuers)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	c.issuers = issuers
	h := c.Headers
	names := []string{h.Principal, h.AdminID, h.AdminName, h.AdminRole}
	for _, n := range names {
		if !reHeader.MatchString(n) {
			return errors.New("config: every headers.* must be a lowercase header name")
		}
	}
	for _, is := range issuers {
		names = append(names, is.ClaimsHeader)
	}
	want := len(names)
	slices.Sort(names)
	if len(slices.Compact(names)) != want {
		return errors.New("config: header names (headers.* and every claims_header) must differ")
	}
	for i, p := range c.HumanPrincipals {
		// ci_header_ne_human_header: a person's principal never looks like a pipeline's.
		if p == "" || strings.HasPrefix(p, "ci:") || auditSafe(p) != p {
			return errors.New("config: invalid human principal")
		}
		// Principals are matched ignoring case (samePrincipal), so two that differ only in case
		// are one person configured twice.
		for _, q := range c.HumanPrincipals[:i] {
			if samePrincipal(p, q) {
				return fmt.Errorf("config: human_principals %q and %q differ only in case; list each person once", q, p)
			}
		}
	}
	if c.Database.DSNFile == "" || !reRole.MatchString(c.Database.ServiceRole) ||
		c.Database.ServiceRole == "public" || strings.HasPrefix(c.Database.ServiceRole, "pg_") {
		return errors.New("config: database.dsn_file and database.service_role (a plain lowercase role name of its own, not public or a pg_ role) are required")
	}
	ceiling, err := pgdb.ParseLabel(c.CeilingMarking)
	if err != nil {
		return fmt.Errorf("config: ceiling_marking: %w", err)
	}
	c.ceiling = ceiling
	if err := c.Upstream.check(); err != nil {
		return err
	}
	if c.SeedLimits != nil {
		seed := QuotaSet{DefaultUSD: c.SeedLimits.DefaultUSD, Defaults: c.SeedLimits.Defaults}
		if err := seed.check(c.Upstream.RequestSeconds); err != nil {
			return fmt.Errorf("config: seed_limits: %w", err)
		}
	}
	if c.MaxConcurrentUpstream <= 0 {
		c.MaxConcurrentUpstream = 4
	}
	if c.TwoPersonRule == nil {
		on := true // default ON until the owner decides (README "Open decisions")
		c.TwoPersonRule = &on
	}
	if c.ClockSkewSeconds < 0 || c.ClockSkewSeconds > 300 {
		return errors.New("config: clock_skew_seconds must be 0-300")
	}
	for _, o := range c.AllowedOrigins {
		if u, err := url.Parse(o); err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" {
			return errors.New("config: allowed_origins must be https origins")
		}
	}
	seen := map[string]bool{}
	for i := range c.Routes {
		r := &c.Routes[i]
		if err := r.check(); err != nil {
			return err
		}
		if seen[r.Model] {
			return errors.New("config: duplicate model route")
		}
		seen[r.Model] = true
	}
	return validOperator(c.Operator())
}

func (r *RouteConfig) check() error {
	if r.Model == "" || auditSafe(r.Model) != r.Model || !slices.Contains(authHeaders, r.AuthHeader) || r.KeyFile == "" {
		return errors.New("config: invalid route")
	}
	if r.Price != nil && !r.Price.valid() {
		return errors.New("config: route price must be finite and not negative")
	}
	if r.MaxCallUSD != nil && (*r.MaxCallUSD < 0 || math.IsInf(*r.MaxCallUSD, 0) || math.IsNaN(*r.MaxCallUSD)) {
		return errors.New("config: route max_call_usd must be finite and not negative")
	}
	u, err := url.Parse(r.UpstreamURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return errors.New("config: invalid upstream_url")
	}
	// The route key travels in a header, so plain http is allowed only to this host.
	if h := u.Hostname(); u.Scheme == "http" && h != "localhost" && !(net.ParseIP(h) != nil && net.ParseIP(h).IsLoopback()) {
		return errors.New("config: upstream_url must be https unless it is loopback")
	}
	if r.APIVersion != "" {
		q := url.Values{}
		q.Set("api-version", r.APIVersion)
		u.RawQuery = q.Encode()
	}
	r.target = u
	return nil
}

// ClaimsHeaders are the headers that carry a verified pipeline payload, one per issuer.
func (c *FileConfig) ClaimsHeaders() []string {
	out := make([]string, 0, len(c.issuers))
	for _, is := range c.issuers {
		out = append(out, is.ClaimsHeader)
	}
	return out
}

// Operator is the decision-relevant subset (Lean `OperatorCfg`).
func (c *FileConfig) Operator() *Operator {
	models := make([]string, 0, len(c.Routes))
	for _, r := range c.Routes {
		models = append(models, r.Model)
	}
	return &Operator{Issuers: c.issuers, RoutedModels: models, Sources: c.Sources, AdminRoles: c.AdminRoles, TwoPerson: *c.TwoPersonRule,
		MaxNamedTTL: time.Duration(c.MaxNamedBranchTTLHours) * time.Hour,
		ClockSkew:   time.Duration(c.ClockSkewSeconds) * time.Second}
}

// samePrincipal reports whether two user principal names name the same person. UPNs are
// case-insensitive, so they are compared with strings.EqualFold; only printable ASCII is folded
// (the configured names are), so a look-alike such as the Kelvin sign never matches a "k".
func samePrincipal(a, b string) bool {
	return isASCII(a) && isASCII(b) && strings.EqualFold(a, b)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// configuredPrincipal is humans' own spelling of p, when p names one of them (samePrincipal). What
// is stored for a person (tokens, usage, owners) uses that spelling, so it stays one key whichever
// case a token carries. A pipeline principal ("ci:...") is never a person.
func configuredPrincipal(humans []string, p string) (string, bool) {
	if p == "" || strings.HasPrefix(p, "ci:") {
		return "", false
	}
	for _, h := range humans {
		if samePrincipal(h, p) {
			return h, true
		}
	}
	return "", false
}
