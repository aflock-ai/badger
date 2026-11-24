package broker

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// This file is formal/BadgerBroker/BrokerPolicy.lean for the primary issuer. Keep the two in step:
// the shared corpus in testdata/decisions.json is decided by this code (through the built-in
// gitlab mapping, federation.go), formal/mirror.py and the generated formal/BadgerBroker/Corpus.lean,
// and all three must give the recorded answer. Lean does not model several issuers yet.

// Kind is Lean `Kind`.
type Kind string

const (
	KindProtected Kind = "protected_branch"
	KindNamed     Kind = "named_branch"
)

// Entry is one policy entry (Lean `Entry`). The principal is derived, never stored.
type Entry struct {
	ID   string `json:"id"`
	Kind Kind   `json:"kind"`
	// Issuer is an issuer id from the operator's issuers; "" is the primary issuer.
	Issuer       string     `json:"issuer,omitempty"`
	ProjectPath  string     `json:"project_path"`
	Ref          string     `json:"ref"`
	Sources      []string   `json:"sources"`
	Models       []string   `json:"models"`
	TriggerUsers []string   `json:"trigger_users"`
	ExpiresAt    *time.Time `json:"expires_at"`
	// MintedBefore admits only tokens issued (iat) before this instant (Lean `mintedOk`).
	MintedBefore *time.Time `json:"minted_before"`
	Enabled      bool       `json:"enabled"`
}

// Principal is Lean `Entry.principal` rendered (`Principal.render`). An entry of a non-primary
// issuer is qualified by the issuer id: "ci:<id>:<project>". A project path never contains ':',
// so the same project under two issuers is two principals.
func (e *Entry) Principal() string {
	p := "ci:"
	if e.Issuer != "" {
		p += e.Issuer + ":"
	}
	if e.Kind == KindNamed {
		return p + e.ProjectPath + "@" + e.Ref
	}
	return p + e.ProjectPath
}

func (e *Entry) equal(o *Entry) bool {
	return e.ID == o.ID && e.Kind == o.Kind && e.Issuer == o.Issuer && e.ProjectPath == o.ProjectPath && e.Ref == o.Ref &&
		slices.Equal(e.Sources, o.Sources) && slices.Equal(e.Models, o.Models) &&
		slices.Equal(e.TriggerUsers, o.TriggerUsers) && e.Enabled == o.Enabled &&
		sameTime(e.ExpiresAt, o.ExpiresAt) && sameTime(e.MintedBefore, o.MintedBefore)
}

func sameTime(a, b *time.Time) bool {
	return (a == nil) == (b == nil) && (a == nil || a.Equal(*b))
}

// Policy is the admin-editable document: entries only. Its version is assigned by the store.
type Policy struct {
	Entries []Entry `json:"entries"`
}

// Operator is the operator-only part of the configuration that decisions depend on (Lean
// `OperatorCfg`). Nothing in the admin API can change it.
type Operator struct {
	Issuers      []*Issuer
	RoutedModels []string
	Sources      []string
	AdminRoles   []string
	TwoPerson    bool
	MaxNamedTTL  time.Duration
	ClockSkew    time.Duration // token exp only: allowed iff now-skew < exp
}

// issuerByKey finds an entry's issuer.
func (o *Operator) issuerByKey(key string) *Issuer {
	for _, is := range o.Issuers {
		if is.Key() == key {
			return is
		}
	}
	return nil
}

// IssuerByHeader is the issuer whose edge provider writes this header, or nil.
func (o *Operator) IssuerByHeader(header string) *Issuer {
	for _, is := range o.Issuers {
		if strings.EqualFold(is.ClaimsHeader, header) {
			return is
		}
	}
	return nil
}

// Op is Lean `Op`.
type Op int

const (
	OpChat Op = iota
	OpOther
)

// Deny reasons, Lean `Reason`; the strings appear in the audit log and the corpus.
const (
	ReasonNoPolicy        = "no_policy"
	ReasonBadClaims       = "bad_claims"
	ReasonWrongIssuer     = "wrong_issuer"
	ReasonWrongAudience   = "wrong_audience"
	ReasonTokenExpired    = "token_expired"
	ReasonTokenLifetime   = "token_lifetime"
	ReasonWrongOperation  = "wrong_operation"
	ReasonNoMatch         = "no_match"
	ReasonModelMissing    = "model_missing"
	ReasonModelNotAllowed = "model_not_allowed"
)

// Decision is Lean `Decision`.
type Decision struct {
	Allow     bool
	Principal string
	EntryID   string
	Model     string
	Reason    string
}

// ReasonUnowned refuses an allowed pipeline whose policy entry has no human owner. It is applied
// after Evaluate (outside the Lean model), so it can only turn an allow into a deny.
const ReasonUnowned = "nhi_unowned"

func deny(reason string) Decision { return Decision{Reason: reason} }

func (o *Operator) matchesSubject(now time.Time, is *Issuer, s *Subject, e *Entry) bool {
	if !e.Enabled || (e.ExpiresAt != nil && !(now.Unix() < e.ExpiresAt.Unix())) {
		return false
	}
	if e.Issuer != s.IssuerKey || s.Project != e.ProjectPath || s.Ref != e.Ref || s.RefType != "branch" {
		return false
	}
	if (e.Kind == KindProtected && s.Protected != "true") || (e.Kind == KindNamed && s.Protected != "false") {
		return false
	}
	if is.ConfigRefTemplate != "" && s.ConfigRef != is.configRef(e.ProjectPath, e.Ref) {
		return false
	}
	if !slices.Contains(e.Sources, s.Source) {
		return false
	}
	if e.MintedBefore != nil && !(s.Iat < e.MintedBefore.Unix()) {
		return false
	}
	return len(e.TriggerUsers) == 0 || slices.Contains(e.TriggerUsers, s.TriggeredBy)
}

// NoMatchDetail says, for a no_match refusal, which check failed for the closest entry: the entry
// of this issuer and project that passed the most checks, in matchesSubject's order. "issuer" when
// the issuer has no entries, "project" when none of its entries names the project. It is for the
// broker's log only, never the response, which would describe the policy to the caller. It
// decides nothing: Decide alone does.
func (o *Operator) NoMatchDetail(entries []Entry, now time.Time, is *Issuer, s *Subject) string {
	checks := []struct {
		name string
		ok   func(e *Entry) bool
	}{
		{"disabled", func(e *Entry) bool { return e.Enabled }},
		{"expired", func(e *Entry) bool { return e.ExpiresAt == nil || now.Unix() < e.ExpiresAt.Unix() }},
		{"ref", func(e *Entry) bool { return s.Ref == e.Ref }},
		{"ref_type", func(*Entry) bool { return s.RefType == "branch" }},
		{"protected", func(e *Entry) bool {
			return !(e.Kind == KindProtected && s.Protected != "true") && !(e.Kind == KindNamed && s.Protected != "false")
		}},
		{"config_ref", func(e *Entry) bool {
			return is.ConfigRefTemplate == "" || s.ConfigRef == is.configRef(e.ProjectPath, e.Ref)
		}},
		{"source", func(e *Entry) bool { return slices.Contains(e.Sources, s.Source) }},
		{"minted_before", func(e *Entry) bool { return e.MintedBefore == nil || s.Iat < e.MintedBefore.Unix() }},
		{"trigger_user", func(e *Entry) bool { return len(e.TriggerUsers) == 0 || slices.Contains(e.TriggerUsers, s.TriggeredBy) }},
	}
	detail, best, ofIssuer := "", -1, false
	for i := range entries {
		e := &entries[i]
		if e.Issuer != s.IssuerKey {
			continue
		}
		ofIssuer = true
		if e.ProjectPath != s.Project {
			continue
		}
		n := 0
		for n < len(checks) && checks[n].ok(e) {
			n++
		}
		if n > best && n < len(checks) {
			detail, best = checks[n].name, n
		}
	}
	switch {
	case !ofIssuer:
		return "issuer"
	case best < 0:
		return "project"
	}
	return detail
}

// Decide is Lean `evaluate` for the issuer whose header carried the payload. payload is the
// decoded JSON (nil when the header did not decode). entries == nil means no usable policy is
// loaded; model == nil means the request named no model. The Subject is returned for audit when
// the payload mapped, allowed or not.
func (o *Operator) Decide(entries []Entry, now time.Time, is *Issuer, payload []byte, op Op, model *string) (Decision, *Subject) {
	if entries == nil {
		return deny(ReasonNoPolicy), nil
	}
	env, ok := parseEnvelope(payload)
	if !ok || is == nil {
		return deny(ReasonBadClaims), nil
	}
	// The payload must be the issuer's whose provider wrote this header: a token of one trusted
	// issuer is never decided as another's.
	if env.iss != is.Issuer {
		return deny(ReasonWrongIssuer), nil
	}
	s, ok := is.subject(env)
	if !ok {
		return deny(ReasonBadClaims), nil
	}
	if env.audIsList || env.aud != is.Audience {
		return deny(ReasonWrongAudience), s
	}
	if !(now.Add(-o.ClockSkew).Unix() < env.exp) {
		return deny(ReasonTokenExpired), s
	}
	// With a cap the broker bounds the token itself: issued at a non-negative time no later than
	// it expires, not in the future beyond the skew, and living at most the cap. iat is bounded
	// on both sides before iat+lim is formed, so nothing here can overflow (exp-iat could). A
	// gitlab issuer without a cap leaves all of this to the edge, as before federation.
	if lim := int64(is.MaxTokenLifetimeSeconds); lim > 0 &&
		(env.iat < 0 || env.iat > env.exp || env.iat > now.Add(o.ClockSkew).Unix() || env.exp > env.iat+lim) {
		return deny(ReasonTokenLifetime), s
	}
	if op != OpChat {
		return deny(ReasonWrongOperation), s
	}
	for i := range entries {
		e := &entries[i]
		if !o.matchesSubject(now, is, s, e) {
			continue
		}
		if model == nil {
			return deny(ReasonModelMissing), s
		}
		if !slices.Contains(e.Models, *model) || !slices.Contains(o.RoutedModels, *model) {
			return deny(ReasonModelNotAllowed), s
		}
		return Decision{Allow: true, Principal: e.Principal(), EntryID: e.ID, Model: *model}, s
	}
	return deny(ReasonNoMatch), s
}

var (
	reID      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	reProject = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)+$`)
	// A generic issuer's project may be a single segment (a Kubernetes namespace).
	reGenericProject = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$`)
	reRef            = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,255}$`)
	reUser           = regexp.MustCompile(`^[A-Za-z0-9._-]{1,255}$`)
)

// Validate is Lean `wellFormed` plus shape rules the model leaves to the parser (identifier
// syntax, sizes). now is the write time, which bounds a named-branch entry's expiry. An empty
// result means the policy may be stored.
func (o *Operator) Validate(p *Policy, now time.Time) []string {
	var errs []string
	add := func(i int, format string, args ...any) {
		errs = append(errs, fmt.Sprintf("entries[%d]: ", i)+fmt.Sprintf(format, args...))
	}
	if p == nil || p.Entries == nil {
		return []string{"entries: required (use [] for none)"}
	}
	if len(p.Entries) > 256 {
		return []string{"entries: at most 256"}
	}
	ids, principals, pairs := map[string]bool{}, map[string]bool{}, map[[3]string]bool{}
	for i := range p.Entries {
		e := &p.Entries[i]
		if !reID.MatchString(e.ID) {
			add(i, "id must match %s", reID)
		}
		// An explicit primary id is the primary issuer: one entry, one principal.
		for _, is := range o.Issuers {
			if is.Primary && e.Issuer == is.ID {
				e.Issuer = ""
			}
		}
		is := o.issuerByKey(e.Issuer)
		if is == nil {
			add(i, "issuer %q is not one the operator trusts", e.Issuer)
		}
		project := reProject
		if is != nil && is.Type == "generic" {
			project = reGenericProject
		}
		if !project.MatchString(e.ProjectPath) {
			add(i, "project_path must be a namespace/project path")
		}
		if !reRef.MatchString(e.Ref) || strings.Contains(e.Ref, "..") {
			add(i, "ref must be a branch name")
		}
		if len(e.Sources) == 0 {
			add(i, "sources: at least one")
		}
		for _, s := range e.Sources {
			if !slices.Contains(o.Sources, s) {
				add(i, "source %q is not one the operator allows", s)
			}
		}
		if len(e.Models) == 0 {
			add(i, "models: at least one")
		}
		for _, m := range e.Models {
			if !slices.Contains(o.RoutedModels, m) {
				add(i, "model %q is not routed", m)
			}
		}
		if e.TriggerUsers == nil {
			e.TriggerUsers = []string{}
		}
		for _, u := range e.TriggerUsers {
			if !reUser.MatchString(u) {
				add(i, "trigger user %q is malformed", u)
			}
		}
		switch e.Kind {
		case KindProtected:
		case KindNamed:
			if len(e.TriggerUsers) == 0 {
				add(i, "a named_branch entry must list trigger_users")
			}
			if e.ExpiresAt == nil {
				add(i, "a named_branch entry must set expires_at")
			} else if e.ExpiresAt.Unix() > now.Add(o.MaxNamedTTL).Unix() {
				add(i, "expires_at is more than %s after now", o.MaxNamedTTL)
			}
		default:
			add(i, "kind must be %q or %q", KindProtected, KindNamed)
		}
		if ids[e.ID] {
			add(i, "duplicate id %q", e.ID)
		}
		if principals[e.Principal()] {
			add(i, "duplicate principal %q (one protected_branch entry per project)", e.Principal())
		}
		pair := [3]string{e.Issuer, e.ProjectPath, e.Ref}
		if pairs[pair] {
			add(i, "duplicate project and ref")
		}
		ids[e.ID], principals[e.Principal()], pairs[pair] = true, true, true
	}
	return errs
}

// validOperator refuses an operator config the model does not describe.
func validOperator(o *Operator) error {
	if len(o.Issuers) == 0 || len(o.RoutedModels) == 0 || len(o.Sources) == 0 || len(o.AdminRoles) == 0 {
		return errors.New("issuers, routes, sources and admin_roles are required")
	}
	if o.MaxNamedTTL <= 0 || o.ClockSkew < 0 {
		return errors.New("max_named_branch_ttl must be positive and clock_skew non-negative")
	}
	return nil
}
