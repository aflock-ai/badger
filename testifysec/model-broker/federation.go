package broker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
)

// Workload identity federation. The edge verifies each pipeline or workload token against the
// keys pinned for its issuer and forwards the verified payload in that issuer's own header. The
// broker trusts a payload only for the issuer bound to the header it arrived in, maps the
// issuer's claims to a Subject, and decides on the Subject alone. Policy never reads raw claims.

// IssuerConfig is one trusted issuer in the operator file (config.json "issuers").
type IssuerConfig struct {
	ID       string `json:"id"`
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	// ClaimsHeader is the header the edge's provider for this issuer forwards the payload in.
	ClaimsHeader string `json:"claims_header"`
	// MaxTokenLifetimeSeconds bounds exp - iat. 0 is allowed only for a gitlab issuer, whose edge
	// provider enforces max_lifetime itself (the configuration before federation).
	MaxTokenLifetimeSeconds int `json:"max_token_lifetime_seconds"`
	// Type is "gitlab" (built-in claim mapping) or "generic" (Mapping below).
	Type    string              `json:"type"`
	Primary bool                `json:"primary"`
	Mapping map[string]ClaimRef `json:"mapping"`
	// Require: claims every token from this issuer must carry with exactly this string value.
	Require map[string]string `json:"require"`
	// RefPrefix is stripped from the mapped ref and must be present (GitHub: "refs/heads/").
	RefPrefix string `json:"ref_prefix"`
	// ConfigRefTemplate is the only CI config an entry accepts: {project_path} then {ref}.
	ConfigRefTemplate string `json:"config_ref_template"`
}

// ClaimRef names where a Subject field comes from: a claim (a name, or a path into nested
// objects) or a constant the operator asserts.
type ClaimRef struct {
	Path  []string
	Const *string
}

func (c *ClaimRef) UnmarshalJSON(raw []byte) error {
	var v struct {
		Claim json.RawMessage `json:"claim"`
		Const *string         `json:"const"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return err
	}
	if (v.Claim == nil) == (v.Const == nil) {
		return errors.New("mapping: exactly one of claim or const")
	}
	if v.Const != nil {
		c.Const = v.Const
		return nil
	}
	var one string
	if json.Unmarshal(v.Claim, &one) == nil {
		c.Path = []string{one}
	} else if json.Unmarshal(v.Claim, &c.Path) != nil {
		return errors.New("mapping: claim is a name or a list of names")
	}
	if len(c.Path) == 0 || slices.Contains(c.Path, "") {
		return errors.New("mapping: empty claim name")
	}
	return nil
}

// Subject fields. Policy entries match these, whatever the issuer called them.
const (
	FieldSub         = "sub"
	FieldProject     = "project"
	FieldRef         = "ref"
	FieldRefType     = "ref_type"
	FieldProtected   = "protected"
	FieldSource      = "source"
	FieldTriggeredBy = "triggered_by"
	FieldConfigRef   = "config_ref"
)

var (
	subjectFields  = []string{FieldSub, FieldProject, FieldRef, FieldRefType, FieldProtected, FieldSource, FieldTriggeredBy, FieldConfigRef}
	requiredFields = []string{FieldProject, FieldRef, FieldRefType, FieldProtected, FieldSource}
)

// Subject is a verified token mapped to issuer-neutral fields. A field the issuer does not map
// is "". IssuerKey is "" for the primary issuer and the issuer id otherwise (Entry.Issuer).
type Subject struct {
	IssuerKey   string
	Sub         string
	Project     string
	Ref         string
	RefType     string
	Protected   string
	Source      string
	TriggeredBy string
	ConfigRef   string
	Iat, Exp    int64
}

// Issuer is a checked IssuerConfig.
type Issuer struct {
	IssuerConfig
	mapping  map[string]ClaimRef
	optional map[string]bool // gitlab only: claims that may be absent (as before federation)
}

// Key is what an entry names: "" for the primary issuer.
func (is *Issuer) Key() string {
	if is.Primary {
		return ""
	}
	return is.ID
}

func (is *Issuer) configRef(project, ref string) string {
	return strings.NewReplacer("{project_path}", project, "{ref}", ref).Replace(is.ConfigRefTemplate)
}

// gitlabMapping is GitLab's CI job token (id_tokens), exactly the claims the broker read before
// federation: ref_protected and user_login may be absent, sub is not read.
func gitlabMapping() (map[string]ClaimRef, map[string]bool) {
	c := func(name string) ClaimRef { return ClaimRef{Path: []string{name}} }
	return map[string]ClaimRef{
		FieldProject: c("project_path"), FieldRef: c("ref"), FieldRefType: c("ref_type"),
		FieldProtected: c("ref_protected"), FieldSource: c("pipeline_source"), FieldTriggeredBy: c("user_login"),
		FieldConfigRef: c("ci_config_ref_uri"),
	}, map[string]bool{FieldProtected: true, FieldTriggeredBy: true}
}

var reIssuerID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

func validTemplate(t string) bool {
	pi, ri := strings.Index(t, "{project_path}"), strings.Index(t, "{ref}")
	return strings.Count(t, "{project_path}") == 1 && strings.Count(t, "{ref}") == 1 && pi >= 0 && ri > pi
}

// compileIssuers checks the operator's issuer list. Every rule here fails closed at start.
func compileIssuers(cfgs []IssuerConfig) ([]*Issuer, error) {
	if len(cfgs) == 0 || len(cfgs) > 16 {
		return nil, errors.New("issuers: one to 16 required")
	}
	ids, isss, headers, primaries := map[string]bool{}, map[string]bool{}, map[string]bool{}, 0
	out := make([]*Issuer, 0, len(cfgs))
	for i, c := range cfgs {
		bad := func(msg string) error { return fmt.Errorf("issuers[%d]: %s", i, msg) }
		if !reIssuerID.MatchString(c.ID) || ids[c.ID] {
			return nil, bad("id must be unique and match " + reIssuerID.String())
		}
		if c.Issuer == "" || auditSafe(c.Issuer) != c.Issuer || isss[c.Issuer] {
			return nil, bad("issuer must be set, plain and unique")
		}
		if c.Audience == "" || auditSafe(c.Audience) != c.Audience {
			return nil, bad("audience must be set")
		}
		if !reHeader.MatchString(c.ClaimsHeader) || headers[c.ClaimsHeader] {
			return nil, bad("claims_header must be a unique lowercase header name")
		}
		if c.MaxTokenLifetimeSeconds < 0 || c.MaxTokenLifetimeSeconds > 86400 ||
			(c.MaxTokenLifetimeSeconds == 0 && c.Type != "gitlab") {
			return nil, bad("max_token_lifetime_seconds must be 1-86400 (0 only for gitlab)")
		}
		for k, v := range c.Require {
			if k == "" || v == "" {
				return nil, bad("require needs claim names and values")
			}
		}
		if c.Primary {
			primaries++
		}
		is := &Issuer{IssuerConfig: c}
		switch c.Type {
		case "gitlab":
			if c.Mapping != nil || c.RefPrefix != "" {
				return nil, bad("a gitlab issuer has the built-in mapping")
			}
			is.mapping, is.optional = gitlabMapping()
		case "generic":
			for k := range c.Mapping {
				if !slices.Contains(subjectFields, k) {
					return nil, bad(fmt.Sprintf("mapping: unknown field %q", k))
				}
			}
			for _, k := range requiredFields {
				if _, ok := c.Mapping[k]; !ok {
					return nil, bad(fmt.Sprintf("mapping: %q is required", k))
				}
			}
			is.mapping, is.optional = c.Mapping, map[string]bool{}
		default:
			return nil, bad(`type must be "gitlab" or "generic"`)
		}
		if _, mapped := is.mapping[FieldConfigRef]; mapped != (c.ConfigRefTemplate != "") {
			return nil, bad("config_ref_template is required exactly when config_ref is mapped")
		}
		if c.ConfigRefTemplate != "" && !validTemplate(c.ConfigRefTemplate) {
			return nil, bad("config_ref_template must contain {project_path} then {ref}, once each")
		}
		ids[c.ID], isss[c.Issuer], headers[c.ClaimsHeader] = true, true, true
		out = append(out, is)
	}
	if primaries > 1 {
		return nil, errors.New("issuers: at most one primary")
	}
	return out, nil
}

// envelope is the part of every payload that identifies its issuer and lifetime.
type envelope struct {
	iss       string
	aud       string
	audIsList bool // never matches
	exp, iat  int64
	claims    map[string]json.RawMessage
}

// parseEnvelope: a single JSON object; iss a string; aud a string or a list of strings; exp and
// iat integers (a quoted number is refused).
func parseEnvelope(raw []byte) (*envelope, bool) {
	var m map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	if raw == nil || dec.Decode(&m) != nil || m == nil || dec.More() {
		return nil, false
	}
	e := &envelope{claims: m}
	if v, ok := m["iss"]; !ok || json.Unmarshal(v, &e.iss) != nil {
		return nil, false
	}
	aud, ok := m["aud"]
	if !ok {
		return nil, false
	}
	if json.Unmarshal(aud, &e.aud) != nil {
		var list []string
		if json.Unmarshal(aud, &list) != nil {
			return nil, false
		}
		e.aud, e.audIsList = "", true
	}
	for _, f := range []struct {
		name string
		dst  *int64
	}{{"exp", &e.exp}, {"iat", &e.iat}} {
		raw, present := m[f.name]
		if !present {
			return nil, false
		}
		var v any
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		if d.Decode(&v) != nil {
			return nil, false
		}
		num, isNumber := v.(json.Number)
		if !isNumber {
			return nil, false
		}
		if *f.dst, ok = intOf(num); !ok {
			return nil, false
		}
	}
	return e, true
}

func intOf(n json.Number) (int64, bool) {
	if i, err := n.Int64(); err == nil {
		return i, true
	}
	f, err := n.Float64()
	if err != nil || f != math.Trunc(f) || f < 0 || f > 1<<53 {
		return 0, false
	}
	return int64(f), true
}

// lookup follows a claim path. A missing claim is (nil, false).
func lookup(claims map[string]json.RawMessage, path []string) (json.RawMessage, bool) {
	v, ok := claims[path[0]]
	for _, name := range path[1:] {
		if !ok {
			return nil, false
		}
		var obj map[string]json.RawMessage
		if json.Unmarshal(v, &obj) != nil || obj == nil {
			return nil, false
		}
		v, ok = obj[name]
	}
	return v, ok
}

// subject maps the payload. Every required claim must be present; every present mapped claim
// must be a JSON string (a boolean ref_protected is refused rather than coerced).
func (is *Issuer) subject(e *envelope) (*Subject, bool) {
	for name, want := range is.Require {
		v, ok := e.claims[name]
		var got string
		if !ok || json.Unmarshal(v, &got) != nil || got != want {
			return nil, false
		}
	}
	vals := map[string]string{}
	for field, ref := range is.mapping {
		if ref.Const != nil {
			vals[field] = *ref.Const
			continue
		}
		raw, ok := lookup(e.claims, ref.Path)
		if !ok {
			if is.optional[field] {
				continue
			}
			return nil, false
		}
		// json.Unmarshal accepts null into a string as ""; a null claim is not a string.
		var s string
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &s) != nil {
			return nil, false
		}
		vals[field] = s
	}
	if is.RefPrefix != "" {
		ref, ok := strings.CutPrefix(vals[FieldRef], is.RefPrefix)
		if !ok {
			return nil, false
		}
		vals[FieldRef] = ref
	}
	return &Subject{IssuerKey: is.Key(), Sub: vals[FieldSub], Project: vals[FieldProject], Ref: vals[FieldRef],
		RefType: vals[FieldRefType], Protected: vals[FieldProtected], Source: vals[FieldSource],
		TriggeredBy: vals[FieldTriggeredBy], ConfigRef: vals[FieldConfigRef], Iat: e.iat, Exp: e.exp}, true
}
