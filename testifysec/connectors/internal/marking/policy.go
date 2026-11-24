package marking

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"slices"
	"strings"
)

// A Policy is a deployment's marking policy: the scheme its labels are read under and where its
// data comes from. The data-flow block keeps aflock's field names (classify, flowRules) so a policy
// reads the same in both products, but its keys are markings in an ordered scheme, not free names.
//
//   - classify maps a marking to the sources it labels, as typed globs: connector:<instance>/<tool>,
//     mcp:<server>/<tool> (aflock's mcp__server__tool is accepted too), model:<route> and
//     path:<glob>. url: is refused: no gateway checks URL destinations, and a rule nothing enforces
//     would be a false promise.
//   - A source several globs match takes the join of all their markings: the higher of two
//     comparable markings, and for incomparable ones a marking above both. A narrower glob never
//     lowers what a broader one says. A source whose matches join to no banner is refused, and a
//     gateway that knows its sources finds it at start (Uncovered).
//   - default labels a source no glob matches. It is required, and it is "refuse" or a marking at
//     the scheme's top level: never a lower guess.
//   - flowRules only deny: "<tag or marking>-><destination glob>" refuses a flow the scheme's
//     dominance would allow. They never allow anything dominance refuses.
type Policy struct {
	Scheme    *Scheme
	classify  []classified
	def       *Marking // nil: refuse
	flowRules []flowRule
}

type classified struct {
	marking  Marking
	patterns []*regexp.Regexp
	globs    []string
}

type flowRule struct {
	text    string
	label   *Marking // a marking the label must dominate, or
	token   string   // a token the label must carry
	dest    *regexp.Regexp
	message string
}

type filePolicy struct {
	Schema   string `json:"schema"`
	Note     string `json:"note,omitempty"`
	SchemeOf *struct {
		Preset string `json:"preset,omitempty"`
		File   string `json:"file,omitempty"`
		SHA256 string `json:"sha256"`
	} `json:"scheme,omitempty"`
	DataFlow struct {
		Classify  map[string][]string `json:"classify"`
		Default   string              `json:"default"`
		FlowRules []struct {
			Deny    string `json:"deny"`
			Message string `json:"message,omitempty"`
		} `json:"flowRules,omitempty"`
	} `json:"dataFlow"`
}

var policyFields = fieldNames(reflect.TypeFor[filePolicy]())

// ErrUnmapped is Classify's refusal for a source no glob matches under a policy whose default is
// "refuse".
var ErrUnmapped = errors.New("no marking is configured for this source and the policy refuses unmapped sources")

const maxPolicyBytes = 256 << 10

var (
	sourceKind = regexp.MustCompile(`^(connector|mcp|model|path):`)
	globChars  = regexp.MustCompile(`^[A-Za-z0-9._~@+*/-]{1,256}$`)
)

// LoadPolicy reads a marking policy. scheme resolves a {"file": ...} reference to the file's bytes;
// it may be nil when the policy names a preset or no scheme (us-gov). The scheme's digest must be
// the one the policy pins.
func LoadPolicy(name string, raw []byte, scheme func(file string) ([]byte, error)) (*Policy, error) {
	fail := func(path, format string, a ...any) (*Policy, error) {
		return nil, fmt.Errorf("marking policy %s: %s: %s", name, path, fmt.Sprintf(format, a...))
	}
	if len(raw) > maxPolicyBytes {
		return fail("$", "larger than %d bytes", maxPolicyBytes)
	}
	if err := noDuplicateKeys(raw, policyFields); err != nil {
		return fail("$", "%v", err)
	}
	var f filePolicy
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&f); err != nil {
		return fail("$", "not a policy: %v", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return fail("$", "trailing data")
	}
	if f.Schema != "badger.marking-policy/v1" {
		return fail("schema", "must be badger.marking-policy/v1")
	}
	if !freeText(f.Note) {
		return fail("note", "only printable ASCII, at most 1024 bytes")
	}
	p := &Policy{Scheme: usGov}
	if ref := f.SchemeOf; ref != nil {
		var s *Scheme
		var err error
		switch {
		case (ref.Preset == "") == (ref.File == ""):
			return fail("scheme", "name a preset or a file, not both")
		case ref.Preset != "":
			s, err = Preset(ref.Preset)
		case scheme == nil:
			err = errors.New("no scheme files are available here")
		default:
			var b []byte
			if b, err = scheme(ref.File); err == nil {
				s, err = LoadScheme(ref.File, b)
			}
		}
		if err != nil {
			return fail("scheme", "%v", err)
		}
		if s.Digest() != ref.SHA256 {
			return fail("scheme.sha256", "the %s scheme's digest is %s, the policy pins %s", s.Name, s.Digest(), ref.SHA256)
		}
		p.Scheme = s
	}
	s := p.Scheme.r()
	if f.DataFlow.Classify == nil {
		return fail("dataFlow.classify", "required")
	}
	banners := make([]string, 0, len(f.DataFlow.Classify))
	for b := range f.DataFlow.Classify {
		banners = append(banners, b)
	}
	slices.Sort(banners)
	for _, b := range banners {
		path := fmt.Sprintf("dataFlow.classify[%q]", b)
		m, err := s.Parse(b)
		if err != nil {
			return fail(path, "not a %s marking: %v", s.Name, err)
		}
		for _, other := range p.classify {
			if s.banner(other.marking) == s.banner(m) {
				return fail(path, "%s is classified twice", s.banner(m))
			}
		}
		c := classified{marking: m}
		if len(f.DataFlow.Classify[b]) == 0 {
			return fail(path, "no sources")
		}
		for _, g := range f.DataFlow.Classify[b] {
			re, glob, err := sourceGlob(g)
			if err != nil {
				return fail(path, "%v", err)
			}
			c.patterns, c.globs = append(c.patterns, re), append(c.globs, glob)
		}
		p.classify = append(p.classify, c)
	}
	switch def := f.DataFlow.Default; {
	case def == "":
		return fail("dataFlow.default", `required: "refuse" or a marking at the top level`)
	case def != "refuse":
		m, err := s.Parse(def)
		if err != nil {
			return fail("dataFlow.default", "not a %s marking: %v", s.Name, err)
		}
		if m.Level != len(s.Levels)-1 {
			return fail("dataFlow.default", `an unmapped source is "refuse" or the top level (%s), never lower`, s.Levels[len(s.Levels)-1].Name)
		}
		p.def = &m
	}
	for i, r := range f.DataFlow.FlowRules {
		path := fmt.Sprintf("dataFlow.flowRules[%d]", i)
		lhs, rhs, ok := strings.Cut(r.Deny, "->")
		lhs, rhs = strings.TrimSpace(lhs), strings.TrimSpace(rhs)
		if !ok || strings.Contains(rhs, "->") || lhs == "" || rhs == "" || !freeText(r.Message) {
			return fail(path, `a rule is "deny": "<tag or marking>-><destination glob>"`)
		}
		rule := flowRule{text: r.Deny, message: r.Message}
		if m, err := s.Parse(lhs); err == nil {
			rule.label = &m
		} else if s.knows(lhs) {
			rule.token = lhs
		} else {
			return fail(path, "%q is neither a %s marking nor one of its tokens", lhs, s.Name)
		}
		var err error
		if rule.dest, _, err = sourceGlob(rhs); err != nil {
			return fail(path, "%v", err)
		}
		p.flowRules = append(p.flowRules, rule)
	}
	return p, nil
}

// sourceGlob compiles a typed glob: "*" within one segment, "**" across segments. Both match any
// character but the segment separator, newlines included: a file name may hold one.
func sourceGlob(g string) (*regexp.Regexp, string, error) {
	// aflock's mcp__<server>__<tool>: accepted only when it splits one way. A name with another
	// "__", or a part that starts or ends with "_", could be read as two different sources.
	if rest, ok := strings.CutPrefix(g, "mcp__"); ok {
		parts := strings.Split(rest, "__")
		if len(parts) != 2 || slices.ContainsFunc(parts, func(p string) bool {
			return p == "" || strings.HasPrefix(p, "_") || strings.HasSuffix(p, "_")
		}) {
			return nil, "", fmt.Errorf("%q: an mcp__server__tool name must split one way; write mcp:<server>/<tool>", g)
		}
		g = "mcp:" + parts[0] + "/" + parts[1]
	}
	if strings.HasPrefix(g, "url:") {
		return nil, "", fmt.Errorf("%q: url sources are not supported: no gateway checks URL destinations", g)
	}
	k := sourceKind.FindString(g)
	if k == "" {
		return nil, "", fmt.Errorf("%q: a source is connector:, mcp:, model: or path:", g)
	}
	rest := g[len(k):]
	if !globChars.MatchString(rest) || strings.Contains(rest, "***") {
		return nil, "", fmt.Errorf("%q: a glob holds letters, digits, . _ ~ @ + - / and *", g)
	}
	var re strings.Builder
	re.WriteString("^" + regexp.QuoteMeta(k))
	for i := 0; i < len(rest); i++ {
		switch {
		case strings.HasPrefix(rest[i:], "**"):
			re.WriteString("(?s:.*)") // across segments, newlines in a name included
			i++
		case rest[i] == '*':
			re.WriteString("[^/]*")
		default:
			re.WriteString(regexp.QuoteMeta(rest[i : i+1]))
		}
	}
	re.WriteString("$")
	return regexp.MustCompile(re.String()), g, nil
}

// knows reports whether w is one of the scheme's require tokens.
func (s *Scheme) knows(w string) bool {
	for _, g := range s.Groups {
		if g.Kind == "require" && slices.ContainsFunc(g.Tokens, func(t Token) bool { return t.Token == w }) {
			return true
		}
	}
	return false
}

// carries reports whether a marking holds the token, written plainly, with the specified prefix,
// or with a sub-compartment.
func (s *Scheme) carries(m Marking, token string) bool {
	for _, g := range s.Groups {
		if g.Kind != "require" {
			continue
		}
		for _, w := range m.get(g.Name) {
			if g.SpecifiedPrefix != "" {
				w = strings.TrimPrefix(w, g.SpecifiedPrefix)
			}
			if w == token || strings.HasPrefix(w, token+"-") && g.lookupOK(w, token) {
				return true
			}
		}
	}
	return false
}

// lookupOK reports whether w is token with a sub-compartment the token takes.
func (g Group) lookupOK(w, token string) bool {
	t, ok := g.lookup(w)
	return ok && t.Token == token
}

func (s *Scheme) joinAll(ms []Marking) (Marking, error) {
	j := s.Bottom()
	for _, m := range ms {
		var err error
		if j, err = s.join(j, m); err != nil {
			return Marking{}, err
		}
	}
	return j, nil
}

// Classify is a source's marking: the join of the markings of every glob it matches, or the
// default when it matches none (ErrUnmapped when the default is "refuse").
func (p *Policy) Classify(source string) (Marking, error) {
	var hit []Marking
	for _, c := range p.classify {
		if slices.ContainsFunc(c.patterns, func(re *regexp.Regexp) bool { return re.MatchString(source) }) {
			hit = append(hit, c.marking)
		}
	}
	if len(hit) == 0 {
		if p.def == nil {
			return Marking{}, fmt.Errorf("%s: %w", source, ErrUnmapped)
		}
		return *p.def, nil
	}
	return p.Scheme.r().joinAll(hit)
}

// Uncovered lists the sources Classify would refuse: a gateway that knows every tool it serves
// checks them all when it starts, so no refusal waits for a call.
func (p *Policy) Uncovered(sources []string) []string {
	var out []string
	for _, s := range sources {
		if _, err := p.Classify(s); err != nil {
			out = append(out, s)
		}
	}
	return out
}

// Denied reports the first flow rule that refuses sending content labelled label to destination,
// with its message. A rule only denies: dominance is checked separately and first.
func (p *Policy) Denied(label Marking, destination string) (string, bool) {
	for _, r := range p.flowRules {
		if !r.dest.MatchString(destination) {
			continue
		}
		hit := false
		if r.label != nil {
			hit = p.Scheme.Dominates(label, *r.label)
		} else {
			hit = p.Scheme.r().carries(label, r.token)
		}
		if hit {
			if r.message != "" {
				return r.message, true
			}
			return "refused by the marking policy: " + r.text, true
		}
	}
	return "", false
}
