package marking

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
)

// The engine: parsing, banners, dominance and join, read from a Scheme. Every rule that names a
// level, a token or a country comes from the scheme's data; the kinds of group are the code here.

// usGov is the default scheme, the one every process uses unless it is configured otherwise.
var usGov = mustPreset("us-gov")

func mustPreset(name string) *Scheme {
	s, err := Preset(name)
	if err != nil {
		panic("marking: preset " + name + ": " + err.Error())
	}
	return s
}

// current is the process scheme once Configure has set one; nil is us-gov.
var current atomic.Pointer[Scheme]

// process is the scheme this process parses, compares and prints labels with.
func process() *Scheme {
	if s := current.Load(); s != nil {
		return s
	}
	return usGov
}

// ErrSchemeMismatch is the refusal to compare or combine markings read under different
// classification schemes. Nothing converts a marking from one scheme to another.
var ErrSchemeMismatch = errors.New("these markings belong to different classification schemes and are never compared or combined")

// Configure sets the classification scheme this process uses, once, before it reads any label.
// Setting the scheme it already uses again is allowed; any other change is refused: a deployment
// has one scheme, and changing it is a migration, not a setting. The process uses the rules the
// scheme was loaded with (rules), which nothing outside this package can reach.
func Configure(s *Scheme) error {
	if s == nil || s.digest == "" {
		return errors.New("marking: no scheme to configure")
	}
	c := s.r()
	if current.CompareAndSwap(nil, c) || current.Load().digest == c.digest {
		return nil
	}
	return fmt.Errorf("marking: this process already uses the %s scheme (%s); it cannot change to %s (%s)",
		current.Load().Name, current.Load().digest, s.Name, s.digest)
}

// r is the rules the scheme was loaded with: a deep copy made at load, which every engine method
// uses. A Scheme's exported fields are for reading; changing them changes nothing that is enforced.
func (s *Scheme) r() *Scheme {
	if s.rules != nil {
		return s.rules
	}
	return s
}

// clone is a deep copy: nothing in it is shared with s.
func (s *Scheme) clone() *Scheme {
	c := *s
	c.Levels = slices.Clone(s.Levels)
	c.Retired = slices.Clone(s.Retired)
	c.Groups = make([]Group, len(s.Groups))
	for i, g := range s.Groups {
		g.Levels = slices.Clone(g.Levels)
		g.Countries = slices.Clone(g.Countries)
		tokens := make([]Token, len(g.Tokens))
		for j, t := range g.Tokens {
			t.Levels = slices.Clone(t.Levels)
			tokens[j] = t
		}
		g.Tokens = tokens
		if g.Tetragraphs != nil {
			tetra := map[string][]string{}
			for k, v := range g.Tetragraphs {
				tetra[k] = slices.Clone(v)
			}
			g.Tetragraphs = tetra
		}
		c.Groups[i] = g
	}
	return &c
}

// Current is the scheme this process uses: the one Configure set, or us-gov.
func Current() *Scheme { return process() }

// DigestOf is the digest of the scheme a marking was read under.
func DigestOf(m Marking) string { return schemeOf(m).digest }

// IsDefault reports whether s is the us-gov preset, the scheme of every deployment that names none.
func (s *Scheme) IsDefault() bool { return s.digest == usGov.digest }

// schemeOf is the scheme a marking was read under.
func schemeOf(m Marking) *Scheme {
	if m.scheme == nil {
		return usGov
	}
	return m.scheme
}

// owns reports whether every marking was read under s (the same digest).
func (s *Scheme) owns(ms ...Marking) bool {
	for _, m := range ms {
		if schemeOf(m).digest != s.digest {
			return false
		}
	}
	return true
}

// mark is the value a marking read under s records: nil for us-gov, so a us-gov marking is the
// same value however it was made.
func (s *Scheme) mark() *Scheme {
	if s.digest == usGov.digest {
		return nil
	}
	return s.r()
}

// Parse reads a banner under this scheme.
func (s *Scheme) Parse(banner string) (Marking, error) { return s.r().parse(banner) }

// Banner renders m, which must have been read under this scheme.
func (s *Scheme) Banner(m Marking) (string, error) {
	s = s.r()
	if !s.owns(m) {
		return "", ErrSchemeMismatch
	}
	return s.banner(m), nil
}

// Dominates reports whether a may hold content marked b. It is false (a refusal) when either was
// read under another scheme.
func (s *Scheme) Dominates(a, b Marking) bool { s = s.r(); return s.owns(a, b) && s.dominates(a, b) }

// Join is the high-water update of a and b; ErrSchemeMismatch when either was read under another
// scheme.
func (s *Scheme) Join(a, b Marking) (Marking, error) {
	s = s.r()
	if !s.owns(a, b) {
		return Marking{}, ErrSchemeMismatch
	}
	return s.join(a, b)
}

// Bottom is the lowest label of the scheme: its lowest level and nothing else.
func (s *Scheme) Bottom() Marking { return Marking{scheme: s.r().mark()} }

// suffixWord is an opaque sub-compartment after a token and a hyphen.
var suffixWord = regexp.MustCompile(`^[A-Z0-9]+$`)

// field is the Marking field holding a require group's tokens, or nil for a group no field holds
// (those are in Tags).
func (m *Marking) field(group string) *[]string {
	switch group {
	case "sci":
		return &m.SCI
	case "sap":
		return &m.SAP
	case "aea":
		return &m.AEA
	case "nonic":
		return &m.NonIC
	case "controls":
		return &m.Controls
	case "categories":
		return &m.Categories
	}
	return nil
}

// get is a require group's tokens.
func (m *Marking) get(group string) []string {
	if f := m.field(group); f != nil {
		return *f
	}
	return m.Tags[group]
}

// put sets a require group's tokens. An empty group adds nothing to Tags.
func (m *Marking) put(group string, l []string) {
	if f := m.field(group); f != nil {
		*f = l
		return
	}
	if len(l) == 0 {
		delete(m.Tags, group)
		return
	}
	if m.Tags == nil {
		m.Tags = map[string][]string{}
	}
	m.Tags[group] = l
}

func (s *Scheme) kind(k string) *Group {
	for i := range s.Groups {
		if s.Groups[i].Kind == k {
			return &s.Groups[i]
		}
	}
	return nil
}

// catchAll is the group that also holds the release lines: it reads its banner group word by
// word, after every other group has declined it.
func (s *Scheme) catchAll() *Group {
	rel := s.kind("release")
	for i := range s.Groups {
		if rel != nil && s.Groups[i].Name == rel.InGroup {
			return &s.Groups[i]
		}
	}
	return nil
}

func (g *Group) allowed(level int) bool {
	return len(g.Levels) == 0 || slices.Contains(g.Levels, level)
}

func (g *Group) tokenAllowed(t Token, level int) bool {
	if len(t.Levels) == 0 {
		return g.allowed(level)
	}
	return slices.Contains(t.Levels, level)
}

// lookup finds the group's token for a word: the token itself or, for a token that takes one, the
// token with an opaque sub-compartment.
func (g *Group) lookup(w string) (Token, bool) {
	for _, t := range g.Tokens {
		if t.Token == w {
			return t, true
		}
	}
	for _, t := range g.Tokens {
		if rest, ok := strings.CutPrefix(w, t.Token+"-"); ok && t.Suffix && suffixWord.MatchString(rest) {
			return t, true
		}
	}
	return Token{}, false
}

// accepts reports whether the group takes the word at the level.
func (g *Group) accepts(w string, level int) bool {
	switch {
	case g.Prefix != "":
		id, ok := strings.CutPrefix(w, g.Prefix)
		return ok && sapToken.MatchString(id)
	case g.SpecifiedPrefix != "":
		base, specified := strings.CutPrefix(w, g.SpecifiedPrefix)
		t, ok := g.lookup(base)
		if !ok || !g.tokenAllowed(t, level) {
			return false
		}
		return t.Variant == "either" || (t.Variant == "specified") == specified
	}
	t, ok := g.lookup(w)
	return ok && g.tokenAllowed(t, level)
}

// variantKey sorts specified tokens before basic ones, each alphabetically.
func (g *Group) variantKey(w string) string {
	if strings.HasPrefix(w, g.SpecifiedPrefix) {
		return "0" + w
	}
	return "1" + w
}

func (s *Scheme) parse(in string) (Marking, error) {
	m := Marking{scheme: s.mark()}
	in = strings.ToUpper(strings.TrimSpace(in))
	if !bannerChars.MatchString(in) {
		return m, errors.New("a marking holds only letters, digits, spaces, commas, hyphens and slashes")
	}
	groups := strings.Split(in, "//")
	for _, g := range groups {
		for _, r := range s.Retired {
			if g == r.Token {
				return m, errors.New(r.Message)
			}
		}
	}
	m.Level = slices.IndexFunc(s.Levels, func(l Level) bool { return l.Name == groups[0] })
	if m.Level < 0 {
		return Marking{}, fmt.Errorf("unknown classification level %q", groups[0])
	}
	last := 0
	for gi, g := range groups[1:] {
		pos, err := s.group(&m, strings.Split(g, "/"), gi == 0)
		if err != nil {
			return m, err
		}
		if pos <= last {
			return m, fmt.Errorf("marking group %q is out of order or repeated", g)
		}
		last = pos
	}
	if rel := s.kind("release"); rel != nil && m.RelTo != nil && s.homeOnly(m) {
		return m, fmt.Errorf("%s contradicts %s", rel.ReleaseLine, rel.NoRelease)
	}
	return m, nil
}

// group records one //-separated group and returns its banner position. Groups are tried in the
// scheme's order; the catch-all group, read word by word, comes last.
func (s *Scheme) group(m *Marking, toks []string, first bool) (int, error) {
	catch := s.catchAll()
	for gi := range s.Groups {
		g := &s.Groups[gi]
		if g.Kind == "release" || g == catch || !g.allowed(m.Level) || (g.First && !first) {
			continue
		}
		if g.Kind == "sourced" {
			word := g.Tokens[0].Token
			if len(toks) != 1 || (toks[0] != word && !strings.HasPrefix(toks[0], word+" ")) {
				continue
			}
			if !g.tokenAllowed(g.Tokens[0], m.Level) {
				return 0, fmt.Errorf("%s is not allowed at %s", word, s.Levels[m.Level].Name)
			}
			rel := s.kind("release")
			m.HasFGI = true
			for _, c := range strings.Fields(strings.TrimPrefix(toks[0], word)) {
				if !slices.Contains(rel.Countries, c) && rel.Tetragraphs[c] == nil {
					return 0, fmt.Errorf("unknown country code %q in %s", c, word)
				}
				m.FGI = append(m.FGI, c)
			}
			return g.Position, nil
		}
		if slices.ContainsFunc(toks, func(t string) bool { return !g.accepts(t, m.Level) }) {
			continue
		}
		if g.SpecifiedPrefix != "" {
			slices.SortFunc(toks, func(a, b string) int { return strings.Compare(g.variantKey(a), g.variantKey(b)) })
			m.put(g.Name, toks)
		} else {
			m.put(g.Name, sorted(toks))
		}
		return g.Position, nil
	}
	if catch == nil {
		return 0, s.refusal(toks, m.Level)
	}
	rel := s.kind("release")
	for _, t := range toks {
		for _, line := range []string{rel.ReleaseLine, rel.DisplayLine} {
			if strings.HasPrefix(t, line+" ") && !rel.allowed(m.Level) {
				return 0, fmt.Errorf("%s is not allowed at %s", line, s.Levels[m.Level].Name)
			}
		}
		switch {
		case strings.HasPrefix(t, rel.ReleaseLine+" "):
			l, err := s.releaseList(t[len(rel.ReleaseLine)+1:])
			if err != nil {
				return 0, err
			}
			if m.RelTo != nil {
				return 0, fmt.Errorf("%s appears more than once", rel.ReleaseLine)
			}
			m.RelTo = l
		case strings.HasPrefix(t, rel.DisplayLine+" "):
			l, err := s.releaseList(t[len(rel.DisplayLine)+1:])
			if err != nil {
				return 0, err
			}
			if m.DisplayOnly != nil {
				return 0, fmt.Errorf("%s appears more than once", rel.DisplayLine)
			}
			m.DisplayOnly = l
		default:
			tok, ok := catch.lookup(t)
			if !ok {
				return 0, fmt.Errorf("unknown marking token %q", t)
			}
			if !catch.tokenAllowed(tok, m.Level) {
				return 0, fmt.Errorf("%s is not allowed at %s", t, s.Levels[m.Level].Name)
			}
			// The word as written: a token with a sub-compartment keeps it, so two compartments
			// stay two labels.
			word := tok.Token
			if tok.Suffix {
				word = t
			}
			if l := m.get(catch.Name); !slices.Contains(l, word) {
				m.put(catch.Name, append(l, word))
			}
		}
	}
	return catch.Position, nil
}

// refusal says why no group took a banner group: a word no group knows, or a word whose group
// knows it at other levels. A marking is never raised to make a word fit.
func (s *Scheme) refusal(toks []string, level int) error {
	for _, t := range toks {
		known := false
		for gi := range s.Groups {
			g := &s.Groups[gi]
			if g.Kind == "require" && g.accepts(t, level) {
				known = true
			}
		}
		if known {
			continue
		}
		for _, g := range s.Groups {
			if _, ok := g.lookup(t); ok && g.Kind == "require" {
				return fmt.Errorf("%s is not allowed at %s", t, s.Levels[level].Name)
			}
		}
		return fmt.Errorf("unknown marking token %q", t)
	}
	return fmt.Errorf("marking group %q mixes groups", strings.Join(toks, "/"))
}

// releaseList checks a list such as "USA, AUS, GBR, FVEY": the home country first, then
// countries, then tetragraphs, each alphabetical and known.
func (s *Scheme) releaseList(text string) ([]string, error) {
	rel := s.kind("release")
	l := strings.Split(text, ",")
	for i := range l {
		l[i] = strings.TrimSpace(l[i])
	}
	if l[0] != rel.Home {
		return nil, fmt.Errorf("a release list must start with %s", rel.Home)
	}
	for i, c := range l[1:] {
		prev := l[i]
		_, tetra := rel.Tetragraphs[c]
		_, prevTetra := rel.Tetragraphs[prev]
		switch {
		case !tetra && !slices.Contains(rel.Countries, c), c == rel.Home:
			return nil, fmt.Errorf("unknown or repeated country code %q", c)
		case i > 0 && (prevTetra && !tetra || prevTetra == tetra && prev >= c):
			return nil, fmt.Errorf("release list out of order at %q", c)
		}
	}
	return l, nil
}

// banner renders the canonical banner: the level, then each group in banner position.
func (s *Scheme) banner(m Marking) string {
	out := []string{s.Levels[m.Level].Name}
	add := func(l []string) {
		if len(l) > 0 {
			out = append(out, strings.Join(l, "/"))
		}
	}
	order := slices.Clone(s.Groups)
	slices.SortStableFunc(order, func(a, b Group) int { return a.Position - b.Position })
	catch, rel := s.catchAll(), s.kind("release")
	for _, g := range order {
		switch {
		case g.Kind == "release":
		case g.Kind == "sourced":
			if m.HasFGI {
				out = append(out, strings.Join(append([]string{g.Tokens[0].Token}, m.FGI...), " "))
			}
		case catch != nil && g.Name == catch.Name:
			// Table order; a token's sub-compartments, sorted, where the token stands.
			var d []string
			words := sorted(m.get(g.Name))
			for _, t := range g.Tokens {
				for _, w := range words {
					if w == t.Token || t.Suffix && strings.HasPrefix(w, t.Token+"-") {
						d = append(d, w)
					}
				}
			}
			if m.RelTo != nil {
				d = append(d, rel.ReleaseLine+" "+strings.Join(m.RelTo, ", "))
			}
			if m.DisplayOnly != nil {
				d = append(d, rel.DisplayLine+" "+strings.Join(m.DisplayOnly, ", "))
			}
			add(d)
		default:
			if g.Kind == "require" {
				add(m.get(g.Name))
			}
		}
	}
	return strings.Join(out, "//")
}

// dominates: a's level is at least b's; a carries every token of every require group b carries,
// except a group a's level absorbs; sourced content is held only by a holder that names at least
// its countries (concealed only by concealed); and a's release and display are within b's.
func (s *Scheme) dominates(a, b Marking) bool {
	if a.Level < b.Level {
		return false
	}
	for _, g := range s.Groups {
		switch g.Kind {
		case "require":
			if g.AbsorbedFrom >= 0 && a.Level >= g.AbsorbedFrom {
				continue
			}
			if !superset(a.get(g.Name), b.get(g.Name)) {
				return false
			}
		case "sourced":
			if b.HasFGI && (!a.HasFGI || len(a.FGI) > 0 && (len(b.FGI) == 0 || !superset(a.FGI, b.FGI))) {
				return false
			}
		}
	}
	return subset(s.release(a), s.release(b)) && subset(s.display(a), s.display(b))
}

// join is a marking that dominates both. It is the least such marking except where it marks
// higher on purpose (disjoint release lists become home-only; a display restriction that only one
// side carries, or that no list can express, becomes a display list of the home country); the Lean
// model in testifysec/formal/contract proves it is never lower than the least one. It refuses with
// ErrNoBanner when the joined level does not allow a group the join carries (raising the level is
// not its call), and with ErrBannerTooLong when the banner would not read back.
func (s *Scheme) join(a, b Marking) (Marking, error) {
	j := Marking{Level: max(a.Level, b.Level), HasFGI: a.HasFGI || b.HasFGI, scheme: s.mark()}
	for _, g := range s.Groups {
		if g.Kind != "require" || g.AbsorbedFrom >= 0 && j.Level >= g.AbsorbedFrom {
			continue
		}
		l := union(a.get(g.Name), b.get(g.Name))
		if g.SpecifiedPrefix != "" {
			slices.SortFunc(l, func(x, y string) int { return strings.Compare(g.variantKey(x), g.variantKey(y)) })
		}
		j.put(g.Name, l)
	}
	for _, g := range s.Groups {
		carried := g.Kind == "sourced" && j.HasFGI || g.Kind == "require" && len(j.get(g.Name)) > 0
		if carried && !g.allowed(j.Level) {
			return Marking{}, ErrNoBanner
		}
	}
	if j.HasFGI && !(a.HasFGI && len(a.FGI) == 0 || b.HasFGI && len(b.FGI) == 0) {
		j.FGI = union(a.FGI, b.FGI)
	}
	if rel := s.kind("release"); rel != nil {
		s.joinRelease(&j, a, b, rel)
	}
	text := s.banner(j)
	if len(text) > maxBanner {
		return Marking{}, ErrBannerTooLong
	}
	// Every carried token must stand, in its own group, at the joined level: otherwise the banner
	// would read back as something else (another group's token of the same word) or not at all.
	for _, g := range s.Groups {
		if g.Kind == "require" && slices.ContainsFunc(j.get(g.Name), func(w string) bool { return !g.accepts(w, j.Level) }) {
			return Marking{}, ErrNoBanner
		}
		if g.Kind == "sourced" && j.HasFGI && !g.tokenAllowed(g.Tokens[0], j.Level) {
			return Marking{}, ErrNoBanner
		}
	}
	// And the banner must read back as exactly this marking.
	back, err := s.parse(text)
	if err != nil || s.banner(back) != text || !reflect.DeepEqual(LatticeOf(back), LatticeOf(j)) {
		return Marking{}, ErrNoBanner
	}
	return j, nil
}

func (s *Scheme) joinRelease(j *Marking, a, b Marking, rel *Group) {
	ra, rb := s.release(a), s.release(b)
	switch {
	case subset(ra, rb):
		j.RelTo = a.RelTo
	case subset(rb, ra):
		j.RelTo = b.RelTo
	default:
		var l []string
		for c := range ra {
			if rb[c] && c != rel.Home {
				l = append(l, c)
			}
		}
		slices.Sort(l)
		if len(l) == 0 {
			g := s.noReleaseGroup()
			j.put(g, union(j.get(g), []string{rel.NoRelease}))
		} else {
			j.RelTo = append([]string{rel.Home}, l...)
		}
	}
	if s.homeOnly(*j) {
		j.RelTo = nil
	}
	// Display: who may see it without release. The join may show it only where both may.
	if da, db := s.display(a), s.display(b); da != nil || db != nil {
		d, rj := da, s.release(*j)
		if d == nil {
			d = db
		} else if db != nil {
			for c := range d {
				if !db[c] {
					delete(d, c)
				}
			}
		}
		var extra []string
		for c := range d {
			if c != rel.Home && (rj == nil || !rj[c]) {
				extra = append(extra, c)
			}
		}
		slices.Sort(extra)
		// An unrestricted release would let it be shown to anyone: restrict it to the list.
		if len(extra) > 0 || rj == nil {
			j.DisplayOnly = append([]string{rel.Home}, extra...)
		}
	}
}

// noReleaseGroup is the require group that owns the release group's no-release token: the one whose
// token carries the release group's portion, resolved at load. Another group may have a token of
// the same word at other levels; that one is not the restriction.
func (s *Scheme) noReleaseGroup() string { return s.kind("release").noReleaseIn }

// homeOnly reports whether m carries the no-release token.
func (s *Scheme) homeOnly(m Marking) bool {
	return slices.Contains(m.get(s.noReleaseGroup()), s.kind("release").NoRelease)
}

// display is who may see the marking's content: those it may be released to, plus its display
// list. nil means anyone.
func (s *Scheme) display(m Marking) map[string]bool {
	r := s.release(m)
	if r == nil {
		return nil
	}
	d := map[string]bool{}
	for c := range r {
		d[c] = true
	}
	for c := range s.expand(m.DisplayOnly) {
		d[c] = true
	}
	return d
}

// release is the set of countries the marking allows release to; nil means unrestricted.
func (s *Scheme) release(m Marking) map[string]bool {
	rel := s.kind("release")
	switch {
	case rel == nil:
		return nil
	case s.homeOnly(m):
		return map[string]bool{rel.Home: true}
	case m.RelTo != nil:
		return s.expand(m.RelTo)
	case rel.RestrictedFrom >= 0 && m.Level >= rel.RestrictedFrom:
		return map[string]bool{rel.Home: true} // no release decision recorded
	case m.DisplayOnly != nil:
		return map[string]bool{rel.Home: true} // display, not release, to the listed countries
	}
	return nil
}

func (s *Scheme) expand(l []string) map[string]bool {
	rel := s.kind("release")
	out := map[string]bool{}
	for _, c := range l {
		if members, ok := rel.Tetragraphs[c]; ok {
			for _, m := range members {
				out[m] = true
			}
		} else {
			out[c] = true
		}
	}
	return out
}

// forPortion is the banner word of the token whose portion mark is p.
func (s *Scheme) forPortion(p string) (string, bool) {
	for _, g := range s.Groups {
		for _, t := range g.Tokens {
			if t.Portion == p && p != "" {
				return t.Token, true
			}
		}
	}
	return "", false
}
