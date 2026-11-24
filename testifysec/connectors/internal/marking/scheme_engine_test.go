package marking

import (
	"encoding/json"
	"errors"
	"math/rand/v2"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) *Scheme {
	t.Helper()
	raw, err := os.ReadFile("testdata/schemes/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := LoadScheme(name+".json", raw)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func must(t *testing.T, s *Scheme, banner string) Marking {
	t.Helper()
	m, err := s.Parse(banner)
	if err != nil {
		t.Fatalf("%s: %q: %v", s.Name, banner, err)
	}
	return m
}

func banner(t *testing.T, s *Scheme, m Marking) string {
	t.Helper()
	b, err := s.Banner(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCorporateParse(t *testing.T) {
	s := preset(t, "corporate")
	for in, want := range map[string]string{
		"public":                         "PUBLIC",
		"INTERNAL":                       "INTERNAL",
		"INTERNAL//EXPORT":               "INTERNAL//EXPORT",
		"CONFIDENTIAL//PII/PHI":          "CONFIDENTIAL//PHI/PII",
		"RESTRICTED//PCI/MNPI":           "RESTRICTED//MNPI/PCI",
		"CONFIDENTIAL//CUSTOMER-A1":      "CONFIDENTIAL//CUSTOMER-A1",
		"RESTRICTED//TRADE SECRET/PII":   "RESTRICTED//PII/TRADE SECRET",
		"CONFIDENTIAL//PRIVILEGED/PHI":   "CONFIDENTIAL//PHI/PRIVILEGED",
		" confidential//customer-b2/phi": "CONFIDENTIAL//CUSTOMER-B2/PHI",
	} {
		m := must(t, s, in)
		if got := banner(t, s, m); got != want {
			t.Errorf("%q: banner %q, want %q", in, got, want)
		}
		if again := must(t, s, want); !reflect.DeepEqual(again, m) {
			t.Errorf("%q does not read back", want)
		}
	}
}

// A tag below its minimum level is refused, never raised to fit; so is anything the scheme does
// not know, including another scheme's words.
func TestCorporateRefuses(t *testing.T) {
	s := preset(t, "corporate")
	for in, want := range map[string]string{
		"INTERNAL//PHI":                      "PHI is not allowed at INTERNAL",
		"PUBLIC//EXPORT":                     "EXPORT is not allowed at PUBLIC",
		"PUBLIC//PII":                        "PII is not allowed at PUBLIC",
		"CONFIDENTIAL//PHI//PII":             "out of order or repeated",
		"CONFIDENTIAL//PHX":                  "unknown marking token",
		"CONFIDENTIAL//CUSTOMER-":            "unknown marking token",
		"CONFIDENTIAL//CUSTOMER-A-":          "unknown marking token",
		"HIGHLY CONFIDENTIAL":                "unknown classification level",
		tab.Levels[3].Banner:                 "unknown classification level",
		"CONFIDENTIAL//" + tab.SCI.Tokens[0]: "unknown marking token",
	} {
		if _, err := s.Parse(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", in, err, want)
		}
	}
}

// Join takes the higher level and every tag of both; nothing is dropped. Dominance needs every
// tag: a higher level without the tag does not hold the content.
func TestCorporateJoinAndDominance(t *testing.T) {
	s := preset(t, "corporate")
	j, err := s.Join(must(t, s, "CONFIDENTIAL//PHI"), must(t, s, "RESTRICTED//PCI"))
	if err != nil || banner(t, s, j) != "RESTRICTED//PCI/PHI" {
		t.Fatalf("join: %v %v", j, err)
	}
	for _, c := range []struct {
		a, b string
		ok   bool
	}{
		{"RESTRICTED//PCI/PHI", "CONFIDENTIAL//PHI", true},
		{"RESTRICTED", "CONFIDENTIAL//PHI", false},
		{"CONFIDENTIAL//PHI", "CONFIDENTIAL//PHI/PII", false},
		{"CONFIDENTIAL//CUSTOMER-A1", "CONFIDENTIAL//CUSTOMER-B2", false},
		{"CONFIDENTIAL//CUSTOMER-A1/CUSTOMER-B2", "CONFIDENTIAL//CUSTOMER-B2", true},
		{"INTERNAL", "CONFIDENTIAL", false},
		{"RESTRICTED", "PUBLIC", true},
	} {
		if got := s.Dominates(must(t, s, c.a), must(t, s, c.b)); got != c.ok {
			t.Errorf("%s dominates %s: %v, want %v", c.a, c.b, got, c.ok)
		}
	}
	l := LatticeOf(must(t, s, "CONFIDENTIAL//PII/CUSTOMER-A1"))
	if !slices.Equal(l.Tags, []string{"handling/CUSTOMER-A1", "handling/PII"}) || l.Release != nil {
		t.Errorf("lattice %+v", l)
	}
}

func TestCustomSchemes(t *testing.T) {
	hc := fixture(t, "healthcare")
	if _, err := hc.Parse("CONFIDENTIAL//SUD"); err == nil {
		t.Error("SUD below RESTRICTED parsed")
	}
	j, err := hc.Join(must(t, hc, "RESTRICTED//SUD"), must(t, hc, "CONFIDENTIAL//PHI/PII"))
	if err != nil || banner(t, hc, j) != "RESTRICTED//PHI/PII/SUD" {
		t.Errorf("healthcare join %v %v", j, err)
	}
	fs := fixture(t, "finserv")
	m := must(t, fs, "RESTRICTED//MNPI//DEAL-ALPHA 7")
	if banner(t, fs, m) != "RESTRICTED//MNPI//DEAL-ALPHA 7" || fs.Dominates(must(t, fs, "RESTRICTED//MNPI"), m) {
		t.Errorf("finserv deal codes: %v", m)
	}
	if _, err := fs.Parse("CONFIDENTIAL//PCI"); err == nil {
		t.Error("PCI below RESTRICTED parsed in finserv")
	}
}

// A marking read under one scheme is never compared with, combined with or printed by another:
// Dominates is false both ways, Join and Banner refuse. The zero Marking is a us-gov marking.
func TestSchemeMismatchRefused(t *testing.T) {
	gov, corp := preset(t, "us-gov"), preset(t, "corporate")
	g, c := must(t, gov, tab.Levels[0].Banner), must(t, corp, "PUBLIC")
	for _, pair := range [][2]Marking{{g, c}, {c, g}, {Marking{}, c}, {c, Marking{}}} {
		for _, s := range []*Scheme{gov, corp} {
			if s.Dominates(pair[0], pair[1]) {
				t.Errorf("%s: dominates across schemes", s.Name)
			}
			if _, err := s.Join(pair[0], pair[1]); !errors.Is(err, ErrSchemeMismatch) {
				t.Errorf("%s: join across schemes: %v", s.Name, err)
			}
		}
	}
	if _, err := gov.Banner(c); !errors.Is(err, ErrSchemeMismatch) {
		t.Error("us-gov printed a corporate marking")
	}
	// The same scheme loaded twice is the same scheme.
	again := preset(t, "corporate")
	if !again.Dominates(c, must(t, corp, "PUBLIC")) {
		t.Error("a second load of the same scheme refused its markings")
	}
	if !reflect.DeepEqual(must(t, gov, tab.Levels[0].Banner), Marking{}) || !reflect.DeepEqual(gov.Bottom(), Marking{}) {
		t.Error("a us-gov marking is not the plain value")
	}
}

// Configure sets the process scheme once; the same scheme again is allowed, another is refused,
// and from then on the package functions refuse markings read under another scheme.
func TestConfigureOnce(t *testing.T) {
	t.Cleanup(func() { current.Store(nil) })
	corp, gov := preset(t, "corporate"), preset(t, "us-gov")
	before, err := Parse(tab.Levels[1].Banner)
	if err != nil {
		t.Fatal(err)
	}
	if err := Configure(corp); err != nil {
		t.Fatal(err)
	}
	if err := Configure(preset(t, "corporate")); err != nil {
		t.Errorf("configuring the same scheme again: %v", err)
	}
	if err := Configure(gov); err == nil || !strings.Contains(err.Error(), "cannot change") {
		t.Errorf("changing the scheme: %v", err)
	}
	m, err := Parse("CONFIDENTIAL//PHI")
	if err != nil || m.String() != "CONFIDENTIAL//PHI" {
		t.Fatalf("process parse: %v %v", m, err)
	}
	if _, err := Parse(tab.Levels[1].Banner); err == nil {
		t.Error("a us-gov banner parsed under the corporate process scheme")
	}
	if Dominates(m, before) || Dominates(m, Marking{}) {
		t.Error("a marking read before the change compared under the new scheme")
	}
	if _, err := Join(m, before); !errors.Is(err, ErrSchemeMismatch) {
		t.Errorf("join with a marking read before the change: %v", err)
	}
	if b := Bottom(); b.String() != "PUBLIC" || !Dominates(m, b) {
		t.Errorf("bottom %v", b)
	}
}

// labels draws markings of a scheme from its own tokens.
func labels(s *Scheme, n int, seed uint64) []Marking {
	r := rand.New(rand.NewPCG(seed, 7))
	var words []string
	for _, g := range s.Groups {
		if g.Kind != "require" {
			continue
		}
		for _, t := range g.Tokens {
			w := t.Token
			if t.Variant == "specified" {
				w = g.SpecifiedPrefix + w
			}
			words = append(words, w)
		}
		if g.Prefix != "" {
			words = append(words, g.Prefix+"X1")
		}
	}
	var out []Marking
	for len(out) < n {
		b := s.Levels[r.IntN(len(s.Levels))].Name
		if r.IntN(3) > 0 {
			b += "//" + words[r.IntN(len(words))]
		}
		if m, err := s.Parse(b); err == nil {
			out = append(out, m)
		}
	}
	return out
}

// The structural rules hold in every scheme: a join never lowers a level or drops a token it is
// not absorbing, dominates both sides, and reads back; dominance is reflexive and transitive.
func TestInvariantsEveryScheme(t *testing.T) {
	for _, s := range []*Scheme{preset(t, "us-gov"), preset(t, "corporate"), fixture(t, "healthcare"), fixture(t, "finserv")} {
		ms := labels(s, 120, 11)
		for _, a := range ms {
			if !s.Dominates(a, a) {
				t.Errorf("%s: %s does not dominate itself", s.Name, banner(t, s, a))
			}
			if back := must(t, s, banner(t, s, a)); !reflect.DeepEqual(back, a) {
				t.Errorf("%s: %s does not read back", s.Name, banner(t, s, a))
			}
			for _, b := range ms {
				j, err := s.Join(a, b)
				if err != nil {
					if !errors.Is(err, ErrNoBanner) && !errors.Is(err, ErrBannerTooLong) {
						t.Errorf("%s: join: %v", s.Name, err)
					}
					continue
				}
				if j.Level != max(a.Level, b.Level) || !s.Dominates(j, a) || !s.Dominates(j, b) {
					t.Errorf("%s: join of %s and %s is %s", s.Name, banner(t, s, a), banner(t, s, b), banner(t, s, j))
				}
				for _, g := range s.Groups {
					if g.Kind != "require" || g.AbsorbedFrom >= 0 && j.Level >= g.AbsorbedFrom {
						continue
					}
					if !superset(j.get(g.Name), a.get(g.Name)) || !superset(j.get(g.Name), b.get(g.Name)) {
						t.Errorf("%s: join of %s and %s dropped a %s token", s.Name, banner(t, s, a), banner(t, s, b), g.Name)
					}
				}
				for _, c := range ms[:20] {
					if s.Dominates(a, b) && s.Dominates(b, c) && !s.Dominates(a, c) {
						t.Errorf("%s: dominance not transitive", s.Name)
					}
				}
			}
		}
	}
}

// The rules in force are the ones a scheme was loaded with: changing a Scheme's exported fields,
// before or after Configure, changes nothing that is enforced, through the package functions or
// the scheme's own methods.
func TestSchemeRulesCannotBeChanged(t *testing.T) {
	t.Cleanup(func() { current.Store(nil) })
	corp := preset(t, "corporate")
	corp.Groups = nil
	if err := Configure(corp); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse("INTERNAL//PHI"); err == nil || !strings.Contains(err.Error(), "not allowed at INTERNAL") {
		t.Errorf("a change before Configure reached the rules: %v", err)
	}
	m, err := Parse("CONFIDENTIAL//PHI")
	if err != nil {
		t.Fatal(err)
	}
	corp.Levels[0].Name = "RESTRICTED"
	top, err := corp.Parse("RESTRICTED")
	if err != nil {
		t.Fatal(err)
	}
	if top.Level != 3 || Dominates(Bottom(), top) || corp.Dominates(corp.Bottom(), top) {
		t.Errorf("a renamed level changed what RESTRICTED means: level %d", top.Level)
	}
	if m.String() != "CONFIDENTIAL//PHI" || Bottom().String() != "PUBLIC" {
		t.Error("a change reached markings or banners")
	}
}

// A lattice records its scheme, so lattices of different schemes are told apart; a us-gov
// lattice serializes as it always has.
func TestLatticeScheme(t *testing.T) {
	gov, corp := preset(t, "us-gov"), preset(t, "corporate")
	if a, b := LatticeOf(gov.Bottom()), LatticeOf(corp.Bottom()); reflect.DeepEqual(a, b) || b.Scheme != corp.Digest() || a.Scheme != "" {
		t.Errorf("bottom lattices: %+v %+v", a, b)
	}
	raw, err := json.Marshal(LatticeOf(gov.Bottom()))
	if err != nil || strings.Contains(string(raw), "scheme") || strings.Contains(string(raw), "tags") {
		t.Errorf("us-gov lattice JSON %s", raw)
	}
}

// (Preset shapes, loaded in preset mode.) A scheme may keep its no-release token and release lines in any group, limit the release group
// to some levels, and limit a token to some levels; the engine follows each.
func TestReleaseInAnyGroup(t *testing.T) {
	s, err := load("r.json", []byte(`{"schema": "badger.marking-scheme/v1", "name": "r", "version": 1,
		"levels": [{"name": "LOW"}, {"name": "HIGH"}],
		"groups": [{"name": "handling", "kind": "require", "position": 1, "tokens": [{"token": "HOME ONLY", "portion": "HO"}, {"token": "X", "levels": [0]}]},
			{"name": "rel", "kind": "release", "position": 1, "levels": [0], "inGroup": "handling", "home": "AAA", "noReleasePortion": "HO",
			 "releaseLine": "REL TO", "displayLine": "SHOW TO", "countries": ["AAA", "BBB", "CCC"]}]}`), true)
	if err != nil {
		t.Fatal(err)
	}
	j, err := s.Join(must(t, s, "LOW//REL TO AAA, BBB"), must(t, s, "LOW//REL TO AAA, CCC"))
	if err != nil || banner(t, s, j) != "LOW//HOME ONLY" {
		t.Fatalf("disjoint release lists: %v %v", j, err)
	}
	if back := must(t, s, banner(t, s, j)); !reflect.DeepEqual(back, j) {
		t.Error("the home-only join does not read back")
	}
	if _, err := s.Parse("HIGH//REL TO AAA, BBB"); err == nil || !strings.Contains(err.Error(), "REL TO is not allowed at HIGH") {
		t.Errorf("a release line above the release group's levels: %v", err)
	}
	if _, err := s.Parse("LOW//HOME ONLY/REL TO AAA, BBB"); err == nil {
		t.Error("a release line beside the no-release token parsed")
	}
	if _, err := s.Join(must(t, s, "LOW//X"), must(t, s, "HIGH")); !errors.Is(err, ErrNoBanner) {
		t.Errorf("a join carrying a token above its levels: %v", err)
	}
}

// (Preset shapes, loaded in preset mode.) A sourced token of several words is removed whole before
// the country list is read, with or without countries.
func TestSourcedTokenOfSeveralWords(t *testing.T) {
	s, err := load("w.json", []byte(`{"schema": "badger.marking-scheme/v1", "name": "w", "version": 1,
		"levels": [{"name": "LOW"}, {"name": "HIGH"}],
		"groups": [{"name": "handling", "kind": "require", "position": 1, "tokens": [{"token": "HOME ONLY", "portion": "HO"}]},
			{"name": "rel", "kind": "release", "position": 1, "inGroup": "handling", "home": "AAA", "noReleasePortion": "HO",
			 "releaseLine": "REL TO", "displayLine": "SHOW TO", "countries": ["AAA", "BBB"]},
			{"name": "src", "kind": "sourced", "position": 2, "tokens": [{"token": "SRC INFO"}]}]}`), true)
	if err != nil {
		t.Fatal(err)
	}
	m := must(t, s, "HIGH//SRC INFO")
	if !m.HasFGI || len(m.FGI) != 0 || banner(t, s, m) != "HIGH//SRC INFO" {
		t.Errorf("concealed source: %+v %q", m, banner(t, s, m))
	}
	m = must(t, s, "HIGH//SRC INFO BBB")
	if !m.HasFGI || !slices.Equal(m.FGI, []string{"BBB"}) || banner(t, s, m) != "HIGH//SRC INFO BBB" {
		t.Errorf("named source: %+v %q", m, banner(t, s, m))
	}
}

// (Preset shapes, loaded in preset mode.) A sourced token limited to some levels is refused at the others; sub-compartments in the group
// that holds the release lines stay distinct.
func TestSourcedLevelsAndCompartments(t *testing.T) {
	s, err := load("c.json", []byte(`{"schema": "badger.marking-scheme/v1", "name": "c", "version": 1,
		"levels": [{"name": "LOW"}, {"name": "HIGH"}],
		"groups": [{"name": "handling", "kind": "require", "position": 1, "tokens": [{"token": "HOME ONLY", "portion": "HO"}, {"token": "X", "suffix": true}]},
			{"name": "rel", "kind": "release", "position": 1, "inGroup": "handling", "home": "AAA", "noReleasePortion": "HO",
			 "releaseLine": "REL TO", "displayLine": "SHOW TO", "countries": ["AAA", "BBB"]},
			{"name": "src", "kind": "sourced", "position": 2, "tokens": [{"token": "SRC", "levels": [1]}]}]}`), true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Parse("LOW//SRC"); err == nil || !strings.Contains(err.Error(), "SRC is not allowed at LOW") {
		t.Errorf("a sourced token below its levels: %v", err)
	}
	must(t, s, "HIGH//SRC BBB")
	a, b := must(t, s, "LOW//X-A"), must(t, s, "LOW//X-B")
	if s.Dominates(a, b) || s.Dominates(b, a) {
		t.Error("two compartments of one token compared as one")
	}
	j, err := s.Join(a, b)
	if err != nil || banner(t, s, j) != "LOW//X-A/X-B" {
		t.Errorf("join of two compartments: %v %v", j, err)
	}
	if m := must(t, s, "LOW//X-B/HOME ONLY/X-A"); banner(t, s, m) != "LOW//HOME ONLY/X-A/X-B" {
		t.Errorf("banner order: %s", banner(t, s, m))
	}
}

// A join keeps each token in its own group, at the joined level. A word two groups take at
// different levels must not reread as the other group's token: LOW//X (group a) joined with HIGH
// has no banner, because X at HIGH would be group b's.
func TestJoinChecksTokensInTheirGroups(t *testing.T) {
	s, err := LoadScheme("x.json", []byte(`{"schema": "badger.marking-scheme/v1", "name": "x", "version": 1,
		"levels": [{"name": "LOW"}, {"name": "HIGH"}],
		"groups": [{"name": "a", "kind": "require", "position": 1, "tokens": [{"token": "X", "levels": [0]}]},
			{"name": "b", "kind": "require", "position": 2, "tokens": [{"token": "X", "levels": [1]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	low, high := must(t, s, "LOW//X"), must(t, s, "HIGH//X")
	if !reflect.DeepEqual(low.Tags, map[string][]string{"a": {"X"}}) || !reflect.DeepEqual(high.Tags, map[string][]string{"b": {"X"}}) {
		t.Fatalf("groups: %v %v", low.Tags, high.Tags)
	}
	if j, err := s.Join(low, must(t, s, "HIGH")); !errors.Is(err, ErrNoBanner) {
		t.Errorf("join moved a token to another group: %v %v", j.Tags, err)
	}
	if s.Dominates(high, low) {
		t.Error("group b's X held group a's X")
	}
}

// (Preset shapes, loaded in preset mode.) Two schemes that differ only in which group owns the
// no-release token restrict release differently, so they never share a digest.
func TestNoReleaseOwnerInDigest(t *testing.T) {
	scheme := func(portion string) *Scheme {
		t.Helper()
		s, err := load("n.json", []byte(`{"schema": "badger.marking-scheme/v1", "name": "n", "version": 1,
		"levels": [{"name": "LOW"}, {"name": "HIGH"}],
		"groups": [{"name": "low", "kind": "require", "position": 1, "levels": [0], "tokens": [{"token": "HOME ONLY", "portion": "HL"}]},
			{"name": "high", "kind": "require", "position": 2, "levels": [1], "tokens": [{"token": "HOME ONLY", "portion": "HH"}]},
			{"name": "rel", "kind": "release", "position": 2, "inGroup": "high", "home": "AAA", "noReleasePortion": "`+portion+`",
			 "releaseLine": "REL TO", "displayLine": "SHOW TO", "countries": ["AAA", "BBB"]}]}`), true)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	low, high := scheme("HL"), scheme("HH")
	m := must(t, high, "HIGH//HOME ONLY")
	if r := high.release(m); len(r) != 1 || !r["AAA"] {
		t.Fatalf("owner high: the no-release token did not restrict release: %v", r)
	}
	if r := low.release(must(t, low, "HIGH//HOME ONLY")); len(r) == 1 {
		t.Fatalf("owner low: group high's token restricted release: %v", r)
	}
	if low.Digest() == high.Digest() {
		t.Error("two schemes with different no-release owners share a digest")
	}
}

// (Preset shapes, loaded in preset mode.) The no-release token's owner is the group whose token
// carries the release group's portion, even when another group has a token of the same word at
// other levels.
func TestNoReleaseOwnerByPortion(t *testing.T) {
	s, err := load("n.json", []byte(`{"schema": "badger.marking-scheme/v1", "name": "n", "version": 1,
		"levels": [{"name": "LOW"}, {"name": "HIGH"}],
		"groups": [{"name": "low", "kind": "require", "position": 1, "levels": [0], "tokens": [{"token": "HOME ONLY"}]},
			{"name": "high", "kind": "require", "position": 2, "levels": [1], "tokens": [{"token": "HOME ONLY", "portion": "HO"}]},
			{"name": "rel", "kind": "release", "position": 2, "inGroup": "high", "home": "AAA", "noReleasePortion": "HO",
			 "releaseLine": "REL TO", "displayLine": "SHOW TO", "countries": ["AAA", "BBB"]}]}`), true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Parse("HIGH//HOME ONLY/REL TO AAA, BBB"); err == nil || !strings.Contains(err.Error(), "contradicts") {
		t.Errorf("a release list beside the no-release token parsed: %v", err)
	}
	m := must(t, s, "HIGH//HOME ONLY")
	if r := s.release(m); len(r) != 1 || !r["AAA"] {
		t.Errorf("the no-release token did not restrict release: %v", r)
	}
}
