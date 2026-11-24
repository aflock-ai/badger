package marking

// A frozen copy of the parser, banner, dominance, join and lattice code as it was before the
// engine read its rules from a scheme (identifiers prefixed "legacy", comments removed). The
// differential tests (differential_test.go) hold the scheme-driven engine with the us-gov preset
// to exactly this behaviour. Do not edit it to make a test pass: a difference is a regression.

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// legacyNoForeign is read when called: tab is filled by init, after package variables.
func legacyNoForeign() string {
	for _, p := range controlOrder() {
		if p[1] == "NF" {
			return p[0]
		}
	}
	return ""
}

func legacyParse(s string) (Marking, error) {
	var m Marking
	s = strings.ToUpper(strings.TrimSpace(s))
	if !bannerChars.MatchString(s) {
		return m, errors.New("a marking holds only letters, digits, spaces, commas, hyphens and slashes")
	}
	groups := strings.Split(s, "//")
	for _, g := range groups {
		if slices.Contains(tab.Legacy.Tokens, g) {
			return m, errors.New("a retired legacy marking (DoDI 5200.48); configure a current one")
		}
	}
	m.Level = -1
	for i, l := range tab.Levels {
		if groups[0] == l.Banner {
			m.Level = i
		}
	}
	if m.Level < 0 {
		return m, fmt.Errorf("unknown classification level %q", groups[0])
	}
	last := 0
	for gi, g := range groups[1:] {
		toks := strings.Split(g, "/")
		kind, err := m.legacyGroup(toks, gi == 0)
		if err != nil {
			return m, err
		}
		if kind <= last {
			return m, fmt.Errorf("marking group %q is out of order or repeated", g)
		}
		last = kind
	}
	if m.RelTo != nil && slices.Contains(m.Controls, legacyNoForeign()) {
		return m, errors.New("REL TO contradicts " + legacyNoForeign())
	}
	if m.Level < Confidential {
		for _, c := range m.Controls {
			if !slices.ContainsFunc(tab.CUILDC.Tokens, func(p [2]string) bool { return p[0] == c }) {
				return m, fmt.Errorf("%s is a classified dissemination control", c)
			}
		}
	}
	return m, nil
}

func (m *Marking) legacyGroup(toks []string, first bool) (int, error) {
	all := func(f func(string) bool) bool {
		return !slices.ContainsFunc(toks, func(t string) bool { return !f(t) })
	}
	classified := m.Level >= Confidential
	switch {
	case classified && all(func(t string) bool {
		return sciToken.MatchString(t) && slices.Contains(tab.SCI.Tokens, strings.SplitN(t, "-", 2)[0])
	}):
		m.SCI = sorted(toks)
		return 1, nil
	case classified && all(func(t string) bool {
		return strings.HasPrefix(t, tab.SAP.Prefix) && sapToken.MatchString(t[len(tab.SAP.Prefix):])
	}):
		m.SAP = sorted(toks)
		return 2, nil
	case m.Level != controlled && all(func(t string) bool { return slices.Contains(tab.AEA.Tokens, t) }):
		m.AEA = sorted(toks)
		return 3, nil
	case m.Level != controlled && len(toks) == 1 && (toks[0] == tab.FGI.Token || strings.HasPrefix(toks[0], tab.FGI.Token+" ")):
		m.HasFGI = true
		for _, c := range strings.Fields(toks[0])[1:] {
			if !slices.Contains(tab.Release.Countries, c) && tab.Release.Tetragraphs[c] == nil {
				return 0, fmt.Errorf("unknown country code %q in FGI", c)
			}
			m.FGI = append(m.FGI, c)
		}
		return 4, nil
	case m.Level == controlled && first && all(legacyValidCategory):
		m.Categories = toks
		slices.SortFunc(m.Categories, func(a, b string) int { return strings.Compare(legacyCatKey(a), legacyCatKey(b)) })
		return 5, nil
	case m.Level != controlled && all(func(t string) bool { return slices.Contains(tab.NonIC.Tokens, t) }):
		m.NonIC = sorted(toks)
		return 7, nil
	}
	for _, t := range toks {
		switch {
		case strings.HasPrefix(t, "REL TO "):
			l, err := legacyReleaseList(t[len("REL TO "):])
			if err != nil {
				return 0, err
			}
			if m.RelTo != nil {
				return 0, errors.New("REL TO appears more than once")
			}
			m.RelTo = l
		case strings.HasPrefix(t, "DISPLAY ONLY "):
			l, err := legacyReleaseList(t[len("DISPLAY ONLY "):])
			if err != nil {
				return 0, err
			}
			if m.DisplayOnly != nil {
				return 0, errors.New("DISPLAY ONLY appears more than once")
			}
			m.DisplayOnly = l
		default:
			table := controlOrder()
			if m.Level == controlled {
				table = tab.CUILDC.Tokens
			}
			i := slices.IndexFunc(table, func(p [2]string) bool { return t == p[0] })
			if i < 0 {
				return 0, fmt.Errorf("unknown marking token %q", t)
			}
			if !slices.Contains(m.Controls, table[i][0]) {
				m.Controls = append(m.Controls, table[i][0])
			}
		}
	}
	return 6, nil
}

func legacyValidCategory(t string) bool {
	c, sp := strings.CutPrefix(t, "SP-")
	if slices.Contains(tab.CUICat.Either, c) {
		return true
	}
	if sp {
		return slices.Contains(tab.CUICat.Specified, c)
	}
	return slices.Contains(tab.CUICat.Basic, c)
}

func legacyCatKey(c string) string {
	if strings.HasPrefix(c, "SP-") {
		return "0" + c
	}
	return "1" + c
}

func legacyReleaseList(s string) ([]string, error) {
	l := strings.Split(s, ",")
	for i := range l {
		l[i] = strings.TrimSpace(l[i])
	}
	if l[0] != "USA" {
		return nil, errors.New("a release list must start with USA")
	}
	for i, c := range l[1:] {
		prev := l[i]
		_, tetra := tab.Release.Tetragraphs[c]
		_, prevTetra := tab.Release.Tetragraphs[prev]
		switch {
		case !tetra && !slices.Contains(tab.Release.Countries, c), c == "USA":
			return nil, fmt.Errorf("unknown or repeated country code %q", c)
		case i > 0 && (prevTetra && !tetra || prevTetra == tetra && prev >= c):
			return nil, fmt.Errorf("release list out of order at %q", c)
		}
	}
	return l, nil
}

func (m Marking) legacyString() string {
	g := []string{tab.Levels[m.Level].Banner}
	add := func(l []string) {
		if len(l) > 0 {
			g = append(g, strings.Join(l, "/"))
		}
	}
	add(m.SCI)
	add(m.SAP)
	add(m.AEA)
	if m.HasFGI {
		g = append(g, strings.Join(append([]string{tab.FGI.Token}, m.FGI...), " "))
	}
	add(m.Categories)
	var d []string
	for _, p := range controlOrder() {
		if slices.Contains(m.Controls, p[0]) && !slices.Contains(d, p[0]) {
			d = append(d, p[0])
		}
	}
	if m.RelTo != nil {
		d = append(d, "REL TO "+strings.Join(m.RelTo, ", "))
	}
	if m.DisplayOnly != nil {
		d = append(d, "DISPLAY ONLY "+strings.Join(m.DisplayOnly, ", "))
	}
	add(d)
	add(m.NonIC)
	return strings.Join(g, "//")
}

func legacyDominates(a, b Marking) bool {
	switch {
	case a.Level < b.Level,
		!legacySuperset(a.SCI, b.SCI), !legacySuperset(a.SAP, b.SAP), !legacySuperset(a.AEA, b.AEA),
		!legacySuperset(a.NonIC, b.NonIC), !legacySuperset(a.Controls, b.Controls),
		b.HasFGI && (!a.HasFGI || len(a.FGI) > 0 && (len(b.FGI) == 0 || !legacySuperset(a.FGI, b.FGI))),
		a.Level < Confidential && !legacySuperset(a.Categories, b.Categories):
		return false
	}
	ra, rb := legacyRelease(a), legacyRelease(b)
	return legacySubset(ra, rb) && legacySubset(legacyDisplay(a), legacyDisplay(b))
}

func legacyJoin(a, b Marking) (Marking, error) {
	j := Marking{
		Level: max(a.Level, b.Level),
		SCI:   legacyUnion(a.SCI, b.SCI), SAP: legacyUnion(a.SAP, b.SAP), AEA: legacyUnion(a.AEA, b.AEA),
		NonIC: legacyUnion(a.NonIC, b.NonIC), Controls: legacyUnion(a.Controls, b.Controls),
		HasFGI: a.HasFGI || b.HasFGI,
	}
	if j.Level > Unclassified && j.Level < Confidential && (j.HasFGI || len(j.AEA) > 0 || len(j.NonIC) > 0) {
		return Marking{}, ErrNoBanner
	}
	if j.Level < Confidential {
		j.Categories = legacyUnion(a.Categories, b.Categories)
		slices.SortFunc(j.Categories, func(x, y string) int { return strings.Compare(legacyCatKey(x), legacyCatKey(y)) })
	}
	if j.HasFGI && !(a.HasFGI && len(a.FGI) == 0 || b.HasFGI && len(b.FGI) == 0) {
		j.FGI = legacyUnion(a.FGI, b.FGI)
	}
	ra, rb := legacyRelease(a), legacyRelease(b)
	switch {
	case legacySubset(ra, rb):
		j.RelTo = a.RelTo
	case legacySubset(rb, ra):
		j.RelTo = b.RelTo
	default:
		var l []string
		for c := range ra {
			if rb[c] && c != "USA" {
				l = append(l, c)
			}
		}
		slices.Sort(l)
		if len(l) == 0 {
			j.Controls = legacyUnion(j.Controls, []string{legacyNoForeign()})
		} else {
			j.RelTo = append([]string{"USA"}, l...)
		}
	}
	if slices.Contains(j.Controls, legacyNoForeign()) {
		j.RelTo = nil
	}
	if da, db := legacyDisplay(a), legacyDisplay(b); da != nil || db != nil {
		d, rj := da, legacyRelease(j)
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
			if c != "USA" && (rj == nil || !rj[c]) {
				extra = append(extra, c)
			}
		}
		slices.Sort(extra)
		if len(extra) > 0 || rj == nil {
			j.DisplayOnly = append([]string{"USA"}, extra...)
		}
	}
	if len(j.legacyString()) > maxBanner {
		return Marking{}, ErrBannerTooLong
	}
	return j, nil
}

func legacyDisplay(m Marking) map[string]bool {
	r := legacyRelease(m)
	if r == nil {
		return nil
	}
	d := map[string]bool{}
	for c := range r {
		d[c] = true
	}
	for c := range legacyExpand(m.DisplayOnly) {
		d[c] = true
	}
	return d
}

func legacyRelease(m Marking) map[string]bool {
	switch {
	case slices.Contains(m.Controls, legacyNoForeign()):
		return map[string]bool{"USA": true}
	case m.RelTo != nil:
		return legacyExpand(m.RelTo)
	case m.Level >= Confidential:
		return map[string]bool{"USA": true}
	case m.DisplayOnly != nil:
		return map[string]bool{"USA": true}
	}
	return nil
}

func legacyExpand(l []string) map[string]bool {
	s := map[string]bool{}
	for _, c := range l {
		if members, ok := tab.Release.Tetragraphs[c]; ok {
			for _, m := range members {
				s[m] = true
			}
		} else {
			s[c] = true
		}
	}
	return s
}

func legacySubset(a, b map[string]bool) bool {
	if b == nil {
		return true
	}
	if a == nil {
		return false
	}
	for c := range a {
		if !b[c] {
			return false
		}
	}
	return true
}

func legacySuperset(a, b []string) bool {
	return !slices.ContainsFunc(b, func(x string) bool { return !slices.Contains(a, x) })
}

func legacyUnion(a, b []string) []string {
	if len(a)+len(b) == 0 {
		return nil
	}
	return sorted(append(slices.Clone(a), b...))
}

func legacyLatticeOf(m Marking) Lattice {
	set := func(s []string) []string {
		if len(s) == 0 {
			return []string{}
		}
		return sorted(s)
	}
	keys := func(s map[string]bool) []string {
		if s == nil {
			return nil
		}
		return append([]string{}, slices.Sorted(maps.Keys(s))...)
	}
	return Lattice{Level: m.Level, SCI: set(m.SCI), SAP: set(m.SAP), AEA: set(m.AEA), NonIC: set(m.NonIC),
		Controls: set(m.Controls), HasFGI: m.HasFGI, FGI: set(m.FGI), Categories: set(m.Categories),
		Release: keys(legacyRelease(m)), Display: keys(legacyDisplay(m))}
}
