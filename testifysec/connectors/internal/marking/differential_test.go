package marking

import (
	"errors"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"
)

// candidates is one list of group texts per banner group, built from today's tables (never from
// literals), with near misses that must be refused: wrong variants, bad suffixes, out-of-order
// release lists, portion marks where banner words belong, unknown words.
func candidates() [][]string {
	var sci, aea, fgi, cat, nonic, ctl, rel []string
	for _, t := range tab.SCI.Tokens {
		sci = append(sci, t, t+"-G", t+"-G1-X", t+"-")
	}
	sap := []string{tab.SAP.Prefix + "BUTTERED POPCORN", tab.SAP.Prefix + "X-", tab.SAP.Prefix + "X ", tab.SAP.Prefix, tab.SAP.Prefix + "-A"}
	aea = append(aea, tab.AEA.Tokens...)
	f := tab.FGI.Token
	fgi = []string{f, f + " GBR", f + " FRA GBR", f + " FVEY", f + " XYZ", f + "GBR"}
	for i, t := range tab.CUICat.Basic {
		cat = append(cat, t)
		if i%7 == 0 {
			cat = append(cat, "SP-"+t)
		}
	}
	for i, t := range tab.CUICat.Specified {
		cat = append(cat, "SP-"+t)
		if i%5 == 0 {
			cat = append(cat, t)
		}
	}
	for _, t := range tab.CUICat.Either {
		cat = append(cat, t, "SP-"+t)
	}
	nonic = append(nonic, tab.NonIC.Tokens...)
	for _, p := range controlOrder() {
		ctl = append(ctl, p[0], p[1])
	}
	rel = []string{"REL TO USA, GBR", "REL TO USA, FVEY", "REL TO USA, AUS, GBR, FVEY", "REL TO GBR, USA", "REL TO USA",
		"REL TO USA, GBR, AUS", "REL TO USA, NATO, FVEY", "REL TO USA, XYZ", "DISPLAY ONLY USA, GBR", "DISPLAY ONLY USA, FVEY",
		"DISPLAY ONLY GBR", "REL TO USA, USA"}
	junk := append([]string{"ZZ", "", " ", "SECRETISH"}, tab.Legacy.Tokens...)
	return [][]string{sci, sap, aea, fgi, cat, nonic, ctl, rel, junk}
}

// banners are the differential corpus: every level alone and with every candidate group, pairs of
// tokens inside one group, and random two- and three-group banners in and out of order.
func banners() []string {
	cands := candidates()
	var all []string
	for _, g := range cands {
		all = append(all, g...)
	}
	var out []string
	for _, l := range tab.Levels {
		out = append(out, l.Banner, strings.ToLower(l.Banner), " "+l.Banner+" ")
		for _, c := range all {
			out = append(out, l.Banner+"//"+c)
		}
	}
	r := rand.New(rand.NewPCG(1, 2))
	pick := func(g []string) string { return g[r.IntN(len(g))] }
	for range 30000 {
		l := tab.Levels[r.IntN(len(tab.Levels))].Banner
		g1 := cands[r.IntN(len(cands)-1)]
		within := pick(g1) + "/" + pick(g1)
		out = append(out, l+"//"+within)
		parts := []string{l}
		for range 1 + r.IntN(3) {
			parts = append(parts, pick(cands[r.IntN(len(cands))]))
		}
		out = append(out, strings.Join(parts, "//"))
	}
	return out
}

func TestDifferentialParse(t *testing.T) {
	ok, refused := 0, 0
	for _, b := range banners() {
		want, werr := legacyParse(b)
		got, gerr := Parse(b)
		switch {
		case (werr == nil) != (gerr == nil):
			t.Errorf("Parse(%q): engine %v, legacy %v", b, gerr, werr)
		case werr != nil:
			refused++
		case !reflect.DeepEqual(got, want):
			t.Errorf("Parse(%q): engine %+v, legacy %+v", b, got, want)
		case got.String() != want.legacyString():
			t.Errorf("Parse(%q): banner %q, legacy %q", b, got.String(), want.legacyString())
		default:
			ok++
		}
	}
	t.Logf("%d banners parse, %d refused, the same way in both", ok, refused)
	if ok < 500 || refused < 500 {
		t.Errorf("corpus too thin: %d parsed, %d refused", ok, refused)
	}
}

// parsedSample is a spread of distinct parsed markings for the pairwise checks.
func parsedSample() []Marking {
	seen := map[string]bool{}
	var out []Marking
	for _, b := range banners() {
		m, err := legacyParse(b)
		if err != nil || seen[m.legacyString()] {
			continue
		}
		seen[m.legacyString()] = true
		out = append(out, m)
	}
	r := rand.New(rand.NewPCG(3, 4))
	r.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out[:min(len(out), 450)]
}

func TestDifferentialDominatesJoinLattice(t *testing.T) {
	ms := parsedSample()
	for _, a := range ms {
		if !reflect.DeepEqual(LatticeOf(a), legacyLatticeOf(a)) {
			t.Errorf("LatticeOf(%s) differs", a.legacyString())
		}
		for _, b := range ms {
			if Dominates(a, b) != legacyDominates(a, b) {
				t.Errorf("Dominates(%s, %s): engine %v", a.legacyString(), b.legacyString(), Dominates(a, b))
			}
			got, gerr := Join(a, b)
			want, werr := legacyJoin(a, b)
			if !errors.Is(gerr, werr) || (werr == nil) != (gerr == nil) || !reflect.DeepEqual(got, want) {
				t.Errorf("Join(%s, %s): engine %+v %v, legacy %+v %v", a.legacyString(), b.legacyString(), got, gerr, want, werr)
			}
		}
	}
	t.Logf("%d markings, %d pairs", len(ms), len(ms)*len(ms))
}

func FuzzDifferentialParse(f *testing.F) {
	for _, b := range banners()[:2000] {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b string) {
		want, werr := legacyParse(b)
		got, gerr := Parse(b)
		if (werr == nil) != (gerr == nil) || (werr == nil && (!reflect.DeepEqual(got, want) || got.String() != want.legacyString())) {
			t.Errorf("Parse(%q): engine %+v %v, legacy %+v %v", b, got, gerr, want, werr)
		}
	})
}
