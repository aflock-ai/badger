package marking

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

// The contract vectors' markings, as the formal step reads them.
func vectorMarkings(t *testing.T) ([]Marking, []struct {
	A, B      int
	Dominates bool
}) {
	t.Helper()
	raw, err := os.ReadFile("../../formal/contract/vectors/contract-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Markings []struct {
			Marking struct {
				Level                       int
				SCI, SAP, AEA, FGI          []string
				HasFGI                      bool
				Categories, Controls, NonIC []string
				RelTo, DisplayOnly          []string
			}
		}
		Dominates []struct {
			A, B      int
			Dominates bool
		}
	}
	if err := json.Unmarshal(raw, &d); err != nil || len(d.Markings) == 0 || len(d.Dominates) == 0 {
		t.Fatalf("contract vectors: %v", err)
	}
	nilIfEmpty := func(l []string) []string {
		if len(l) == 0 {
			return nil
		}
		return l
	}
	out := make([]Marking, len(d.Markings))
	for i, x := range d.Markings {
		c := x.Marking
		var controls []string
		for _, p := range c.Controls {
			w, ok := ControlForPortion(p)
			if !ok {
				t.Fatalf("unknown control portion %q", p)
			}
			controls = append(controls, w)
		}
		out[i] = Marking{Level: c.Level, SCI: nilIfEmpty(c.SCI), SAP: nilIfEmpty(c.SAP), AEA: nilIfEmpty(c.AEA),
			FGI: nilIfEmpty(c.FGI), HasFGI: c.HasFGI, Categories: nilIfEmpty(c.Categories), Controls: nilIfEmpty(controls),
			NonIC: nilIfEmpty(c.NonIC), RelTo: nilIfEmpty(c.RelTo), DisplayOnly: nilIfEmpty(c.DisplayOnly)}
	}
	return out, d.Dominates
}

// latticeDominates is the rule on Lattice, written as the database writes it.
func latticeDominates(a, b Lattice) bool {
	sup := func(x, y []string) bool {
		return !slices.ContainsFunc(y, func(s string) bool { return !slices.Contains(x, s) })
	}
	sub := func(x, y []string) bool { return y == nil || x != nil && sup(y, x) }
	return a.Level >= b.Level && sup(a.SCI, b.SCI) && sup(a.SAP, b.SAP) && sup(a.AEA, b.AEA) &&
		sup(a.NonIC, b.NonIC) && sup(a.Controls, b.Controls) &&
		(!b.HasFGI || a.HasFGI && (len(a.FGI) == 0 || len(b.FGI) > 0 && sup(a.FGI, b.FGI))) &&
		(a.Level >= 2 || sup(a.Categories, b.Categories)) &&
		sub(a.Release, b.Release) && sub(a.Display, b.Display)
}

// The comparable form loses nothing: on every pair of contract markings the Lattice rule agrees
// with Dominates and with the contract.
func TestLatticeAgreesWithDominates(t *testing.T) {
	ms, pairs := vectorMarkings(t)
	for _, p := range pairs {
		a, b := ms[p.A], ms[p.B]
		if got := latticeDominates(LatticeOf(a), LatticeOf(b)); got != p.Dominates || got != Dominates(a, b) {
			t.Errorf("%d over %d: lattice %v, Dominates %v, contract %v", p.A, p.B, got, Dominates(a, b), p.Dominates)
		}
	}
	// A release list that names nobody restricts everything: it stays an empty list, never nil
	// (unrestricted), so nothing released anywhere may hold content carrying it.
	none, usa := Marking{Level: 3, RelTo: []string{}}, Marking{Level: 3}
	if l := LatticeOf(none); l.Release == nil || len(l.Release) != 0 || l.Display == nil {
		t.Fatalf("empty release list: %+v", l)
	}
	if latticeDominates(LatticeOf(usa), LatticeOf(none)) || Dominates(usa, none) {
		t.Fatal("an empty release list read as unrestricted")
	}
	// Sets come out sorted, deduplicated and never nil, whatever order they went in.
	u := LatticeOf(Marking{Level: 3, SCI: []string{"B", "A", "B"}, Controls: []string{"Y", "X"}, RelTo: []string{"GBR", "USA"}})
	if !slices.Equal(u.SCI, []string{"A", "B"}) || !slices.Equal(u.Controls, []string{"X", "Y"}) ||
		!slices.Equal(u.Release, []string{"GBR", "USA"}) || u.SAP == nil || u.AEA == nil || u.NonIC == nil || u.FGI == nil || u.Categories == nil {
		t.Fatalf("set fields: %+v", u)
	}
	l := LatticeOf(ms[0])
	if l.SCI == nil || l.Controls == nil || l.Release != nil {
		t.Fatalf("bottom: %+v", l)
	}
}
