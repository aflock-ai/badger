package marking

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"
)

// The formal step's replay of the platform contract's conformance vectors against the marking
// package. This file is the runner's (.pushgate/steps/formal-harness): formal.sh copies it into a
// scratch copy of the package with the commit's own test files removed, so a commit cannot replace
// it. CONTRACT_VECTORS is the vectors file to replay; any platform can replay the same file.
func contractVectors(t *testing.T) contractDoc {
	t.Helper()
	path := os.Getenv("CONTRACT_VECTORS")
	if path == "" {
		t.Fatal("CONTRACT_VECTORS is not set; run .pushgate/steps/formal.sh")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var d contractDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	if d.Schema != "badger.contract.vectors/v1" || len(d.Markings) == 0 || len(d.Dominates) == 0 || len(d.Join) == 0 || len(d.Flow) == 0 {
		t.Fatalf("contract vectors %s: unexpected schema or empty surface", path)
	}
	return d
}

type contractMarking struct {
	Level                       int
	SCI, SAP, AEA, FGI          []string
	HasFGI                      bool
	Categories, Controls, NonIC []string
	RelTo, DisplayOnly          []string
}

type contractDoc struct {
	Schema      string
	Tetragraphs map[string][]string
	Markings    []struct {
		Index   int
		Name    string
		Marking contractMarking
	}
	Dominates []struct {
		A, B      int
		Dominates bool
	}
	Join []struct {
		A, B    int
		Refused bool
		Join    contractMarking
		Least   bool
	}
	Flow []struct {
		Name     string
		Events   []map[string]int
		Expect   []bool
		Contract []bool
	}
}

// marking builds the Go struct. Controls are written as portion marks; a slice the model leaves
// empty is nil here, as Parse leaves it.
func (c contractMarking) marking(t *testing.T) Marking {
	t.Helper()
	banner := map[string]string{}
	for _, p := range controlOrder() {
		banner[p[1]] = p[0]
	}
	var controls []string
	for _, p := range c.Controls {
		b, ok := banner[p]
		if !ok {
			t.Fatalf("contract vectors: unknown control portion %q", p)
		}
		controls = append(controls, b)
	}
	set := func(l []string) []string {
		if len(l) == 0 {
			return nil
		}
		return sorted(l)
	}
	list := func(l []string) []string {
		if len(l) == 0 {
			return nil
		}
		return l
	}
	return Marking{Level: c.Level, SCI: set(c.SCI), SAP: set(c.SAP), AEA: set(c.AEA), FGI: set(c.FGI), HasFGI: c.HasFGI,
		Categories: set(c.Categories), Controls: set(controls), NonIC: set(c.NonIC), RelTo: list(c.RelTo),
		DisplayOnly: list(c.DisplayOnly)}
}

func sameSet(a, b []string) bool { return slices.Equal(sorted(a), sorted(b)) }

func sameMarking(a, b Marking) bool {
	return a.Level == b.Level && a.HasFGI == b.HasFGI && sameSet(a.SCI, b.SCI) &&
		sameSet(a.SAP, b.SAP) && sameSet(a.AEA, b.AEA) && sameSet(a.FGI, b.FGI) && sameSet(a.Categories, b.Categories) &&
		sameSet(a.Controls, b.Controls) && sameSet(a.NonIC, b.NonIC) && sameSet(a.RelTo, b.RelTo) &&
		sameSet(a.DisplayOnly, b.DisplayOnly)
}

func TestContractVectorsTables(t *testing.T) {
	d := contractVectors(t)
	for name, members := range d.Tetragraphs {
		if !sameSet(tab.Release.Tetragraphs[name], members) {
			t.Errorf("tetragraph %s: tokens.json has %v, the model %v", name, tab.Release.Tetragraphs[name], members)
		}
	}
}

func TestContractVectorsDominates(t *testing.T) {
	d := contractVectors(t)
	m := make([]Marking, len(d.Markings))
	for i, x := range d.Markings {
		m[i] = x.Marking.marking(t)
	}
	for _, v := range d.Dominates {
		if got := Dominates(m[v.A], m[v.B]); got != v.Dominates {
			t.Errorf("Dominates(%s, %s) = %v, contract says %v", d.Markings[v.A].Name, d.Markings[v.B].Name, got, v.Dominates)
		}
	}
}

func TestContractVectorsJoin(t *testing.T) {
	d := contractVectors(t)
	m := make([]Marking, len(d.Markings))
	for i, x := range d.Markings {
		m[i] = x.Marking.marking(t)
	}
	above, refused := 0, 0
	for _, v := range d.Join {
		a, b := d.Markings[v.A].Name, d.Markings[v.B].Name
		got, err := Join(m[v.A], m[v.B])
		if v.Refused {
			refused++
			if !errors.Is(err, ErrNoBanner) {
				t.Errorf("Join(%s, %s) = %s, %v; contract says it has no banner and is refused with ErrNoBanner", a, b, got, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("Join(%s, %s) refused (%v), contract says it joins", a, b, err)
			continue
		}
		want := v.Join.marking(t)
		if !sameMarking(got, want) {
			t.Errorf("Join(%s, %s) = %+v, the model's transcription computes %+v", a, b, got, want)
		}
		if !Dominates(got, m[v.A]) || !Dominates(got, m[v.B]) {
			t.Errorf("Join(%s, %s) = %s does not dominate both", a, b, got)
		}
		if !v.Least {
			above++
		}
	}
	t.Logf("%d of %d joins refused, %d mark above the least upper bound (by design; see dominance.go)",
		refused, len(d.Join), above)
}

// The session: Join on every read, Dominates on every send, and nothing sent after a Join is
// refused (the session has no banner). The gateway's check must compute exactly this
// (testifysec/CONNECTORS.md); it is not built yet, so this replays the primitives.
func TestContractVectorsFlow(t *testing.T) {
	d := contractVectors(t)
	for _, f := range d.Flow {
		var session Marking
		live := true
		var got []bool
		for _, e := range f.Events {
			if i, ok := e["read"]; ok {
				if live {
					j, err := Join(session, d.Markings[i].Marking.marking(t))
					session, live = j, err == nil
				}
			} else {
				got = append(got, live && Dominates(d.Markings[e["send"]].Marking.marking(t), session))
			}
		}
		if !slices.Equal(got, f.Expect) {
			t.Errorf("flow %q: sends %v, contract vectors expect %v", f.Name, got, f.Expect)
		}
		for i := range got {
			if got[i] && !f.Contract[i] {
				t.Errorf("flow %q: send %d allowed where the contract denies it (write down)", f.Name, i)
			}
		}
	}
}
