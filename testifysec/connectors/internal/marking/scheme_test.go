package marking

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func preset(t *testing.T, name string) *Scheme {
	t.Helper()
	s, err := Preset(name)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func group(t *testing.T, s *Scheme, name string) Group {
	t.Helper()
	i := slices.IndexFunc(s.Groups, func(g Group) bool { return g.Name == name })
	if i < 0 {
		t.Fatalf("%s: no group %q", s.Name, name)
	}
	return s.Groups[i]
}

func words(g Group) []string {
	var out []string
	for _, tok := range g.Tokens {
		out = append(out, tok.Token)
	}
	return out
}

// controlled is the controlled-unclassified level's position (the level constants in marking.go).
const controlled = Unclassified + 1

// above is every level from l up, as the scheme lists a group allowed from l.
func above(l, n int) []int {
	var out []int
	for i := l; i < n; i++ {
		out = append(out, i)
	}
	return out
}

func except(l, n int) []int {
	var out []int
	for i := range n {
		if i != l {
			out = append(out, i)
		}
	}
	return out
}

// The us-gov preset expresses exactly the tables and level rules the parser applies today
// (marking.go): same words, same order, same portions, and each group allowed at the levels where
// the parser accepts it. The engine does not read the preset yet; this pins that it can.
func TestPresetUSGovIsTodaysTables(t *testing.T) {
	s := preset(t, "us-gov")
	n := len(tab.Levels)
	if len(s.Levels) != n {
		t.Fatalf("levels: %d, tokens.json has %d", len(s.Levels), n)
	}
	for i, l := range tab.Levels {
		if s.Levels[i].Name != l.Banner {
			t.Errorf("level %d: %q, tokens.json %q", i, s.Levels[i].Name, l.Banner)
		}
	}
	check := func(name string, got, want any) {
		t.Helper()
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s: preset %v, today %v", name, got, want)
		}
	}
	sci := group(t, s, "sci")
	check("sci words", words(sci), tab.SCI.Tokens)
	check("sci levels", sci.Levels, above(Confidential, n))
	for _, tok := range sci.Tokens {
		if !tok.Suffix {
			t.Errorf("sci %s: no sub-compartment suffix", tok.Token)
		}
	}
	sap := group(t, s, "sap")
	check("sap prefix", sap.Prefix, tab.SAP.Prefix)
	check("sap levels", sap.Levels, above(Confidential, n))
	aea := group(t, s, "aea")
	check("aea words", words(aea), tab.AEA.Tokens)
	check("aea levels", aea.Levels, except(controlled, n))
	fgi := group(t, s, "fgi")
	check("fgi words", words(fgi), []string{tab.FGI.Token})
	check("fgi levels", fgi.Levels, except(controlled, n))
	nonic := group(t, s, "nonic")
	check("nonic words", words(nonic), tab.NonIC.Tokens)
	check("nonic levels", nonic.Levels, except(controlled, n))

	cat := group(t, s, "categories")
	check("categories levels", cat.Levels, []int{controlled})
	check("categories absorbed from", cat.AbsorbedFrom, Confidential)
	if !cat.First || cat.SpecifiedPrefix != "SP-" {
		t.Errorf("categories: first %v, specified prefix %q", cat.First, cat.SpecifiedPrefix)
	}
	var basic, specified, either []string
	for _, tok := range cat.Tokens {
		switch tok.Variant {
		case "basic":
			basic = append(basic, tok.Token)
		case "specified":
			specified = append(specified, tok.Token)
		case "either":
			either = append(either, tok.Token)
		}
	}
	check("basic", basic, tab.CUICat.Basic)
	check("specified", specified, tab.CUICat.Specified)
	check("either", either, tab.CUICat.Either)

	// Controls: canonical order is controlOrder() without repeats; a classified dissemination
	// control is allowed only from CONFIDENTIAL, a controlled-unclassified one at every level.
	ctl := group(t, s, "controls")
	var want []string
	for _, p := range controlOrder() {
		if !slices.Contains(want, p[0]) {
			want = append(want, p[0])
		}
	}
	check("control words", words(ctl), want)
	for _, tok := range ctl.Tokens {
		ldc := slices.ContainsFunc(tab.CUILDC.Tokens, func(p [2]string) bool { return p[0] == tok.Token })
		wantLevels := above(Confidential, n)
		if ldc {
			wantLevels = nil
		}
		check("control "+tok.Token+" levels", tok.Levels, wantLevels)
		if c, _ := ControlForPortion(tok.Portion); c != tok.Token {
			t.Errorf("control %s: portion %q is %q today", tok.Token, tok.Portion, c)
		}
	}
	rel := group(t, s, "release")
	noForeign, _ := ControlForPortion("NF")
	check("no-release token", rel.NoRelease, noForeign)
	check("home", rel.Home, "USA")
	check("restricted from", rel.RestrictedFrom, Confidential)
	check("in group", rel.InGroup, "controls")
	check("countries", rel.Countries, tab.Release.Countries)
	if len(rel.Tetragraphs) != len(tab.Release.Tetragraphs) {
		t.Errorf("tetragraphs: %d, today %d", len(rel.Tetragraphs), len(tab.Release.Tetragraphs))
	}
	for k, v := range tab.Release.Tetragraphs {
		check("tetragraph "+k, rel.Tetragraphs[k], v)
	}
	var retired []string
	for _, r := range s.Retired {
		retired = append(retired, r.Token)
	}
	check("retired", retired, tab.Legacy.Tokens)
	// The parser tries groups in this order; non-IC comes before the dissemination group.
	var order []string
	for _, g := range s.Groups {
		order = append(order, g.Name)
	}
	check("try order", order, []string{"sci", "sap", "aea", "fgi", "categories", "nonic", "controls", "release"})
}

func TestPresetCorporate(t *testing.T) {
	s := preset(t, "corporate")
	var levels []string
	for _, l := range s.Levels {
		levels = append(levels, l.Name)
	}
	if got := strings.Join(levels, " < "); got != "PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED" {
		t.Fatalf("levels %s", got)
	}
	h := group(t, s, "handling")
	if h.Kind != "require" || h.AbsorbedFrom != -1 {
		t.Errorf("handling: kind %s, absorbed from %d (a tag is never dropped by a join)", h.Kind, h.AbsorbedFrom)
	}
	min := map[string]int{}
	for _, tok := range h.Tokens {
		min[tok.Token] = tok.Levels[0]
		if tok.Suffix != (tok.Token == "CUSTOMER") {
			t.Errorf("%s: suffix %v", tok.Token, tok.Suffix)
		}
	}
	want := map[string]int{"PHI": 2, "PII": 2, "PCI": 2, "MNPI": 2, "PRIVILEGED": 2, "TRADE SECRET": 2, "CUSTOMER": 2, "EXPORT": 1}
	if fmt.Sprint(min) != fmt.Sprint(want) {
		t.Errorf("minimum levels %v, want %v", min, want)
	}
}

// A preset's name never reaches the file system as a path.
func TestPresetNames(t *testing.T) {
	for _, name := range []string{"", "nope", "../tokens", "us-gov.json", "US-GOV", "schemes/us-gov"} {
		if _, err := Preset(name); err == nil {
			t.Errorf("preset %q loaded", name)
		}
	}
}

func TestSchemeRefusals(t *testing.T) {
	raw, err := os.ReadFile("testdata/schemes/refusals.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct{ Refusals map[string]string }
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob("testdata/schemes/refusals/*.json")
	if len(files) != len(doc.Refusals) {
		t.Errorf("%d refusal files, %d expectations", len(files), len(doc.Refusals))
	}
	for name, want := range doc.Refusals {
		b, err := os.ReadFile("testdata/schemes/refusals/" + name + ".json")
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		_, err = LoadScheme(name+".json", b)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want an error containing %q", name, err, want)
		}
	}
}

// The shapes only presets may use are still validated in full when a preset uses them.
func TestPresetShapeRefusals(t *testing.T) {
	raw, err := os.ReadFile("testdata/schemes/preset-refusals.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct{ Refusals map[string]string }
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob("testdata/schemes/preset-refusals/*.json")
	if len(files) != len(doc.Refusals) {
		t.Errorf("%d preset refusal files, %d expectations", len(files), len(doc.Refusals))
	}
	for name, want := range doc.Refusals {
		b, err := os.ReadFile("testdata/schemes/preset-refusals/" + name + ".json")
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if _, err := load(name+".json", b, true); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want an error containing %q", name, err, want)
		}
	}
}

func scheme(levels int, tokens int) string {
	var l, tk []string
	for i := range levels {
		l = append(l, fmt.Sprintf(`{"name": "L%d"}`, i))
	}
	for i := range tokens {
		tk = append(tk, fmt.Sprintf(`{"token": "T%d"}`, i))
	}
	return fmt.Sprintf(`{"schema": "badger.marking-scheme/v1", "name": "t", "version": 1, "levels": [%s],
		"groups": [{"name": "tags", "kind": "require", "position": 1, "tokens": [%s]}]}`,
		strings.Join(l, ","), strings.Join(tk, ","))
}

func TestSchemeBounds(t *testing.T) {
	for _, c := range []struct {
		levels, tokens int
		ok             bool
	}{{16, 1, true}, {17, 1, false}, {2, 4096, true}, {2, 4097, false}} {
		_, err := LoadScheme("bounds.json", []byte(scheme(c.levels, c.tokens)))
		if (err == nil) != c.ok {
			t.Errorf("%d levels, %d tokens: %v", c.levels, c.tokens, err)
		}
	}
	// The largest number a scheme may hold loads; one more is refused (refusals.json has the rest).
	for v, ok := range map[string]bool{"999999": true, "1000000": false} {
		_, err := LoadScheme("version.json", []byte(strings.Replace(scheme(2, 1), `"version": 1`, `"version": `+v, 1)))
		if (err == nil) != ok {
			t.Errorf("version %s: %v", v, err)
		}
	}
	big := `{"schema": "badger.marking-scheme/v1", "name": "t", "version": 1, "note": "` + strings.Repeat("x", 256<<10) + `"}`
	if _, err := LoadScheme("big.json", []byte(big)); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversize file: %v", err)
	}
}

// The digest covers what a label means and nothing else: key order, spacing and reasons do not
// change it; a token, a level or a minimum level does.
func TestSchemeDigest(t *testing.T) {
	load := func(src string) string {
		t.Helper()
		s, err := LoadScheme("d.json", []byte(src))
		if err != nil {
			t.Fatal(err)
		}
		return s.Digest()
	}
	base := load(`{"schema": "badger.marking-scheme/v1", "name": "t", "version": 1,
		"levels": [{"name": "LOW"}, {"name": "HIGH"}],
		"groups": [{"name": "tags", "kind": "require", "position": 1, "tokens": [{"token": "A", "minLevel": "HIGH"}]}]}`)
	if !strings.HasPrefix(base, "sha256:") || len(base) != len("sha256:")+64 {
		t.Fatalf("digest %q", base)
	}
	same := load(`{"groups": [{"tokens": [{"reason": "why", "minLevel": 1, "token": "A"}], "position": 1, "kind": "require", "name": "tags"}],
		"levels": [{"name": "LOW", "reason": "low"}, {"name": "HIGH"}], "note": "n", "version": 1, "name": "t", "schema": "badger.marking-scheme/v1"}`)
	if same != base {
		t.Errorf("reordered keys, reasons and a level by position changed the digest")
	}
	for name, src := range map[string]string{
		"token":     `"tokens": [{"token": "A", "minLevel": "HIGH"}, {"token": "B"}]`,
		"min level": `"tokens": [{"token": "A"}]`,
	} {
		other := load(`{"schema": "badger.marking-scheme/v1", "name": "t", "version": 1,
			"levels": [{"name": "LOW"}, {"name": "HIGH"}],
			"groups": [{"name": "tags", "kind": "require", "position": 1, ` + src + `}]}`)
		if other == base {
			t.Errorf("a changed %s kept the digest", name)
		}
	}
	if preset(t, "us-gov").Digest() == preset(t, "corporate").Digest() {
		t.Error("two presets share a digest")
	}
}

// Each preset's digest is pinned: a change to a preset's meaning is a new preset version, never an
// edit, because stored labels are bound to the digest. The TypeScript port pins the same values.
func TestPresetDigestsPinned(t *testing.T) {
	for name, want := range map[string]string{
		"us-gov":    "sha256:f06d5cd645497e86b647d8f800c8ec92b14b03a225484b8a44735d6be75a2189",
		"corporate": "sha256:90db5dc18987919f5b118a4e81dcef9a95a80903235ee41c6d6999c3cd7cb62d",
	} {
		if got := preset(t, name).Digest(); got != want {
			t.Errorf("%s digest %s, pinned %s", name, got, want)
		}
	}
}

// (Preset shapes, loaded in preset mode.) A release line limited to some levels does not conflict with a word another group accepts only
// at other levels.
func TestReleaseLinesAtTheirLevels(t *testing.T) {
	_, err := load("r.json", []byte(`{"schema": "badger.marking-scheme/v1", "name": "r", "version": 1,
		"levels": [{"name": "LOW"}, {"name": "HIGH"}],
		"groups": [{"name": "tags", "kind": "require", "position": 1, "levels": [1], "tokens": [{"token": "HOME ONLY", "portion": "HO"}]},
			{"name": "rel", "kind": "release", "position": 1, "levels": [1], "inGroup": "tags", "home": "AAA", "noReleasePortion": "HO",
			 "releaseLine": "REL TO", "displayLine": "SHOW TO", "countries": ["AAA"]},
			{"name": "other", "kind": "require", "position": 2, "levels": [0], "tokens": [{"token": "REL TO AAA"}]}]}`), true)
	if err != nil {
		t.Fatal(err)
	}
}

// (Preset shapes, loaded in preset mode.) A sourced token limited to some levels does not conflict with a word another group accepts only
// at other levels.
func TestSourcedTokenAtItsLevels(t *testing.T) {
	_, err := load("s.json", []byte(`{"schema": "badger.marking-scheme/v1", "name": "s", "version": 1,
		"levels": [{"name": "LOW"}, {"name": "HIGH"}],
		"groups": [{"name": "tags", "kind": "require", "position": 1, "tokens": [{"token": "HOME ONLY", "portion": "HO"}, {"token": "SRC", "levels": [0]}]},
			{"name": "rel", "kind": "release", "position": 1, "inGroup": "tags", "home": "AAA", "noReleasePortion": "HO",
			 "releaseLine": "REL TO", "displayLine": "SHOW TO", "countries": ["AAA"]},
			{"name": "src", "kind": "sourced", "position": 2, "tokens": [{"token": "SRC", "levels": [1]}]}]}`), true)
	if err != nil {
		t.Fatal(err)
	}
}
