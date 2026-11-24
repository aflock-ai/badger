package marking

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func schemeFiles(file string) ([]byte, error) {
	if filepath.Base(file) != file {
		return nil, errors.New("a scheme file is named, never a path")
	}
	return os.ReadFile(filepath.Join("testdata/schemes", file))
}

func policy(t *testing.T, name string) *Policy {
	t.Helper()
	raw, err := os.ReadFile("testdata/policies/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := LoadPolicy(name+".json", raw, schemeFiles)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func classify(t *testing.T, p *Policy, source string) string {
	t.Helper()
	m, err := p.Classify(source)
	if err != nil {
		return "error: " + err.Error()
	}
	b, err := p.Scheme.Banner(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPolicyClassify(t *testing.T) {
	p := policy(t, "enterprise")
	for source, want := range map[string]string{
		"connector:jira/search_issues": "INTERNAL",
		"connector:jira-a1/get_issue":  "CONFIDENTIAL//CUSTOMER-A1",
		"connector:hr/get_employee":    "RESTRICTED//PII",
		"connector:legal/a/b/c":        "CONFIDENTIAL//PRIVILEGED",
		"mcp:search/query":             "INTERNAL",
		"path:design/chip/rtl.v":       "INTERNAL//EXPORT",
		"connector:jira":               "error: connector:jira: " + ErrUnmapped.Error(),
		"connector:jira/a/b":           "error: connector:jira/a/b: " + ErrUnmapped.Error(),
		"connector:unknown/tool":       "error: connector:unknown/tool: " + ErrUnmapped.Error(),
	} {
		if got := classify(t, p, source); got != want {
			t.Errorf("%s: %q, want %q", source, got, want)
		}
	}
}

// Several matching globs join: a narrower glob never lowers a broader one, and incomparable
// markings give one above both.
func TestPolicyPrecedenceIsJoin(t *testing.T) {
	raw := `{"schema": "badger.marking-policy/v1",
		"scheme": {"preset": "corporate", "sha256": "` + preset(t, "corporate").Digest() + `"},
		"dataFlow": {"classify": {
			"RESTRICTED": ["connector:jira/**"],
			"INTERNAL": ["connector:jira/public/*"],
			"CONFIDENTIAL//PHI": ["connector:clinic/*"],
			"CONFIDENTIAL//PCI": ["connector:clinic/billing"]},
		"default": "refuse"}}`
	p, err := LoadPolicy("p.json", []byte(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := classify(t, p, "connector:jira/public/x"); got != "RESTRICTED" {
		t.Errorf("narrow lower glob: %s", got)
	}
	if got := classify(t, p, "connector:clinic/billing"); got != "CONFIDENTIAL//PCI/PHI" {
		t.Errorf("incomparable matches: %s", got)
	}
}

func TestPolicyDefault(t *testing.T) {
	fs := policy(t, "finserv")
	if got := classify(t, fs, "connector:new/tool"); got != "RESTRICTED" {
		t.Errorf("default top level: %s", got)
	}
	if u := fs.Uncovered([]string{"connector:new/tool"}); len(u) != 0 {
		t.Errorf("a top-level default covers everything: %v", u)
	}
	ent := policy(t, "enterprise")
	if u := ent.Uncovered([]string{"connector:jira/a", "connector:new/tool", "connector:hr/x"}); strings.Join(u, ",") != "connector:new/tool" {
		t.Errorf("uncovered %v", u)
	}
}

// Rules only deny, on top of dominance; a tag rule matches the tag written any way the scheme
// allows (with a sub-compartment, for instance).
func TestPolicyFlowRules(t *testing.T) {
	ent := policy(t, "enterprise")
	corp := ent.Scheme
	priv := must(t, corp, "CONFIDENTIAL//PRIVILEGED")
	if msg, ok := ent.Denied(priv, "connector:chat/post"); !ok || msg != "privileged material stays out of chat" {
		t.Errorf("privileged to chat: %q %v", msg, ok)
	}
	if _, ok := ent.Denied(priv, "connector:legal/x"); ok {
		t.Error("a rule denied a destination it does not name")
	}
	if _, ok := ent.Denied(must(t, corp, "CONFIDENTIAL//PII"), "connector:chat/post"); ok {
		t.Error("a rule denied a label without its tag")
	}
	fs := policy(t, "finserv")
	if msg, ok := fs.Denied(must(t, fs.Scheme, "RESTRICTED//PCI"), "model:internal-1"); !ok || !strings.Contains(msg, "PCI->model:**") {
		t.Errorf("default message: %q %v", msg, ok)
	}
	hc := policy(t, "healthcare")
	if _, ok := hc.Denied(must(t, hc.Scheme, "RESTRICTED//SUD"), "model:clinical"); !ok {
		t.Error("SUD to a model allowed")
	}
	raw := `{"schema": "badger.marking-policy/v1", "scheme": {"preset": "corporate", "sha256": "` + corp.Digest() + `"},
		"dataFlow": {"classify": {"INTERNAL": ["connector:a/*"]}, "default": "refuse", "flowRules": [{"deny": "CUSTOMER->model:*"}]}}`
	p, err := LoadPolicy("p.json", []byte(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Denied(must(t, corp, "CONFIDENTIAL//CUSTOMER-A1"), "model:x"); !ok {
		t.Error("a tag rule missed the tag with a sub-compartment")
	}
}

func TestPolicyRefusals(t *testing.T) {
	corp := preset(t, "corporate").Digest()
	pol := func(scheme, dataFlow string) string {
		return `{"schema": "badger.marking-policy/v1", "scheme": ` + scheme + `, "dataFlow": ` + dataFlow + `}`
	}
	ref := `{"preset": "corporate", "sha256": "` + corp + `"}`
	for name, c := range map[string]struct{ raw, want string }{
		"bad schema":         {`{"schema": "badger.marking-policy/v2", "dataFlow": {"classify": {}, "default": "refuse"}}`, "must be badger.marking-policy/v1"},
		"unknown field":      {pol(ref, `{"classify": {}, "default": "refuse", "allow": []}`), "unknown field"},
		"duplicate key":      {pol(ref, `{"classify": {"INTERNAL": ["connector:a/*"], "internal": ["connector:b/*"]}, "default": "refuse"}`), "appears twice"},
		"classified twice":   {pol(ref, `{"classify": {"INTERNAL": ["connector:a/*"], "INTERNAL ": ["connector:b/*"]}, "default": "refuse"}`), "classified twice"},
		"digest mismatch":    {pol(`{"preset": "corporate", "sha256": "sha256:00"}`, `{"classify": {}, "default": "refuse"}`), "the policy pins sha256:00"},
		"preset and file":    {pol(`{"preset": "corporate", "file": "x.json", "sha256": "x"}`, `{"classify": {}, "default": "refuse"}`), "not both"},
		"other scheme words": {pol(ref, `{"classify": {"`+tab.Levels[0].Banner+`": ["connector:a/*"]}, "default": "refuse"}`), "not a corporate marking"},
		"no default":         {pol(ref, `{"classify": {}}`), "required"},
		"default below top":  {pol(ref, `{"classify": {}, "default": "INTERNAL"}`), "never lower"},
		"default public":     {pol(ref, `{"classify": {}, "default": "PUBLIC"}`), "never lower"},
		"url source":         {pol(ref, `{"classify": {"INTERNAL": ["url:*.example.com"]}, "default": "refuse"}`), "url sources are not supported"},
		"untyped source":     {pol(ref, `{"classify": {"INTERNAL": ["Read:**/internal/**"]}, "default": "refuse"}`), "a source is connector:"},
		"bad glob":           {pol(ref, `{"classify": {"INTERNAL": ["connector:a/$x"]}, "default": "refuse"}`), "a glob holds"},
		"empty sources":      {pol(ref, `{"classify": {"INTERNAL": []}, "default": "refuse"}`), "no sources"},
		"unparseable rule":   {pol(ref, `{"classify": {}, "default": "refuse", "flowRules": [{"deny": "PHI to model:*"}]}`), `a rule is "deny"`},
		"rule two arrows":    {pol(ref, `{"classify": {}, "default": "refuse", "flowRules": [{"deny": "PHI->model:*->x"}]}`), `a rule is "deny"`},
		"rule unknown tag":   {pol(ref, `{"classify": {}, "default": "refuse", "flowRules": [{"deny": "XYZ->model:*"}]}`), "neither a corporate marking nor one of its tokens"},
		"rule url dest":      {pol(ref, `{"classify": {}, "default": "refuse", "flowRules": [{"deny": "PHI->url:*"}]}`), "url sources are not supported"},
		"scheme file absent": {pol(`{"file": "healthcare.json", "sha256": "x"}`, `{"classify": {}, "default": "refuse"}`), "no scheme files are available"},
	} {
		if _, err := LoadPolicy("p.json", []byte(c.raw), nil); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// aflock's MCP tool form is accepted, so a policy reads the same in both products.
func TestPolicyAflockMCPForm(t *testing.T) {
	raw := `{"schema": "badger.marking-policy/v1", "scheme": {"preset": "corporate", "sha256": "` + preset(t, "corporate").Digest() + `"},
		"dataFlow": {"classify": {"CONFIDENTIAL//PII": ["mcp__user-data__*"]}, "default": "refuse"}}`
	p, err := LoadPolicy("p.json", []byte(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := classify(t, p, "mcp:user-data/get_user"); got != "CONFIDENTIAL//PII" {
		t.Errorf("aflock form: %s", got)
	}
}

// A policy with no scheme is a us-gov policy, as every existing deployment is.
func TestPolicyDefaultScheme(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"schema": "badger.marking-policy/v1",
		"dataFlow": map[string]any{"classify": map[string]any{tab.Levels[0].Banner: []string{"connector:a/*"}}, "default": tab.Levels[len(tab.Levels)-1].Banner}})
	p, err := LoadPolicy("p.json", raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Scheme.Digest() != preset(t, "us-gov").Digest() {
		t.Error("no scheme is not us-gov")
	}
}

// The example tables' digests are pinned in the example policies; a change to a table must update
// its policy, which is what a deployment would have to do.
func TestPolicyFixtureDigests(t *testing.T) {
	for _, name := range []string{"enterprise", "healthcare", "finserv"} {
		policy(t, name)
	}
}

// A name with a newline in it is still matched: a glob never lets a file escape a rule by its name.
func TestPolicyGlobsMatchNewlines(t *testing.T) {
	raw := `{"schema": "badger.marking-policy/v1", "scheme": {"preset": "corporate", "sha256": "` + preset(t, "corporate").Digest() + `"},
		"dataFlow": {"classify": {"CONFIDENTIAL//PII": ["path:exports/**", "path:drop/*"]}, "default": "refuse",
		"flowRules": [{"deny": "PII->path:exports/**"}]}}`
	p, err := LoadPolicy("p.json", []byte(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{"path:exports/report\n.txt", "path:exports/a/b\nc", "path:drop/x\ny"} {
		if got := classify(t, p, src); got != "CONFIDENTIAL//PII" {
			t.Errorf("%q: %s", src, got)
		}
	}
	if _, ok := p.Denied(must(t, p.Scheme, "CONFIDENTIAL//PII"), "path:exports/report\n.txt"); !ok {
		t.Error("a newline in the name escaped the deny rule")
	}
}

// aflock's shorthand is refused when it could name two sources; the typed form says which.
func TestPolicyAflockFormIsUnambiguous(t *testing.T) {
	corp := preset(t, "corporate").Digest()
	for _, g := range []string{"mcp__search__get__*", "mcp__a___b", "mcp___a__b", "mcp__a__", "mcp____b"} {
		raw := `{"schema": "badger.marking-policy/v1", "scheme": {"preset": "corporate", "sha256": "` + corp + `"},
			"dataFlow": {"classify": {}, "default": "refuse", "flowRules": [{"deny": "PII->` + g + `"}]}}`
		if _, err := LoadPolicy("p.json", []byte(raw), nil); err == nil || !strings.Contains(err.Error(), "must split one way") {
			t.Errorf("%s: %v", g, err)
		}
	}
	raw := `{"schema": "badger.marking-policy/v1", "scheme": {"preset": "corporate", "sha256": "` + corp + `"},
		"dataFlow": {"classify": {}, "default": "refuse", "flowRules": [{"deny": "PII->mcp:search/get__*"}]}}`
	p, err := LoadPolicy("p.json", []byte(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Denied(must(t, p.Scheme, "CONFIDENTIAL//PII"), "mcp:search/get__secret"); !ok {
		t.Error("the typed form missed a tool whose name holds __")
	}
}
