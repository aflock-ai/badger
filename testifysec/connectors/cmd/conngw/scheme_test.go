package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/badger/testifysec/connectors/marking"
)

func corporate(t *testing.T) *marking.Scheme {
	t.Helper()
	s, err := marking.Preset("corporate")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// configWith is a valid one-connector profile with a markingScheme entry and the connector's
// classification.
func configWith(t *testing.T, scheme, classification string) string {
	t.Helper()
	key := strings.Repeat("A", 43) + "="
	digest := "sha256:" + strings.Repeat("0", 64)
	c := `{"listen":":8443","certFile":"/c","keyFile":"/k","audience":"a","namespaces":["ws"],"labelsFile":"/var/lib/conngw/labels","hostDigest":"` + hostDigest + `","signers":{"vendor":"` + key + `"}` +
		scheme + `,"connectors":[{"name":"jira","bundle":"/plugins/jira","digest":"` + digest + `","signer":"vendor","baseUrl":"https://j.example.invalid","tokenPath":"/t","socket":"/run/conngw/p.sock","uid":61000,"gid":61000,"grants":[{"workspaces":["ws/alice"]}],"classification":"` + classification + `"}]}`
	p := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The profile pins the deployment's scheme; connectors' classifications are read under it.
func TestProfileScheme(t *testing.T) {
	lv := levels(t)
	corp := corporate(t)
	pin := `,"markingScheme":{"preset":"corporate","sha256":"` + corp.Digest() + `"}`
	c, err := load(configWith(t, pin, "CONFIDENTIAL//PHI"))
	if err != nil {
		t.Fatal(err)
	}
	if c.scheme.Digest() != corp.Digest() || marking.DigestOf(c.Sources[0].marking) != corp.Digest() || marking.Banner(c.Sources[0].marking) != "CONFIDENTIAL//PHI" {
		t.Errorf("corporate profile: %v %s", c.scheme.Name, marking.Banner(c.Sources[0].marking))
	}
	abs, err := filepath.Abs("../../internal/marking/testdata/schemes/healthcare.json")
	if err != nil {
		t.Fatal(err)
	}
	hc, err := marking.LoadScheme("healthcare.json", must(os.ReadFile(abs)))
	if err != nil {
		t.Fatal(err)
	}
	if c, err := load(configWith(t, `,"markingScheme":{"file":"`+abs+`","sha256":"`+hc.Digest()+`"}`, "RESTRICTED//SUD")); err != nil || c.scheme.Name != "healthcare" {
		t.Errorf("scheme file: %v", err)
	}
	if c, err := load(configWith(t, "", lv[1])); err != nil || !c.scheme.IsDefault() {
		t.Errorf("no markingScheme is us-gov: %v", err)
	}
	for name, c := range map[string]struct{ scheme, classification, want string }{
		"other scheme's words": {pin, lv[1], "classification"},
		"digest mismatch":      {`,"markingScheme":{"preset":"corporate","sha256":"sha256:00"}`, "PUBLIC", "the profile pins sha256:00"},
		"preset and file":      {`,"markingScheme":{"preset":"corporate","file":"/x","sha256":"x"}`, "PUBLIC", "not both"},
		"relative file":        {`,"markingScheme":{"file":"healthcare.json","sha256":"x"}`, "PUBLIC", "absolute path"},
		"unknown preset":       {`,"markingScheme":{"preset":"civilian","sha256":"x"}`, "PUBLIC", "unknown marking scheme preset"},
		"no scheme for words":  {"", "CONFIDENTIAL//PHI", "classification"},
	} {
		if _, err := load(configWith(t, c.scheme, c.classification)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

// A labels file names its scheme; one written under another scheme is refused, never read. A
// us-gov file keeps the version 1 header byte for byte.
func TestLabelsFileScheme(t *testing.T) {
	dir := t.TempDir()
	corp, gov := corporate(t), marking.Current()
	gp := filepath.Join(dir, "gov")
	if err := initLabels(gp, gov); err != nil {
		t.Fatal(err)
	}
	if b := must(os.ReadFile(gp)); string(b) != labelsHeader+"\n" {
		t.Errorf("us-gov header %q", b)
	}
	cp := filepath.Join(dir, "corp")
	if err := initLabels(cp, corp); err != nil {
		t.Fatal(err)
	}
	if b := must(os.ReadFile(cp)); string(b) != `{"conngw-labels":2,"scheme":"`+corp.Digest()+`"}`+"\n" {
		t.Errorf("corporate header %q", b)
	}
	l, err := openLabels(cp, corp)
	if err != nil {
		t.Fatal(err)
	}
	l.file.Close()
	if _, err := openLabels(cp, gov); err == nil || !strings.Contains(err.Error(), "holds another scheme's labels") {
		t.Errorf("corporate file under us-gov: %v", err)
	}
	if _, err := openLabels(gp, corp); err == nil || !strings.Contains(err.Error(), "holds us-gov labels") || !strings.Contains(err.Error(), "marking-migrate") {
		t.Errorf("us-gov file under corporate: %v", err)
	}
	forged := filepath.Join(dir, "forged")
	if err := os.WriteFile(forged, []byte(`{"conngw-labels":2,"scheme":"sha256:00"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openLabels(forged, corp); err == nil {
		t.Error("a header naming another digest was read")
	}
}

// A caller's declaration names the scheme its classification is read under; another scheme, or
// none against a corporate connector, never matches.
func TestDeclarationScheme(t *testing.T) {
	lv := levels(t)
	corp := corporate(t)
	m, err := corp.Parse("CONFIDENTIAL//PHI")
	if err != nil {
		t.Fatal(err)
	}
	src := source{Name: "ehr", Classification: "CONFIDENTIAL//PHI", marking: m, scheme: corp}
	if !src.matches(declared{Classification: "CONFIDENTIAL//PHI", Scheme: corp.Digest()}) {
		t.Error("a matching declaration refused")
	}
	if src.matches(declared{Classification: "CONFIDENTIAL//PHI"}) {
		t.Error("a declaration without the scheme matched a corporate connector")
	}
	gov := mustSource(t, "jira", lv[1])
	if gov.matches(declared{Classification: lv[1], Scheme: corp.Digest()}) {
		t.Error("a declaration naming another scheme matched a us-gov connector")
	}
	if !gov.matches(declared{Classification: lv[1]}) {
		t.Error("a us-gov declaration without a scheme refused")
	}
	if !gov.matches(declared{Classification: lv[1], Scheme: marking.Current().Digest()}) {
		t.Error("a us-gov declaration naming the us-gov digest refused")
	}
}

// Answers carry the scheme next to the banner, except under us-gov, whose answers are unchanged.
func TestMetaScheme(t *testing.T) {
	lv := levels(t)
	corp := corporate(t)
	m, _ := corp.Parse("CONFIDENTIAL//PHI")
	s := &stream{conn: source{marking: m, scheme: corp}}
	inner := s.meta(m)[metaKey].(map[string]any)
	if inner["scheme"] != corp.Digest() || inner["banner"] != "CONFIDENTIAL//PHI" {
		t.Errorf("corporate meta %v", inner)
	}
	g := &stream{conn: mustSource(t, "jira", lv[1])}
	if _, ok := g.meta(g.conn.marking)[metaKey].(map[string]any)["scheme"]; ok {
		t.Error("a us-gov answer names a scheme")
	}
}

// The workspace floor is read under the profile's scheme, like the connectors' classifications.
func TestFloorUnderTheProfileScheme(t *testing.T) {
	corp := corporate(t)
	pin := `,"markingScheme":{"preset":"corporate","sha256":"` + corp.Digest() + `"},"floor":"INTERNAL","admins":["ctl/controller"]`
	c, err := load(configWith(t, pin, "CONFIDENTIAL//PHI"))
	if err != nil {
		t.Fatal(err)
	}
	if c.floor == nil || marking.Banner(*c.floor) != "INTERNAL" || marking.DigestOf(*c.floor) != corp.Digest() {
		t.Errorf("floor %v", c.floor)
	}
	if _, err := load(configWith(t, strings.Replace(pin, `"floor":"INTERNAL"`, `"floor":"`+levels(t)[0]+`"`, 1), "CONFIDENTIAL//PHI")); err == nil {
		t.Error("a us-gov floor loaded under the corporate scheme")
	}
}
