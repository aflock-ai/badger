package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"unicode/utf8"
)

func fixture(t *testing.T, path string) *Bundle {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := parseBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func docs(t *testing.T, overlays ...string) *Docs {
	t.Helper()
	var ov []Overlay
	for _, dir := range overlays {
		ov = append(ov, Overlay{Name: "site", Bundle: fixture(t, dir+"/bundle.json")})
	}
	d, err := newDocs(fixture(t, "testdata/bundle.json"), ov)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func call(t *testing.T, d *Docs, tool string, args string) string {
	t.Helper()
	text, isErr := d.call(tool, json.RawMessage(args))
	if isErr {
		t.Fatalf("%s(%s) failed: %s", tool, args, text)
	}
	return text
}

func TestParseBundleRefusesMalformed(t *testing.T) {
	good, _ := os.ReadFile("testdata/bundle.json")
	cases := map[string]string{
		"schema":        strings.Replace(string(good), `"schema": 1`, `"schema": 2`, 1),
		"badger root":   strings.Replace(string(good), `"name": "badger"`, `"name": "other"`, 1),
		"duplicate id":  strings.Replace(string(good), `"id": "index"`, `"id": "admin/install-gateway"`, 1),
		"unknown field": strings.Replace(string(good), `"schema": 1`, `"schema": 1, "extra": true`, 1),
		"not json":      "{",
	}
	for name, raw := range cases {
		if _, err := parseBundle([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSectionsSkipFencedCodeAndNumberRepeats(t *testing.T) {
	b := fixture(t, "testdata/bundle.json")
	var got []string
	for _, s := range sections(b.Topics[0].Body) {
		got = append(got, s.Slug)
	}
	want := []string{"install-the-model-gateway", "build", "write-the-configuration", "build-1"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("slugs %v, want %v", got, want)
	}
}

func TestEveryTopicIsListedAndReadable(t *testing.T) {
	d := docs(t)
	list := call(t, d, "list_topics", `{}`)
	for _, topic := range d.base.Topics {
		if !strings.Contains(list, topic.ID) {
			t.Errorf("list_topics misses %s", topic.ID)
		}
		body := call(t, d, "read", `{"topic":"`+topic.ID+`"}`)
		if !strings.Contains(body, "# "+topic.Title) {
			t.Errorf("read %s: no title in %q", topic.ID, body)
		}
	}
	section := call(t, d, "read", `{"topic":"admin/install-gateway#write-the-configuration"}`)
	if !strings.Contains(section, "Set maxRecords.") || strings.Contains(section, "Run go build.") {
		t.Fatalf("section read returned %q", section)
	}
	if !strings.HasPrefix(call(t, d, "read", `{"topic":"index.md"}`), "badger 4.3.0 at 0123456789ab") {
		t.Fatal("a read is not headed with the version it describes")
	}
	if text, isErr := d.call("read", json.RawMessage(`{"topic":"admin/nope"}`)); !isErr || !strings.Contains(text, "admin/install-gateway") {
		t.Fatalf("unknown topic: %v %q", isErr, text)
	}
}

func TestSearchFindsConfigFieldsAndSections(t *testing.T) {
	d := docs(t)
	got := call(t, d, "search", `{"query":"maxStreams"}`)
	if !strings.Contains(got, "config conngw maxStreams") {
		t.Fatalf("search maxStreams: %q", got)
	}
	got = call(t, d, "search", `{"query":"configuration maxRecords"}`)
	if !strings.HasPrefix(strings.SplitN(got, "\n", 3)[1], "- admin/install-gateway#write-the-configuration") {
		t.Fatalf("search did not rank the section first: %q", got)
	}
	if text, _ := d.call("search", json.RawMessage(`{"query":""}`)); !strings.Contains(text, "query") {
		t.Fatalf("empty query: %q", text)
	}
}

func TestConfigReference(t *testing.T) {
	d := docs(t)
	got := call(t, d, "get_config_reference", `{"component":"conngw"}`)
	for _, want := range []string{"`maxStreams`", "`int`", "default `64`", "testifysec/connectors/cmd/conngw/main.go:97", "0123456789ab"} {
		if !strings.Contains(got, want) {
			t.Errorf("config reference misses %q in %q", want, got)
		}
	}
	if text, isErr := d.call("get_config_reference", json.RawMessage(`{"component":"nope"}`)); !isErr || !strings.Contains(text, "conngw") {
		t.Fatalf("unknown component: %v %q", isErr, text)
	}
}

func TestVersionAndBuildCheck(t *testing.T) {
	d := docs(t)
	var v struct {
		Badger struct{ Version, Commit string } `json:"badger"`
	}
	if err := json.Unmarshal([]byte(call(t, d, "version", `{}`)), &v); err != nil || v.Badger.Version != "4.3.0" || v.Badger.Commit != "0123456789abcdef0123456789abcdef01234567" {
		t.Fatalf("version: %+v %v", v, err)
	}
	b := d.base
	if err := checkBuild(b, "0123456789abcdef0123456789abcdef01234567", false); err != nil {
		t.Fatal(err)
	}
	if err := checkBuild(b, "", false); err != nil {
		t.Fatalf("a build without VCS stamps is allowed: %v", err)
	}
	if err := checkBuild(b, "ffffffffffffffffffffffffffffffffffffffff", false); err == nil {
		t.Fatal("a bundle from another commit was accepted")
	}
}

func TestOverlayAddsTopicsAndNeverReplaces(t *testing.T) {
	d := docs(t, "testdata/overlay")
	list := call(t, d, "list_topics", `{}`)
	if !strings.Contains(list, "overlay/site/index") || !strings.Contains(list, "- index ") {
		t.Fatalf("list with overlay: %q", list)
	}
	if got := call(t, d, "read", `{"topic":"index"}`); !strings.Contains(got, "A coding agent for enclaves.") {
		t.Fatalf("the overlay replaced a public topic: %q", got)
	}
	got := call(t, d, "read", `{"topic":"overlay/site/index"}`)
	if !strings.Contains(got, "Use the site's gateway settings.") || !strings.Contains(got, "built against badger 4.2.0") {
		t.Fatalf("overlay read: %q", got)
	}
	if !strings.Contains(call(t, d, "search", `{"query":"site gateway settings"}`), "overlay/site/index") {
		t.Fatal("search does not reach the overlay")
	}
	if !strings.Contains(call(t, d, "version", `{}`), `"name": "site"`) {
		t.Fatal("version does not report the overlay")
	}
	if _, err := loadOverlay("testdata/no-such-dir"); err == nil {
		t.Fatal("a missing overlay was accepted")
	}
}

func TestStdio(t *testing.T) {
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read","arguments":{"topic":"index"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"resources/list"}`,
		`not json`,
	}, "\n") + "\n"
	var out bytes.Buffer
	if err := serve(docs(t), strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 5 {
		t.Fatalf("%d replies: %q", len(lines), out.String())
	}
	var list struct {
		Result struct {
			Tools []struct {
				Name        string
				Annotations map[string]bool
			}
		}
	}
	json.Unmarshal([]byte(lines[1]), &list)
	var names []string
	for _, tool := range list.Result.Tools {
		names = append(names, tool.Name)
		if !tool.Annotations["readOnlyHint"] {
			t.Errorf("%s is not marked read-only", tool.Name)
		}
	}
	if strings.Join(names, ",") != "list_topics,search,read,get_config_reference,version" {
		t.Fatalf("tools %v", names)
	}
	for i, want := range []string{`"protocolVersion":"2025-06-18"`, `"tools"`, `A coding agent for enclaves.`, `"code":-32601`, `"code":-32700`} {
		if !strings.Contains(lines[i], want) {
			t.Errorf("reply %d misses %s: %s", i+1, want, lines[i])
		}
	}
}

func TestSlugsNeverCollide(t *testing.T) {
	var got []string
	for _, s := range sections("# Build\n\n## Build-1\n\n## Build\n\n## Build\n") {
		got = append(got, s.Slug)
	}
	if strings.Join(got, ",") != "build,build-1,build-2,build-3" {
		t.Fatalf("slugs %v", got)
	}
}

func TestTildeAndLongerFencesHideHeadings(t *testing.T) {
	body := "# A\n~~~sh\n# a comment\n~~~\n## B\n````md\n```\n# not a heading\n```\n````\n## C\n```sh\n# also not\n~~~\n# still code\n```\n## D\n"
	var got []string
	for _, s := range sections(body) {
		got = append(got, s.Slug)
	}
	if strings.Join(got, ",") != "a,b,c,d" {
		t.Fatalf("slugs %v", got)
	}
}

func TestSnippetSurvivesTextThatGrowsWhenLowercased(t *testing.T) {
	text := strings.Repeat("Ⱥ", 100) + " needle " + strings.Repeat("Ⱥ", 100)
	got := snippet(text, []string{"needle"})
	if !strings.Contains(got, "needle") || !utf8.ValidString(got) {
		t.Fatalf("snippet %q", got)
	}
	if got := snippet(strings.Repeat("Ⱥ", 300), []string{"absent"}); !utf8.ValidString(got) {
		t.Fatalf("snippet without a match is not valid UTF-8: %q", got)
	}
}
