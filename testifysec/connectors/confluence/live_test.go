package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/badger/testifysec/connectors/sdk"

	"github.com/aflock-ai/badger/testifysec/connectors/internal/fakeserver"
)

// Responses recorded from a disposable Confluence Data Center 9.2.14 with invented data, the
// connector's own requests replayed against them. The pages carry marking-like labels and first
// lines; the banner is the connector's own on every one.
func TestLiveFixtures(t *testing.T) {
	const lp = "/confluence/rest/api"
	pageQ := "expand=" + pageExpand
	var routes []fakeserver.Route
	for _, id := range []string{"1081381", "1081382", "1081383", "1081384", "1081385", "1081386", "1081387", "1081388", "1081390", "1081391"} {
		routes = append(routes, fakeserver.Route{Method: "GET", Path: lp + "/content/" + id, Query: pageQ, Fixture: "page-" + id + ".json"})
	}
	routes = append(routes,
		fakeserver.Route{Method: "GET", Path: lp + "/content/1081349/child/page", Query: "limit=25&start=0", Fixture: "children-1081349-0.json"},
		fakeserver.Route{Method: "GET", Path: lp + "/content/1081349/child/page", Query: "limit=25&start=25", Fixture: "children-1081349-25.json"},
		fakeserver.Route{Method: "GET", Path: lp + "/space", Query: "limit=25&start=0", Fixture: "spaces.json"},
	)
	fake := fakeserver.New(t, "testdata/live", routes...)
	tok := filepath.Join(t.TempDir(), "token")
	os.WriteFile(tok, []byte(sentinel), 0o600)
	s, err := sdk.New(spec, sdk.Config{BaseURL: fake.URL + "/confluence", TokenFile: tok, InsecureLoopbackHTTP: true, Classification: "UNCLASSIFIED"})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"1081381", "1081382", "1081383", "1081384", "1081385", "1081386", "1081387", "1081388", "1081390", "1081391"} {
		r := call(s, "confluence_get_page", `{"id":"`+id+`"}`)
		must(t, r, false, "id: "+id)
		if r.Banner != "UNCLASSIFIED" {
			t.Errorf("page %s: banner %q", id, r.Banner)
		}
	}
	must(t, call(s, "confluence_list_children", `{"id":"1081349"}`), false, "25 results (start 0)", "more results: call again with start=25")
	r := call(s, "confluence_list_children", `{"id":"1081349","start":25}`)
	must(t, r, false, "5 results (start 25)")
	if strings.Contains(r.Text, "more results") {
		t.Errorf("last page offers more:\n%s", r.Text)
	}
	must(t, call(s, "confluence_list_spaces", `{}`), false, "ENG: Engineering")
}
