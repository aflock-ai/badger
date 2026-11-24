// Command confluence is Badger's Confluence Data Center / Server connector: CQL search, pages
// as markdown, children and spaces, and (with --enable-writes) page create and a version-checked
// update, over the REST content API with the user's personal access token.
//
// Classification. A Confluence instance holds one classification: every result carries the
// connector's administrator-set marking, and the connector reads nothing about classification
// from Confluence (labels, page bodies, panels, tables).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/aflock-ai/badger/testifysec/connectors/sdk"
)

const api = "/rest/api"

var (
	idRE     = regexp.MustCompile(`^[0-9]{1,20}$`)
	spaceRE  = regexp.MustCompile(`^~?[A-Za-z0-9][A-Za-z0-9_.@-]{0,254}$`)
	cursorRE = regexp.MustCompile(`^[A-Za-z0-9_=+/%-]{1,512}$`)
)

var spec = sdk.Spec{Name: "confluence", Version: "0.1.0", Scheme: sdk.Bearer,
	Tools: func(c *sdk.Client) []sdk.Tool { return (&conf{c: c}).tools() }}

func main() { sdk.Main(spec) }

type conf struct {
	c *sdk.Client
}

type content struct {
	ID          json.Number // a string for content, a number for spaces
	Type, Title string
	Key, Name   string // set on spaces
	Space       struct{ Key, Name string }
	Version     struct {
		Number int
		When   string
		By     struct{ DisplayName string }
	}
	Ancestors []struct{ ID string }
	Body      struct {
		Storage struct{ Value string }
	}
	Metadata struct{ Labels *labelPage }
	Links    struct{ WebUI string } `json:"_links"`
}

type labelPage struct {
	Results []struct{ Name string }
}

func orNoLabels(l *labelPage) *labelPage {
	if l == nil {
		return &labelPage{}
	}
	return l
}

type page struct {
	Results []content
	Start   int
	Size    int
	Links   struct{ Next string } `json:"_links"`
}

// classNote ends every tool description.
const classNote = " Every result carries the connector's configured classification marking."

func (f *conf) tools() []sdk.Tool {
	read := func(name, desc string, schema json.RawMessage, h func(context.Context, json.RawMessage) (sdk.Result, error)) sdk.Tool {
		return sdk.Tool{Name: name, Description: desc + classNote, InputSchema: schema, Handler: wrapErr(h)}
	}
	t := []sdk.Tool{
		read("confluence_search", "Search content with CQL (e.g. `space = ENG and type = page and text ~ \"release\"`). limit 1-50 (default 10); "+
			"page with start, or cursor when the result says so. Returns ids, titles and spaces.",
			sdk.ObjectSchema(map[string]string{"cql": "string", "limit": "integer", "start": "integer", "cursor": "string"}, "cql"), f.search),
		read("confluence_get_page", "Get a page as markdown with its labels, version and ancestor ids. Pass id, or space (key) and exact title.",
			sdk.ObjectSchema(map[string]string{"id": "string", "space": "string", "title": "string"}), f.getPage),
		read("confluence_list_children", "List the child pages of a page id. limit 1-50 (default 25), start to page.",
			sdk.ObjectSchema(map[string]string{"id": "string", "limit": "integer", "start": "integer"}, "id"), f.children),
		read("confluence_list_spaces", "List spaces you can see. limit 1-50 (default 25), start to page, type global or personal.",
			sdk.ObjectSchema(map[string]string{"limit": "integer", "start": "integer", "type": "string"}), f.spaces),
	}
	w := []sdk.Tool{
		{Name: "confluence_create_page", Write: true, Handler: wrapErr(f.create),
			Description: "Create a page in a space (key), optionally under parent_id. body is markdown: headings, paragraphs, lists, " +
				"fenced code, bold, inline code and http(s) links. Changes the service.",
			InputSchema: sdk.ObjectSchema(map[string]string{"space": "string", "title": "string", "body": "string", "parent_id": "string"}, "space", "title", "body")},
		{Name: "confluence_update_page", Write: true, Handler: wrapErr(f.update),
			Description: "Replace a page body (markdown, as for create) and optionally its title. version must be the page's current " +
				"version number from confluence_get_page; the update is refused if the page has changed since. Changes the service.",
			InputSchema: sdk.ObjectSchema(map[string]string{"id": "string", "version": "integer", "body": "string", "title": "string"}, "id", "version", "body")},
	}
	for i := range w {
		w[i].Description += classNote
	}
	return append(t, w...)
}

func (f *conf) search(ctx context.Context, args json.RawMessage) (sdk.Result, error) {
	var a struct {
		CQL    string `json:"cql"`
		Limit  int    `json:"limit"`
		Start  int    `json:"start"`
		Cursor string `json:"cursor"`
	}
	if err := sdk.Decode(args, &a); err != nil {
		return sdk.Result{}, err
	}
	if a.CQL == "" || len(a.CQL) > 2000 || clean(a.CQL) != a.CQL {
		return sdk.Result{}, errors.New("cql must be 1-2000 printable characters")
	}
	q, err := paging(a.Limit, 10, a.Start)
	if err != nil {
		return sdk.Result{}, err
	}
	if a.Cursor != "" {
		if !cursorRE.MatchString(a.Cursor) {
			return sdk.Result{}, errors.New("cursor is not one this connector returned")
		}
		q.Set("cursor", a.Cursor)
	}
	q.Set("cql", a.CQL)
	q.Set("expand", "space")
	return f.list(ctx, api+"/content/search", q, func(c content) string {
		return fmt.Sprintf("- %s [%s] %s (space %s)", c.ID, c.Type, oneLine(c.Title), c.Space.Key)
	})
}

func (f *conf) children(ctx context.Context, args json.RawMessage) (sdk.Result, error) {
	var a struct {
		ID    string `json:"id"`
		Limit int    `json:"limit"`
		Start int    `json:"start"`
	}
	if err := sdk.Decode(args, &a); err != nil {
		return sdk.Result{}, err
	}
	if !idRE.MatchString(a.ID) {
		return sdk.Result{}, errors.New("id must be a numeric page id")
	}
	q, err := paging(a.Limit, 25, a.Start)
	if err != nil {
		return sdk.Result{}, err
	}
	return f.list(ctx, api+"/content/"+a.ID+"/child/page", q, func(c content) string {
		return fmt.Sprintf("- %s %s", c.ID, oneLine(c.Title))
	})
}

func (f *conf) spaces(ctx context.Context, args json.RawMessage) (sdk.Result, error) {
	var a struct {
		Limit int    `json:"limit"`
		Start int    `json:"start"`
		Type  string `json:"type"`
	}
	if err := sdk.Decode(args, &a); err != nil {
		return sdk.Result{}, err
	}
	q, err := paging(a.Limit, 25, a.Start)
	if err != nil {
		return sdk.Result{}, err
	}
	switch a.Type {
	case "":
	case "global", "personal":
		q.Set("type", a.Type)
	default:
		return sdk.Result{}, errors.New("type must be global or personal")
	}
	return f.list(ctx, api+"/space", q, func(c content) string {
		return fmt.Sprintf("- %s: %s", c.Key, oneLine(c.Name))
	})
}

// list fetches one page of a paged collection (content or spaces) and renders each item.
func (f *conf) list(ctx context.Context, path string, q url.Values, line func(content) string) (sdk.Result, error) {
	b, err := f.c.Get(ctx, path, q)
	if err != nil {
		return sdk.Result{}, err
	}
	var p page
	if err := json.Unmarshal(b, &p); err != nil {
		return sdk.Result{}, errors.New("unexpected response from the service")
	}
	start, _ := strconv.Atoi(q.Get("start"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	var s strings.Builder
	fmt.Fprintf(&s, "%d results (start %d)\n", len(p.Results), start)
	for _, c := range p.Results {
		s.WriteString(line(c) + "\n")
	}
	if p.Links.Next != "" {
		u, _ := url.Parse(p.Links.Next)
		var nq url.Values
		if u != nil {
			nq = u.Query()
		}
		// Confluence DC 9.2 sends offset (start=) next links only; the cursor branch is for
		// servers that send cursor= links and has not been exercised against a live one.
		if cursorRE.MatchString(nq.Get("cursor")) {
			s.WriteString("more results: call again with cursor=" + nq.Get("cursor") + "\n")
		} else {
			// Use the service's next offset; fall back to start+limit so a sparse or
			// empty page still advances.
			next, err := strconv.Atoi(nq.Get("start"))
			if err != nil || next <= start {
				next = start + limit
			}
			if next > maxStart {
				fmt.Fprintf(&s, "more results exist past start=%d, the furthest this connector pages; narrow the query\n", maxStart)
			} else {
				fmt.Fprintf(&s, "more results: call again with start=%d\n", next)
			}
		}
	}
	return sdk.Result{Text: s.String()}, nil
}

const maxStart = 100000 // the furthest offset this connector pages to

func paging(limit, def, start int) (url.Values, error) {
	if limit == 0 {
		limit = def
	}
	if limit < 1 || limit > 50 || start < 0 || start > maxStart {
		return nil, errors.New("limit must be 1-50 and start 0-100000")
	}
	return url.Values{"limit": {strconv.Itoa(limit)}, "start": {strconv.Itoa(start)}}, nil
}

const pageExpand = "body.storage,version,space,ancestors,metadata.labels"

func (f *conf) getPage(ctx context.Context, args json.RawMessage) (sdk.Result, error) {
	var a struct{ ID, Space, Title string }
	if err := sdk.Decode(args, &a); err != nil {
		return sdk.Result{}, err
	}
	var c content
	switch {
	case a.ID != "" && a.Space == "" && a.Title == "":
		if !idRE.MatchString(a.ID) {
			return sdk.Result{}, errors.New("id must be a numeric page id")
		}
		if err := f.getJSON(ctx, api+"/content/"+a.ID, url.Values{"expand": {pageExpand}}, &c); err != nil {
			return sdk.Result{}, err
		}
	case a.ID == "" && a.Space != "" && a.Title != "":
		if err := checkSpaceTitle(a.Space, a.Title); err != nil {
			return sdk.Result{}, err
		}
		var p page
		q := url.Values{"spaceKey": {a.Space}, "title": {a.Title}, "type": {"page"}, "expand": {pageExpand}}
		if err := f.getJSON(ctx, api+"/content", q, &p); err != nil {
			return sdk.Result{}, err
		}
		if len(p.Results) == 0 {
			return sdk.Result{}, fmt.Errorf("no page titled %q in space %s, or not visible to you", a.Title, a.Space)
		}
		c = p.Results[0]
	default:
		return sdk.Result{}, errors.New("pass id, or space and title")
	}
	if c.ID == "" {
		return sdk.Result{}, errors.New("unexpected response from the service: the page has no id")
	}
	return f.render(c), nil
}

func (f *conf) render(c content) sdk.Result {
	var labels []string
	if c.Metadata.Labels != nil {
		for _, l := range c.Metadata.Labels.Results {
			labels = append(labels, l.Name)
		}
	}
	body := storageToMarkdown(c.Body.Storage.Value)
	var s strings.Builder
	fmt.Fprintf(&s, "# %s\nid: %s, space: %s, version: %d, updated %s by %s\n", oneLine(c.Title), c.ID, c.Space.Key,
		c.Version.Number, c.Version.When, oneLine(c.Version.By.DisplayName))
	if len(c.Ancestors) > 0 {
		var path []string
		for _, an := range c.Ancestors {
			path = append(path, an.ID)
		}
		s.WriteString("ancestors (ids): " + strings.Join(path, " > ") + "\n")
	}
	if len(labels) > 0 {
		s.WriteString("labels: " + strings.Join(labels, ", ") + "\n")
	}
	s.WriteString("link: " + c.Links.WebUI + "\n\n" + body)
	return sdk.Result{Text: s.String()}
}

func (f *conf) create(ctx context.Context, args json.RawMessage) (sdk.Result, error) {
	var a struct {
		Space, Title, Body string
		ParentID           string `json:"parent_id"`
	}
	if err := sdk.Decode(args, &a); err != nil {
		return sdk.Result{}, err
	}
	if err := checkSpaceTitle(a.Space, a.Title); err != nil {
		return sdk.Result{}, err
	}
	if strings.TrimSpace(a.Body) == "" { // Decode does not enforce required fields
		return sdk.Result{}, errors.New("body is required")
	}
	req := map[string]any{"type": "page", "title": a.Title, "space": map[string]string{"key": a.Space},
		"body": map[string]any{"storage": map[string]string{"value": markdownToStorage(a.Body), "representation": "storage"}}}
	if a.ParentID != "" {
		if !idRE.MatchString(a.ParentID) {
			return sdk.Result{}, errors.New("parent_id must be a numeric page id")
		}
		req["ancestors"] = []map[string]string{{"id": a.ParentID}}
	}
	return f.write(ctx, http.MethodPost, api+"/content", req, "created")
}

func (f *conf) update(ctx context.Context, args json.RawMessage) (sdk.Result, error) {
	var a struct {
		ID, Body, Title string
		Version         int
	}
	if err := sdk.Decode(args, &a); err != nil {
		return sdk.Result{}, err
	}
	if !idRE.MatchString(a.ID) {
		return sdk.Result{}, errors.New("id must be a numeric page id")
	}
	if a.Version < 1 { // Decode does not enforce required fields
		return sdk.Result{}, errors.New("version is required: the page's current version number from confluence_get_page")
	}
	if strings.TrimSpace(a.Body) == "" {
		return sdk.Result{}, errors.New("body is required")
	}
	var cur content
	if err := f.getJSON(ctx, api+"/content/"+a.ID, url.Values{"expand": {"version,space"}}, &cur); err != nil {
		return sdk.Result{}, err
	}
	if a.Version != cur.Version.Number {
		return sdk.Result{}, fmt.Errorf("version conflict: page %s is at version %d, you passed %d; re-read it with confluence_get_page before updating", a.ID, cur.Version.Number, a.Version)
	}
	if a.Title == "" {
		a.Title = cur.Title
	}
	if err := checkSpaceTitle(cur.Space.Key, a.Title); err != nil {
		return sdk.Result{}, err
	}
	storage := markdownToStorage(a.Body)
	req := map[string]any{"id": a.ID, "type": "page", "title": a.Title, "version": map[string]int{"number": a.Version + 1},
		"body": map[string]any{"storage": map[string]string{"value": storage, "representation": "storage"}}}
	res, err := f.write(ctx, http.MethodPut, api+"/content/"+a.ID, req, "updated")
	var he *sdk.HTTPError
	if errors.As(err, &he) && he.Status == 409 {
		return res, fmt.Errorf("version conflict: page %s changed while updating; re-read it with confluence_get_page", a.ID)
	}
	return res, err
}

func (f *conf) write(ctx context.Context, method, path string, req any, verb string) (sdk.Result, error) {
	body, _ := json.Marshal(req)
	b, err := f.c.Do(ctx, method, path, url.Values{"expand": {"space,version"}}, "application/json", body)
	if err != nil {
		return sdk.Result{}, err
	}
	var c content
	if err := json.Unmarshal(b, &c); err != nil {
		return sdk.Result{}, errors.New("unexpected response from the service")
	}
	return sdk.Result{Text: fmt.Sprintf("%s page %s %q in space %s, now version %d\nlink: %s", verb, c.ID, oneLine(c.Title), c.Space.Key, c.Version.Number, c.Links.WebUI)}, nil
}

func (f *conf) getJSON(ctx context.Context, path string, q url.Values, v any) error {
	b, err := f.c.Get(ctx, path, q)
	if err != nil {
		return err
	}
	if json.Unmarshal(b, v) != nil {
		return errors.New("unexpected response from the service")
	}
	return nil
}

func checkSpaceTitle(space, title string) error {
	if !spaceRE.MatchString(space) {
		return errors.New("space must be a space key such as ENG or ~username")
	}
	if title == "" || len(title) > 255 || clean(title) != title || strings.ContainsAny(title, "\n\t") {
		return errors.New("title must be 1-255 printable characters on one line")
	}
	return nil
}

// wrapErr turns a Confluence error body ({"statusCode":400,"message":"..."}) into its message.
func wrapErr(h func(context.Context, json.RawMessage) (sdk.Result, error)) func(context.Context, json.RawMessage) (sdk.Result, error) {
	return func(ctx context.Context, args json.RawMessage) (sdk.Result, error) {
		r, err := h(ctx, args)
		var he *sdk.HTTPError
		if errors.As(err, &he) && (he.Status == 400 || he.Status == 409 || he.Status == 422) {
			var e struct{ Message string }
			if json.Unmarshal([]byte(he.Body), &e) == nil && oneLine(e.Message) != "" {
				return r, fmt.Errorf("confluence rejected the request (HTTP %d): %s", he.Status, cut(oneLine(e.Message), 200))
			}
		}
		return r, err
	}
}
