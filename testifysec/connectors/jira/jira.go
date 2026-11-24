package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/aflock-ai/badger/testifysec/connectors/sdk"
)

const (
	defaultPage = 20
	maxPage     = 50
	maxFields   = 20
)

var (
	issueKey   = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,49}-[1-9][0-9]{0,9}$`)
	projectKey = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,49}$`)
	fieldName  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
)

// searchFields are what jira_search asks for when the caller names none.
var searchFields = []string{"summary", "status", "issuetype", "priority", "assignee", "updated"}

type jira struct {
	c *sdk.Client
}

func tools(j *jira) []sdk.Tool {
	return []sdk.Tool{
		{Name: "jira_search", Description: "Search issues with JQL. Returns one page (default 20, at most 50) of key, status, summary, type, priority, assignee and updated date; pass start_at from the previous page's next_page to continue. fields adds or replaces the returned fields (Jira field ids).",
			InputSchema: schema(`"jql":{"type":"string","description":"JQL query"},"start_at":{"type":"integer","minimum":0},"max_results":{"type":"integer","minimum":1,"maximum":50},"fields":{"type":"array","items":{"type":"string"},"maxItems":20}`, "jql"),
			Handler:     j.search},
		{Name: "jira_get_issue", Description: "Get one issue by key (PROJ-123): summary, status, type, priority, assignee, reporter, labels, components, description as markdown, and linked issues.",
			InputSchema: schema(`"key":{"type":"string","description":"issue key, e.g. PROJ-123"}`, "key"), Handler: j.getIssue},
		{Name: "jira_list_comments", Description: "List an issue's comments, oldest first, one page at a time (default 20, at most 50).",
			InputSchema: schema(`"key":{"type":"string"},"start_at":{"type":"integer","minimum":0},"max_results":{"type":"integer","minimum":1,"maximum":50}`, "key"), Handler: j.listComments},
		{Name: "jira_add_comment", Description: "Add a comment (Jira wiki markup) to an issue. Changes the service.", Write: true,
			InputSchema: schema(`"key":{"type":"string"},"body":{"type":"string"}`, "key", "body"), Handler: j.addComment},
		{Name: "jira_create_issue", Description: "Create an issue in a project. Changes the service.", Write: true,
			InputSchema: schema(`"project":{"type":"string","description":"project key, e.g. PROJ"},"issue_type":{"type":"string","description":"issue type name, e.g. Task"},"summary":{"type":"string"},"description":{"type":"string","description":"Jira wiki markup"}`, "project", "issue_type", "summary"),
			Handler:     j.createIssue},
		{Name: "jira_transition_issue", Description: "Move an issue through its workflow by transition name or id. If the transition is not available, the error lists the ones that are. Changes the service.", Write: true,
			InputSchema: schema(`"key":{"type":"string"},"transition":{"type":"string","description":"transition name or id"}`, "key", "transition"), Handler: j.transition},
	}
}

func schema(props string, required ...string) json.RawMessage {
	req, _ := json.Marshal(required)
	return json.RawMessage(`{"type":"object","properties":{` + props + `},"required":` + string(req) + `,"additionalProperties":false}`)
}

// issuePath validates key before it becomes a path segment, then escapes it anyway.
func issuePath(key string, rest ...string) (string, error) {
	if !issueKey.MatchString(key) {
		return "", fmt.Errorf("invalid issue key %q: want PROJECT-123 (upper-case project key)", key)
	}
	p := "/rest/api/2/issue/" + url.PathEscape(key)
	for _, r := range rest {
		p += "/" + url.PathEscape(r)
	}
	return p, nil
}

// page applies the default and the cap; zero means the default.
func page(start, max int) (int, int, error) {
	if start < 0 || max < 0 {
		return 0, 0, errors.New("start_at and max_results must not be negative")
	}
	if max == 0 {
		max = defaultPage
	}
	return start, min(max, maxPage), nil
}

// clip cuts s to at most n bytes on a rune boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "..."
}

// jiraErr words 403 as Jira means it and shortens Jira's {"errorMessages":[...],"errors":{field:msg}} bodies on 400, 409 and 422
// (the statuses egress shows a detail for) to the messages alone, capped.
func jiraErr(err error) error {
	var he *sdk.HTTPError
	if !errors.As(err, &he) {
		return err
	}
	// Jira answers 403, not 404, for an issue the user cannot see; a rejected token is 401.
	if he.Status == http.StatusForbidden {
		return errors.New("not visible to this credential, or does not exist (HTTP 403)")
	}
	if he.Detail == "" {
		return err
	}
	var body struct {
		ErrorMessages []string          `json:"errorMessages"`
		Errors        map[string]string `json:"errors"`
	}
	if json.Unmarshal([]byte(he.Body), &body) != nil {
		return err
	}
	msgs := body.ErrorMessages
	keys := make([]string, 0, len(body.Errors))
	for k := range body.Errors {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		msgs = append(msgs, k+": "+body.Errors[k])
	}
	if len(msgs) == 0 {
		return err
	}
	msg := clip(strings.Join(strings.Fields(strings.Join(msgs, "; ")), " "), 300)
	return fmt.Errorf("the service rejected the request (HTTP %d): %s", he.Status, msg)
}

func (j *jira) get(ctx context.Context, path string, q url.Values, v any) error {
	b, err := j.c.Get(ctx, path, q)
	if err != nil {
		return jiraErr(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return errors.New("unexpected response from the service")
	}
	return nil
}

func (j *jira) send(ctx context.Context, method, path string, body any, v any) error {
	payload, _ := json.Marshal(body)
	b, err := j.c.Do(ctx, method, path, nil, "application/json", payload)
	if err != nil {
		return jiraErr(err)
	}
	if v != nil && json.Unmarshal(b, v) != nil {
		return errors.New("unexpected response from the service")
	}
	return nil
}

type named struct{ Name, Value, DisplayName, Key string }

func (n *named) String() string {
	if n == nil {
		return ""
	}
	for _, s := range []string{n.DisplayName, n.Name, n.Value, n.Key} {
		if s != "" {
			return s
		}
	}
	return ""
}

type linked struct {
	Key    string
	Fields struct {
		Summary string
		Status  *named
	}
}

type fields struct {
	Summary     string
	Status      *named
	IssueType   *named `json:"issuetype"`
	Priority    *named
	Assignee    *named
	Reporter    *named
	Labels      []string
	Components  []named
	Description string
	Created     string
	Updated     string
	Comment     *commentPage
	IssueLinks  []struct {
		Type                      struct{ Inward, Outward string }
		InwardIssue, OutwardIssue *linked
	} `json:"issuelinks"`
}

type comment struct {
	ID      string
	Author  *named
	Body    string
	Created string
}

type commentPage struct {
	StartAt, Total int
	Comments       []comment
}

type issue struct {
	Key    string
	Fields json.RawMessage
}

// decode reads an issue's fields; a response whose fields are missing or malformed is an error,
// not an empty issue.
func decode(it issue) (fields, map[string]json.RawMessage, error) {
	var f fields
	var raw map[string]json.RawMessage
	if json.Unmarshal(it.Fields, &raw) != nil || raw == nil || json.Unmarshal(it.Fields, &f) != nil {
		return f, raw, fmt.Errorf("unexpected response from the service: the fields of %s are missing or malformed", clip(it.Key, 40))
	}
	return f, raw, nil
}

// values flattens a field value (string, number, option object, user, array) to strings.
func values(raw json.RawMessage) []string {
	var s string
	var n named
	var arr []json.RawMessage
	var num json.Number
	switch {
	case len(raw) == 0 || string(raw) == "null":
		return nil
	case json.Unmarshal(raw, &s) == nil:
		return []string{s}
	case json.Unmarshal(raw, &arr) == nil:
		var out []string
		for _, e := range arr {
			out = append(out, values(e)...)
		}
		return out
	case json.Unmarshal(raw, &n) == nil && n.String() != "":
		return []string{n.String()}
	case json.Unmarshal(raw, &num) == nil:
		return []string{num.String()}
	}
	return nil
}

func or(s, dflt string) string {
	if s == "" {
		return dflt
	}
	return s
}

func day(ts string) string { return ts[:min(len(ts), 10)] }

func stamp(ts string) string {
	if len(ts) < 16 {
		return ts
	}
	return ts[:10] + " " + ts[11:16]
}

func (j *jira) search(ctx context.Context, args json.RawMessage) (sdk.Result, error) {
	var a struct {
		JQL        string   `json:"jql"`
		StartAt    int      `json:"start_at"`
		MaxResults int      `json:"max_results"`
		Fields     []string `json:"fields"`
	}
	if err := sdk.Decode(args, &a); err != nil {
		return sdk.Result{}, err
	}
	if strings.TrimSpace(a.JQL) == "" {
		return sdk.Result{}, errors.New("jql is required")
	}
	start, max, err := page(a.StartAt, a.MaxResults)
	if err != nil {
		return sdk.Result{}, err
	}
	if len(a.Fields) > maxFields {
		return sdk.Result{}, fmt.Errorf("at most %d fields", maxFields)
	}
	want := searchFields
	if len(a.Fields) > 0 {
		want = []string{"summary", "status"}
	}
	for _, f := range a.Fields {
		if !fieldName.MatchString(f) {
			return sdk.Result{}, fmt.Errorf("invalid field %q", f)
		}
	}
	want = appendNew(want, a.Fields...)
	q := url.Values{"jql": {a.JQL}, "startAt": {strconv.Itoa(start)}, "maxResults": {strconv.Itoa(max)}, "fields": {strings.Join(want, ",")}}
	var resp struct {
		StartAt, Total int
		Issues         []issue
	}
	if err := j.get(ctx, "/rest/api/2/search", q, &resp); err != nil {
		return sdk.Result{}, err
	}
	var b strings.Builder
	if len(resp.Issues) == 0 {
		fmt.Fprintf(&b, "no issues match (total %d)\n", resp.Total)
	} else {
		fmt.Fprintf(&b, "issues %d-%d of %d\n", resp.StartAt+1, resp.StartAt+len(resp.Issues), resp.Total)
	}
	for _, it := range resp.Issues {
		f, raw, err := decode(it)
		if err != nil {
			return sdk.Result{}, err
		}
		var info []string
		if len(a.Fields) == 0 {
			info = []string{or(f.IssueType.String(), "?"), or(f.Priority.String(), "no priority"), or(f.Assignee.String(), "unassigned"), "updated " + day(f.Updated)}
		}
		fmt.Fprintf(&b, "- **%s** [%s] %s", it.Key, f.Status.String(), f.Summary)
		if len(info) > 0 {
			fmt.Fprintf(&b, " (%s)", strings.Join(info, ", "))
		}
		b.WriteString("\n")
		for _, name := range a.Fields {
			if name != "summary" && name != "status" {
				v := clip(strings.Join(values(raw[name]), ", "), 200)
				fmt.Fprintf(&b, "  %s: %s\n", name, or(v, "(empty)"))
			}
		}
	}
	if next := resp.StartAt + len(resp.Issues); len(resp.Issues) > 0 && next < resp.Total {
		fmt.Fprintf(&b, "next page: start_at=%d\n", next)
	}
	return sdk.Result{Text: b.String()}, nil
}

func appendNew(list []string, add ...string) []string {
	out := slices.Clone(list)
	for _, a := range add {
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

// fetch gets the named fields of one issue.
func (j *jira) fetch(ctx context.Context, key string, show ...string) (issue, error) {
	p, err := issuePath(key)
	if err != nil {
		return issue{}, err
	}
	var it issue
	err = j.get(ctx, p, url.Values{"fields": {strings.Join(show, ",")}}, &it)
	return it, err
}

func (j *jira) getIssue(ctx context.Context, args json.RawMessage) (sdk.Result, error) {
	var a struct {
		Key string `json:"key"`
	}
	if err := sdk.Decode(args, &a); err != nil {
		return sdk.Result{}, err
	}
	it, err := j.fetch(ctx, a.Key, "summary", "status", "issuetype", "priority", "assignee", "reporter", "labels", "components", "description", "created", "updated", "issuelinks")
	if err != nil {
		return sdk.Result{}, err
	}
	f, _, err := decode(it)
	if err != nil {
		return sdk.Result{}, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# %s: %s\n", or(it.Key, a.Key), f.Summary)
	comps := make([]string, len(f.Components))
	for i, c := range f.Components {
		comps[i] = c.String()
	}
	for _, kv := range [][2]string{
		{"status", f.Status.String()}, {"type", f.IssueType.String()}, {"priority", f.Priority.String()},
		{"assignee", or(f.Assignee.String(), "unassigned")}, {"reporter", f.Reporter.String()},
		{"labels", strings.Join(f.Labels, ", ")}, {"components", strings.Join(comps, ", ")},
		{"created", stamp(f.Created)}, {"updated", stamp(f.Updated)},
	} {
		if kv[1] != "" {
			fmt.Fprintf(&b, "%s: %s\n", kv[0], kv[1])
		}
	}
	if d := strings.TrimSpace(f.Description); d != "" {
		b.WriteString("\n" + wikiToMarkdown(d) + "\n")
	}
	if len(f.IssueLinks) > 0 {
		b.WriteString("\n## Links\n")
		for _, l := range f.IssueLinks {
			rel, other := l.Type.Outward, l.OutwardIssue
			if other == nil {
				rel, other = l.Type.Inward, l.InwardIssue
			}
			if other != nil {
				fmt.Fprintf(&b, "- %s %s [%s] %s\n", rel, other.Key, other.Fields.Status.String(), other.Fields.Summary)
			}
		}
	}
	return sdk.Result{Text: b.String()}, nil
}

func (j *jira) listComments(ctx context.Context, args json.RawMessage) (sdk.Result, error) {
	var a struct {
		Key        string `json:"key"`
		StartAt    int    `json:"start_at"`
		MaxResults int    `json:"max_results"`
	}
	if err := sdk.Decode(args, &a); err != nil {
		return sdk.Result{}, err
	}
	start, limit, err := page(a.StartAt, a.MaxResults)
	if err != nil {
		return sdk.Result{}, err
	}
	// The first page usually comes embedded in the issue; Jira caps that embedded list, and a page
	// beyond it comes from the comment endpoint.
	it, err := j.fetch(ctx, a.Key, "comment")
	if err != nil {
		return sdk.Result{}, err
	}
	f, _, err := decode(it)
	if err != nil {
		return sdk.Result{}, err
	}
	var emb commentPage
	if f.Comment != nil {
		emb = *f.Comment
	}
	// Clamp before adding so a huge start_at cannot overflow.
	n := len(emb.Comments)
	total := max(emb.Total, n)
	start = min(start, total)
	var shown []comment
	if emb.StartAt == 0 && (n >= total || start <= n && limit <= n-start) {
		s0 := min(start, n)
		shown = emb.Comments[s0 : s0+min(limit, n-s0)]
	} else {
		p, _ := issuePath(a.Key, "comment")
		var pg commentPage
		q := url.Values{"startAt": {strconv.Itoa(start)}, "maxResults": {strconv.Itoa(limit)}, "orderBy": {"created"}}
		if err := j.get(ctx, p, q, &pg); err != nil {
			return sdk.Result{}, err
		}
		shown, total = pg.Comments[:min(len(pg.Comments), limit)], pg.Total
	}
	var b strings.Builder
	if len(shown) == 0 {
		fmt.Fprintf(&b, "no comments on %s at start_at=%d (total %d)\n", a.Key, start, total)
	} else {
		fmt.Fprintf(&b, "comments %d-%d of %d on %s\n", start+1, start+len(shown), total, a.Key)
	}
	for _, c := range shown {
		fmt.Fprintf(&b, "\n### %s by %s, %s\n%s\n", c.ID, or(c.Author.String(), "unknown"), stamp(c.Created), wikiToMarkdown(strings.TrimSpace(c.Body)))
	}
	if next := start + len(shown); len(shown) > 0 && next < total {
		fmt.Fprintf(&b, "\nnext page: start_at=%d\n", next)
	}
	return sdk.Result{Text: b.String()}, nil
}

func (j *jira) addComment(ctx context.Context, args json.RawMessage) (sdk.Result, error) {
	var a struct {
		Key  string `json:"key"`
		Body string `json:"body"`
	}
	if err := sdk.Decode(args, &a); err != nil {
		return sdk.Result{}, err
	}
	p, err := issuePath(a.Key, "comment")
	if err != nil {
		return sdk.Result{}, err
	}
	if strings.TrimSpace(a.Body) == "" {
		return sdk.Result{}, errors.New("body is empty")
	}
	var resp struct{ ID string }
	if err := j.send(ctx, http.MethodPost, p, map[string]string{"body": a.Body}, &resp); err != nil {
		return sdk.Result{}, err
	}
	return sdk.Result{Text: fmt.Sprintf("comment %s added to %s", resp.ID, a.Key)}, nil
}

func (j *jira) createIssue(ctx context.Context, args json.RawMessage) (sdk.Result, error) {
	var a struct {
		Project     string `json:"project"`
		IssueType   string `json:"issue_type"`
		Summary     string `json:"summary"`
		Description string `json:"description"`
	}
	if err := sdk.Decode(args, &a); err != nil {
		return sdk.Result{}, err
	}
	if !projectKey.MatchString(a.Project) {
		return sdk.Result{}, fmt.Errorf("invalid project key %q: want upper-case letters, digits and _", a.Project)
	}
	if strings.TrimSpace(a.Summary) == "" || utf8.RuneCountInString(a.Summary) > 255 || strings.ContainsAny(a.Summary, "\r\n") {
		return sdk.Result{}, errors.New("summary must be one line of 1-255 characters")
	}
	if strings.TrimSpace(a.IssueType) == "" {
		return sdk.Result{}, errors.New("issue_type is required")
	}
	f := map[string]any{"project": map[string]string{"key": a.Project}, "issuetype": map[string]string{"name": a.IssueType}, "summary": a.Summary}
	if a.Description != "" {
		f["description"] = a.Description
	}
	var resp struct{ Key string }
	if err := j.send(ctx, http.MethodPost, "/rest/api/2/issue", map[string]any{"fields": f}, &resp); err != nil {
		return sdk.Result{}, err
	}
	return sdk.Result{Text: "created " + resp.Key}, nil
}

func (j *jira) transition(ctx context.Context, args json.RawMessage) (sdk.Result, error) {
	var a struct {
		Key        string `json:"key"`
		Transition string `json:"transition"`
	}
	if err := sdk.Decode(args, &a); err != nil {
		return sdk.Result{}, err
	}
	p, err := issuePath(a.Key, "transitions")
	if err != nil {
		return sdk.Result{}, err
	}
	if strings.TrimSpace(a.Transition) == "" {
		return sdk.Result{}, errors.New("transition is required: a transition name or id")
	}
	var resp struct{ Transitions []struct{ ID, Name string } }
	if err := j.get(ctx, p, nil, &resp); err != nil {
		return sdk.Result{}, err
	}
	// An exact id wins over any name, across the whole list; a name must match exactly one.
	want := strings.TrimSpace(a.Transition)
	var byID, byName []int
	var avail []string
	for i, t := range resp.Transitions {
		if t.ID == want {
			byID = append(byID, i)
		}
		if strings.EqualFold(t.Name, want) {
			byName = append(byName, i)
		}
		avail = append(avail, t.ID+" "+t.Name)
	}
	pick := byID
	if len(pick) == 0 {
		pick = byName
	}
	if len(pick) > 1 {
		var names []string
		for _, i := range pick {
			names = append(names, resp.Transitions[i].ID+" "+resp.Transitions[i].Name)
		}
		return sdk.Result{}, fmt.Errorf("transition %q matches more than one transition on %s (%s); give the id", a.Transition, a.Key, strings.Join(names, ", "))
	}
	if len(pick) == 1 {
		t := resp.Transitions[pick[0]]
		body := map[string]any{"transition": map[string]string{"id": t.ID}}
		if err := j.send(ctx, http.MethodPost, p, body, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.Result{Text: fmt.Sprintf("%s: applied transition %s (%s)", a.Key, t.Name, t.ID)}, nil
	}
	return sdk.Result{}, fmt.Errorf("no transition %q on %s; available: %s", a.Transition, a.Key, or(strings.Join(avail, ", "), "none"))
}
