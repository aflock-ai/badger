// Command gitlab is the GitLab self-managed connector (REST API v4). It reads projects, issues,
// merge requests, diffs, files, pipelines and job logs, and with --enable-writes creates issues
// and adds notes. It has no tool that pushes code, merges, or changes project settings: code
// goes through pushgate, not through a connector.
//
// Classification. A GitLab instance holds one classification: every result carries the
// connector's administrator-set marking. The connector reads nothing about classification from
// GitLab content (labels, topics, files).
//
// Known limit: a file whose path contains ";" cannot be read. Its escaped path holds %3B, which
// the egress lock refuses as a path parameter, so the call fails closed.
//
// Settings beyond the shared ones, from the administrator's profile only:
//
//	--auth=private-token|bearer  (BADGER_CONNECTOR_GITLAB_AUTH) PRIVATE-TOKEN header for personal or
//	                             project tokens (default), Authorization: Bearer for OAuth tokens
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/aflock-ai/badger/testifysec/connectors/sdk"
)

const (
	fileCap      = 40 << 10  // bytes of a file shown
	diffFileCap  = 8 << 10   // bytes of one file's diff shown
	diffTotalCap = 40 << 10  // bytes of diff shown per call
	logCap       = 32 << 10  // bytes of job log tail shown
	logFetch     = 256 << 10 // bytes of job log read from the end
	maxTailLines = 2000
)

func main() { sdk.Main(newSpec()) }

// newSpec registers the GitLab-only settings through Spec.Flags. Without Parse (tests that call
// sdk.New directly) the default applies: PRIVATE-TOKEN.
func newSpec() sdk.Spec {
	return sdk.Spec{Name: "gitlab", Version: "0.1.0", Scheme: sdk.PrivateToken,
		Flags: func(fs *flag.FlagSet) func(*sdk.Spec) error {
			auth := fs.String("auth", sdk.Env("BADGER_CONNECTOR_GITLAB_AUTH", "private-token"), "private-token (PAT, project token) or bearer (OAuth)")
			return func(s *sdk.Spec) error {
				switch *auth {
				case "private-token":
					s.Scheme = sdk.PrivateToken
				case "bearer":
					s.Scheme = sdk.Bearer
				default:
					return fmt.Errorf("--auth %q: use private-token or bearer", *auth)
				}
				return nil
			}
		},
		Tools: func(c *sdk.Client) []sdk.Tool { return (&gitlab{c: c}).tools() },
	}
}

type gitlab struct {
	c *sdk.Client
}

// tool adapts a typed handler: strict decoding in, GitLab error bodies mapped out.
func tool[A any](name, desc string, write bool, schema json.RawMessage, run func(context.Context, A) (sdk.Result, error)) sdk.Tool {
	return sdk.Tool{Name: name, Description: desc, Write: write, InputSchema: schema,
		Handler: func(ctx context.Context, raw json.RawMessage) (sdk.Result, error) {
			var a A
			if err := sdk.Decode(raw, &a); err != nil {
				return sdk.Result{}, err
			}
			r, err := run(ctx, a)
			return r, gitlabError(err)
		}}
}

// schema builds an object schema from "name:type:description" entries; required names the
// required ones.
func schema(props []string, required ...string) json.RawMessage {
	p := map[string]any{}
	for _, s := range props {
		f := strings.SplitN(s, ":", 3)
		prop := map[string]any{"type": f[1], "description": f[2]}
		if f[1] == "array" {
			prop["items"] = map[string]string{"type": "string"}
		}
		p[f[0]] = prop
	}
	b, _ := json.Marshal(map[string]any{"type": "object", "properties": p, "required": append([]string{}, required...), "additionalProperties": false})
	return b
}

// bannerNote tells the model what the result banner means.
const bannerNote = "The result's classification banner is the connector's configured marking."

const (
	pProject = "project:string:numeric project id or full path, e.g. group/subgroup/project"
	pPage    = "page:integer:page number, default 1"
	pPerPage = "per_page:integer:items per page, 1-100, default 20"
	pIID     = "iid:integer:the project-scoped number shown as #N or !N"
	pNotes   = "notes:integer:how many discussion threads to include, 0-100, default 20; 0 leaves them out"
)

type pageArgs struct {
	Page    int `json:"page"`
	PerPage int `json:"per_page"`
}

func (p *pageArgs) apply(q url.Values) error {
	if p.Page == 0 {
		p.Page = 1
	}
	if p.PerPage == 0 {
		p.PerPage = 20
	}
	if p.Page < 1 || p.Page > 10000 || p.PerPage < 1 || p.PerPage > 100 {
		return errors.New("page must be 1-10000 and per_page 1-100")
	}
	q.Set("page", strconv.Itoa(p.Page))
	q.Set("per_page", strconv.Itoa(p.PerPage))
	return nil
}

// more reads GitLab's X-Next-Page. GitLab sends paging headers on every list; when a proxy has
// stripped them, a full page is the only hint.
func (p pageArgs) more(h http.Header, n int) string {
	if next, err := strconv.Atoi(h.Get("X-Next-Page")); err == nil && next > p.Page {
		return fmt.Sprintf("\n[more results: request page %d]", next)
	}
	if h.Get("X-Page") == "" && n >= p.PerPage {
		return fmt.Sprintf("\n[page %d is full and the service sent no paging headers; more may exist: request page %d]", p.Page, p.Page+1)
	}
	return "\n[end of results]"
}

func (g *gitlab) tools() []sdk.Tool { return append(g.readTools(), g.writeTools()...) }

func (g *gitlab) readTools() []sdk.Tool {
	return []sdk.Tool{
		tool("gitlab_get_project", "Get a project: path, default branch, visibility, topics, description. "+bannerNote, false,
			schema([]string{pProject}, "project"), g.getProject),
		tool("gitlab_search_issues", "List or search a project's issues, newest first. Paged. "+bannerNote, false,
			schema([]string{pProject, "state:string:opened, closed or all", "labels:string:comma-separated labels, all must match",
				"search:string:text to find in title and description", pPage, pPerPage}, "project"), g.searchIssues),
		tool("gitlab_get_issue", "Get one issue with its description and the first discussion threads (system notes left out). "+bannerNote, false,
			schema([]string{pProject, pIID, pNotes}, "project", "iid"), g.getIssue),
		tool("gitlab_list_merge_requests", "List a project's merge requests, newest first. Paged. "+bannerNote, false,
			schema([]string{pProject, "state:string:opened, closed, merged, locked or all", "labels:string:comma-separated labels",
				"search:string:text to find in title and description", "source_branch:string:source branch", "target_branch:string:target branch",
				pPage, pPerPage}, "project"), g.listMergeRequests),
		tool("gitlab_get_merge_request", "Get one merge request with its description and discussion threads, including the file and line of review comments. "+bannerNote, false,
			schema([]string{pProject, pIID, pNotes}, "project", "iid"), g.getMergeRequest),
		tool("gitlab_get_merge_request_diff", "Get a merge request's changed files and diffs, capped per file and per call. Paged by file. "+bannerNote, false,
			schema([]string{pProject, pIID, pPage, pPerPage}, "project", "iid"), g.getDiff),
		tool("gitlab_get_file", "Get a text file from the repository at a branch, tag or commit. Binary files are refused, and a path containing \";\" cannot be read. "+bannerNote, false,
			schema([]string{pProject, "path:string:file path inside the repository, e.g. cmd/app/main.go",
				"ref:string:branch, tag or commit; default the project's default branch"}, "project", "path"), g.getFile),
		tool("gitlab_list_pipelines", "List a project's pipelines, newest first, or with pipeline_id the jobs of one pipeline (job ids feed gitlab_get_job_log).", false,
			schema([]string{pProject, "ref:string:branch or tag", "status:string:pipeline status, e.g. failed, success, running",
				"pipeline_id:integer:list this pipeline's jobs instead", pPage, pPerPage}, "project"), g.listPipelines),
		tool("gitlab_get_job_log", "Get the last lines of a CI job's log, with terminal escapes removed. "+bannerNote, false,
			schema([]string{pProject, "job_id:integer:job id from gitlab_list_pipelines", "tail_lines:integer:lines from the end, 1-2000, default 200"},
				"project", "job_id"), g.getJobLog),
	}
}

// --- validation: everything is refused before a request is built ---

var (
	segment = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}$`)
	enums   = map[string][]string{
		"issue":   {"opened", "closed", "all"},
		"mr":      {"opened", "closed", "merged", "locked", "all"},
		"pstatus": {"created", "waiting_for_resource", "preparing", "pending", "running", "success", "failed", "canceled", "skipped", "manual", "scheduled"},
	}
)

// projectPath returns the escaped /projects/:id prefix for a numeric id or a full path.
func projectPath(p string) (string, error) {
	if _, err := strconv.ParseUint(p, 10, 31); err == nil {
		return "/projects/" + p, nil
	}
	segs := strings.Split(p, "/")
	if len(p) > 1024 || len(segs) < 2 {
		return "", fmt.Errorf("project %q: give a numeric id or a full path like group/project", p)
	}
	for _, s := range segs {
		if !segment.MatchString(s) || strings.Contains(s, "..") {
			return "", fmt.Errorf("project %q: invalid path segment", p)
		}
	}
	return "/projects/" + url.PathEscape(p), nil
}

// checkRef applies git check-ref-format's rules (plus no leading "-"), so any name git accepts,
// such as release/v1.2.3+build or feature/@alice, passes. A ref travels in the query string.
func checkRef(r string) error {
	if r == "" {
		return nil
	}
	bad := len(r) > 1024 || r == "@" || strings.HasPrefix(r, "-") || strings.HasPrefix(r, "/") || strings.HasSuffix(r, "/") ||
		strings.HasSuffix(r, ".") || strings.Contains(r, "..") || strings.Contains(r, "@{") || !utf8.ValidString(r) ||
		strings.ContainsFunc(r, func(c rune) bool { return c < 0x20 || c == 0x7f || strings.ContainsRune(" ~^:?*[\\", c) })
	for _, c := range strings.Split(r, "/") {
		bad = bad || c == "" || strings.HasPrefix(c, ".") || strings.HasSuffix(c, ".lock")
	}
	if bad {
		return fmt.Errorf("ref %q: not a valid branch, tag or commit name", r)
	}
	return nil
}

func checkFilePath(p string) error {
	if p == "" || len(p) > 1024 || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\\\x00") {
		return fmt.Errorf("path %q: give a relative path inside the repository", p)
	}
	for _, s := range strings.Split(p, "/") {
		if s == "" || s == "." || s == ".." || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return fmt.Errorf("path %q: empty, dot or control-character segments are refused", p)
		}
	}
	return nil
}

func checkIID(n int, what string) error {
	if n < 1 || n > 1<<31-1 {
		return fmt.Errorf("%s must be a positive integer", what)
	}
	return nil
}

func checkEnum(kind, v string) error {
	for _, e := range enums[kind] {
		if v == e {
			return nil
		}
	}
	if v == "" {
		return nil
	}
	return fmt.Errorf("%q: use one of %s", v, strings.Join(enums[kind], ", "))
}

// notesLimit is the discussion count: 20 when omitted, and an explicit 0 means none.
func notesLimit(n *int) (int, error) {
	if n == nil {
		return 20, nil
	}
	if *n < 0 || *n > 100 {
		return 0, errors.New("notes must be 0-100")
	}
	return *n, nil
}

// --- requests ---

func (g *gitlab) get(ctx context.Context, path string, q url.Values, v any) error {
	_, err := g.getPage(ctx, path, q, v)
	return err
}

// getPage is get that also returns the paging headers.
func (g *gitlab) getPage(ctx context.Context, path string, q url.Values, v any) (http.Header, error) {
	b, h, err := g.c.GetWithHeaders(ctx, path, q)
	if err != nil {
		return nil, err
	}
	// null decodes into a zero value without error; a project or item that came back as null is
	// refused like any malformed response.
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) || json.Unmarshal(b, v) != nil {
		return nil, errors.New("unexpected response from the service")
	}
	return h, nil
}

func deref(l *[]string) []string {
	if l == nil {
		return nil
	}
	return *l
}

type project struct {
	ID             int       `json:"id"`
	Path           string    `json:"path_with_namespace"`
	Description    string    `json:"description"`
	DefaultBranch  string    `json:"default_branch"`
	Visibility     string    `json:"visibility"`
	WebURL         string    `json:"web_url"`
	Topics         *[]string `json:"topics"`
	Archived       bool      `json:"archived"`
	LastActivityAt string    `json:"last_activity_at"`
	OpenIssues     int       `json:"open_issues_count"`
}

// project fetches the project for every project-scoped read: it resolves the path, checks the
// project exists, and gives getFile the default branch.
func (g *gitlab) project(ctx context.Context, id string) (string, project, sdk.Result, error) {
	var p project
	path, err := projectPath(id)
	if err != nil {
		return "", p, sdk.Result{}, err
	}
	if err = g.get(ctx, path, nil, &p); err == nil && (p.ID == 0 || p.Path == "") {
		err = errors.New("unexpected response from the service: project metadata is missing")
	}
	return path, p, sdk.Result{}, err
}

func (g *gitlab) getProject(ctx context.Context, a struct {
	Project string `json:"project"`
}) (sdk.Result, error) {
	_, p, r, err := g.project(ctx, a.Project)
	if err != nil {
		return r, err
	}
	r.Text = fmt.Sprintf("# %s (id %d)\nvisibility: %s, default branch: %s, archived: %t, open issues: %d\ntopics: %s\nlast activity: %s\nweb: %s\n\n%s",
		p.Path, p.ID, p.Visibility, p.DefaultBranch, p.Archived, p.OpenIssues, strings.Join(deref(p.Topics), ", "), p.LastActivityAt, p.WebURL, p.Description)
	return r, nil
}

type user struct {
	Username string `json:"username"`
}

// item is an issue or a merge request.
type item struct {
	IID         int       `json:"iid"`
	Title       string    `json:"title"`
	State       string    `json:"state"`
	Description string    `json:"description"`
	Labels      *[]string `json:"labels"`
	Author      user      `json:"author"`
	Assignees   []user    `json:"assignees"`
	Milestone   *struct{ Title string }
	WebURL      string `json:"web_url"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	Source      string `json:"source_branch"`
	Target      string `json:"target_branch"`
	Draft       bool   `json:"draft"`
	MergeStatus string `json:"detailed_merge_status"`
	SHA         string `json:"sha"`
	isMR        bool
}

func (it *item) ref() string {
	if it.isMR {
		return fmt.Sprintf("!%d", it.IID)
	}
	return fmt.Sprintf("#%d", it.IID)
}

func (it *item) head() string { return fmt.Sprintf("%s [%s] %s", it.ref(), it.State, it.Title) }

func (it *item) line() string {
	s := it.head() + fmt.Sprintf("\n  author: %s, updated: %s", it.Author.Username, it.UpdatedAt)
	if it.isMR {
		s += fmt.Sprintf(", %s -> %s", it.Source, it.Target)
	}
	if l := deref(it.Labels); len(l) > 0 {
		s += "\n  labels: " + strings.Join(l, ", ")
	}
	return s
}

type listArgs struct {
	Project string `json:"project"`
	State   string `json:"state"`
	Labels  string `json:"labels"`
	Search  string `json:"search"`
	Source  string `json:"source_branch"`
	Target  string `json:"target_branch"`
	pageArgs
}

func (g *gitlab) list(ctx context.Context, a listArgs, kind string) (sdk.Result, error) {
	q := url.Values{}
	if err := a.apply(q); err != nil {
		return sdk.Result{}, err
	}
	if err := checkEnum(map[bool]string{true: "mr", false: "issue"}[kind == "merge_requests"], a.State); err != nil {
		return sdk.Result{}, err
	}
	for _, b := range []string{a.Source, a.Target} {
		if err := checkRef(b); err != nil {
			return sdk.Result{}, err
		}
	}
	if len(a.Search) > 200 || len(a.Labels) > 1000 {
		return sdk.Result{}, errors.New("search or labels too long")
	}
	for k, v := range map[string]string{"state": a.State, "labels": a.Labels, "search": a.Search, "source_branch": a.Source, "target_branch": a.Target} {
		if v != "" {
			q.Set(k, v)
		}
	}
	path, _, r, err := g.project(ctx, a.Project)
	if err != nil {
		return r, err
	}
	var items []item
	h, err := g.getPage(ctx, path+"/"+kind, q, &items)
	if err != nil {
		return r, err
	}
	var b strings.Builder
	for i := range items {
		items[i].isMR = kind == "merge_requests"
		b.WriteString(items[i].line() + "\n")
	}
	r.Text = b.String() + a.more(h, len(items))
	return r, nil
}

func (g *gitlab) searchIssues(ctx context.Context, a listArgs) (sdk.Result, error) {
	if a.Source != "" || a.Target != "" {
		return sdk.Result{}, errors.New("issues have no branches")
	}
	return g.list(ctx, a, "issues")
}

func (g *gitlab) listMergeRequests(ctx context.Context, a listArgs) (sdk.Result, error) {
	return g.list(ctx, a, "merge_requests")
}

type itemArgs struct {
	Project string `json:"project"`
	IID     int    `json:"iid"`
	Notes   *int   `json:"notes"`
}

type note struct {
	ID        int    `json:"id"`
	Body      string `json:"body"`
	Author    user   `json:"author"`
	CreatedAt string `json:"created_at"`
	System    bool   `json:"system"`
	Resolved  bool   `json:"resolved"`
	// Position is set on diff notes. GitLab returns it from /discussions; a deleted line has
	// only old_path and old_line.
	Position *struct {
		OldPath string `json:"old_path"`
		NewPath string `json:"new_path"`
		OldLine *int   `json:"old_line"`
		NewLine *int   `json:"new_line"`
	} `json:"position"`
}

func (n note) where() string {
	switch p := n.Position; {
	case p == nil:
		return ""
	case p.NewLine != nil:
		return fmt.Sprintf(" on %s:%d", p.NewPath, *p.NewLine)
	case p.OldLine != nil:
		return fmt.Sprintf(" on %s:%d (old)", p.OldPath, *p.OldLine)
	}
	return " on " + n.Position.NewPath
}

func (g *gitlab) getItem(ctx context.Context, a itemArgs, kind string) (sdk.Result, error) {
	if err := checkIID(a.IID, "iid"); err != nil {
		return sdk.Result{}, err
	}
	notes, err := notesLimit(a.Notes)
	if err != nil {
		return sdk.Result{}, err
	}
	path, _, r, err := g.project(ctx, a.Project)
	if err != nil {
		return r, err
	}
	base := fmt.Sprintf("%s/%s/%d", path, kind, a.IID)
	var it item
	if err := g.get(ctx, base, nil, &it); err != nil {
		return r, err
	}
	// {} or another item decodes without error; only the item asked for is shown.
	if it.IID != a.IID {
		return r, errors.New("unexpected response from the service: the item's number is missing or not the one requested")
	}
	it.isMR = kind == "merge_requests"
	var b strings.Builder
	fmt.Fprintf(&b, "# %s: %s\nstate: %s, author: %s, created: %s, updated: %s\n", it.ref(), it.Title, it.State, it.Author.Username, it.CreatedAt, it.UpdatedAt)
	if it.isMR {
		fmt.Fprintf(&b, "branches: %s -> %s, draft: %t, merge status: %s, head: %s\n", it.Source, it.Target, it.Draft, it.MergeStatus, it.SHA)
	}
	var as []string
	for _, u := range it.Assignees {
		as = append(as, u.Username)
	}
	fmt.Fprintf(&b, "assignees: %s\nlabels: %s\n", strings.Join(as, ", "), strings.Join(deref(it.Labels), ", "))
	if it.Milestone != nil {
		fmt.Fprintf(&b, "milestone: %s\n", it.Milestone.Title)
	}
	fmt.Fprintf(&b, "web: %s\n\n%s\n", it.WebURL, it.Description)
	if notes > 0 {
		// Discussions, not /notes: they carry diff positions and group replies into threads.
		var threads []struct {
			Notes []note `json:"notes"`
		}
		q := url.Values{"page": {"1"}, "per_page": {strconv.Itoa(notes)}}
		h, err := g.getPage(ctx, base+"/discussions", q, &threads)
		if err != nil {
			return r, err
		}
		b.WriteString("\n## Discussions\n")
		for _, t := range threads {
			for i, n := range t.Notes {
				if n.System {
					continue
				}
				indent, state := "", ""
				if i > 0 {
					indent = "  reply: "
				} else if n.Resolved {
					state = " [resolved]"
				}
				fmt.Fprintf(&b, "\n%s%s (%s)%s%s:\n%s\n", indent, n.Author.Username, n.CreatedAt, n.where(), state, n.Body)
			}
		}
		if next := h.Get("X-Next-Page"); next != "" || len(threads) == notes && h.Get("X-Page") == "" {
			fmt.Fprintf(&b, "\n[showing the first %d discussions]\n", notes)
		}
	}
	r.Text = b.String()
	return r, nil
}

func (g *gitlab) getIssue(ctx context.Context, a itemArgs) (sdk.Result, error) {
	return g.getItem(ctx, a, "issues")
}

func (g *gitlab) getMergeRequest(ctx context.Context, a itemArgs) (sdk.Result, error) {
	return g.getItem(ctx, a, "merge_requests")
}

// head cuts s to at most n bytes on a rune boundary.
func head(s string, n int) (string, bool) {
	if len(s) <= n {
		return s, false
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n], true
}

func (g *gitlab) getDiff(ctx context.Context, a struct {
	Project string `json:"project"`
	IID     int    `json:"iid"`
	pageArgs
}) (sdk.Result, error) {
	q := url.Values{}
	if err := a.apply(q); err != nil {
		return sdk.Result{}, err
	}
	if err := checkIID(a.IID, "iid"); err != nil {
		return sdk.Result{}, err
	}
	path, _, r, err := g.project(ctx, a.Project)
	if err != nil {
		return r, err
	}
	// /diffs (GitLab 15.7+) pages by file, unlike the deprecated /changes.
	var files []struct {
		Old      string `json:"old_path"`
		New      string `json:"new_path"`
		Diff     string `json:"diff"`
		NewFile  bool   `json:"new_file"`
		Renamed  bool   `json:"renamed_file"`
		Deleted  bool   `json:"deleted_file"`
		TooLarge *bool  `json:"too_large"`
		// Collapsed: GitLab left the diff out (too many changes in the merge request), even
		// though too_large is false.
		Collapsed *bool `json:"collapsed"`
	}
	h, err := g.getPage(ctx, fmt.Sprintf("%s/merge_requests/%d/diffs", path, a.IID), q, &files)
	if err != nil {
		return r, err
	}
	var b strings.Builder
	var skipped []string
	used := 0
	for _, f := range files {
		if used >= diffTotalCap {
			skipped = append(skipped, f.New)
			continue
		}
		name := f.New
		switch {
		case f.Renamed:
			name = f.Old + " -> " + f.New
		case f.NewFile:
			name += " (new file)"
		case f.Deleted:
			name += " (deleted)"
		}
		fmt.Fprintf(&b, "### %s\n", name)
		if f.Diff == "" {
			// No content change only when GitLab says it omitted nothing; older versions leave the
			// flags out, and then an empty diff is unknown, not unchanged.
			switch {
			case f.TooLarge != nil && *f.TooLarge:
				b.WriteString("[diff not returned by GitLab: too large]\n\n")
			case f.Collapsed != nil && *f.Collapsed:
				b.WriteString("[diff not returned by GitLab: collapsed; the file has changes, see the merge request in GitLab]\n\n")
			case f.TooLarge != nil && f.Collapsed != nil:
				b.WriteString("[no content change]\n\n")
			default:
				b.WriteString("[diff not available from GitLab; the file may have changes, see the merge request in GitLab]\n\n")
			}
			continue
		}
		d, cut := head(f.Diff, min(diffFileCap, diffTotalCap-used))
		used += len(d)
		fmt.Fprintf(&b, "```diff\n%s\n```\n", strings.TrimSuffix(d, "\n"))
		if cut {
			fmt.Fprintf(&b, "[diff truncated: showed %d of %d bytes]\n", len(d), len(f.Diff))
		}
		b.WriteString("\n")
	}
	if len(skipped) > 0 {
		fmt.Fprintf(&b, "[total diff budget reached; not shown: %s]\n", strings.Join(skipped, ", "))
	}
	r.Text = b.String() + a.more(h, len(files))
	return r, nil
}

func (g *gitlab) getFile(ctx context.Context, a struct {
	Project string `json:"project"`
	Path    string `json:"path"`
	Ref     string `json:"ref"`
}) (sdk.Result, error) {
	if err := checkFilePath(a.Path); err != nil {
		return sdk.Result{}, err
	}
	if err := checkRef(a.Ref); err != nil {
		return sdk.Result{}, err
	}
	path, p, r, err := g.project(ctx, a.Project)
	if err != nil {
		return r, err
	}
	ref := a.Ref
	if ref == "" {
		ref = p.DefaultBranch
	}
	q := url.Values{}
	if ref != "" {
		q.Set("ref", ref)
	}
	body, err := g.c.Get(ctx, path+"/repository/files/"+url.PathEscape(a.Path)+"/raw", q)
	if err != nil {
		return r, err
	}
	if bytes.IndexByte(body[:min(len(body), 8000)], 0) >= 0 || !utf8.Valid(body) {
		return r, fmt.Errorf("%s is a binary file (%d bytes); the connector returns text files only", a.Path, len(body))
	}
	text := string(body)
	shown, cut := head(text, fileCap)
	r.Text = fmt.Sprintf("# %s @ %s\n\n```\n%s\n```", a.Path, ref, strings.TrimSuffix(shown, "\n"))
	if cut {
		r.Text += fmt.Sprintf("\n[file truncated: showed %d of %d bytes]", len(shown), len(text))
	}
	return r, nil
}

func (g *gitlab) listPipelines(ctx context.Context, a struct {
	Project    string `json:"project"`
	Ref        string `json:"ref"`
	Status     string `json:"status"`
	PipelineID int    `json:"pipeline_id"`
	pageArgs
}) (sdk.Result, error) {
	q := url.Values{}
	if err := a.apply(q); err != nil {
		return sdk.Result{}, err
	}
	if err := errors.Join(checkRef(a.Ref), checkEnum("pstatus", a.Status)); err != nil {
		return sdk.Result{}, err
	}
	if a.PipelineID != 0 {
		if err := checkIID(a.PipelineID, "pipeline_id"); err != nil {
			return sdk.Result{}, err
		}
	}
	path, _, r, err := g.project(ctx, a.Project)
	if err != nil {
		return r, err
	}
	var b strings.Builder
	var h http.Header
	n := 0
	if a.PipelineID != 0 {
		var jobs []struct {
			ID       int     `json:"id"`
			Name     string  `json:"name"`
			Stage    string  `json:"stage"`
			Status   string  `json:"status"`
			Duration float64 `json:"duration"`
			WebURL   string  `json:"web_url"`
		}
		if h, err = g.getPage(ctx, fmt.Sprintf("%s/pipelines/%d/jobs", path, a.PipelineID), q, &jobs); err != nil {
			return r, err
		}
		for _, j := range jobs {
			fmt.Fprintf(&b, "%d [%s] %s/%s %.0fs %s\n", j.ID, j.Status, j.Stage, j.Name, j.Duration, j.WebURL)
		}
		n = len(jobs)
	} else {
		for k, v := range map[string]string{"ref": a.Ref, "status": a.Status} {
			if v != "" {
				q.Set(k, v)
			}
		}
		var ps []struct {
			ID        int    `json:"id"`
			Status    string `json:"status"`
			Ref       string `json:"ref"`
			SHA       string `json:"sha"`
			Source    string `json:"source"`
			CreatedAt string `json:"created_at"`
			WebURL    string `json:"web_url"`
		}
		if h, err = g.getPage(ctx, path+"/pipelines", q, &ps); err != nil {
			return r, err
		}
		for _, p := range ps {
			fmt.Fprintf(&b, "%d [%s] %s %.12s %s %s %s\n", p.ID, p.Status, p.Ref, p.SHA, p.Source, p.CreatedAt, p.WebURL)
		}
		n = len(ps)
	}
	r.Text = b.String() + a.more(h, n)
	return r, nil
}

var (
	// Every terminal escape: CSI, OSC (window titles, hyperlinks, clipboard writes) and DCS/SOS/PM/APC
	// strings up to their terminator or the end of the line, and two-byte escapes.
	termSeq = regexp.MustCompile(`\x1b(\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(\x07|\x1b\\)?|[PX^_][^\x1b]*(\x1b\\)?|[ -/]*[0-~]?)`)
	section = regexp.MustCompile(`section_(start|end):\d+:[A-Za-z0-9_.-]+(\[[^\]]*\])?`)
)

func (g *gitlab) getJobLog(ctx context.Context, a struct {
	Project   string `json:"project"`
	JobID     int    `json:"job_id"`
	TailLines int    `json:"tail_lines"`
}) (sdk.Result, error) {
	if a.TailLines == 0 {
		a.TailLines = 200
	}
	if a.TailLines < 1 || a.TailLines > maxTailLines {
		return sdk.Result{}, fmt.Errorf("tail_lines must be 1-%d", maxTailLines)
	}
	if err := checkIID(a.JobID, "job_id"); err != nil {
		return sdk.Result{}, err
	}
	path, _, r, err := g.project(ctx, a.Project)
	if err != nil {
		return r, err
	}
	// Tail reads only the end of the log, so a log over the response cap still works.
	body, dropped, err := g.c.Tail(ctx, fmt.Sprintf("%s/jobs/%d/trace", path, a.JobID), nil, logFetch)
	if err != nil {
		return r, err
	}
	lines := strings.Split(strings.TrimRight(strings.ToValidUTF8(string(body), "?"), "\n"), "\n")
	if dropped && len(lines) > 1 {
		lines = lines[1:] // the first line was cut by the byte range
	}
	lines = lines[max(0, len(lines)-a.TailLines):]
	for i, l := range lines {
		l = section.ReplaceAllString(termSeq.ReplaceAllString(strings.TrimSuffix(l, "\r"), ""), "")
		if j := strings.LastIndexByte(l, '\r'); j >= 0 { // progress output overwrites itself
			l = l[j+1:]
		}
		l = strings.Map(func(c rune) rune { // any control character left, C0 or C1, except tab
			if c != '\t' && (c < 0x20 || c == 0x7f || c >= 0x80 && c <= 0x9f) {
				return -1
			}
			return c
		}, l)
		lines[i] = l
	}
	text := strings.Join(lines, "\n")
	note := ""
	if len(text) > logCap {
		cut := len(text) - logCap
		for cut < len(text) && !utf8.RuneStart(text[cut]) {
			cut++
		}
		text = text[cut:]
		note = fmt.Sprintf("[log truncated to the last %d bytes]\n", len(text))
	}
	r.Text = fmt.Sprintf("# job %d log, last %d lines\n%s```\n%s\n```", a.JobID, len(lines), note, text)
	return r, nil
}

// gitlabError turns GitLab's error JSON ({"message": "..."}, {"message": {"field": ["..."]}},
// {"error": "..."}) into one line of at most 300 bytes, for the statuses whose body says what the
// model got wrong (400, 409, 422). HTTPError.Body is already credential-scrubbed.
func gitlabError(err error) error {
	var he *sdk.HTTPError
	if !errors.As(err, &he) || he.Detail == "" {
		return err
	}
	var body struct {
		Message json.RawMessage `json:"message"`
		Error   json.RawMessage `json:"error"`
	}
	msg := he.Detail
	if json.Unmarshal([]byte(he.Body), &body) == nil {
		if m := strings.Join(strings.Fields(flatten(body.Message)+flatten(body.Error)), " "); m != "" {
			msg, _ = head(m, 300)
		}
	}
	return fmt.Errorf("GitLab rejected the request (HTTP %d): %s", he.Status, msg)
}

func flatten(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var list []string // {"message": ["..."]} on 409 and some 422s
	if json.Unmarshal(raw, &list) == nil {
		return strings.Join(list, "; ")
	}
	var m map[string][]string
	if json.Unmarshal(raw, &m) == nil {
		var parts []string
		for k, v := range m {
			parts = append(parts, k+" "+strings.Join(v, ", "))
		}
		sort.Strings(parts)
		return strings.Join(parts, "; ")
	}
	return ""
}
