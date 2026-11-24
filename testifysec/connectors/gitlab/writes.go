package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/aflock-ai/badger/testifysec/connectors/sdk"
)

// Write tools, registered only with --enable-writes. Deliberately absent: anything that pushes,
// merges, or changes project settings. Code reaches a repository through pushgate.

const maxWriteBytes = 64 << 10

// normLabel is a label title as GitLab will store it, or stricter: GitLab strips whitespace from a
// title before saving it, and this also trims invisible format characters (zero-width space,
// BOM), so the label sent is the label saved.
func normLabel(l string) string {
	return strings.TrimFunc(l, func(r rune) bool { return r == 0 || unicode.IsSpace(r) || unicode.Is(unicode.Cf, r) })
}

// quickAction matches a line GitLab may run as a quick action (/label, /close, /assign, ...).
// A quick action in a description or comment acts with the connector's credential and would
// get around every check here. GitLab skips quick
// actions in code blocks; this refuses those lines too rather than parse markdown.
var quickAction = regexp.MustCompile(`(?m)^[ \t]*/[A-Za-z]`)

func checkQuickActions(field, s string) error {
	if quickAction.MatchString(strings.ReplaceAll(s, "\r", "\n")) {
		return fmt.Errorf("%s has a line starting with \"/\", which GitLab runs as a quick action (/label, /close, /assign, ...); "+
			"the connector refuses quick actions: rephrase the line or wrap the text in backticks", field)
	}
	return nil
}

func (g *gitlab) writeTools() []sdk.Tool {
	return []sdk.Tool{
		tool("gitlab_create_issue", "Create an issue in a project. Changes the service.", true,
			schema([]string{pProject, "title:string:issue title", "description:string:markdown body", "labels:array:labels to set"}, "project", "title"), g.createIssue),
		tool("gitlab_add_note", "Add a comment to an issue or merge request. Changes the service.", true,
			schema([]string{pProject, "target:string:issue or merge_request", pIID, "body:string:markdown comment"}, "project", "target", "iid", "body"), g.addNote),
	}
}

func (g *gitlab) post(ctx context.Context, path string, body map[string]string, v any) error {
	for k, s := range body {
		if len(s) > maxWriteBytes {
			return fmt.Errorf("%s is over %d bytes", k, maxWriteBytes)
		}
	}
	b, _ := json.Marshal(body)
	resp, err := g.c.Do(ctx, http.MethodPost, path, nil, "application/json", b)
	if err != nil {
		return err
	}
	// null decodes into a zero value without error; the write is unconfirmed, not done.
	if bytes.Equal(bytes.TrimSpace(resp), []byte("null")) || json.Unmarshal(resp, v) != nil {
		return errors.New("unexpected response from the service: the write was not confirmed")
	}
	return nil
}

func (g *gitlab) createIssue(ctx context.Context, a struct {
	Project     string   `json:"project"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Labels      []string `json:"labels"`
}) (sdk.Result, error) {
	path, err := projectPath(a.Project)
	if err != nil {
		return sdk.Result{}, err
	}
	if err := checkQuickActions("description", a.Description); err != nil {
		return sdk.Result{}, err
	}
	// GitLab's 255 limit counts characters, not bytes.
	if strings.TrimSpace(a.Title) == "" || utf8.RuneCountInString(a.Title) > 255 {
		return sdk.Result{}, errors.New("title must be 1-255 characters")
	}
	labels := make([]string, len(a.Labels))
	for i, l := range a.Labels {
		n := normLabel(l)
		if n == "" || strings.ContainsAny(n, ",\x00") || utf8.RuneCountInString(n) > 255 {
			return sdk.Result{}, fmt.Errorf("label %q refused: empty, too long, or contains a comma", l)
		}
		labels[i] = n
	}
	body := map[string]string{"title": a.Title}
	if a.Description != "" {
		body["description"] = a.Description
	}
	if len(labels) > 0 {
		body["labels"] = strings.Join(labels, ",")
	}
	var it item
	if err := g.post(ctx, path+"/issues", body, &it); err != nil {
		return sdk.Result{}, err
	}
	if it.IID <= 0 {
		return sdk.Result{}, errors.New("unexpected response from the service: no issue number came back, so the write was not confirmed")
	}
	return sdk.Result{Text: fmt.Sprintf("created issue #%d: %s", it.IID, it.WebURL)}, nil
}

func (g *gitlab) addNote(ctx context.Context, a struct {
	Project string `json:"project"`
	Target  string `json:"target"`
	IID     int    `json:"iid"`
	Body    string `json:"body"`
}) (sdk.Result, error) {
	path, err := projectPath(a.Project)
	if err != nil {
		return sdk.Result{}, err
	}
	if a.Target != "issue" && a.Target != "merge_request" {
		return sdk.Result{}, errors.New("target must be issue or merge_request")
	}
	if err := checkIID(a.IID, "iid"); err != nil {
		return sdk.Result{}, err
	}
	if err := checkQuickActions("body", a.Body); err != nil {
		return sdk.Result{}, err
	}
	if strings.TrimSpace(a.Body) == "" {
		return sdk.Result{}, errors.New("body is empty")
	}
	kind, label, sigil := "issues", "issue", "#"
	if a.Target == "merge_request" {
		kind, label, sigil = "merge_requests", "merge request", "!"
	}
	var n note
	if err := g.post(ctx, fmt.Sprintf("%s/%s/%d/notes", path, kind, a.IID), map[string]string{"body": a.Body}, &n); err != nil {
		return sdk.Result{}, err
	}
	if n.ID <= 0 {
		return sdk.Result{}, errors.New("unexpected response from the service: no note id came back, so the write was not confirmed")
	}
	return sdk.Result{Text: fmt.Sprintf("note %d added to %s %s%d", n.ID, label, sigil, a.IID)}, nil
}
