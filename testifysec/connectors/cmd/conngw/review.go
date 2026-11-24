package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
)

// errUnauthenticated is a token the API server does not accept for the audience; errNotWorkspace
// is an authenticated identity that is not a workspace service account.
var (
	errUnauthenticated = errors.New("token not authenticated")
	errNotWorkspace    = errors.New("not a workspace service account")
)

// reviewer names the workspace a projected service-account token speaks for, by asking the API
// server (TokenReview). The token must be bound to audience, and its service account must live in
// one of namespaces: only that workspace's pod mounts it, so a caller cannot present another
// workspace's. One gateway serves every namespace listed.
type reviewer struct {
	url        string       // the API server's TokenReview endpoint
	client     *http.Client // trusts the API server's CA
	tokenFile  string       // this pod's own service-account token, re-read per review (it rotates)
	audience   string
	namespaces []string
	admins     []string // "<namespace>/<account>" identities allowed the admin API
}

// workspace returns "<namespace>/<service account>" for an authenticated workspace token.
func (r *reviewer) workspace(ctx context.Context, token string) (string, error) {
	ns, account, err := r.identity(ctx, token)
	if err != nil {
		return "", err
	}
	if !slices.Contains(r.namespaces, ns) {
		return "", errNotWorkspace
	}
	return ns + "/" + account, nil
}

// admin returns the identity of an authenticated token only if the profile names it as an
// administrator (the workspace controller).
func (r *reviewer) admin(ctx context.Context, token string) (string, error) {
	ns, account, err := r.identity(ctx, token)
	if errors.Is(err, errNotWorkspace) {
		return "", errNotAdmin
	}
	if err != nil {
		return "", err
	}
	if id := ns + "/" + account; slices.Contains(r.admins, id) {
		return id, nil
	}
	return "", errNotAdmin
}

// identity reviews a projected token for this pod's audience and returns its service account.
func (r *reviewer) identity(ctx context.Context, token string) (string, string, error) {
	own, err := os.ReadFile(r.tokenFile)
	if err != nil {
		return "", "", errors.New("cannot read the connector pod's service-account token")
	}
	body, _ := json.Marshal(map[string]any{
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenReview",
		"spec":       map[string]any{"token": token, "audiences": []string{r.audience}},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(own)))
	req.Header.Set("Content-Type", "application/json")
	// Never follow a redirect: it would resend the workspace's token to wherever it points.
	client := *r.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("token review unavailable: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated && res.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("token review answered %d", res.StatusCode)
	}
	var tr struct {
		Status struct {
			Authenticated bool     `json:"authenticated"`
			Audiences     []string `json:"audiences"`
			User          struct {
				Username string `json:"username"`
			} `json:"user"`
		} `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&tr); err != nil {
		return "", "", errors.New("token review answer unreadable")
	}
	// An API server that ignores spec.audiences returns none; the token is then not known to be
	// bound to this audience, so it is refused like an unauthenticated one.
	if !tr.Status.Authenticated || !slices.Contains(tr.Status.Audiences, r.audience) {
		return "", "", errUnauthenticated
	}
	rest, ok := strings.CutPrefix(tr.Status.User.Username, "system:serviceaccount:")
	ns, account, _ := strings.Cut(rest, ":")
	if !ok || !dnsLabel.MatchString(ns) || !dnsLabel.MatchString(account) {
		return "", "", errNotWorkspace
	}
	return ns, account, nil
}
