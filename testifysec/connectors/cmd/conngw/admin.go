package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/aflock-ai/badger/testifysec/connectors/marking"
)

// errNotAdmin is an authenticated identity that the profile does not name as an administrator.
var errNotAdmin = errors.New("not an administrator")

// The admin API is the workspace controller's: it registers the workspaces it creates and seeds a
// fork before the fork's pod exists. It is on only when the profile sets a floor (the level every
// new workspace may reach without a copy) and names its administrators.
//
//	POST /admin/register  {"workspace","owner"}                  -> {"label","ceiling"}
//	POST /admin/fork      {"parent","child","owner","ceiling"}   -> {"label","ceiling"}
//	GET  /admin/workspace?workspace=<ns>/<account>               -> {"label","ceiling","owner","registered"}
//
// An empty label is a workspace that has read nothing.
func (g *gateway) serveAdmin(w http.ResponseWriter, r *http.Request) {
	// Admin requests are the controller's and few, so every answer closes the connection: net/http
	// then never waits to drain a body a refused request declared and did not send. A body that is
	// read is read under a deadline.
	w.Header().Set("Connection", "close")
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(cmp.Or(g.adminRead, 5*time.Second)))
	if g.floor == nil {
		http.NotFound(w, r)
		return
	}
	if _, ok := g.authenticate(w, r, func(ctx context.Context, token string) (string, error) {
		return g.review.admin(ctx, token)
	}); !ok {
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/admin/register":
		var in struct{ Workspace, Owner string }
		if !decodeBody(w, r, &in) || !g.validWorkspace(w, in.Workspace) {
			return
		}
		ceiling, err := g.labels.register(in.Workspace, in.Owner, *g.floor)
		if err != nil {
			g.adminError(w, err)
			return
		}
		label, labelled, _, _, _ := g.labels.describe(in.Workspace)
		g.log.Info("registered", "workspace", in.Workspace, "ceiling", marking.Banner(ceiling))
		writeJSON(w, map[string]string{"label": bannerIf(label, labelled), "ceiling": marking.Banner(ceiling)})
	case r.Method == http.MethodPost && r.URL.Path == "/admin/fork":
		var in struct{ Parent, Child, Owner, Ceiling string }
		if !decodeBody(w, r, &in) || !g.validWorkspace(w, in.Parent) || !g.validWorkspace(w, in.Child) {
			return
		}
		ceiling, err := marking.Parse(in.Ceiling)
		if err != nil {
			http.Error(w, "ceiling is not a marking", http.StatusBadRequest)
			return
		}
		// The fork's ceiling includes the floor, as every registered workspace's does.
		if ceiling, err = marking.Join(*g.floor, ceiling); err != nil {
			http.Error(w, "ceiling is not a marking", http.StatusBadRequest)
			return
		}
		label, err := g.labels.fork(in.Parent, in.Child, in.Owner, ceiling)
		if err != nil {
			g.adminError(w, err)
			return
		}
		_, labelled, _, _, _ := g.labels.describe(in.Child)
		g.log.Info("forked", "parent", in.Parent, "child", in.Child, "label", bannerIf(label, labelled), "ceiling", marking.Banner(ceiling))
		writeJSON(w, map[string]string{"label": bannerIf(label, labelled), "ceiling": marking.Banner(ceiling)})
	case r.Method == http.MethodGet && r.URL.Path == "/admin/workspace":
		ws := r.URL.Query().Get("workspace")
		if !g.validWorkspace(w, ws) {
			return
		}
		label, labelled, owner, ceiling, registered := g.labels.describe(ws)
		out := map[string]any{"label": bannerIf(label, labelled), "registered": registered, "owner": owner, "ceiling": ""}
		if registered {
			out["ceiling"] = marking.Banner(ceiling)
		}
		writeJSON(w, out)
	default:
		http.NotFound(w, r)
	}
}

// authenticate reviews the bearer token with check and writes the refusal itself when it fails.
func (g *gateway) authenticate(w http.ResponseWriter, r *http.Request, check func(context.Context, string) (string, error)) (string, bool) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" || len(token) > 16<<10 {
		http.Error(w, "token required", http.StatusUnauthorized)
		return "", false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	id, err := check(ctx, token)
	switch {
	case errors.Is(err, errUnauthenticated):
		http.Error(w, "token not accepted", http.StatusUnauthorized)
	case errors.Is(err, errNotWorkspace), errors.Is(err, errNotAdmin):
		http.Error(w, "forbidden", http.StatusForbidden)
	case err != nil:
		g.log.Error("token review failed", "err", err)
		http.Error(w, "token review unavailable", http.StatusServiceUnavailable)
	default:
		return id, true
	}
	return "", false
}

// validWorkspace accepts "<namespace>/<account>" in a namespace this pod serves.
func (g *gateway) validWorkspace(w http.ResponseWriter, ws string) bool {
	ns, account, ok := strings.Cut(ws, "/")
	if !ok || !slices.Contains(g.namespaces, ns) || !dnsLabel.MatchString(account) {
		http.Error(w, "not a workspace this pod serves", http.StatusBadRequest)
		return false
	}
	return true
}

func (g *gateway) adminError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errOwner), errors.Is(err, errNotNew), errors.Is(err, errUnregistered), errors.Is(err, errWriteDown):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, marking.ErrNoBanner), errors.Is(err, marking.ErrBannerTooLong):
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		// The labels file could not be written: nothing more is registered until a restart.
		g.log.Error("admin request not recorded", "err", err)
		http.Error(w, "not recorded", http.StatusServiceUnavailable)
	}
}

// decodeBody reads a small JSON object with known fields only.
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
	if err == nil {
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		if err = d.Decode(v); err == nil {
			if _, err = d.Token(); err == io.EOF {
				return true
			}
		}
	}
	http.Error(w, "unreadable request", http.StatusBadRequest)
	return false
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func bannerIf(m marking.Marking, ok bool) string {
	if !ok {
		return ""
	}
	return marking.Banner(m)
}
