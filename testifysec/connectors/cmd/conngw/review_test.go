package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestTokenReviewNamesTheWorkspace(t *testing.T) {
	own := t.TempDir() + "/token"
	if err := os.WriteFile(own, []byte("pod-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var answer string
	var status int
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Kind string
			Spec struct {
				Token     string
				Audiences []string
			}
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if r.Header.Get("Authorization") != "Bearer pod-token" || req.Kind != "TokenReview" || req.Spec.Token != "ws-token" ||
			len(req.Spec.Audiences) != 1 || req.Spec.Audiences[0] != "badger-connectors" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(answer))
	}))
	defer api.Close()
	r := &reviewer{url: api.URL, client: api.Client(), tokenFile: own, audience: "badger-connectors", namespaces: []string{"badger-ws"}}

	ok := func(user string, audiences string) string {
		return `{"status":{"authenticated":true,"audiences":` + audiences + `,"user":{"username":"` + user + `"}}}`
	}
	for _, tc := range []struct {
		name, answer string
		status       int
		ws           string
		err          error
	}{
		{"workspace", ok("system:serviceaccount:badger-ws:alice", `["badger-connectors"]`), 201, "badger-ws/alice", nil},
		{"not authenticated", `{"status":{"authenticated":false}}`, 201, "", errUnauthenticated},
		{"audience not confirmed", ok("system:serviceaccount:badger-ws:alice", `[]`), 201, "", errUnauthenticated},
		{"other audience", ok("system:serviceaccount:badger-ws:alice", `["kubernetes"]`), 201, "", errUnauthenticated},
		{"other namespace", ok("system:serviceaccount:kube-system:default", `["badger-connectors"]`), 201, "", errNotWorkspace},
		{"a person", ok("alice@example.invalid", `["badger-connectors"]`), 201, "", errNotWorkspace},
		{"empty name", ok("system:serviceaccount:badger-ws:", `["badger-connectors"]`), 201, "", errNotWorkspace},
		{"api error", `{}`, 500, "", nil},
		{"unreadable", `not json`, 201, "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			answer, status = tc.answer, tc.status
			ws, err := r.workspace(context.Background(), "ws-token")
			switch {
			case tc.ws != "":
				if err != nil || ws != tc.ws {
					t.Fatalf("got %q %v, want %q", ws, err, tc.ws)
				}
			case tc.err != nil:
				if !errors.Is(err, tc.err) {
					t.Fatalf("got %q %v, want %v", ws, err, tc.err)
				}
			default:
				if err == nil || errors.Is(err, errUnauthenticated) || errors.Is(err, errNotWorkspace) {
					t.Fatalf("got %q %v, want an unavailable error", ws, err)
				}
			}
		})
	}

	// A redirect is never followed, so the workspace's token goes nowhere else.
	var reached bool
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	defer elsewhere.Close()
	for _, code := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, elsewhere.URL, code)
		}))
		rr := &reviewer{url: redirect.URL, client: elsewhere.Client(), tokenFile: own, audience: "badger-connectors", namespaces: []string{"badger-ws"}}
		if _, err := rr.workspace(context.Background(), "ws-token"); err == nil || reached {
			t.Fatalf("%d: err %v, redirect followed %v", code, err, reached)
		}
		redirect.Close()
	}

	// Without its own token the pod cannot ask, and says so rather than letting anyone in.
	r.tokenFile = t.TempDir() + "/absent"
	if _, err := r.workspace(context.Background(), "ws-token"); err == nil {
		t.Fatal("review without the pod's token succeeded")
	}
}

// The admin API's own check, through a real TokenReview answer: only an identity the profile lists
// in admins passes. A workspace, a listed name in another namespace, an unlisted service account, a
// person and an unauthenticated token are all refused.
func TestOnlyListedAdminsPassTheAdminReview(t *testing.T) {
	own := t.TempDir() + "/token"
	if err := os.WriteFile(own, []byte("pod-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var answer string
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(answer))
	}))
	defer api.Close()
	r := &reviewer{url: api.URL, client: api.Client(), tokenFile: own, audience: "badger-connectors",
		namespaces: []string{"badger-ws"}, admins: []string{"ctl/controller"}}
	user := func(name string) string {
		return `{"status":{"authenticated":true,"audiences":["badger-connectors"],"user":{"username":"` + name + `"}}}`
	}
	answer = user("system:serviceaccount:ctl:controller")
	if id, err := r.admin(context.Background(), "t"); err != nil || id != "ctl/controller" {
		t.Fatalf("listed admin: %q %v", id, err)
	}
	for name, a := range map[string]string{
		"a workspace":           user("system:serviceaccount:badger-ws:alice"),
		"listed name, other ns": user("system:serviceaccount:badger-ws:controller"),
		"unlisted account":      user("system:serviceaccount:ctl:other"),
		"a person":              user("controller@example.invalid"),
		"other audience":        `{"status":{"authenticated":true,"audiences":["kubernetes"],"user":{"username":"system:serviceaccount:ctl:controller"}}}`,
		"not authenticated":     `{"status":{"authenticated":false}}`,
	} {
		answer = a
		if id, err := r.admin(context.Background(), "t"); err == nil || id != "" {
			t.Errorf("%s: passed as %q", name, id)
		}
	}
	// And a listed admin's token is not a workspace's.
	answer = user("system:serviceaccount:ctl:controller")
	if _, err := r.workspace(context.Background(), "t"); !errors.Is(err, errNotWorkspace) {
		t.Fatalf("admin as workspace: %v", err)
	}
}
