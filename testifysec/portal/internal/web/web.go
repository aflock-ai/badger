// Package web serves the portal's HTML and its open HTTP API (api/openapi.yaml).
package web

import (
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/aflock-ai/badger/testifysec/portal/internal/auth"
	"github.com/aflock-ai/badger/testifysec/portal/internal/issue"
	"github.com/aflock-ai/badger/testifysec/portal/internal/profile"
	"github.com/aflock-ai/badger/testifysec/portal/internal/store"
	"github.com/aflock-ai/badger/testifysec/portal/internal/users"
)

type (
	Role          = auth.Role
	Principal     = auth.Principal
	Authenticator = auth.Authenticator
)

const (
	Admin    = auth.Admin
	Approver = auth.Approver
	Auditor  = auth.Auditor
)

type Server struct {
	Auth  Authenticator
	Users *users.Service
	// Origins are extra origins trusted for state-changing requests (for example a reverse
	// proxy's public origin); same-origin requests need no entry.
	Origins  []string
	Issuer   *issue.Issuer
	Profiles store.ProfileStore
}

//go:embed profiles.html
var pages embed.FS

// The shared Badger theme, a byte-identical copy of testifysec/branding/theme/theme.css. Inlined
// into each page, so the pages load nothing and still run no script.
//
//go:embed theme.css
var themeCSS string
var theme = template.CSS(themeCSS)
var listPage = template.Must(template.ParseFS(pages, "profiles.html"))

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	mux.Handle("GET /{$}", s.guard(s.page, Admin, Approver, Auditor))
	mux.Handle("GET /api/v1/profiles", s.guard(s.list, Admin, Approver, Auditor))
	mux.Handle("POST /api/v1/profiles/{profileId}/versions", s.guard(s.create, Admin))
	mux.Handle("GET /api/v1/profiles/{profileId}/trust", s.guard(s.trust, Admin, Auditor))
	mux.Handle("GET /api/v1/profiles/{profileId}/versions", s.guard(s.history, Admin, Approver, Auditor))
	mux.Handle("GET /api/v1/profiles/{profileId}/versions/{seq}", s.guard(s.version(false), Admin, Approver, Auditor))
	mux.Handle("GET /api/v1/profiles/{profileId}/versions/{seq}/envelope", s.guard(s.version(true), Admin, Approver, Auditor))
	mux.Handle("GET /api/v1/deployments/{deploymentId}/assignment", s.guard(s.assignment, Admin, Approver, Auditor))
	mux.Handle("PUT /api/v1/deployments/{deploymentId}/assignment", s.guard(s.assign, Admin))
	mux.HandleFunc("GET /.well-known/badger-portal", discovery)
	mux.Handle("GET /api/v1/users", s.guard(s.listUsers, Admin, Approver, Auditor))
	mux.Handle("POST /api/v1/users", s.guard(s.provision, Admin))
	mux.Handle("POST /api/v1/users/{userId}/role-requests", s.guard(s.requestRole, Admin))
	mux.Handle("POST /api/v1/users/{userId}/drop-role", s.guard(s.dropRole, Admin))
	mux.Handle("PUT /api/v1/users/{userId}/deployments/{deploymentId}", s.guard(s.membership(true), Admin))
	mux.Handle("DELETE /api/v1/users/{userId}/deployments/{deploymentId}", s.guard(s.membership(false), Admin))
	mux.Handle("POST /api/v1/users/{userId}/offboard", s.guard(s.offboard, Admin))
	mux.Handle("GET /api/v1/role-requests", s.guard(s.pending, Admin, Approver, Auditor))
	mux.Handle("GET /users", s.guard(s.usersPage, Admin, Approver, Auditor))
	mux.Handle("POST /api/v1/role-requests/{requestId}/approve", s.guard(s.decide(true), Approver))
	mux.Handle("POST /api/v1/role-requests/{requestId}/reject", s.guard(s.decide(false), Approver))
	return mux
}

func (s *Server) guard(next func(http.ResponseWriter, *http.Request, Principal), roles ...Role) http.Handler {
	csrf := http.NewCrossOriginProtection()
	for _, o := range s.Origins {
		if err := csrf.AddTrustedOrigin(o); err != nil {
			panic(err)
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A browser sends the admin's IdP session on any request to this origin, so a page on
		// another origin could make the browser act for the admin. Refuse cross-origin
		// state changes (Sec-Fetch-Site / Origin) and anything but a JSON body, which a
		// cross-origin form or a CORS-simple request cannot send.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if err := csrf.Check(r); err != nil {
				problem(w, http.StatusForbidden, "cross-origin", "cross-origin requests may not change state")
				return
			}
			if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
				problem(w, http.StatusUnsupportedMediaType, "invalid-request", "Content-Type must be application/json")
				return
			}
		}
		p, err := s.Auth.Authenticate(r)
		if err == nil && !p.Role.Valid() {
			err = errors.New("no portal role")
		}
		if err != nil {
			problem(w, http.StatusUnauthorized, "unauthenticated", err.Error())
			return
		}
		for _, role := range roles {
			if p.Role == role {
				next(w, r, p)
				return
			}
		}
		problem(w, http.StatusForbidden, "forbidden", "role "+string(p.Role)+" may not do this")
	})
}

// summary is a version without its envelope, for lists and create responses.
func summary(v store.Version) store.Version { v.Envelope = nil; return v }

func (s *Server) list(w http.ResponseWriter, _ *http.Request, _ Principal) {
	vs, err := s.Profiles.List()
	if err != nil {
		problem(w, http.StatusInternalServerError, "store", "profile store unavailable")
		return
	}
	items := make([]store.Version, 0, len(vs))
	for _, v := range vs {
		items = append(items, summary(v))
	}
	reply(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) create(w http.ResponseWriter, r *http.Request, p Principal) {
	var req issue.Request
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := decodeOne(dec, &req); err != nil || req.ProfileID != "" {
		problem(w, http.StatusBadRequest, "invalid-request", "body must be {deploymentId, notBefore, expiresAt}, and for schemaVersion 3 also {gateway, connectors}")
		return
	}
	req.ProfileID = r.PathValue("profileId")
	v, err := s.Issuer.Issue(p.Name, string(p.Role), req)
	var invalid issue.Invalid
	switch {
	case errors.As(err, &invalid):
		problem(w, http.StatusBadRequest, "invalid-profile", invalid.Reason)
	case errors.Is(err, store.ErrExists):
		problem(w, http.StatusConflict, "sequence-conflict", "sequence already issued; retry")
	case err != nil:
		problem(w, http.StatusInternalServerError, "issue-failed", "signing or storage failed")
	default:
		reply(w, http.StatusCreated, summary(v))
	}
}

// trust returns the build-provisioned admission trust input for one profile, so the build
// administrator compiles exactly this portal's keys in.
func (s *Server) trust(w http.ResponseWriter, r *http.Request, _ Principal) {
	id := r.PathValue("profileId")
	if !profile.ValidIdentifier(id) {
		problem(w, http.StatusBadRequest, "invalid-request", "profileId must be an identifier")
		return
	}
	v, ok, err := s.Profiles.Latest(id)
	if err != nil || !ok {
		problem(w, http.StatusNotFound, "not-found", "no signed version of this profile")
		return
	}
	reply(w, http.StatusOK, s.Issuer.Trust(v))
}

func (s *Server) history(w http.ResponseWriter, r *http.Request, _ Principal) {
	vs, err := s.Profiles.Versions(r.PathValue("profileId"))
	if errors.Is(err, store.ErrProfileID) {
		problem(w, http.StatusBadRequest, "invalid-request", "profileId must be an identifier")
		return
	} else if err != nil {
		problem(w, http.StatusInternalServerError, "store", "profile store unavailable")
		return
	}
	items := make([]store.Version, 0, len(vs))
	for _, v := range vs {
		items = append(items, summary(v))
	}
	reply(w, http.StatusOK, map[string]any{"items": items})
}

var canonicalSequence = regexp.MustCompile(`^[1-9][0-9]{0,15}$`)

// version serves one version's summary, or its envelope byte-for-byte as signed.
func (s *Server) version(envelope bool) func(http.ResponseWriter, *http.Request, Principal) {
	return func(w http.ResponseWriter, r *http.Request, _ Principal) {
		raw := r.PathValue("seq")
		seq, err := strconv.ParseUint(raw, 10, 64)
		if !canonicalSequence.MatchString(raw) || err != nil || seq > profile.MaxSequence {
			problem(w, http.StatusNotFound, "not-found", "no such version")
			return
		}
		v, ok, err := s.Profiles.Get(r.PathValue("profileId"), seq)
		switch {
		case errors.Is(err, store.ErrProfileID):
			problem(w, http.StatusBadRequest, "invalid-request", "profileId must be an identifier")
		case err != nil:
			problem(w, http.StatusInternalServerError, "store", "profile store unavailable")
		case !ok:
			problem(w, http.StatusNotFound, "not-found", "no such version")
		case envelope:
			w.Header().Set("Content-Type", "application/vnd.dsse.envelope.v1+json")
			w.Header().Set("ETag", `"sha256:`+v.EnvelopeSHA256+`"`)
			w.Write(v.Envelope)
		default:
			reply(w, http.StatusOK, summary(v))
		}
	}
}

func (s *Server) assignment(w http.ResponseWriter, r *http.Request, _ Principal) {
	a, ok, err := s.Issuer.Assignments.Assignment(r.PathValue("deploymentId"))
	switch {
	case errors.Is(err, store.ErrProfileID):
		problem(w, http.StatusBadRequest, "invalid-request", "deploymentId must be an identifier")
	case err != nil:
		problem(w, http.StatusInternalServerError, "store", "assignment store unavailable")
	case !ok:
		problem(w, http.StatusNotFound, "not-found", "deployment has no assignment")
	default:
		reply(w, http.StatusOK, a)
	}
}

func (s *Server) assign(w http.ResponseWriter, r *http.Request, p Principal) {
	var req struct {
		ProfileID string `json:"profileId"`
		Sequence  uint64 `json:"sequence"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := decodeOne(dec, &req); err != nil {
		problem(w, http.StatusBadRequest, "invalid-request", "body must be {profileId, sequence}")
		return
	}
	a, err := s.Issuer.Assign(p.Name, string(p.Role), r.PathValue("deploymentId"), req.ProfileID, req.Sequence)
	var invalid issue.Invalid
	switch {
	case errors.As(err, &invalid):
		problem(w, http.StatusBadRequest, "invalid-request", invalid.Reason)
	case errors.Is(err, issue.Missing):
		problem(w, http.StatusNotFound, "not-found", err.Error())
	case errors.Is(err, issue.Rollback):
		problem(w, http.StatusConflict, "rollback", err.Error())
	case err != nil:
		problem(w, http.StatusInternalServerError, "assign-failed", "audit or storage failed")
	default:
		reply(w, http.StatusOK, a)
	}
}

// decodeOne decodes exactly one JSON value; trailing content is an error, so a request
// cannot carry a second document past a proxy or a log that reads only the first.
func decodeOne(dec *json.Decoder, v any) error {
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing content after the JSON body")
	}
	return nil
}

func (s *Server) listUsers(w http.ResponseWriter, _ *http.Request, _ Principal) {
	all, err := s.Users.Store.Users()
	if err != nil {
		problem(w, http.StatusInternalServerError, "store", "user store unavailable")
		return
	}
	reply(w, http.StatusOK, map[string]any{"items": append([]users.User{}, all...)})
}

func (s *Server) provision(w http.ResponseWriter, r *http.Request, p Principal) {
	var id users.Identity
	if !decodeBody(w, r, &id) {
		return
	}
	u, act, err := s.Users.Provision(p, id)
	userReply(w, http.StatusCreated, map[string]any{"user": u, "activation": act}, err)
}

func (s *Server) dropRole(w http.ResponseWriter, r *http.Request, p Principal) {
	if !decodeBody(w, r, &struct{}{}) {
		return
	}
	u, err := s.Users.DropRole(p, r.PathValue("userId"))
	userReply(w, http.StatusOK, u, err)
}

func (s *Server) requestRole(w http.ResponseWriter, r *http.Request, p Principal) {
	var body struct {
		Role Role `json:"role"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	req, err := s.Users.RequestRole(p, r.PathValue("userId"), body.Role)
	userReply(w, http.StatusCreated, req, err)
}

func (s *Server) decide(approve bool) func(http.ResponseWriter, *http.Request, Principal) {
	return func(w http.ResponseWriter, r *http.Request, p Principal) {
		req, err := s.Users.Decide(p, r.PathValue("requestId"), approve)
		userReply(w, http.StatusOK, req, err)
	}
}

func (s *Server) membership(add bool) func(http.ResponseWriter, *http.Request, Principal) {
	return func(w http.ResponseWriter, r *http.Request, p Principal) {
		if !decodeBody(w, r, &struct{}{}) {
			return
		}
		do := s.Users.Unassign
		if add {
			do = s.Users.Assign
		}
		u, err := do(p, r.PathValue("userId"), r.PathValue("deploymentId"))
		userReply(w, http.StatusOK, u, err)
	}
}

func (s *Server) offboard(w http.ResponseWriter, r *http.Request, p Principal) {
	if !decodeBody(w, r, &struct{}{}) {
		return
	}
	u, err := s.Users.Offboard(p, r.PathValue("userId"))
	userReply(w, http.StatusOK, u, err)
}

func (s *Server) pending(w http.ResponseWriter, _ *http.Request, _ Principal) {
	open, err := s.Users.Pending()
	userReply(w, http.StatusOK, map[string]any{"items": append([]users.Request{}, open...)}, err)
}

func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := decodeOne(dec, v); err != nil {
		problem(w, http.StatusBadRequest, "invalid-request", "malformed or unknown fields in body")
		return false
	}
	return true
}

func userReply(w http.ResponseWriter, status int, v any, err error) {
	switch {
	case err == nil:
		reply(w, status, v)
	case errors.Is(err, users.ErrForbidden):
		problem(w, http.StatusForbidden, "forbidden", "not allowed for this principal; an approver may not decide a request it made or about itself")
	case errors.Is(err, users.ErrInvalid):
		problem(w, http.StatusBadRequest, "invalid-request", err.Error())
	case errors.Is(err, users.ErrMissing):
		problem(w, http.StatusNotFound, "not-found", err.Error())
	case errors.Is(err, users.ErrExists), errors.Is(err, users.ErrDecided), errors.Is(err, users.ErrBootstrapLive), errors.Is(err, users.ErrStale):
		problem(w, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, users.ErrState):
		problem(w, http.StatusConflict, "invalid-state", err.Error())
	default:
		problem(w, http.StatusInternalServerError, "users-failed", "audit or storage failed")
	}
}

// discovery is public: it names no tenant, deployment or key, only where the API is.
func discovery(w http.ResponseWriter, _ *http.Request) {
	reply(w, http.StatusOK, map[string]any{"specVersion": "0.2.0", "apiBase": "/api/v1",
		"profilePayloadType": profile.PayloadType, "authentication": []string{"idp"}})
}

func (s *Server) page(w http.ResponseWriter, _ *http.Request, p Principal) {
	vs, err := s.Profiles.List()
	if err != nil {
		http.Error(w, "profile store unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self' 'unsafe-inline'")
	listPage.Execute(w, map[string]any{"Theme": theme, "Principal": p, "Profiles": vs, "PayloadType": profile.PayloadType})
}

//go:embed users.html
var usersHTML string
var usersPage = template.Must(template.New("users").Parse(usersHTML))

// usersPage is read-only: actions go through the JSON API, because the cross-origin guard
// refuses form posts and the pages run no script.
func (s *Server) usersPage(w http.ResponseWriter, _ *http.Request, p Principal) {
	all, err := s.Users.Store.Users()
	open, perr := s.Users.Pending()
	if err != nil || perr != nil {
		http.Error(w, "user store unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self' 'unsafe-inline'")
	subjects := make(map[string]string, len(all))
	for _, u := range all {
		subjects[u.ID] = u.Subject
	}
	usersPage.Execute(w, map[string]any{"Theme": theme, "Principal": p, "Users": all, "Pending": open, "Subjects": subjects})
}

func reply(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

// problem writes an RFC 9457 problem document. "error" repeats the stable code as an
// extension member so clients that read a bare {"error": code} body work unchanged.
func problem(w http.ResponseWriter, status int, code, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"type": "urn:badger:portal:" + code,
		"title": strings.ReplaceAll(code, "-", " "), "status": status, "detail": detail, "error": code})
}
