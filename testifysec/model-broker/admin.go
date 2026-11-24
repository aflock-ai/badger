package broker

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The admin API (API.md), on the admin listener only. formal/BadgerBroker/PolicyAdmin.lean
// `handle`: a request carrying a pipeline payload is refused whatever else it carries
// (`payload_makes_pipeline`, `pipeline_cannot_administer`); otherwise the caller must hold one of
// the operator's admin roles, as the edge reports it.

type apiError struct {
	Code    string   `json:"code"`
	Message string   `json:"message"`
	Details []string `json:"details,omitempty"`
	Current *int64   `json:"current_version,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, e apiError) {
	writeJSON(w, status, map[string]apiError{"error": e})
}

type adminCaller struct{ id, name string }

// caller is Lean `callerOf` then `adminId`. A refusal is audited and answered.
func (b *Broker) caller(w http.ResponseWriter, r *http.Request) (*adminCaller, bool) {
	c, status, code, msg := b.identify(r)
	if c == nil {
		b.store.Audit(AuditRecord{Kind: "refused", Reason: code, Version: b.currentVersion()})
		writeErr(w, status, apiError{Code: code, Message: msg})
		return nil, false
	}
	return c, true
}

// identify is the one admin check: no model-traffic credential, an allowed origin, exactly one
// verified id from the edge's IdP sign-in, and a group the operator lists in admin_roles.
func (b *Broker) identify(r *http.Request) (c *adminCaller, status int, code, msg string) {
	h := b.cfg.Headers
	if code := b.modelCredential(r); code != "" {
		return nil, http.StatusForbidden, code, "model-traffic credentials cannot use the admin listener"
	}
	if !b.originOK(r) {
		return nil, http.StatusForbidden, "bad_origin", "origin not allowed"
	}
	ids, roles, names := r.Header.Values(h.AdminID), r.Header.Values(h.AdminRole), r.Header.Values(h.AdminName)
	if len(ids) != 1 || len(roles) != 1 || len(names) > 1 || ids[0] == "" || auditSafe(ids[0]) != ids[0] {
		return nil, http.StatusUnauthorized, "no_identity", "no verified identity"
	}
	if !slices.Contains(b.cfg.AdminRoles, roles[0]) {
		return nil, http.StatusForbidden, "not_admin", "an admin role is required"
	}
	c = &adminCaller{id: ids[0]}
	if len(names) == 1 && auditSafe(names[0]) == names[0] {
		c.name = names[0]
	}
	return c, 0, "", ""
}

// modelCredential names the model-traffic credential r carries, or "". A pipeline payload, the
// edge's person header and any Authorization header (workspace, device and provisioner tokens
// are all bearer) belong to model traffic and never to an admin request.
func (b *Broker) modelCredential(r *http.Request) string {
	h := b.cfg.Headers
	switch {
	case b.hasPipelinePayload(r):
		return "pipeline_forbidden"
	case len(r.Header.Values(h.Principal)) != 0, len(r.Header.Values("Authorization")) != 0:
		return "model_credential_forbidden"
	}
	return ""
}

// adminSession reports whether r carries any admin identity header. Model listeners refuse it:
// an admin session is never served as a model user.
func (b *Broker) adminSession(r *http.Request) bool {
	h := b.cfg.Headers
	return len(r.Header.Values(h.AdminID)) != 0 || len(r.Header.Values(h.AdminRole)) != 0 || len(r.Header.Values(h.AdminName)) != 0
}

// AdminIdentity is the admin check for handlers mounted beside the admin API: the caller's
// verified id and display name, or ok false. It neither audits nor answers.
func (b *Broker) AdminIdentity(r *http.Request) (id, name string, ok bool) {
	c, _, _, _ := b.identify(r)
	if c == nil {
		return "", "", false
	}
	return c.id, c.name, true
}

// Mount is a handler served on the admin listener under Prefix (a path with no trailing slash),
// behind the same admin check as the admin API. It sees the path with Prefix removed.
type Mount struct {
	Prefix  string
	Handler http.Handler
}

// Admin is the admin listener: the admin API under /admin/v1/ and each mount, and nothing else.
// Every request but health must pass the admin check first, so a mount can rely on it.
func (b *Broker) Admin(mounts ...Mount) http.Handler {
	api := b.adminHandler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !common(w, r) || b.health(w, r) {
			return
		}
		if _, ok := b.caller(w, r); !ok {
			return
		}
		// A browser says where a request came from (fetch metadata); a write it sends on behalf of
		// another site, or of a sibling site, is refused before any handler sees it. A client that is
		// not a browser sends none and is unaffected.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if s := r.Header.Values("Sec-Fetch-Site"); len(s) != 0 && (len(s) != 1 || s[0] != "same-origin") {
				b.store.Audit(AuditRecord{Kind: "refused", Reason: "cross_site", Version: b.currentVersion()})
				writeErr(w, http.StatusForbidden, apiError{Code: "cross_site", Message: "a write from another site is refused"})
				return
			}
		}
		p := r.URL.Path
		if strings.HasPrefix(p, "/admin/v1/") {
			api.ServeHTTP(w, r)
			return
		}
		for _, m := range mounts {
			switch {
			case p == m.Prefix && (r.Method == http.MethodGet || r.Method == http.MethodHead):
				http.Redirect(w, r, m.Prefix+"/", http.StatusMovedPermanently)
				return
			case strings.HasPrefix(p, m.Prefix+"/"):
				http.StripPrefix(m.Prefix, m.Handler).ServeHTTP(w, r)
				return
			}
		}
		failure(w, http.StatusNotFound)
	})
}

func (b *Broker) currentVersion() int64 {
	if v := b.store.Active(); v != nil {
		return v.N
	}
	return int64(len(b.store.Versions()))
}

func (b *Broker) adminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/v1/config", func(w http.ResponseWriter, r *http.Request) {
		o := b.op
		issuers := make([]map[string]any, 0, len(o.Issuers))
		for _, is := range o.Issuers {
			issuers = append(issuers, map[string]any{"id": is.ID, "issuer": is.Issuer, "audience": is.Audience,
				"type": is.Type, "primary": is.Primary, "config_ref_template": is.ConfigRefTemplate,
				"max_token_lifetime_seconds": is.MaxTokenLifetimeSeconds})
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"issuers": issuers,
			"models":  o.RoutedModels, "sources": o.Sources, "admin_roles": o.AdminRoles,
			"two_person_rule": o.TwoPerson, "max_named_branch_ttl_seconds": int64(o.MaxNamedTTL.Seconds()),
			"kinds": []Kind{KindProtected, KindNamed},
			// USD per million tokens by model, shown on the limit editor to size a budget.
			"prices": b.up.usage.prices})
	})
	mux.HandleFunc("GET /admin/v1/policy", func(w http.ResponseWriter, r *http.Request) {
		v := b.store.Active()
		if v == nil {
			n := int64(len(b.store.Versions()))
			w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(n, 10)))
			writeJSON(w, http.StatusOK, map[string]any{"version": n, "entries": []Entry{}, "active": false})
			return
		}
		w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(v.N, 10)))
		writeJSON(w, http.StatusOK, b.withPrincipals(v))
	})
	mux.HandleFunc("PUT /admin/v1/policy", func(w http.ResponseWriter, r *http.Request) {
		c, ok := b.caller(w, r)
		if !ok {
			return
		}
		ifMatch, ok := b.ifMatch(w, r)
		if !ok {
			return
		}
		var body struct {
			Entries []Entry `json:"entries"`
			Comment string  `json:"comment"`
		}
		if !decodeBody(w, r, &body) {
			return
		}
		if len(body.Comment) > 1000 {
			writeErr(w, http.StatusUnprocessableEntity, apiError{Code: "invalid_policy", Message: "comment over 1000 bytes"})
			return
		}
		res, err := b.store.Put(b.op, ifMatch, body.Entries, c.id, c.name, body.Comment, b.now())
		b.writeResult(w, res, err)
	})
	mux.HandleFunc("GET /admin/v1/policy/versions", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"versions": b.store.Versions()})
	})
	mux.HandleFunc("GET /admin/v1/policy/versions/{n}", func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.ParseInt(r.PathValue("n"), 10, 64)
		v, verr := b.store.Version(n)
		if err != nil || verr != nil {
			writeErr(w, http.StatusNotFound, apiError{Code: "not_found", Message: "no such version"})
			return
		}
		writeJSON(w, http.StatusOK, b.withPrincipals(v))
	})
	mux.HandleFunc("GET /admin/v1/proposals", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"proposals": b.store.OpenProposals()})
	})
	mux.HandleFunc("POST /admin/v1/proposals/{id}/approve", func(w http.ResponseWriter, r *http.Request) {
		c, ok := b.caller(w, r)
		if !ok {
			return
		}
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeErr(w, http.StatusNotFound, apiError{Code: "not_found", Message: "no such open proposal"})
			return
		}
		res, err := b.store.Approve(b.op, id, c.id, c.name, b.now())
		b.writeResult(w, res, err)
	})
	mux.HandleFunc("POST /admin/v1/proposals/{id}/reject", func(w http.ResponseWriter, r *http.Request) {
		c, ok := b.caller(w, r)
		if !ok {
			return
		}
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err == nil {
			err = b.store.Reject(id, c.id, c.name, b.now())
		}
		if err != nil {
			b.writeResult(w, WriteResult{}, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"rejected": id})
	})
	mux.HandleFunc("GET /admin/v1/audit", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		after, _ := strconv.ParseInt(q.Get("after"), 10, 64)
		limit, err := strconv.Atoi(q.Get("limit"))
		if err != nil || limit <= 0 || limit > 500 {
			limit = 100
		}
		recs, err := b.store.AuditAfter(after, limit)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, apiError{Code: "store_unavailable", Message: "audit log unreadable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"records": recs})
	})
	b.consoleRoutes(mux)
	mux.HandleFunc("GET /admin/v1/usage/principals", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		filter, err := parseUsageFilter(q.Get("kind"), q.Get("model"))
		if err != nil {
			writeErr(w, http.StatusBadRequest, apiError{Code: "bad_filter", Message: err.Error()})
			return
		}
		if err := checkRange(q.Get("from"), q.Get("to")); err != nil {
			writeErr(w, http.StatusBadRequest, apiError{Code: "bad_range", Message: err.Error()})
			return
		}
		rows, err := b.up.usage.byPrincipal(q.Get("from"), q.Get("to"), filter)
		if err != nil {
			writeErr(w, http.StatusServiceUnavailable, apiError{Code: "usage_unavailable", Message: "the usage ledger cannot be read; usage is unknown, not zero"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"rows": rows, "since": b.up.usage.opened.Format(time.RFC3339)})
	})
	b.quotaRoutes(mux)
	b.ownerRoutes(mux)
	mux.HandleFunc("GET /admin/v1/usage", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Has("from") || q.Has("to") {
			filter, err := parseUsageFilter(q.Get("kind"), q.Get("model"))
			if err != nil {
				writeErr(w, http.StatusBadRequest, apiError{Code: "bad_filter", Message: err.Error()})
				return
			}
			if err := checkRange(q.Get("from"), q.Get("to")); err != nil {
				writeErr(w, http.StatusBadRequest, apiError{Code: "bad_range", Message: err.Error()})
				return
			}
			days, err := b.up.usage.history(q.Get("from"), q.Get("to"))
			if err != nil {
				writeErr(w, http.StatusServiceUnavailable, apiError{Code: "usage_unavailable", Message: "the usage ledger cannot be read; usage is unknown, not zero"})
				return
			}
			filter.apply(days)
			writeJSON(w, http.StatusOK, map[string]any{"days": days, "since": b.up.usage.opened.Format(time.RFC3339),
				"owners": b.principalOwners()})
			return
		}
		raw, err := b.up.usage.reportAll(b.now())
		if err != nil {
			writeErr(w, http.StatusServiceUnavailable, apiError{Code: "usage_unavailable", Message: "the usage ledger cannot be read; usage is unknown, not zero"})
			return
		}
		var today map[string]any
		json.Unmarshal(raw, &today)
		today["owners"] = b.principalOwners()
		writeJSON(w, http.StatusOK, today)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reads need the admin role too: the policy names projects and people.
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			if _, ok := b.caller(w, r); !ok {
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}

type entryView struct {
	Entry
	Principal string `json:"principal"`
}

func (b *Broker) withPrincipals(v *Version) map[string]any {
	es := make([]entryView, len(v.Entries))
	for i, e := range v.Entries {
		es[i] = entryView{e, e.Principal()}
	}
	active := b.store.Active()
	return map[string]any{"version": v.N, "entries": es, "author": v.Author, "author_name": v.AuthorName,
		"approver": v.Approver, "comment": v.Comment, "created": v.Created, "sha256": v.SHA256,
		"active": active != nil && active.N == v.N}
}

func (b *Broker) ifMatch(w http.ResponseWriter, r *http.Request) (int64, bool) {
	tags := r.Header.Values("If-Match")
	if len(tags) == 0 {
		writeErr(w, http.StatusPreconditionRequired, apiError{Code: "if_match_required", Message: "send If-Match with the version you edited"})
		return 0, false
	}
	n, ok := parseVersionTag(tags[0])
	if len(tags) != 1 || !ok {
		writeErr(w, http.StatusBadRequest, apiError{Code: "bad_if_match", Message: `If-Match must be one version, e.g. "7"`})
		return 0, false
	}
	return n, true
}

func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeErr(w, http.StatusUnsupportedMediaType, apiError{Code: "json_required", Message: "Content-Type must be application/json"})
		return false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256<<10))
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, apiError{Code: "too_large", Message: "body over 256 KiB"})
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil || dec.More() {
		writeErr(w, http.StatusBadRequest, apiError{Code: "bad_json", Message: "body is not the expected JSON"})
		return false
	}
	return true
}

func (b *Broker) writeResult(w http.ResponseWriter, res WriteResult, err error) {
	cur := b.currentVersion()
	switch {
	case errors.Is(err, errNoProposal):
		writeErr(w, http.StatusNotFound, apiError{Code: "not_found", Message: err.Error()})
	case errors.Is(err, errSameAuthor):
		writeErr(w, http.StatusForbidden, apiError{Code: "same_author", Message: err.Error()})
	case err != nil:
		writeErr(w, http.StatusServiceUnavailable, apiError{Code: "store_unavailable", Message: "policy store refused the write"})
	case res.Stale:
		writeErr(w, http.StatusPreconditionFailed, apiError{Code: "stale_version", Message: "the policy changed; reload and edit again", Current: &cur})
	case res.Invalid != nil:
		writeErr(w, http.StatusUnprocessableEntity, apiError{Code: "invalid_policy", Message: "the policy was not saved", Details: res.Invalid})
	case res.Proposal != nil:
		writeJSON(w, http.StatusAccepted, map[string]any{"proposal": res.Proposal,
			"message": "adds an unprotected-branch entry; another admin must approve it"})
	default:
		w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(res.Version.N, 10)))
		writeJSON(w, http.StatusCreated, b.withPrincipals(res.Version))
	}
}
