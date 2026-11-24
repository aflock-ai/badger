// Package broker is a model broker for people and CI pipelines. See README.md.
package broker

import (
	"database/sql"
	"encoding/base64"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aflock-ai/badger/testifysec/connectors/marking"
	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
)

// Broker holds everything the listeners share. formal/BadgerBroker/BrokerPolicy.lean `serve`.
type Broker struct {
	cfg    *FileConfig
	op     *Operator
	store  *Store
	tokens *tokenRegistry
	up     *upstream
	quotas *quotaBook
	owners *ownerBook
	// quotaLocks holds a one-slot channel per principal with a quota: its calls run one at a time.
	quotaLocks sync.Map
	// device holds device sign-in's pending consents and codes (device.go), in memory only.
	device *deviceState
	now    func() time.Time
	// bottom is the lowest label: people the edge signed in run at it (they are neither admins
	// nor workspaces).
	bottom pgdb.Label
}

// underCeiling reports whether the deployment's ceiling dominates l.
func (b *Broker) underCeiling(l pgdb.Label) bool {
	return l.Valid() && pgdb.Dominates(b.cfg.Ceiling(), l)
}

func newBroker(cfg *FileConfig, db *sql.DB, store *Store, client *http.Client) *Broker {
	up := newUpstream(cfg.Routes, cfg.MaxConcurrentUpstream, client, cfg.Upstream)
	ceiling := cfg.Ceiling()
	book := openUsage(db, ceiling, time.Now())
	book.setPrices(up.usage.prices)
	reserve := map[string]float64{}
	for _, rt := range cfg.Routes {
		if rt.MaxCallUSD != nil {
			reserve[rt.Model] = *rt.MaxCallUSD
		}
	}
	book.setReserve(reserve)
	book.window = callWindow(cfg.Upstream)
	book.retryEvery(5 * time.Second)
	up.usage = book
	docs := documents{db: db, label: ceiling}
	b := &Broker{cfg: cfg, op: cfg.Operator(), store: store, tokens: openTokens(db, ceiling), up: up, now: time.Now,
		quotas: &quotaBook{docs: docs, maxTimeout: cfg.Upstream.RequestSeconds}, owners: &ownerBook{docs: docs}, device: newDeviceState(),
		bottom: pgdb.LabelOf(marking.Marking{})}
	b.seedLimits()
	return b
}

func common(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.EscapedPath() != r.URL.Path {
		failure(w, http.StatusNotFound)
		return false
	}
	return true
}

func (b *Broker) originOK(r *http.Request) bool {
	o := r.Header.Values("Origin")
	return len(o) == 0 || (len(o) == 1 && slices.Contains(b.cfg.AllowedOrigins, o[0]))
}

func (b *Broker) health(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/healthz":
	case "/readyz":
		// Readiness is local credential availability, not successful inference.
		if !b.up.ready() {
			failure(w, http.StatusServiceUnavailable)
			return true
		}
	default:
		return false
	}
	if r.Method != http.MethodGet {
		failure(w, http.StatusMethodNotAllowed)
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
	return true
}

// peoplePath answers the people's routes for a principal already established.
func (b *Broker) peoplePath(w http.ResponseWriter, r *http.Request, principal string, label pgdb.Label) {
	if r.URL.Path == "/" {
		showPage(w, principal, b.up.order)
		return
	}
	if !b.originOK(r) {
		failure(w, http.StatusForbidden)
		return
	}
	switch r.URL.Path {
	case "/v1/usage":
		out, err := b.up.usage.report(label, principal, b.now())
		if err != nil {
			writeErr(w, http.StatusServiceUnavailable, apiError{Code: "usage_unavailable", Message: "the usage ledger cannot be read; usage is unknown, not zero"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
		return
	case "/v1/models":
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(b.up.modelList))
		return
	case "/v1/limits":
		// The managed agent's own limits, read at its start; it cannot be held to them (quota.go).
		s, err := b.quotas.current()
		if err != nil {
			writeErr(w, http.StatusServiceUnavailable, apiError{Code: "quota_unavailable", Message: "limits cannot be read"})
			return
		}
		_, l := s.effective(principal)
		writeJSON(w, http.StatusOK, map[string]*int{"steps": l.Steps, "context": l.Context, "output": l.Output, "timeout_seconds": l.TimeoutSeconds})
		return
	}
	chat, status := readChat(w, r)
	if status != 0 {
		failure(w, status)
		return
	}
	rt := b.up.order[0]
	if chat.model != nil {
		if rt = b.up.routes[*chat.model]; rt == nil {
			failure(w, http.StatusBadRequest)
			return
		}
	}
	release, limits, ok := b.withinQuota(w, r, principal, label)
	if !ok {
		return
	}
	defer release()
	b.up.forward(w, r, principal, label, usageAttr{}, rt, chat, limits)
}

// peopleMethod checks path and method for the people's routes; false means it has answered.
func peopleMethod(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		failure(w, http.StatusNotFound)
		return false
	}
	method := http.MethodGet
	switch r.URL.Path {
	case "/", "/v1/models", "/v1/usage", "/v1/limits":
	case "/v1/chat/completions":
		method = http.MethodPost
	default:
		failure(w, http.StatusNotFound)
		return false
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		failure(w, http.StatusMethodNotAllowed)
		return false
	}
	return true
}

// Internal is the listener workspaces reach (Lean `serve` `.internal`). It serves a person only
// by the workspace token the request presents (Authorization: Bearer bbt_...), never by a header
// it could set itself, and refuses anything carrying a pipeline payload
// (`internal_ignores_principal_header`, `internal_never_pipeline`, `workspace_served_as_owner`).
func (b *Broker) Internal() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !common(w, r) || b.health(w, r) {
			return
		}
		if b.adminSession(r) {
			failure(w, http.StatusForbidden)
			return
		}
		if b.hasPipelinePayload(r) {
			failure(w, http.StatusUnauthorized)
			return
		}
		if b.cfg.DeviceLogin && r.URL.Path == "/device/token" && r.URL.RawQuery == "" {
			b.deviceToken(w, r)
			return
		}
		if !peopleMethod(w, r) {
			return
		}
		auth := r.Header.Values("Authorization")
		if len(auth) != 1 || !strings.HasPrefix(auth[0], "Bearer ") {
			failure(w, http.StatusUnauthorized)
			return
		}
		rec, ok := b.tokens.AuthRec(strings.TrimPrefix(auth[0], "Bearer "), b.cfg.HumanPrincipals, b.now())
		if !ok {
			failure(w, http.StatusUnauthorized)
			return
		}
		// A workspace's own requests run at its label; one that no longer parses, or sits above
		// the ceiling, is refused.
		label, err := pgdb.ParseLabel(rec.Marking)
		if err != nil || !b.underCeiling(label) {
			failure(w, http.StatusForbidden)
			return
		}
		b.peoplePath(w, r, rec.Principal, label)
	})
}

// Edge is the listener only the edge can reach (network policy). It serves pipelines, decided
// by the policy on the verified payload the edge forwards; people, by the principal header the
// edge sets after sign-in. A request carrying a payload is a pipeline request and its principal
// header is never read (Lean `edge_payload_ignores_principal_header`). The admin API is on the
// admin listener; a request carrying an admin identity is refused here.
func (b *Broker) Edge() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !common(w, r) || b.health(w, r) {
			return
		}
		if b.adminSession(r) {
			failure(w, http.StatusForbidden)
			return
		}
		if b.cfg.DeviceLogin && r.URL.Path == "/device/authorize" {
			b.deviceAuthorize(w, r)
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			failure(w, http.StatusNotFound)
			return
		}
		op := OpOther
		if r.URL.Path == "/v1/chat/completions" && r.Method == http.MethodPost {
			op = OpChat
		}
		// At most one issuer's header, holding one value: two payloads are never merged or chosen between.
		var issuer *Issuer
		var values []string
		for _, h := range b.cfg.ClaimsHeaders() {
			if vs := r.Header.Values(h); len(vs) != 0 {
				issuer, values = b.op.IssuerByHeader(h), append(values, vs...)
			}
		}
		if len(values) == 0 {
			// A person the edge signed in (Lean `edge_person_listed`).
			if !peopleMethod(w, r) {
				return
			}
			ps := r.Header.Values(b.cfg.Headers.Principal)
			var person string
			if len(ps) == 1 {
				person, _ = configuredPrincipal(b.cfg.HumanPrincipals, ps[0])
			}
			if person == "" {
				failure(w, http.StatusUnauthorized)
				return
			}
			b.peoplePath(w, r, person, b.bottom)
			return
		}
		if len(values) != 1 {
			failure(w, http.StatusUnauthorized)
			return
		}
		if len(r.Header.Values("Origin")) != 0 {
			// The edge refuses Origin on pipeline calls (no browser may act as a pipeline).
			failure(w, http.StatusForbidden)
			return
		}
		payload := decodePayload(values[0])
		var chat *chatRequest
		var model *string
		if op == OpChat {
			var status int
			if chat, status = readChat(w, r); status != 0 {
				failure(w, status)
				return
			}
			model = chat.model
		}
		now := b.now()
		var entries []Entry
		version := int64(0)
		if v := b.store.Active(); v != nil {
			entries, version = v.Entries, v.N
		}
		d, subject := b.op.Decide(entries, now, issuer, payload, op, model)
		// A pipeline is a non-human identity: it is served only when a person owns its entry.
		owner := ""
		if d.Allow {
			if h, ok := b.ownerOf(d.EntryID); ok {
				owner = h
			} else {
				d = Decision{Principal: d.Principal, EntryID: d.EntryID, Model: d.Model, Reason: ReasonUnowned}
			}
		}
		rec := AuditRecord{Time: now.UTC(), Kind: "decision", Version: version, Principal: d.Principal,
			EntryID: d.EntryID, Model: d.Model, Reason: d.Reason, Decision: "deny", Owner: owner}
		if d.Allow {
			rec.Decision = "allow"
		}
		// The header names the issuer even when its payload did not map.
		rec.Issuer = auditSafe(issuer.ID)
		if subject != nil {
			rec.Project, rec.Ref, rec.Source = auditSafe(subject.Project), auditSafe(subject.Ref), auditSafe(subject.Source)
			rec.UserLogin = auditSafe(subject.TriggeredBy)
		}
		if d.Allow {
			// Denials go to the log only, so a flood of refused tokens cannot fill the volume.
			if b.store.Audit(rec) != nil {
				failure(w, http.StatusServiceUnavailable)
				return
			}
		}
		// Every refusal answers the same way per status; only this log says which check failed
		// (detail, for no_match), so the response never describes the policy.
		detail := ""
		if d.Reason == ReasonNoMatch && subject != nil {
			detail = b.op.NoMatchDetail(entries, now, issuer, subject)
		}
		log.Printf("ci decision=%s reason=%s detail=%s principal=%s issuer=%s user=%s project=%s ref=%s ref_type=%s source=%s model=%s policy_version=%d",
			rec.Decision, logField(rec.Reason), logField(detail), logField(rec.Principal), logField(rec.Issuer), logField(rec.UserLogin), logField(rec.Project),
			logField(rec.Ref), logField(refType(subject)), logField(rec.Source), logField(rec.Model), version)
		if !d.Allow {
			status := http.StatusForbidden
			switch d.Reason {
			case ReasonBadClaims, ReasonWrongIssuer, ReasonWrongAudience, ReasonTokenExpired, ReasonTokenLifetime:
				status = http.StatusUnauthorized
			case ReasonWrongOperation:
				status = http.StatusNotFound
			case ReasonNoPolicy:
				status = http.StatusServiceUnavailable
			}
			failure(w, status)
			return
		}
		release, limits, ok := b.withinQuota(w, r, d.Principal, b.cfg.Ceiling())
		if !ok {
			return
		}
		defer release()
		w.Header().Set("X-Broker-Owner", owner)
		trigger := ""
		if subject != nil {
			trigger = auditSafe(subject.TriggeredBy)
		}
		b.up.forward(w, r, d.Principal, b.cfg.Ceiling(), usageAttr{Owner: owner, TriggeredBy: trigger}, b.up.routes[d.Model], chat, limits)
	})
}

func refType(s *Subject) string {
	if s == nil {
		return ""
	}
	return s.RefType
}

func logField(s string) string {
	if s == "" {
		return "-"
	}
	return auditSafe(s)
}

// decodePayload reads Envoy's forward_payload_header value: the verified JWT payload,
// base64url without padding. Anything else is nil, an unparseable payload (Lean `claims = none`).
func decodePayload(v string) []byte {
	if len(v) > 16<<10 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(v, "="))
	if err != nil {
		return nil
	}
	return raw
}

// hasPipelinePayload: the request carries any issuer's payload header.
func (b *Broker) hasPipelinePayload(r *http.Request) bool {
	for _, h := range b.cfg.ClaimsHeaders() {
		if len(r.Header.Values(h)) != 0 {
			return true
		}
	}
	return false
}
