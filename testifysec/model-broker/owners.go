package broker

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// OwnerSet links every pipeline policy entry (a non-human identity) to the human accountable for
// it, by entry id. A pipeline whose entry has no owner is refused, so every model call a pipeline
// makes traces to a person.
type OwnerSet struct {
	Version int64             `json:"version"`
	Owners  map[string]string `json:"owners"` // entry id -> human principal
}

var errOwnerVersion = errors.New("owner version changed")

// ownerBook holds the OwnerSet in the "owners" document. An unreadable document refuses every
// pipeline: a link to a person that silently disappears is worse than an outage.
type ownerBook struct{ docs documents }

func (o *ownerBook) current() (OwnerSet, error) {
	s := OwnerSet{Owners: map[string]string{}}
	v, err := o.docs.load("owners", &s)
	if err != nil {
		return OwnerSet{}, err
	}
	if s.Owners == nil {
		s.Owners = map[string]string{}
	}
	s.Version = v
	return s, nil
}

// of is the human who owns a policy entry.
func (o *ownerBook) of(entryID string) (string, bool) {
	s, err := o.current()
	if err != nil {
		return "", false
	}
	h, ok := s.Owners[entryID]
	return h, ok
}

func (o *ownerBook) put(base int64, owners map[string]string) (OwnerSet, error) {
	next := OwnerSet{Version: base + 1, Owners: owners}
	if err := o.docs.put("owners", base, next); err != nil {
		if errors.Is(err, errDocVersion) {
			return OwnerSet{}, errOwnerVersion
		}
		return OwnerSet{}, err
	}
	return next, nil
}

// ownerOf is the entry's owner, only if it is still one of the configured people: removing a
// person from human_principals orphans their pipelines.
func (b *Broker) ownerOf(entryID string) (string, bool) {
	h, ok := b.owners.of(entryID)
	if !ok {
		return "", false
	}
	return configuredPrincipal(b.cfg.HumanPrincipals, h)
}

// principalOwners maps each active entry's principal to its owner, for usage reports.
func (b *Broker) principalOwners() map[string]string {
	out := map[string]string{}
	if v := b.store.Active(); v != nil {
		for i := range v.Entries {
			if h, ok := b.ownerOf(v.Entries[i].ID); ok {
				out[v.Entries[i].Principal()] = h
			}
		}
	}
	return out
}

func (b *Broker) ownerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/v1/owners", func(w http.ResponseWriter, r *http.Request) {
		s, err := b.owners.current()
		if err != nil {
			writeErr(w, http.StatusServiceUnavailable, apiError{Code: "owners_unavailable", Message: err.Error()})
			return
		}
		entries := []map[string]any{}
		if v := b.store.Active(); v != nil {
			for i := range v.Entries {
				e := &v.Entries[i]
				view := map[string]any{"id": e.ID, "principal": e.Principal(), "enabled": e.Enabled, "owner": nil}
				if h, ok := b.ownerOf(e.ID); ok {
					view["owner"] = h
				}
				entries = append(entries, view)
			}
		}
		w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(s.Version, 10)))
		writeJSON(w, http.StatusOK, map[string]any{"version": s.Version, "owners": s.Owners, "entries": entries,
			"humans": b.cfg.HumanPrincipals})
	})
	mux.HandleFunc("PUT /admin/v1/owners", func(w http.ResponseWriter, r *http.Request) {
		c, ok := b.caller(w, r)
		if !ok {
			return
		}
		base, ok := b.ifMatch(w, r)
		if !ok {
			return
		}
		var body struct {
			Owners  map[string]string `json:"owners"`
			Comment string            `json:"comment"`
		}
		if !decodeBody(w, r, &body) {
			return
		}
		if body.Owners == nil {
			body.Owners = map[string]string{}
		}
		for id, h := range body.Owners {
			person, ok := configuredPrincipal(b.cfg.HumanPrincipals, h)
			if id == "" || len(id) > 200 || auditSafe(id) != id || !ok {
				writeErr(w, http.StatusUnprocessableEntity, apiError{Code: "invalid_owner",
					Message: "each owner must be one of the configured people, for an entry id"})
				return
			}
			body.Owners[id] = person // stored in the configured spelling
		}
		if len(body.Owners) > 1000 || len(body.Comment) > 1000 {
			writeErr(w, http.StatusUnprocessableEntity, apiError{Code: "invalid_owner", Message: "over 1000 owners, or comment over 1000 bytes"})
			return
		}
		saved, err := b.owners.put(base, body.Owners)
		switch {
		case errors.Is(err, errOwnerVersion):
			writeErr(w, http.StatusPreconditionFailed, apiError{Code: "version_changed", Message: "owners changed since you loaded them; reload"})
			return
		case err != nil:
			writeErr(w, http.StatusInternalServerError, apiError{Code: "store_unavailable", Message: "owners not saved"})
			return
		}
		ids := make([]string, 0, len(saved.Owners))
		for id := range saved.Owners {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		parts := make([]string, len(ids))
		for i, id := range ids {
			parts[i] = id + "=" + saved.Owners[id]
		}
		b.store.Audit(AuditRecord{Kind: "owner", Actor: c.id, Name: c.name, Version: b.currentVersion(),
			Comment: strings.TrimSpace(fmt.Sprintf("owners v%d: %s. %s", saved.Version, strings.Join(parts, " "), body.Comment))})
		w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(saved.Version, 10)))
		writeJSON(w, http.StatusOK, saved)
	})
}
