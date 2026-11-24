package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/badger/testifysec/portal/internal/store"
	"github.com/aflock-ai/badger/testifysec/portal/internal/users"
)

// The onboarding model's conformance vectors (testifysec/formal/onboarding, README "The
// vectors"). Every trace whose events this portal implements is replayed against a fresh portal,
// started from the vectors' bootstrap config and, for a trace "from": "initial", the vectors'
// setup steps. Each step must give the expected outcome, error code and number of audit records,
// and the people at the end must match the vector's final state. A trace that needs an event
// the portal does not implement yet is skipped with a log line naming it. The test fails if no
// trace replays, so it cannot pass without checking anything.
const onboardingVectors = "../../../formal/onboarding/vectors/onboarding-vectors.json"

type obPrincipal struct {
	User   *int
	Device *int
	IdP    bool
}

func (p *obPrincipal) UnmarshalJSON(b []byte) error {
	if string(b) == `"idp"` {
		p.IdP = true
		return nil
	}
	var v struct {
		User   *int `json:"user"`
		Device *int `json:"device"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	p.User, p.Device = v.User, v.Device
	return nil
}

type obStep struct {
	Actor obPrincipal `json:"actor"`
	Event struct {
		Kind    string `json:"kind"`
		User    int    `json:"user"`
		Pending int    `json:"pending"`
		Request *struct {
			Kind       string `json:"kind"`
			User       int    `json:"user"`
			Role       string `json:"role"`
			Deployment int    `json:"deployment"`
		} `json:"request"`
	} `json:"event"`
	Outcome string `json:"outcome"`
	Error   string `json:"error"`
	Audit   int    `json:"audit"`
}

type obUser struct {
	ID     int     `json:"id"`
	Status string  `json:"status"`
	Role   *string `json:"role"`
}

type obTrace struct {
	Name  string   `json:"name"`
	From  string   `json:"from"`
	Steps []obStep `json:"steps"`
	Final struct {
		Users []obUser `json:"users"`
	} `json:"final"`
}

type obVectors struct {
	Schema  string `json:"schema"`
	Install []struct {
		ID   int    `json:"id"`
		Role string `json:"role"`
	} `json:"install"`
	Setup  []obStep  `json:"setup"`
	Traces []obTrace `json:"traces"`
}

func obSubject(u int) string { return fmt.Sprintf("CN=Onboarding User %d", u) }

func obUserID(u int) string { return users.Identity{Kind: "oidc", Subject: obSubject(u)}.ID() }

// obMissing names what a step needs that the portal does not implement, or "" if it replays.
func obMissing(s obStep) string {
	if s.Actor.User == nil {
		if s.Actor.IdP {
			return s.Event.Kind + " by the IdP"
		}
		return s.Event.Kind + " by a device key"
	}
	switch s.Event.Kind {
	case "invite", "approve", "reject", "drop-role", "offboard", "list":
		return ""
	case "request":
		if r := s.Event.Request; r != nil && (r.Kind == "grant" || r.Kind == "publish") {
			return ""
		}
		return "request"
	}
	return s.Event.Kind
}

// obRequests maps the model's request numbers to what created them, following the model's
// counter: every successful invite or request takes the next number.
func obRequests(steps []obStep, next int, kinds map[int]string) int {
	for _, s := range steps {
		if s.Outcome != "ok" {
			continue
		}
		switch s.Event.Kind {
		case "invite":
			kinds[next] = "activate"
			next++
		case "request":
			kinds[next] = s.Event.Request.Kind
			next++
		}
	}
	return next
}

type obPortal struct {
	t        *testing.T
	h        http.Handler
	log      *store.PG
	users    *users.PG
	next     int
	requests map[int]string // model request number -> portal request id ("" for a publish)
	decided  map[int]bool
}

func newObPortal(t *testing.T, v obVectors) *obPortal {
	t.Helper()
	srv := NewTestServer(t)
	db := testDB(t)
	files := users.NewPG(db, testLabel)
	// One log for profiles and people, so each step's records are counted in one place.
	log := store.NewPG(db, testLabel)
	srv.Issuer.Audit = log
	boot := map[string]Role{}
	for _, p := range v.Install {
		boot[obSubject(p.ID)] = Role(p.Role)
	}
	srv.Users = &users.Service{Store: files, Audit: log, Now: time.Now, Bootstrap: boot,
		Identify: func(r *http.Request) (users.Identity, error) {
			return users.Identity{Kind: "oidc", Subject: r.Header.Get("X-Test-Subject")}, nil
		}}
	srv.Auth = srv.Users
	return &obPortal{t: t, h: srv.Handler(), log: log, users: files,
		requests: map[int]string{}, decided: map[int]bool{}}
}

func (p *obPortal) records() int {
	n, err := p.log.Records()
	if err != nil {
		p.t.Fatal(err)
	}
	return n
}

func (p *obPortal) call(actor int, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("X-Test-Subject", obSubject(actor))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.h.ServeHTTP(w, r)
	return w
}

// requestPath is the portal's id for model request number n; an unknown number becomes an id
// no request has.
func (p *obPortal) requestPath(n int) string {
	if id, ok := p.requests[n]; ok && id != "" {
		return id
	}
	return strings.Repeat("0", 32)
}

var obStatus = map[string]int{"unauthenticated": 401, "forbidden": 403, "not-found": 404,
	"conflict": 409, "invalid-state": 409, "invalid-request": 400}

func (p *obPortal) step(i int, s obStep) {
	t := p.t
	a := *s.Actor.User
	before := p.records()
	var w *httptest.ResponseRecorder
	switch s.Event.Kind {
	case "invite":
		w = p.call(a, "POST", "/api/v1/users", fmt.Sprintf(`{"kind":"oidc","subject":%q}`, obSubject(s.Event.User)))
	case "request":
		r := s.Event.Request
		if r.Kind == "grant" {
			w = p.call(a, "POST", "/api/v1/users/"+obUserID(r.User)+"/role-requests", fmt.Sprintf(`{"role":%q}`, r.Role))
		} else {
			w = p.call(a, "POST", fmt.Sprintf("/api/v1/profiles/profile-%d/versions", r.Deployment),
				fmt.Sprintf(`{"deploymentId":"deploy-%d","notBefore":"2026-01-01T00:00:00Z","expiresAt":"2099-01-01T00:00:00Z"}`, r.Deployment))
		}
	case "approve", "reject":
		w = p.call(a, "POST", "/api/v1/role-requests/"+p.requestPath(s.Event.Pending)+"/"+s.Event.Kind, `{}`)
	case "drop-role":
		w = p.call(a, "POST", "/api/v1/users/"+obUserID(s.Event.User)+"/drop-role", `{}`)
	case "offboard":
		w = p.call(a, "POST", "/api/v1/users/"+obUserID(s.Event.User)+"/offboard", `{}`)
	case "list":
		w = p.call(a, "GET", "/api/v1/profiles", "")
	}
	what := fmt.Sprintf("step %d (%s by user %d)", i, s.Event.Kind, a)
	switch s.Outcome {
	case "ok":
		if w.Code/100 != 2 {
			t.Fatalf("%s: want success, got %d %s", what, w.Code, w.Body)
		}
	case "refused":
		code := s.Error
		switch {
		case code == "separation-of-duties":
			// The portal answers a self-approval with 403 forbidden and a detail naming the rule.
			code = "forbidden"
		case code == "not-found" && (s.Event.Kind == "approve" || s.Event.Kind == "reject") && p.decided[s.Event.Pending]:
			// Deciding a request twice: the portal answers conflict. The model's follow-up
			// (testifysec/formal/onboarding, #225) changes its answer to conflict too.
			code = "conflict"
		}
		want, ok := obStatus[code]
		if !ok {
			t.Fatalf("%s: refusal %q has no mapping to this portal", what, s.Error)
		}
		if w.Code != want || !strings.Contains(w.Body.String(), `"error":"`+code+`"`) {
			t.Fatalf("%s: want %d %s, got %d %s", what, want, code, w.Code, w.Body)
		}
	default:
		t.Fatalf("%s: outcome %q has no mapping to this portal", what, s.Outcome)
	}
	if got := p.records() - before; got != s.Audit {
		t.Fatalf("%s: want %d audit records, got %d", what, s.Audit, got)
	}
	if s.Outcome != "ok" {
		return
	}
	switch s.Event.Kind {
	case "invite":
		var body struct {
			Activation users.Request `json:"activation"`
		}
		if json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Activation.ID == "" {
			t.Fatalf("%s: no activation request in %s", what, w.Body)
		}
		p.requests[p.next] = body.Activation.ID
		p.next++
	case "request":
		id := ""
		if s.Event.Request.Kind == "grant" {
			var req users.Request
			if json.Unmarshal(w.Body.Bytes(), &req) != nil || req.ID == "" {
				t.Fatalf("%s: no request in %s", what, w.Body)
			}
			id = req.ID
		}
		p.requests[p.next] = id
		p.next++
	case "approve", "reject":
		p.decided[s.Event.Pending] = true
	}
}

// final checks every person the model ends with: the portal's record has the same status and
// role. The portal may hold one more kind of record: an offboarded bootstrap subject, which the
// model keeps as a flag on the bootstrap config rather than as a person.
func (p *obPortal) final(want []obUser, boot map[string]bool) {
	all, err := p.users.Users()
	if err != nil {
		p.t.Fatal(err)
	}
	got := map[string]users.User{}
	for _, u := range all {
		got[u.ID] = u
	}
	for _, u := range want {
		g, ok := got[obUserID(u.ID)]
		role := ""
		if u.Role != nil {
			role = *u.Role
		}
		if !ok || string(g.Status) != u.Status || string(g.Role) != role {
			p.t.Fatalf("final: user %d: want %s %q, got %+v (present %v)", u.ID, u.Status, role, g, ok)
		}
	}
	listed := map[string]bool{}
	for _, u := range want {
		listed[obUserID(u.ID)] = true
	}
	for _, u := range all {
		if !listed[u.ID] && !(boot[u.ID] && u.Status == users.Offboarded) {
			p.t.Fatalf("final: the portal holds a record the model does not: %+v", u)
		}
	}
}

func TestOnboardingVectors(t *testing.T) {
	raw, err := os.ReadFile(onboardingVectors)
	if err != nil {
		t.Fatal(err)
	}
	var v obVectors
	if err := json.Unmarshal(raw, &v); err != nil || v.Schema != "badger.onboarding.vectors/v1" {
		t.Fatalf("vectors: %v schema %q", err, v.Schema)
	}
	for i, s := range v.Setup {
		if m := obMissing(s); m != "" {
			t.Fatalf("setup step %d needs %s, which the portal must implement to replay anything", i, m)
		}
	}
	setupKinds := map[int]string{}
	setupNext := obRequests(v.Setup, 0, setupKinds)
	replayed := 0
	for _, tr := range v.Traces {
		kinds, next := map[int]string{}, 0
		if tr.From == "initial" {
			for k, kind := range setupKinds {
				kinds[k] = kind
			}
			next = setupNext
		}
		obRequests(tr.Steps, next, kinds)
		var missing []string
		seen := map[string]bool{}
		for _, s := range tr.Steps {
			m := obMissing(s)
			if m == "" && (s.Event.Kind == "approve" || s.Event.Kind == "reject") && kinds[s.Event.Pending] == "publish" {
				m = "approving a publish (the portal signs on the admin's request until PR 10)"
			}
			if m != "" && !seen[m] {
				seen[m] = true
				missing = append(missing, m)
			}
		}
		if len(missing) > 0 {
			t.Run(tr.Name, func(t *testing.T) {
				t.Skipf("SKIP: the portal does not implement %s yet", strings.Join(missing, ", "))
			})
			continue
		}
		replayed++
		t.Run(tr.Name, func(t *testing.T) {
			p := newObPortal(t, v)
			if tr.From == "initial" {
				for i, s := range v.Setup {
					p.step(i, s)
				}
			} else if tr.From != "install" {
				t.Fatalf("trace starts from %q", tr.From)
			}
			for i, s := range tr.Steps {
				p.step(i, s)
			}
			boot := map[string]bool{}
			for _, b := range v.Install {
				boot[obUserID(b.ID)] = true
			}
			p.final(tr.Final.Users, boot)
		})
	}
	t.Logf("onboarding vectors: %d of %d traces replayed, %d skipped until the portal implements them",
		replayed, len(v.Traces), len(v.Traces)-replayed)
	if replayed == 0 {
		t.Fatal("no onboarding vector is replayable: the test would pass without checking anything")
	}
}
