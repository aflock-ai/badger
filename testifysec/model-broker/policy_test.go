package broker

import (
	"encoding/json"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

type corpusFile struct {
	Operator struct {
		Issuer            string   `json:"issuer"`
		Audience          string   `json:"audience"`
		ConfigRefTemplate string   `json:"ci_config_ref_template"`
		RoutedModels      []string `json:"routed_models"`
		Sources           []string `json:"sources"`
		AdminRoles        []string `json:"admin_roles"`
		TwoPerson         bool     `json:"two_person_rule"`
		MaxNamedTTL       int64    `json:"max_named_branch_ttl_seconds"`
	} `json:"operator"`
	Entries []Entry `json:"entries"`
	Cases   []struct {
		Name     string   `json:"name"`
		Payload  string   `json:"payload"`
		Now      int64    `json:"now"`
		Op       string   `json:"op"`
		Model    *string  `json:"model"`
		NoPolicy bool     `json:"no_policy"`
		Want     []string `json:"want"`
	} `json:"cases"`
	Validity []struct {
		Name       string  `json:"name"`
		Now        int64   `json:"now"`
		Entries    []Entry `json:"entries"`
		WellFormed bool    `json:"well_formed"`
	} `json:"validity"`
}

func loadCorpus(t *testing.T) (*corpusFile, *Operator) {
	t.Helper()
	raw, err := os.ReadFile("testdata/decisions.json")
	if err != nil {
		t.Fatal(err)
	}
	var c corpusFile
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	// The corpus operator's single issuer, as the primary gitlab issuer: how every existing
	// deployment's entries (no "issuer" field) are decided after federation.
	issuers, err := compileIssuers([]IssuerConfig{{ID: "gitlab-1", Type: "gitlab", Primary: true,
		Issuer: c.Operator.Issuer, Audience: c.Operator.Audience, ClaimsHeader: "x-ci-claims",
		ConfigRefTemplate: c.Operator.ConfigRefTemplate}})
	if err != nil {
		t.Fatal(err)
	}
	o := &Operator{Issuers: issuers, RoutedModels: c.Operator.RoutedModels,
		Sources: c.Operator.Sources, AdminRoles: c.Operator.AdminRoles, TwoPerson: c.Operator.TwoPerson,
		MaxNamedTTL: time.Duration(c.Operator.MaxNamedTTL) * time.Second}
	if err := validOperator(o); err != nil {
		t.Fatal(err)
	}
	return &c, o
}

// TestCorpusAgreesWithLean: every case in testdata/decisions.json is also proved in
// formal/BadgerBroker/Corpus.lean against BrokerPolicy.lean `evaluate`. It is also the migration
// proof: the recorded answers are the single-issuer broker's, and the federated decision with the
// corpus issuer as the primary gitlab issuer must give every one of them (allow or deny, reason,
// principal, entry, model) for entries that name no issuer.
func TestCorpusAgreesWithLean(t *testing.T) {
	c, o := loadCorpus(t)
	if len(c.Cases) < 600 {
		t.Fatalf("corpus shrank to %d cases", len(c.Cases))
	}
	allowed := 0
	for _, tc := range c.Cases {
		entries := c.Entries
		if tc.NoPolicy {
			entries = nil
		}
		op := OpOther
		if tc.Op == "chat" {
			op = OpChat
		}
		got, _ := o.Decide(entries, time.Unix(tc.Now, 0), o.Issuers[0], []byte(tc.Payload), op, tc.Model)
		var want Decision
		if tc.Want[0] == "allow" {
			want = Decision{Allow: true, Principal: tc.Want[1], EntryID: tc.Want[2], Model: tc.Want[3]}
			allowed++
		} else {
			want = Decision{Reason: tc.Want[1]}
		}
		if got != want {
			t.Errorf("%s: got %+v, want %+v", tc.Name, got, want)
		}
	}
	if allowed == 0 {
		t.Fatal("corpus admits nothing (vacuous)")
	}
}

// TestValidityAgreesWithLean: Validate refuses exactly the policies Lean `wellFormed` refuses,
// on the corpus's model-level cases.
func TestValidityAgreesWithLean(t *testing.T) {
	c, o := loadCorpus(t)
	for _, v := range c.Validity {
		errs := o.Validate(&Policy{Entries: v.Entries}, time.Unix(v.Now, 0))
		if (len(errs) == 0) != v.WellFormed {
			t.Errorf("%s: Validate %v, Lean wellFormed %v", v.Name, errs, v.WellFormed)
		}
	}
}

// TestValidateSyntaxRules: rules the Lean model leaves to the parser.
func TestValidateSyntaxRules(t *testing.T) {
	c, o := loadCorpus(t)
	now := time.Unix(c.Cases[0].Now, 0)
	base := c.Entries[0]
	for name, mutate := range map[string]func(e *Entry){
		"id uppercase":      func(e *Entry) { e.ID = "Alpha" },
		"project no group":  func(e *Entry) { e.ProjectPath = "alpha" },
		"project with @":    func(e *Entry) { e.ProjectPath = "group/al@pha" },
		"ref with @":        func(e *Entry) { e.Ref = "ma@in" },
		"ref dotdot":        func(e *Entry) { e.Ref = "a/../b" },
		"empty user":        func(e *Entry) { e.TriggerUsers = []string{""} },
		"user with space":   func(e *Entry) { e.TriggerUsers = []string{"a b"} },
		"unknown kind":      func(e *Entry) { e.Kind = "tag" },
		"ci prefix project": func(e *Entry) { e.ProjectPath = "ci:group/alpha" },
	} {
		e := base
		mutate(&e)
		if errs := o.Validate(&Policy{Entries: []Entry{e}}, now); len(errs) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	if errs := o.Validate(&Policy{}, now); len(errs) == 0 {
		t.Error("null entries accepted")
	}
	if errs := o.Validate(&Policy{Entries: []Entry{}}, now); len(errs) != 0 {
		t.Errorf("empty policy refused: %v", errs)
	}
}

// TestPrincipalsDistinct: distinct_principals, kinds_distinct. Validate refuses two entries that
// would share a principal, and a protected and a named entry never render alike.
func TestPrincipalsDistinct(t *testing.T) {
	c, _ := loadCorpus(t)
	seen := map[string]string{}
	for _, e := range c.Entries {
		if prev, dup := seen[e.Principal()]; dup {
			t.Fatalf("%s and %s share %s", prev, e.ID, e.Principal())
		}
		seen[e.Principal()] = e.ID
		if !strings.HasPrefix(e.Principal(), "ci:") {
			t.Fatalf("render_ciForm: %s", e.Principal())
		}
	}
	if seen["ci:group/sub/beta"] != "beta" || seen["ci:group/sub/beta@feat/x-1"] != "beta-feature" {
		t.Fatalf("principals: %v", seen)
	}
}

// TestNamedBranchEntry: named_requires_trigger_user_and_expiry, unlisted_trigger_user_inert,
// expired_entry_inert, on the shape the first named entry in a deployment takes.
func TestNamedBranchEntry(t *testing.T) {
	c, o := loadCorpus(t)
	now := time.Unix(c.Cases[0].Now, 0)
	model := "model-b"
	is := o.Issuers[0]
	claims := func(user string, protected string) []byte {
		raw, _ := json.Marshal(map[string]any{"iss": is.Issuer, "aud": is.Audience, "exp": now.Unix() + 30*86400,
			"iat": now.Unix() - 3600, "project_path": "group/sub/beta", "ref": "feat/x-1", "ref_type": "branch",
			"ref_protected": protected, "pipeline_source": "web",
			"ci_config_ref_uri": is.configRef("group/sub/beta", "feat/x-1"), "user_login": user})
		return raw
	}
	decide := func(at time.Time, p []byte) Decision {
		d, _ := o.Decide(c.Entries, at, is, p, OpChat, &model)
		return d
	}
	if d := decide(now, claims("alice", "false")); !d.Allow || d.Principal != "ci:group/sub/beta@feat/x-1" {
		t.Fatalf("listed user on named branch: %+v", d)
	}
	if d := decide(now, claims("mallory", "false")); d.Allow || d.Reason != ReasonNoMatch {
		t.Fatalf("unlisted user: %+v", d)
	}
	expiry := c.Entries[2].ExpiresAt
	if d := decide(*expiry, claims("alice", "false")); d.Allow {
		t.Fatalf("at expiry: %+v", d)
	}
	if d := decide(expiry.Add(-time.Second), claims("alice", "false")); !d.Allow {
		t.Fatalf("a second before expiry: %+v", d)
	}
}

// TestNoDefaultPrincipal: served_principal_listed. Every allowed principal is an entry's.
func TestNoDefaultPrincipal(t *testing.T) {
	c, o := loadCorpus(t)
	var principals []string
	for _, e := range c.Entries {
		principals = append(principals, e.Principal())
	}
	for _, tc := range c.Cases {
		d, _ := o.Decide(c.Entries, time.Unix(tc.Now, 0), o.Issuers[0], []byte(tc.Payload), OpChat, tc.Model)
		if d.Allow && !slices.Contains(principals, d.Principal) {
			t.Fatalf("%s: principal %q is no entry's", tc.Name, d.Principal)
		}
	}
}

// TestGitlabPayloadShapes: the built-in gitlab mapping refuses exactly what the broker refused
// before federation (required claims are strings, exp/iat integers, ref_protected never a bool).
func TestGitlabPayloadShapes(t *testing.T) {
	c, o := loadCorpus(t)
	is := o.Issuers[0]
	now := time.Unix(c.Cases[0].Now, 0)
	model := "model-a"
	for _, bad := range []string{``, `null`, `[]`, `{"iss":1}`, `{"iss":"x"} {"iss":"y"}`,
		`{"iss":"I","aud":"A","exp":1.5,"iat":1,"project_path":"a/b","ref":"r","ref_type":"branch","pipeline_source":"web","ci_config_ref_uri":"u"}`,
		`{"iss":"I","aud":"A","exp":"1","iat":1,"project_path":"a/b","ref":"r","ref_type":"branch","pipeline_source":"web","ci_config_ref_uri":"u"}`,
		`{"iss":"I","aud":"A","exp":1,"iat":1,"project_path":"a/b","ref":"r","ref_type":"branch","pipeline_source":"web","ci_config_ref_uri":"u","ref_protected":true}`,
		`{"iss":"I","aud":{"x":1},"exp":1,"iat":1,"project_path":"a/b","ref":"r","ref_type":"branch","pipeline_source":"web","ci_config_ref_uri":"u"}`,
		`{"iss":"I","aud":"A","exp":1,"iat":1,"ref":"r","ref_type":"branch","pipeline_source":"web","ci_config_ref_uri":"u"}`,
	} {
		bad = strings.NewReplacer(`"I"`, strconv.Quote(is.Issuer), `"A"`, strconv.Quote(is.Audience)).Replace(bad)
		if d, _ := o.Decide(c.Entries, now, is, []byte(bad), OpChat, &model); d.Reason != ReasonBadClaims {
			t.Errorf("%s: %+v", bad, d)
		}
	}
	// Optional claims may be absent; a list audience parses and then never matches.
	ok := `{"iss":"I","aud":["A"],"exp":9999999999,"iat":1,"project_path":"a/b","ref":"r","ref_type":"branch","pipeline_source":"web","ci_config_ref_uri":"u"}`
	ok = strings.NewReplacer(`"I"`, strconv.Quote(is.Issuer), `"A"`, strconv.Quote(is.Audience)).Replace(ok)
	if d, s := o.Decide(c.Entries, now, is, []byte(ok), OpChat, &model); d.Reason != ReasonWrongAudience ||
		s == nil || s.Protected != "" || s.TriggeredBy != "" {
		t.Fatalf("%+v %+v", d, s)
	}
}
