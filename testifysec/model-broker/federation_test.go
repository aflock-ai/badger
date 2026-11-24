package broker

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Four issuers: two GitLab instances (one primary), a GitHub-Actions-shaped generic issuer and a
// Kubernetes-service-account-shaped generic issuer with a nested claim and constants.
const fedIssuers = `[
 {"id": "gitlab-1", "type": "gitlab", "primary": true, "issuer": "https://gitlab-1.example.com",
  "audience": "broker", "claims_header": "x-ci-a", "max_token_lifetime_seconds": 3600,
  "config_ref_template": "gitlab-1.example.com/{project_path}//.gitlab-ci.yml@refs/heads/{ref}"},
 {"id": "gitlab-2", "type": "gitlab", "issuer": "https://gitlab-2.example.com",
  "audience": "broker", "claims_header": "x-ci-b", "max_token_lifetime_seconds": 3600,
  "config_ref_template": "gitlab-2.example.com/{project_path}//.gitlab-ci.yml@refs/heads/{ref}"},
 {"id": "actions-1", "type": "generic", "issuer": "https://actions.example.com",
  "audience": "broker", "claims_header": "x-ci-c", "max_token_lifetime_seconds": 600,
  "require": {"repository_owner": "acme"}, "ref_prefix": "refs/heads/",
  "mapping": {"sub": {"claim": "sub"}, "project": {"claim": "repository"}, "ref": {"claim": "ref"},
   "ref_type": {"claim": "ref_type"}, "protected": {"const": "true"}, "source": {"claim": "event_name"},
   "triggered_by": {"claim": "actor"}, "config_ref": {"claim": "job_workflow_ref"}},
  "config_ref_template": "{project_path}/.github/workflows/ci.yml@refs/heads/{ref}"},
 {"id": "cluster-1", "type": "generic", "issuer": "https://k8s.example.com",
  "audience": "broker", "claims_header": "x-ci-d", "max_token_lifetime_seconds": 3600,
  "mapping": {"sub": {"claim": "sub"}, "project": {"claim": ["kubernetes.io", "namespace"]},
   "ref": {"const": "main"}, "ref_type": {"const": "branch"}, "protected": {"const": "true"},
   "source": {"const": "workload"}}}
]`

var fedNow = time.Unix(1_800_000_000, 0)

func fedOperator(t *testing.T) *Operator {
	t.Helper()
	var cfgs []IssuerConfig
	if err := json.Unmarshal([]byte(fedIssuers), &cfgs); err != nil {
		t.Fatal(err)
	}
	issuers, err := compileIssuers(cfgs)
	if err != nil {
		t.Fatal(err)
	}
	return &Operator{Issuers: issuers, RoutedModels: []string{"model-a", "model-b"},
		Sources: []string{"web", "push", "workload"}, AdminRoles: []string{"admin"}, MaxNamedTTL: time.Hour}
}

func fedEntries() []Entry {
	e := func(id, issuer, project string, sources []string, model string) Entry {
		return Entry{ID: id, Kind: KindProtected, Issuer: issuer, ProjectPath: project, Ref: "main",
			Sources: sources, Models: []string{model}, TriggerUsers: []string{}, Enabled: true}
	}
	return []Entry{
		e("gl1-app", "", "group/app", []string{"web"}, "model-a"),
		// The same project path under another GitLab: a different identity.
		e("gl2-app", "gitlab-2", "group/app", []string{"web"}, "model-b"),
		e("gh-app", "actions-1", "acme/app", []string{"push"}, "model-a"),
		e("k8s-ns", "cluster-1", "team-a", []string{"workload"}, "model-a"),
	}
}

// fedToken is a valid payload for the issuer, with overrides (nil deletes a claim).
func fedToken(id string, over map[string]any) []byte {
	exp, iat := fedNow.Unix()+300, fedNow.Unix()-60
	var c map[string]any
	switch id {
	case "gitlab-1", "gitlab-2":
		host := id + ".example.com"
		c = map[string]any{"iss": "https://" + host, "aud": "broker", "exp": exp, "iat": iat,
			"project_path": "group/app", "ref": "main", "ref_type": "branch", "ref_protected": "true",
			"pipeline_source": "web", "user_login": "alice",
			"ci_config_ref_uri": host + "/group/app//.gitlab-ci.yml@refs/heads/main"}
	case "actions-1":
		c = map[string]any{"iss": "https://actions.example.com", "aud": "broker", "exp": exp, "iat": iat,
			"sub": "repo:acme/app:ref:refs/heads/main", "repository": "acme/app", "repository_owner": "acme",
			"ref": "refs/heads/main", "ref_type": "branch", "event_name": "push", "actor": "alice",
			"job_workflow_ref": "acme/app/.github/workflows/ci.yml@refs/heads/main"}
	case "cluster-1":
		c = map[string]any{"iss": "https://k8s.example.com", "aud": "broker", "exp": exp, "iat": iat,
			"sub":           "system:serviceaccount:team-a:runner",
			"kubernetes.io": map[string]any{"namespace": "team-a", "serviceaccount": map[string]any{"name": "runner"}}}
	}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	raw, _ := json.Marshal(c)
	return raw
}

func TestFederatedDecisionPerIssuer(t *testing.T) {
	o := fedOperator(t)
	by := map[string]*Issuer{}
	for _, is := range o.Issuers {
		by[is.ID] = is
	}
	type tc struct {
		header string // the issuer whose edge header carries the payload
		token  []byte
		model  string
		want   string // reason, or the principal when allowed
		allow  bool
	}
	cases := map[string]tc{}
	allowed := map[string][2]string{ // issuer -> principal, model
		"gitlab-1": {"ci:group/app", "model-a"}, "gitlab-2": {"ci:gitlab-2:group/app", "model-b"},
		"actions-1": {"ci:actions-1:acme/app", "model-a"}, "cluster-1": {"ci:cluster-1:team-a", "model-a"},
	}
	maxLife := map[string]int64{"gitlab-1": 3600, "gitlab-2": 3600, "actions-1": 600, "cluster-1": 3600}
	projectClaim := map[string]string{"gitlab-1": "project_path", "gitlab-2": "project_path",
		"actions-1": "repository", "cluster-1": "kubernetes.io"}
	for id, a := range allowed {
		p, m := a[0], a[1]
		cases[id+"/allow"] = tc{id, fedToken(id, nil), m, p, true}
		cases[id+"/wrong issuer"] = tc{id, fedToken(id, map[string]any{"iss": "https://other.example.com"}), m, ReasonWrongIssuer, false}
		cases[id+"/no issuer"] = tc{id, fedToken(id, map[string]any{"iss": nil}), m, ReasonBadClaims, false}
		cases[id+"/wrong audience"] = tc{id, fedToken(id, map[string]any{"aud": "other"}), m, ReasonWrongAudience, false}
		cases[id+"/list audience"] = tc{id, fedToken(id, map[string]any{"aud": []string{"broker"}}), m, ReasonWrongAudience, false}
		cases[id+"/expired"] = tc{id, fedToken(id, map[string]any{"exp": fedNow.Unix()}), m, ReasonTokenExpired, false}
		cases[id+"/lifetime at cap"] = tc{id, fedToken(id, map[string]any{"iat": fedNow.Unix() + 300 - maxLife[id]}), m, p, true}
		cases[id+"/lifetime over cap"] = tc{id, fedToken(id, map[string]any{"iat": fedNow.Unix() + 300 - maxLife[id] - 1}), m, ReasonTokenLifetime, false}
		cases[id+"/mapped claim missing"] = tc{id, fedToken(id, map[string]any{projectClaim[id]: nil}), m, ReasonBadClaims, false}
		cases[id+"/mapped claim not a string"] = tc{id, fedToken(id, map[string]any{projectClaim[id]: 7}), m, ReasonBadClaims, false}
		cases[id+"/mapped claim null"] = tc{id, fedToken(id, map[string]any{projectClaim[id]: json.RawMessage("null")}), m, ReasonBadClaims, false}
		cases[id+"/issued after it expires"] = tc{id, fedToken(id, map[string]any{"iat": fedNow.Unix() + 301}), m, ReasonTokenLifetime, false}
		cases[id+"/issued in the future"] = tc{id, fedToken(id, map[string]any{"iat": fedNow.Unix() + 1, "exp": fedNow.Unix() + 2}), m, ReasonTokenLifetime, false}
		cases[id+"/negative lifetime, far expiry"] = tc{id, fedToken(id, map[string]any{"exp": fedNow.Unix() + 86400, "iat": fedNow.Unix() + 86401}), m, ReasonTokenLifetime, false}
		cases[id+"/iat min int64, exp max"] = tc{id, fedToken(id, map[string]any{"iat": int64(math.MinInt64), "exp": int64(math.MaxInt64)}), m, ReasonTokenLifetime, false}
		cases[id+"/iat min int64"] = tc{id, fedToken(id, map[string]any{"iat": int64(math.MinInt64)}), m, ReasonTokenLifetime, false}
		cases[id+"/iat -1, exp max"] = tc{id, fedToken(id, map[string]any{"iat": -1, "exp": int64(math.MaxInt64)}), m, ReasonTokenLifetime, false}
		cases[id+"/iat 0, exp max"] = tc{id, fedToken(id, map[string]any{"iat": 0, "exp": int64(math.MaxInt64)}), m, ReasonTokenLifetime, false}
		cases[id+"/unknown extra claim ignored"] = tc{id, fedToken(id, map[string]any{"x_extra": "y"}), m, p, true}
		// Every other issuer's valid token, in this issuer's header: never decided as this one's.
		for other := range allowed {
			if other != id {
				cases[id+"/token of "+other] = tc{id, fedToken(other, nil), m, ReasonWrongIssuer, false}
			}
		}
	}
	// Same project path and ref under two GitLabs: each token reaches only its own issuer's entry.
	cases["gitlab-2/not gitlab-1's entry"] = tc{"gitlab-2", fedToken("gitlab-2", nil), "model-a", ReasonModelNotAllowed, false}
	cases["gitlab-1/not gitlab-2's entry"] = tc{"gitlab-1", fedToken("gitlab-1", nil), "model-b", ReasonModelNotAllowed, false}
	cases["gitlab-2/other host's config"] = tc{"gitlab-2", fedToken("gitlab-2", map[string]any{
		"ci_config_ref_uri": "gitlab-1.example.com/group/app//.gitlab-ci.yml@refs/heads/main"}), "model-b", ReasonNoMatch, false}
	// Generic-issuer specifics.
	cases["actions-1/require mismatch"] = tc{"actions-1", fedToken("actions-1", map[string]any{"repository_owner": "evil"}), "model-a", ReasonBadClaims, false}
	cases["actions-1/require missing"] = tc{"actions-1", fedToken("actions-1", map[string]any{"repository_owner": nil}), "model-a", ReasonBadClaims, false}
	cases["actions-1/ref without prefix"] = tc{"actions-1", fedToken("actions-1", map[string]any{"ref": "main"}), "model-a", ReasonBadClaims, false}
	cases["actions-1/tag ref"] = tc{"actions-1", fedToken("actions-1", map[string]any{"ref": "refs/tags/main"}), "model-a", ReasonBadClaims, false}
	cases["actions-1/other workflow"] = tc{"actions-1", fedToken("actions-1", map[string]any{
		"job_workflow_ref": "acme/app/.github/workflows/evil.yml@refs/heads/main"}), "model-a", ReasonNoMatch, false}
	cases["actions-1/source not listed"] = tc{"actions-1", fedToken("actions-1", map[string]any{"event_name": "pull_request"}), "model-a", ReasonNoMatch, false}
	cases["cluster-1/nested claim missing"] = tc{"cluster-1", fedToken("cluster-1", map[string]any{
		"kubernetes.io": map[string]any{"serviceaccount": map[string]any{"name": "runner"}}}), "model-a", ReasonBadClaims, false}
	cases["cluster-1/nested parent not an object"] = tc{"cluster-1", fedToken("cluster-1", map[string]any{"kubernetes.io": "team-a"}), "model-a", ReasonBadClaims, false}
	cases["cluster-1/other namespace"] = tc{"cluster-1", fedToken("cluster-1", map[string]any{
		"kubernetes.io": map[string]any{"namespace": "team-b"}}), "model-a", ReasonNoMatch, false}
	// Optional and constant-backed fields are claims too when mapped: null is refused, not "".
	cases["actions-1/optional sub null"] = tc{"actions-1", fedToken("actions-1", map[string]any{"sub": json.RawMessage("null")}), "model-a", ReasonBadClaims, false}
	cases["actions-1/actor null"] = tc{"actions-1", fedToken("actions-1", map[string]any{"actor": json.RawMessage("null")}), "model-a", ReasonBadClaims, false}
	cases["gitlab-1/optional user_login null"] = tc{"gitlab-1", fedToken("gitlab-1", map[string]any{"user_login": json.RawMessage("null")}), "model-a", ReasonBadClaims, false}
	cases["gitlab-1/optional ref_protected null"] = tc{"gitlab-1", fedToken("gitlab-1", map[string]any{"ref_protected": json.RawMessage("null")}), "model-a", ReasonBadClaims, false}
	cases["actions-1/require null"] = tc{"actions-1", fedToken("actions-1", map[string]any{"repository_owner": json.RawMessage("null")}), "model-a", ReasonBadClaims, false}
	cases["gitlab-1/boolean ref_protected"] = tc{"gitlab-1", fedToken("gitlab-1", map[string]any{"ref_protected": true}), "model-a", ReasonBadClaims, false}
	cases["gitlab-1/undecodable"] = tc{"gitlab-1", nil, "model-a", ReasonBadClaims, false}

	entries := fedEntries()
	for name, c := range cases {
		model := c.model
		d, _ := o.Decide(entries, fedNow, by[c.header], c.token, OpChat, &model)
		if c.allow {
			if !d.Allow || d.Principal != c.want || d.Model != model {
				t.Errorf("%s: %+v, want allow as %s", name, d, c.want)
			}
		} else if d.Allow || d.Reason != c.want {
			t.Errorf("%s: %+v, want %s", name, d, c.want)
		}
	}
	// No issuer at all (the header was not one of ours) fails closed.
	model := "model-a"
	if d, _ := o.Decide(entries, fedNow, nil, fedToken("gitlab-1", nil), OpChat, &model); d.Allow || d.Reason != ReasonBadClaims {
		t.Fatalf("nil issuer: %+v", d)
	}
}

// TestIssuersDistinctIdentities: disabling one GitLab's entry for a project never lets that
// GitLab's token reach the other GitLab's entry for the same project, and principals differ.
func TestIssuersDistinctIdentities(t *testing.T) {
	o := fedOperator(t)
	entries := fedEntries()
	entries[1].Enabled = false
	entries[1].Models = []string{"model-a"}
	model := "model-a"
	if d, _ := o.Decide(entries, fedNow, o.Issuers[1], fedToken("gitlab-2", nil), OpChat, &model); d.Allow || d.Reason != ReasonNoMatch {
		t.Fatalf("gitlab-2 token reached gitlab-1's entry: %+v", d)
	}
	seen := map[string]bool{}
	for _, e := range fedEntries() {
		if seen[e.Principal()] {
			t.Fatalf("principal %s shared", e.Principal())
		}
		seen[e.Principal()] = true
	}
	if errs := o.Validate(&Policy{Entries: fedEntries()}, fedNow); len(errs) != 0 {
		t.Fatalf("same project under two issuers refused: %v", errs)
	}
}

func TestValidateIssuerOnEntries(t *testing.T) {
	o := fedOperator(t)
	base := fedEntries()
	for name, c := range map[string]struct {
		mutate func(es []Entry) []Entry
		ok     bool
	}{
		"unknown issuer": {func(es []Entry) []Entry { es[0].Issuer = "gitlab-9"; return es }, false},
		"duplicate under one issuer": {func(es []Entry) []Entry {
			d := es[1]
			d.ID = "gl2-dup"
			return append(es, d)
		}, false},
		"single-segment gitlab project":  {func(es []Entry) []Entry { es[0].ProjectPath = "app"; return es }, false},
		"single-segment generic project": {func(es []Entry) []Entry { es[3].ProjectPath = "team-a"; return es }, true},
		"colon in generic project":       {func(es []Entry) []Entry { es[3].ProjectPath = "a:b"; return es }, false},
	} {
		es := c.mutate(append([]Entry(nil), base...))
		if errs := o.Validate(&Policy{Entries: es}, fedNow); (len(errs) == 0) != c.ok {
			t.Errorf("%s: %v", name, errs)
		}
	}
	// Naming the primary issuer explicitly is the same entry, the same principal.
	es := append([]Entry(nil), base...)
	es[0].Issuer = "gitlab-1"
	if errs := o.Validate(&Policy{Entries: es}, fedNow); len(errs) != 0 || es[0].Issuer != "" || es[0].Principal() != "ci:group/app" {
		t.Fatalf("explicit primary: %v %+v", errs, es[0])
	}
	// Without a primary issuer an entry must name one.
	noPrimary := fedOperator(t)
	noPrimary.Issuers = noPrimary.Issuers[1:]
	if errs := noPrimary.Validate(&Policy{Entries: base[:1]}, fedNow); len(errs) == 0 {
		t.Fatal("entry without issuer accepted with no primary issuer")
	}
}

func TestIssuerConfigFailsClosed(t *testing.T) {
	good := func() []map[string]any {
		var v []map[string]any
		json.Unmarshal([]byte(fedIssuers), &v)
		return v
	}
	for name, mutate := range map[string]func(v []map[string]any) []map[string]any{
		"none":                    func(v []map[string]any) []map[string]any { return nil },
		"duplicate id":            func(v []map[string]any) []map[string]any { v[1]["id"] = "gitlab-1"; return v },
		"bad id":                  func(v []map[string]any) []map[string]any { v[1]["id"] = "GitLab 2"; return v },
		"duplicate issuer":        func(v []map[string]any) []map[string]any { v[1]["issuer"] = v[0]["issuer"]; return v },
		"duplicate header":        func(v []map[string]any) []map[string]any { v[1]["claims_header"] = "x-ci-a"; return v },
		"no audience":             func(v []map[string]any) []map[string]any { delete(v[1], "audience"); return v },
		"two primaries":           func(v []map[string]any) []map[string]any { v[1]["primary"] = true; return v },
		"unknown type":            func(v []map[string]any) []map[string]any { v[1]["type"] = "github"; return v },
		"generic no lifetime":     func(v []map[string]any) []map[string]any { v[2]["max_token_lifetime_seconds"] = 0; return v },
		"lifetime too long":       func(v []map[string]any) []map[string]any { v[1]["max_token_lifetime_seconds"] = 86401; return v },
		"gitlab with mapping":     func(v []map[string]any) []map[string]any { v[1]["mapping"] = v[2]["mapping"]; return v },
		"gitlab without template": func(v []map[string]any) []map[string]any { delete(v[1], "config_ref_template"); return v },
		"template reversed": func(v []map[string]any) []map[string]any {
			v[1]["config_ref_template"] = "{ref}/{project_path}"
			return v
		},
		"generic missing project": func(v []map[string]any) []map[string]any {
			delete(v[2]["mapping"].(map[string]any), "project")
			return v
		},
		"generic unknown field": func(v []map[string]any) []map[string]any {
			v[2]["mapping"].(map[string]any)["repository"] = map[string]any{"claim": "x"}
			return v
		},
		"config_ref unmapped with template": func(v []map[string]any) []map[string]any {
			v[3]["config_ref_template"] = "{project_path}@{ref}"
			return v
		},
		"config_ref mapped without template": func(v []map[string]any) []map[string]any {
			delete(v[2], "config_ref_template")
			return v
		},
		"claim and const": func(v []map[string]any) []map[string]any {
			v[2]["mapping"].(map[string]any)["ref"] = map[string]any{"claim": "ref", "const": "main"}
			return v
		},
		"empty claim path": func(v []map[string]any) []map[string]any {
			v[2]["mapping"].(map[string]any)["ref"] = map[string]any{"claim": []string{}}
			return v
		},
		"empty require value": func(v []map[string]any) []map[string]any {
			v[2]["require"] = map[string]any{"repository_owner": ""}
			return v
		},
	} {
		raw, _ := json.Marshal(mutate(good()))
		var cfgs []IssuerConfig
		if err := json.Unmarshal(raw, &cfgs); err != nil {
			continue // refused while parsing
		}
		if _, err := compileIssuers(cfgs); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestSingleIssuerConfigRefused: the pre-federation top-level issuer fields and headers.claims
// no longer load, so a deployment cannot keep running on a config the broker no longer reads.
func TestSingleIssuerConfigRefused(t *testing.T) {
	raw, err := os.ReadFile("examples/config.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(raw, &m)
	for name, mutate := range map[string]func(m map[string]any){
		"top-level issuer":   func(m map[string]any) { m["issuer"] = "https://gitlab.example.com" },
		"top-level audience": func(m map[string]any) { m["audience"] = "badger-broker" },
		"top-level template": func(m map[string]any) { m["ci_config_ref_template"] = "{project_path}@{ref}" },
		"headers.claims":     func(m map[string]any) { m["headers"].(map[string]any)["claims"] = "x-broker-ci-claims" },
		"claims header reuses a header": func(m map[string]any) {
			m["issuers"].([]any)[0].(map[string]any)["claims_header"] = "x-broker-principal"
		},
	} {
		var c map[string]any
		json.Unmarshal(raw, &c)
		mutate(c)
		out, _ := json.Marshal(c)
		path := filepath.Join(t.TempDir(), "config.json")
		os.WriteFile(path, out, 0o600)
		if _, err := LoadConfig(path); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	path := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(path, raw, 0o600)
	if _, err := LoadConfig(path); err != nil {
		t.Fatalf("example config: %v", err)
	}
}

// fedEdgeCall sends a pipeline call carrying the given headers to the fixture's edge listener.
func fedEdgeCall(f *fixture, headers map[string]string, body string) (int, string) {
	w := do(f.edge, "POST", "/v1/chat/completions", headers, body)
	return w.Code, w.Header().Get("X-Broker-Usage-Principal")
}

// TestEdgeBindsPayloadToItsIssuerHeader: end to end through the edge listener with two GitLabs.
func TestEdgeBindsPayloadToItsIssuerHeader(t *testing.T) {
	f := newFixture(t, false)
	c, _ := loadCorpus(t)
	entries := append(append([]Entry(nil), c.Entries...), Entry{ID: "alpha-gl2", Kind: KindProtected, Issuer: "gitlab-2",
		ProjectPath: "group/alpha", Ref: "main", Sources: []string{"web"}, Models: []string{"model-b"},
		TriggerUsers: []string{}, Enabled: true})
	res, err := f.b.store.Put(f.b.op, f.b.store.Active().N, entries, "u1", "", "second gitlab", testNow)
	if err != nil || res.Version == nil {
		t.Fatalf("put: %+v %v", res, err)
	}
	owners := map[string]string{}
	for _, e := range entries {
		owners[e.ID] = "alice@example.com"
	}
	cur, _ := f.b.owners.current()
	if _, err := f.b.owners.put(cur.Version, owners); err != nil {
		t.Fatal(err)
	}
	gl2 := func(over map[string]any) string {
		o := map[string]any{"iss": testIssuer2, "ci_config_ref_uri": "gitlab-2.example.com/group/alpha//.gitlab-ci.yml@refs/heads/main"}
		for k, v := range over {
			o[k] = v
		}
		return payload(o)
	}
	chatB := `{"model":"model-b","messages":[]}`
	if code, p := fedEdgeCall(f, map[string]string{testHeader2: gl2(nil)}, chatB); code != 200 || p != "ci:gitlab-2:group/alpha" {
		t.Fatalf("second gitlab: %d %q", code, p)
	}
	if code, p := fedEdgeCall(f, map[string]string{"x-broker-ci-claims": payload(nil)}, chatA); code != 200 || p != "ci:group/alpha" {
		t.Fatalf("primary gitlab: %d %q", code, p)
	}
	for name, c := range map[string]struct {
		headers map[string]string
		body    string
		want    int
	}{
		"same project, other gitlab's model":   {map[string]string{testHeader2: gl2(nil)}, chatA, 403},
		"primary token in second header":       {map[string]string{testHeader2: payload(nil)}, chatA, 401},
		"second token in primary header":       {map[string]string{"x-broker-ci-claims": gl2(nil)}, chatB, 401},
		"both headers":                         {map[string]string{"x-broker-ci-claims": payload(nil), testHeader2: gl2(nil)}, chatA, 401},
		"second gitlab lifetime over cap":      {map[string]string{testHeader2: gl2(map[string]any{"iat": testNow.Unix() + 3000 - 3601})}, chatB, 401},
		"second gitlab, primary's config file": {map[string]string{testHeader2: gl2(map[string]any{"ci_config_ref_uri": "gitlab.example.com/group/alpha//.gitlab-ci.yml@refs/heads/main"})}, chatB, 403},
	} {
		if code, _ := fedEdgeCall(f, c.headers, c.body); code != c.want {
			t.Errorf("%s: %d, want %d", name, code, c.want)
		}
	}
	// Any issuer's header is a pipeline payload: refused on the internal listener and the admin API.
	tok := f.issue("ws-alice", "alice@example.com")
	if w := do(f.internal, "POST", "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + tok, testHeader2: gl2(nil)}, chatA); w.Code != 401 {
		t.Fatalf("internal with second header: %d", w.Code)
	}
	if w := do(f.edge, "GET", "/admin/v1/policy", with(admin("u1"), testHeader2, gl2(nil)), ""); w.Code != 403 {
		t.Fatalf("admin with second header: %d", w.Code)
	}
}

// TestDenialLogNamesTheIssuer: a payload that does not map is still attributed to the issuer whose
// header carried it.
func TestDenialLogNamesTheIssuer(t *testing.T) {
	f := newFixture(t, false)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	bad := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + testIssuer2 + `"}`))
	if code, _ := fedEdgeCall(f, map[string]string{testHeader2: bad}, chatA); code != 401 {
		t.Fatalf("malformed payload: %d", code)
	}
	if !strings.Contains(buf.String(), "reason=bad_claims") || !strings.Contains(buf.String(), "issuer=gitlab-2") {
		t.Fatalf("denial log: %q", buf.String())
	}
}
