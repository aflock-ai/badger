package broker

import (
	"bytes"
	"encoding/base64"
	"log"
	"os"
	"strings"
	"testing"
)

// A pipeline refused because no policy entry matched gets one answer, whatever the cause, so the
// response does not hand a caller the policy. The broker's log says which check failed for the
// closest entry, so an admin can see why.
func TestNoMatchRefusalSaysWhyInTheLogOnly(t *testing.T) {
	f := newFixture(t, false)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	gl2 := func(over map[string]any) string {
		c := map[string]any{"iss": testIssuer2, "ci_config_ref_uri": "gitlab-2.example.com/group/alpha//.gitlab-ci.yml@refs/heads/main"}
		for k, v := range over {
			c[k] = v
		}
		return payload(c)
	}
	cases := []struct {
		name, header, payload, detail string
	}{
		{"source", "x-broker-ci-claims", payload(map[string]any{"pipeline_source": "push"}), "source"},
		{"tag", "x-broker-ci-claims", payload(map[string]any{"ref_type": "tag"}), "ref_type"},
		{"project", "x-broker-ci-claims", payload(map[string]any{"project_path": "group/unknown",
			"ci_config_ref_uri": "gitlab.example.com/group/unknown//.gitlab-ci.yml@refs/heads/main"}), "project"},
		{"ref", "x-broker-ci-claims", payload(map[string]any{"ref": "dev",
			"ci_config_ref_uri": "gitlab.example.com/group/alpha//.gitlab-ci.yml@refs/heads/dev"}), "ref"},
		{"unprotected", "x-broker-ci-claims", payload(map[string]any{"ref_protected": "false"}), "protected"},
		{"config", "x-broker-ci-claims", payload(map[string]any{"ci_config_ref_uri": "gitlab.example.com/other//.gitlab-ci.yml@refs/heads/main"}), "config_ref"},
		{"issuer without entries", testHeader2, gl2(nil), "issuer"},
	}
	var first string
	for _, c := range cases {
		buf.Reset()
		w := do(f.edge, "POST", "/v1/chat/completions", map[string]string{c.header: c.payload}, chatA)
		if w.Code != 403 {
			t.Fatalf("%s: %d %s", c.name, w.Code, w.Body)
		}
		if first == "" {
			first = w.Body.String()
		} else if w.Body.String() != first {
			t.Fatalf("%s: refusal body %q differs from %q: the response must not say why", c.name, w.Body, first)
		}
		if strings.Contains(w.Body.String(), c.detail) || w.Header().Get("X-Broker-Refusal") != "" {
			t.Fatalf("%s: the response names the cause: %q", c.name, w.Body)
		}
		if !strings.Contains(buf.String(), "reason=no_match detail="+c.detail+" ") {
			t.Fatalf("%s: log %q lacks detail=%s", c.name, buf.String(), c.detail)
		}
	}
	if f.calls.Load() != 0 {
		t.Fatalf("a refused call reached the upstream")
	}
}

// Refusals that already have their own reason carry no detail.
func TestOtherRefusalsHaveNoDetail(t *testing.T) {
	f := newFixture(t, false)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	w := do(f.edge, "POST", "/v1/chat/completions", map[string]string{"x-broker-ci-claims": payload(nil)},
		`{"model":"model-b","messages":[{"role":"user","content":"hi"}]}`)
	if w.Code != 403 || !strings.Contains(buf.String(), "reason=model_not_allowed detail=- ") {
		t.Fatalf("%d %q", w.Code, buf.String())
	}
}

// NoMatchDetail on its own: the closest entry is the one that passes the most checks.
func TestNoMatchDetailPicksTheClosestEntry(t *testing.T) {
	f := newFixture(t, false)
	is := f.b.op.issuerByKey("")
	for _, c := range []struct {
		over   map[string]any
		detail string
	}{
		// group/sub/beta has a protected entry on "stable" and a named entry on "feat/x-1": a
		// protected run on "feat/x-1" fails the protected entry on its ref and the named entry
		// later, on protection. The named entry is the closer one.
		{map[string]any{"project_path": "group/sub/beta", "ref": "feat/x-1",
			"ci_config_ref_uri": "gitlab.example.com/group/sub/beta//.gitlab-ci.yml@refs/heads/feat/x-1"}, "protected"},
		// The same run, unprotected, from a trigger user the named entry does not list.
		{map[string]any{"project_path": "group/sub/beta", "ref": "feat/x-1", "ref_protected": "false", "user_login": "mallory",
			"ci_config_ref_uri": "gitlab.example.com/group/sub/beta//.gitlab-ci.yml@refs/heads/feat/x-1"}, "trigger_user"},
	} {
		raw, _ := base64.RawURLEncoding.DecodeString(payload(c.over))
		env, _ := parseEnvelope(raw)
		s, ok := is.subject(env)
		if !ok {
			t.Fatal("subject")
		}
		if got := f.b.op.NoMatchDetail(f.b.store.Active().Entries, testNow, is, s); got != c.detail {
			t.Fatalf("%v: detail %q, want %q", c.over, got, c.detail)
		}
	}
}
