package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/aflock-ai/badger/testifysec/connectors/internal/bundle"
	"github.com/aflock-ai/badger/testifysec/connectors/marking"
)

// corpPin is a profile's markingScheme entry for the corporate preset.
func corpPin(t *testing.T) string {
	return `,"markingScheme":{"preset":"corporate","sha256":"` + corporate(t).Digest() + `"}`
}

// policyJSON is a profile's markingPolicy entry on the corporate preset.
func policyJSON(t *testing.T, classify, def, flowRules string) string {
	return `,"markingPolicy":{"schema":"badger.marking-policy/v1","scheme":{"preset":"corporate","sha256":"` + corporate(t).Digest() +
		`"},"dataFlow":{"classify":{` + classify + `},"default":"` + def + `"` + flowRules + `}}`
}

// admitted loads a corporate profile for connector x (tools x_get, x_put) with the policy and admits it.
func admitted(t *testing.T, classification, policy string) (config, error) {
	t.Helper()
	vendor, vendorPriv := newKey(t)
	dir, digest := packBundle(t, []byte(script), "", vendorPriv)
	c, err := load(writeFile(t, "p.json", strings.Replace(profileJSON(b64(vendor), dir, digest, classification, userGrant), `"connectors"`, corpPin(t)[1:]+policy+`,"connectors"`, 1)))
	if err != nil {
		return c, err
	}
	return c, admit(&c)
}

// The profile's markingPolicy sets the connectors' markings, under the profile's own scheme, and
// is the only place that sets them.
func TestPolicyInTheProfile(t *testing.T) {
	both := `"INTERNAL":["connector:x/x_get"],"RESTRICTED//PII":["connector:x/x_put"]`
	if _, err := admitted(t, "", policyJSON(t, both, "refuse", "")); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct{ classification, policy, want string }{
		"classification and policy": {"INTERNAL", policyJSON(t, both, "refuse", ""), "set in one place"},
		"policy on another scheme":  {"", `,"markingPolicy":{"schema":"badger.marking-policy/v1","dataFlow":{"classify":{},"default":"refuse"}}`, "the profile pins"},
		"url source":                {"", policyJSON(t, `"INTERNAL":["url:example.invalid"]`, "refuse", ""), "url sources"},
		"unparseable flow rule":     {"", policyJSON(t, both, "refuse", `,"flowRules":[{"deny":"PII"}]`), "flowRules[0]"},
		"default below the top":     {"", policyJSON(t, both, "INTERNAL", ""), "never lower"},
		"neither":                   {"", "", "classification"},
	} {
		if _, err := admitted(t, c.classification, c.policy); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// At start every tool a connector's signed manifest lists must have a marking: the gateway refuses
// to start, naming each tool the policy leaves out, instead of refusing calls one by one later.
func TestEveryToolIsCoveredAtStart(t *testing.T) {
	_, err := admitted(t, "", policyJSON(t, `"INTERNAL":["connector:x/x_get"]`, "refuse", ""))
	if err == nil || !strings.Contains(err.Error(), "connector:x/x_put") || strings.Contains(err.Error(), "connector:x/x_get") {
		t.Fatalf("uncovered tool: %v", err)
	}
	// A top-level default covers every unmapped tool.
	c, err := admitted(t, "", policyJSON(t, `"INTERNAL":["connector:x/x_get"]`, "RESTRICTED", ""))
	if err != nil {
		t.Fatal(err)
	}
	if got := marking.Banner(c.Sources[0].markingOf("x_put")); got != "RESTRICTED" {
		t.Errorf("x_put under the default: %s", got)
	}
}

// Each tool has its own marking. The connector's marking, which callers declare and the plugin is
// started with, is the join of its tools': the workspace's own check is coarser, never lower.
func TestToolsHaveTheirOwnMarkings(t *testing.T) {
	c, err := admitted(t, "", policyJSON(t, `"INTERNAL":["connector:x/*"],"CONFIDENTIAL//PHI":["connector:x/x_put"],"RESTRICTED//PCI":["connector:x/x_put"]`, "refuse", ""))
	if err != nil {
		t.Fatal(err)
	}
	s := c.Sources[0]
	if got := marking.Banner(s.markingOf("x_get")); got != "INTERNAL" {
		t.Errorf("x_get %s", got)
	}
	// Several matches join: incomparable markings give one above both, never either one.
	if got := marking.Banner(s.markingOf("x_put")); got != "RESTRICTED//PCI/PHI" {
		t.Errorf("x_put %s", got)
	}
	if marking.Banner(s.marking) != "RESTRICTED//PCI/PHI" || s.hello().Classification != "RESTRICTED//PCI/PHI" {
		t.Errorf("connector marking %s, hello %s", marking.Banner(s.marking), s.hello().Classification)
	}
	if !s.matches(declared{Classification: "RESTRICTED//PCI/PHI", Scheme: corporate(t).Digest()}) {
		t.Error("the declaration of the connector's join refused")
	}
	if s.matches(declared{Classification: "INTERNAL", Scheme: corporate(t).Digest()}) {
		t.Error("a declaration of one tool's lower marking matched")
	}
}

// underCorporate runs the calling test again in a child test binary whose process scheme is the
// corporate preset, as conngw's main configures the profile's before it serves (labels are joined
// and compared under the process scheme, which is set once). It reports whether this is the child,
// which runs the test's body.
func underCorporate(t *testing.T) bool {
	t.Helper()
	if os.Getenv("CONNGW_TEST_SCHEME") == "corporate" {
		return true
	}
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), "CONNGW_TEST_SCHEME=corporate")
	if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "PASS") {
		t.Fatalf("under the corporate scheme: %v\n%s", err, out)
	}
	return false
}

// policySource is connector name with tools x_get and x_put, admitted under a corporate policy.
func policySource(t *testing.T, name, classify, flowRules string) source {
	t.Helper()
	p, err := marking.LoadPolicy("p", []byte(policyJSON(t, classify, "refuse", flowRules)[len(`,"markingPolicy":`):]), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := source{Name: name, scheme: p.Scheme, manifest: &bundle.Manifest{Schema: 1, Name: name, Version: "1.0.0", Tools: testTools}}
	if err := s.classify(p); err != nil {
		t.Fatal(err)
	}
	return s
}

// both permits x_get and x_put.
func both() *permit {
	return &permit{tools: map[string]bundle.Tool{"x_get": testTools[0], "x_put": testTools[1]}, writes: true}
}

// framed answers every request with one text item framed by banner.
type framed struct{ banner string }

func (f *framed) start(source) (*process, error) {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	go func() {
		defer outW.Close()
		dec := json.NewDecoder(inR)
		for {
			var m message
			if dec.Decode(&m) != nil {
				return
			}
			b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{
				"content": []any{map[string]any{"type": "text", "text": f.banner + "\ndata\n" + f.banner}}}})
			if _, err := outW.Write(append(b, '\n')); err != nil {
				return
			}
		}
	}()
	return &process{in: inW, out: outR, stop: func() { _ = inR.Close(); _ = outR.Close() }}, nil
}

// toolSession runs one stream to src with permit perm; the log goes to logs.
func toolSession(t *testing.T, l *labels, ws string, src source, logs *bytes.Buffer) (call func(tool string) string, closeFn func()) {
	t.Helper()
	f := &framed{banner: marking.Banner(src.marking)}
	p, _ := f.start(src)
	clientR, clientW := io.Pipe()
	replyR, replyW := io.Pipe()
	log := slog.New(slog.DiscardHandler)
	if logs != nil {
		log = slog.New(slog.NewJSONHandler(logs, nil))
	}
	s := &stream{ws: ws, conn: src, labels: l, log: log, pending: map[string]bool{}, perm: both()}
	go func() { _ = s.answers(p.out, replyW) }()
	go func() { _ = s.requests(clientR, replyW, p.in); _ = p.in.Close() }()
	r := json.NewDecoder(replyR)
	id := 0
	call = func(tool string) string {
		id++
		line := `{"jsonrpc":"2.0","id":` + strings.Repeat("1", id) + `,"method":"tools/call","params":{"name":"` + tool + `","arguments":{}}}`
		if _, err := clientW.Write([]byte(line + "\n")); err != nil {
			t.Fatal(err)
		}
		var reply json.RawMessage
		if err := r.Decode(&reply); err != nil {
			t.Fatal(err)
		}
		return string(reply)
	}
	return call, func() { _ = clientW.Close(); p.stop() }
}

// A read raises the workspace's label to the tool's marking, not the connector's; the answer is
// framed and marked with the tool's marking; and a call goes through only when the tool's marking
// dominates the label.
func TestAReadRaisesToTheToolsMarking(t *testing.T) {
	if !underCorporate(t) {
		return
	}
	src := policySource(t, "x", `"INTERNAL":["connector:x/x_get"],"RESTRICTED//PII":["connector:x/x_put"]`, "")
	l := newLabels()
	call, done := toolSession(t, l, "ws/a", src, nil)
	defer done()
	got := call("x_get")
	if !strings.Contains(got, `"text":"INTERNAL\ndata\nINTERNAL"`) || !strings.Contains(got, `"banner":"INTERNAL"`) {
		t.Fatalf("x_get answer %s", got)
	}
	if label, _, _, _, _ := l.describe("ws/a"); marking.Banner(label) != "INTERNAL" {
		t.Fatalf("label %s after an INTERNAL read", marking.Banner(label))
	}
	if got := call("x_put"); !strings.Contains(got, `"banner":"RESTRICTED//PII"`) || strings.Contains(got, "refused") {
		t.Fatalf("x_put answer %s", got)
	}
	// The label is now RESTRICTED//PII: the INTERNAL tool could carry it down, so it is refused.
	if got := call("x_get"); !strings.Contains(got, "refused by the connector gateway") || !strings.Contains(got, "RESTRICTED//PII") {
		t.Fatalf("x_get after a PII read: %s", got)
	}
}

// A flow rule refuses a call dominance would allow, with its own message; without the rule the same
// call goes through.
func TestFlowRulesOnlyDeny(t *testing.T) {
	if !underCorporate(t) {
		return
	}
	classify := `"RESTRICTED//PII":["connector:x/*"]`
	for _, rule := range []string{"", `,"flowRules":[{"deny":"PII->connector:x/x_put","message":"PII is never written back"}]`} {
		src := policySource(t, "x", classify, rule)
		call, done := toolSession(t, newLabels(), "ws/a", src, nil)
		call("x_get")
		got := call("x_put")
		done()
		if refused := strings.Contains(got, "PII is never written back"); refused != (rule != "") {
			t.Errorf("rule %q: %s", rule, got)
		}
	}
	// A rule never allows: a call dominance refuses stays refused whatever the rules say.
	src := policySource(t, "x", `"INTERNAL":["connector:x/x_get"],"RESTRICTED//PII":["connector:x/x_put"]`, `,"flowRules":[{"deny":"PCI->connector:x/*"}]`)
	call, done := toolSession(t, newLabels(), "ws/a", src, nil)
	defer done()
	call("x_put")
	if got := call("x_get"); !strings.Contains(got, "could carry that content down") {
		t.Errorf("dominance refusal: %s", got)
	}
}

// Every raise is an audit event: the workspace, the source, the label before and after, and the
// scheme. A read that does not change the label is not one.
func TestEachRaiseIsAnAuditEvent(t *testing.T) {
	if !underCorporate(t) {
		return
	}
	src := policySource(t, "x", `"INTERNAL":["connector:x/x_get"],"RESTRICTED//PII":["connector:x/x_put"]`, "")
	var logs bytes.Buffer
	call, done := toolSession(t, newLabels(), "ws/a", src, &logs)
	call("x_get")
	call("x_get")
	call("x_put")
	done()
	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var e map[string]any
		if json.Unmarshal([]byte(line), &e) == nil && e["event"] == "label.raised" {
			events = append(events, e)
		}
	}
	want := []struct{ source, from, to string }{{"connector:x/x_get", "", "INTERNAL"}, {"connector:x/x_put", "INTERNAL", "RESTRICTED//PII"}}
	if len(events) != len(want) {
		t.Fatalf("audit events %v", events)
	}
	for i, w := range want {
		e := events[i]
		if e["workspace"] != "ws/a" || e["source"] != w.source || e["from"] != w.from || e["to"] != w.to || e["scheme"] != corporate(t).Digest() {
			t.Errorf("event %d: %v, want %+v", i, e, w)
		}
	}
}

// aflock #25, the shell path: content does not need the agent's tool calls to leave. Once a
// workspace has read RESTRICTED//PII through the gateway, a raw MCP stream from the same workspace
// (a shell command speaking MCP to the pod, no bridge, no agent) to an INTERNAL connector is refused
// by the gateway, because the label belongs to the workspace, not to a stream or a process.
func TestTheShellPathMeetsTheSameLabel(t *testing.T) {
	if !underCorporate(t) {
		return
	}
	classify := `"RESTRICTED//PII":["connector:hr/*"],"INTERNAL":["connector:wiki/*"]`
	hr, wiki := policySource(t, "hr", classify, ""), policySource(t, "wiki", classify, "")
	l := newLabels()
	agent, done := toolSession(t, l, "ws/a", hr, nil)
	if got := agent("x_get"); strings.Contains(got, "refused") {
		t.Fatalf("hr read: %s", got)
	}
	done()
	shell, done := toolSession(t, l, "ws/a", wiki, nil)
	defer done()
	if got := shell("x_put"); !strings.Contains(got, "refused by the connector gateway") {
		t.Fatalf("raw stream to an INTERNAL connector after a PII read: %s", got)
	}
	// Another workspace is not affected.
	other, done2 := toolSession(t, l, "ws/b", wiki, nil)
	defer done2()
	if got := other("x_put"); strings.Contains(got, "refused") {
		t.Fatalf("another workspace: %s", got)
	}
}
