package broker

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// The page says who enforces which limit and when a change takes effect.
func TestConsoleStatesEnforcement(t *testing.T) {
	f := newFixture(t, false)
	page := do(f.admin, "GET", "/admin/v1/ui/", admin("u1"), "").Body.String()
	for _, want := range []string{
		"Spend and output: enforced by the broker on every call",
		"Agent behavior: applied by the managed agent when a session starts",
		"A change applies to new sessions only",
		"Workloads call the models directly, with no managed agent",
		"Days reset at 00:00 UTC; months at 00:00 UTC on the 1st.",
		`id="lk-who"`, `id="lt-uncapped"`, `id="ov-uncapped"`,
		"Max agent steps per request", "Timeout per model call (seconds)", "Context window (tokens)",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	for _, gone := range []string{"Steps per task", "Time per call", "New quota", `id="tab-quotas"`} {
		if strings.Contains(page, gone) {
			t.Errorf("page still has %q", gone)
		}
	}
}

// probe is a drive script's report: it writes JSON into <pre id="probe">, read back from the DOM.
const probeJS = `const probe=v=>{const p=document.createElement("pre");p.id="probe";p.textContent=JSON.stringify(v);document.body.append(p)};`

func readProbe(t *testing.T, dom string, into any) {
	t.Helper()
	m := regexp.MustCompile(`(?s)<pre id="probe">(.*?)</pre>`).FindStringSubmatch(dom)
	if m == nil {
		t.Fatalf("no probe in page: %s", dom[max(0, len(dom)-3000):])
	}
	text := strings.NewReplacer("&quot;", `"`, "&amp;", "&", "&lt;", "<", "&gt;", ">").Replace(m[1])
	if err := json.Unmarshal([]byte(text), into); err != nil {
		t.Fatalf("probe %s: %v", text, err)
	}
}

// With no default monthly limit, spending is not capped: Overview and Limits say so, and the
// button opens the editor already set to everyone's monthly limit. With a default, they do not.
func TestConsoleUncappedWarningInBrowser(t *testing.T) {
	chrome := findChrome(t)
	f := newFixture(t, false)
	drive := probeJS + waitThen(`#ov-tiles .card`, `const shown=!$("ov-uncapped").hidden, text=$("ov-uncapped").textContent;
$("ov-uncapped").querySelector("button").click();
setTimeout(()=>probe({shown,text,open:$("qd").open,scope:$("qd-scope").value,period:$("qd-period").value,tab:location.hash,limitsShown:!$("lt-uncapped").hidden}),300);`)
	var got struct {
		Shown, Open, LimitsShown bool
		Text, Scope, Period, Tab string
	}
	readProbe(t, chromeRun(t, chrome, "--dump-dom", consoleServer(t, f, "u1", drive).URL+"/admin/v1/ui/#overview"), &got)
	if !got.Shown || !strings.Contains(got.Text, "Spending is not capped. Set a default limit.") || !got.Open ||
		got.Scope != "default" || got.Period != "monthly_usd" || got.Tab != "#limits" || !got.LimitsShown {
		t.Fatalf("uncapped: %+v", got)
	}
	put(t, f, `"0"`, `{"default_usd":100,"principals":{},"defaults":{},"people":{}}`)
	drive = probeJS + waitThen(`#qt-table tr[data-who="default"]`, `probe({ov:!$("ov-uncapped").hidden,lt:!$("lt-uncapped").hidden})`)
	var capped struct{ Ov, Lt bool }
	readProbe(t, chromeRun(t, chrome, "--dump-dom", consoleServer(t, f, "u1", drive).URL+"/admin/v1/ui/#limits"), &capped)
	if capped.Ov || capped.Lt {
		t.Fatalf("capped deployment still warns: %+v", capped)
	}
}

// The effective-limits lookup resolves each field: the principal's own value, else the default,
// else the agent's built-in value. A workload has no agent limits.
func TestConsoleEffectiveLimitsInBrowser(t *testing.T) {
	chrome := findChrome(t)
	f := newFixture(t, false)
	put(t, f, `"0"`, `{"default_usd":50,"principals":{"bob@example.com":30},"defaults":{"daily_usd":10,"steps":60},
"people":{"alice@example.com":{"steps":80,"output":4000},"ci:group/alpha":{"output":2000}}}`)
	drive := probeJS + waitThen(`#qt-table tr[data-who="default"]`, `const out={};
for (const who of ["alice@example.com","bob@example.com","ci:group/alpha"]) {
  $("lk-who").value=who; $("lk-go").click();
  out[who]=Object.fromEntries([...document.querySelectorAll("#lk-table tr[data-field]")].map(r=>[r.dataset.field,[r.dataset.source,r.cells[1].textContent]]));
}
probe(out);`)
	var got map[string]map[string][2]string
	readProbe(t, chromeRun(t, chrome, "--dump-dom", consoleServer(t, f, "u1", drive).URL+"/admin/v1/ui/#limits"), &got)
	want := map[string]map[string][2]string{
		"alice@example.com": {"monthly_usd": {"default", "$50.00"}, "daily_usd": {"default", "$10.00"}, "call_usd": {"none", "No limit"},
			"output": {"own", "4,000 tokens"}, "steps": {"own", "80"}, "context": {"built-in", "131,072 tokens"}, "timeout_seconds": {"built-in", "230 s"}},
		"bob@example.com": {"monthly_usd": {"own", "$30.00"}, "output": {"built-in", "16,384 tokens"}, "steps": {"default", "60"}},
		"ci:group/alpha":  {"monthly_usd": {"default", "$50.00"}, "output": {"own", "2,000 tokens"}},
	}
	for who, fields := range want {
		for k, v := range fields {
			if got[who][k] != v {
				t.Errorf("%s %s = %v, want %v", who, k, got[who][k], v)
			}
		}
	}
	for _, k := range []string{"steps", "context", "timeout_seconds"} {
		if _, ok := got["ci:group/alpha"][k]; ok {
			t.Errorf("a workload is shown an agent limit %s", k)
		}
	}
}

// Agent limits are for people: the picker offers no workload, a workload typed in is refused, and
// the agent table shows the built-in values as formatted numbers.
func TestConsoleAgentLimitsPeopleOnlyInBrowser(t *testing.T) {
	chrome := findChrome(t)
	f := newFixture(t, false)
	drive := probeJS + waitThen(`#lm-table tr[data-who="default"]`, `const people=[...$("ld-people").options].map(o=>o.value);
const def=$("lm-table").querySelector('tr[data-who="default"]').textContent;
$("lm-new").click(); $("ld-who").value="ci:group/alpha"; $("ld-steps").value="9"; $("ld-reason").value="x"; $("ld-save").click();
setTimeout(()=>probe({people,def,msg:$("ld-msg").textContent,max:$("ld-context").max}),300);`)
	var got struct {
		People        []string
		Def, Msg, Max string
	}
	readProbe(t, chromeRun(t, chrome, "--dump-dom", consoleServer(t, f, "u1", drive).URL+"/admin/v1/ui/#limits"), &got)
	if len(got.People) == 0 || strings.Contains(strings.Join(got.People, " "), "ci:") {
		t.Errorf("agent-limit picker offers %v", got.People)
	}
	if !strings.Contains(got.Msg, "people only") {
		t.Errorf("a workload's agent limits were not refused: %q", got.Msg)
	}
	for _, want := range []string{"40", "131,072 tokens", "230 s", "built-in"} {
		if !strings.Contains(got.Def, want) {
			t.Errorf("default agent row %q lacks %q", got.Def, want)
		}
	}
	if got.Max != "262144" {
		t.Errorf("context input max %q", got.Max)
	}
	if v := getLimits(t, f); len(v.People) != 0 {
		t.Fatalf("a workload's agent limits were saved: %+v", v.People)
	}
}
