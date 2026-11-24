package broker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// findChrome is the browser the console tests drive: BADGER_TEST_CHROME, or a usual install.
func findChrome(t *testing.T) string {
	t.Helper()
	chrome := os.Getenv("BADGER_TEST_CHROME")
	if chrome == "" {
		for _, c := range []string{"/usr/bin/google-chrome", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"} {
			if _, err := os.Stat(c); err == nil {
				chrome = c
			}
		}
	}
	if chrome == "" {
		t.Skip("BADGER_TEST_CHROME not set and no Chrome found: the console was not run in a browser")
	}
	return chrome
}

// consoleServer is the edge's part in front of the fixture's admin listener: every request carries
// the signed-in admin, and its own name. When drive is set, the page also loads drive.js (served
// from the same origin, so the console's script-src 'self' admits it), which acts as a person would.
func consoleServer(t *testing.T, f *fixture, who, drive string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range admin(who) {
			r.Header.Set(k, v)
		}
		r.Header.Del("Origin")
		switch r.URL.Path {
		case "/admin/v1/ui/drive.js":
			w.Header().Set("Content-Type", "text/javascript")
			w.Write([]byte(drive))
			return
		case "/admin/v1/ui/":
			rec := httptest.NewRecorder()
			f.admin.ServeHTTP(rec, r)
			for k, v := range rec.Header() {
				w.Header()[k] = v
			}
			body := rec.Body.String()
			if drive != "" {
				body = strings.Replace(body, "</body>", `<script src="drive.js" defer></script></body>`, 1)
			}
			w.Write([]byte(body))
			return
		}
		f.admin.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func chromeRun(t *testing.T, chrome string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	base := []string{"--headless=new", "--no-sandbox", "--disable-gpu", "--user-data-dir=" + t.TempDir(), "--virtual-time-budget=20000"}
	out, err := exec.CommandContext(ctx, chrome, append(base, args...)...).Output()
	if err != nil {
		t.Fatalf("chrome: %v", err)
	}
	return string(out)
}

// waitThen runs body once sel exists in the page (the tab has rendered).
func waitThen(sel, body string) string {
	return `(function go(n){const x=document.querySelector(` + "`" + sel + "`" + `);if(!x){return n>0&&setTimeout(()=>go(n-1),100)}` + body + `})(80);`
}

// The Agent limits tab, in a real headless Chrome: an admin edits a person's steps from the
// dialog, and what the page saved is what the broker then holds, audited with the reason.
func TestConsoleAgentLimitsInBrowser(t *testing.T) {
	chrome := findChrome(t)
	f := newFixture(t, false)
	put(t, f, `"0"`, `{"default_usd":1000,"principals":{},"defaults":{"daily_usd":100,"steps":40},"people":{"alice@example.com":{"steps":80}}}`)
	drive := waitThen(`#lm-table tr[data-who="alice@example.com"] button`, `x.click();$("ld-steps").value="120";$("ld-reason").value="ui test";$("ld-save").click();`)
	dom := chromeRun(t, chrome, "--dump-dom", consoleServer(t, f, "u1", drive).URL+"/admin/v1/ui/#limits")
	for _, want := range []string{`data-who="default"`, `data-who="alice@example.com"`, "What the system can serve", "Saved as version 2. It applies to new sessions."} {
		if !strings.Contains(dom, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	v := getLimits(t, f)
	if s := v.People["alice@example.com"].Steps; s == nil || *s != 120 || *v.Defaults.DailyUSD != 100 || *v.DefaultUSD != 1000 {
		t.Fatalf("after the page saved: %+v %+v", v.People, v.Defaults)
	}
	recs, _ := f.b.store.AuditAfter(0, 500)
	if last := recs[len(recs)-1]; len(last.Changes) != 1 || last.Changes[0].Field != "steps" || *last.Changes[0].Old != 80 ||
		*last.Changes[0].New != 120 || !strings.Contains(last.Comment, "ui test") {
		t.Fatalf("audit %+v", last)
	}
}

// The Limits tab's sentence builder (an old #quotas link opens it): "Limit a person, bob@example.com, to $25 per day" becomes
// bob's daily limit and nothing else.
func TestConsoleQuotaSentenceInBrowser(t *testing.T) {
	chrome := findChrome(t)
	f := newFixture(t, false)
	drive := waitThen(`#qt-table tr[data-who="default"]`, `$("qt-new").click();$("qd-scope").value="person";$("qd-who").value="bob@example.com";
$("qd-period").value="daily_usd";$("qd-period").dispatchEvent(new Event("change"));$("qd-amount").value="25";$("qd-reason").value="pilot";$("qd-save").click();`)
	dom := chromeRun(t, chrome, "--dump-dom", consoleServer(t, f, "u1", drive).URL+"/admin/v1/ui/#quotas")
	if !strings.Contains(dom, "Saved as version 1.") || !strings.Contains(dom, `data-who="bob@example.com"`) {
		t.Fatalf("page did not save and list bob: %s", dom[max(0, len(dom)-3000):])
	}
	v := getLimits(t, f)
	if d := v.People["bob@example.com"].DailyUSD; d == nil || *d != 25 || len(v.Principals) != 0 || v.DefaultUSD != nil {
		t.Fatalf("after the page saved: %+v %+v", v.quotaView, v.People)
	}
}

// The Workloads tab: an admin adds a workload with an owner and a monthly quota from one form. The
// owner, the quota and the policy entry are all saved, and the pipeline is then served.
func TestConsoleAddWorkloadInBrowser(t *testing.T) {
	chrome := findChrome(t)
	f := newFixture(t, false)
	drive := waitThen(`tr[data-id="alpha"]`, `$("wl-new").click();$("wd-id").value="delta-bot";$("wd-project").value="group/delta";$("wd-ref").value="main";
document.querySelector('input[name="wd-source"][value="web"]').checked=true;document.querySelector('input[name="wd-model"][value="model-a"]').checked=true;
$("wd-owner").value="bob@example.com";$("wd-quota").value="12.5";$("wd-reason").value="new release bot";$("wd-save").click();`)
	dom := chromeRun(t, chrome, "--dump-dom", consoleServer(t, f, "u1", drive).URL+"/admin/v1/ui/#workloads")
	if !strings.Contains(dom, "Saved as policy version 2.") || !strings.Contains(dom, `data-id="delta-bot"`) {
		t.Fatalf("page did not save the workload: %s", dom[max(0, len(dom)-3000):])
	}
	if v := getQuotas(t, f); v.Principals["ci:group/delta"] != 12.5 {
		t.Fatalf("quota %+v", v)
	}
	if _, owners, _ := ownersView(t, f); owners["delta-bot"] != "bob@example.com" {
		t.Fatalf("owners %+v", owners)
	}
	claims := payload(map[string]any{"project_path": "group/delta", "ci_config_ref_uri": "gitlab.example.com/group/delta//.gitlab-ci.yml@refs/heads/main"})
	if w := do(f.edge, "POST", "/v1/chat/completions", map[string]string{"x-broker-ci-claims": claims}, chatA); w.Code != 200 || w.Header().Get("X-Broker-Owner") != "bob@example.com" {
		t.Fatalf("the new workload's call: %d %s", w.Code, w.Body)
	}
}

// TestConsoleScreenshots renders each tab with sample data into BADGER_CONSOLE_SCREENSHOTS (a
// directory), light and dark. It checks nothing; it is how the console's look is reviewed.
func TestConsoleScreenshots(t *testing.T) {
	dir := os.Getenv("BADGER_CONSOLE_SCREENSHOTS")
	if dir == "" {
		t.Skip("BADGER_CONSOLE_SCREENSHOTS not set")
	}
	chrome := findChrome(t)
	f := newFixture(t, false)
	priced(f)
	f.b.up.usage.prices["model-b"] = Price{Input: 300, CachedInput: 30, Output: 1200}
	put(t, f, `"0"`, `{"default_usd":50,"principals":{"bob@example.com":30,"ci:group/sub/beta":5},"defaults":{"daily_usd":10,"steps":40,"context":131072,"output":16384,"timeout_seconds":230},
"people":{"alice@example.com":{"steps":80,"context":262144}},"comment":"sample"}`)
	u, now := f.b.up.usage, time.Now()
	for d := 0; d < 30; d++ {
		at := now.Add(-time.Duration(d) * 24 * time.Hour)
		for i := 0; i < 1+(d*7)%5; i++ {
			u.addFor("alice@example.com", "model-b", usageAttr{}, tokens{Prompt: 9000, Cached: 3000, Completion: 1500}, at)
			u.addFor("bob@example.com", "model-b", usageAttr{}, tokens{Prompt: 12000, Completion: 2500}, at)
			u.addFor("ci:group/sub/beta", "model-b", usageAttr{Owner: "alice@example.com", TriggeredBy: "release-bot"}, tokens{Prompt: 4000, Completion: 900}, at)
		}
		u.addFor("ci:group/alpha", "model-a", usageAttr{Owner: "alice@example.com", TriggeredBy: "carol"}, tokens{Prompt: 30000, Completion: 4000}, at)
	}
	// The same console with nothing set, as a new deployment starts: no default limit, no overrides.
	shoot(t, chrome, dir, "console-uncapped-", consoleServer(t, newFixture(t, false), "u1", ""))
	shoot(t, chrome, dir, "console-", consoleServer(t, f, "u1", ""))
	// The limit editor with model prices, and the effective-limits lookup for one person.
	for name, drive := range map[string]string{
		"editor": waitThen(`#qt-table tr[data-who="default"]`, `$("qt-new").click();`),
		"lookup": waitThen(`#qt-table tr[data-who="default"]`, `$("lk-who").value="alice@example.com";$("lk-go").click();`),
	} {
		chromeRun(t, chrome, "--window-size=1280,1000", "--hide-scrollbars", "--screenshot="+filepath.Join(dir, "console-limits-"+name+".png"),
			consoleServer(t, f, "u1", drive).URL+"/admin/v1/ui/#limits")
	}
}

// shoot screenshots each tab of the console at srv, light and dark, as dir/<prefix><tab>-<mode>.png.
func shoot(t *testing.T, chrome, dir, prefix string, srv *httptest.Server) {
	for _, tab := range []string{"overview", "usage", "limits", "workloads"} {
		for _, mode := range []string{"light", "dark"} {
			args := []string{"--window-size=1280,1000", "--hide-scrollbars", "--screenshot=" + filepath.Join(dir, prefix+tab+"-"+mode+".png")}
			// Blink's preferred colour scheme: 0 dark, 1 light; set both ways so the host's own setting never decides.
			args = append(args, map[string]string{"dark": "--blink-settings=preferredColorScheme=0", "light": "--blink-settings=preferredColorScheme=1"}[mode])
			chromeRun(t, chrome, append(args, srv.URL+"/admin/v1/ui/#"+tab)...)
		}
	}
}
