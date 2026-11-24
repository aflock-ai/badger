package broker

import (
	"strings"
	"testing"
)

// The console: one page, its script and styles from the broker itself, behind the admin check,
// with a policy that runs no inline script and loads nothing from elsewhere. The old usage page
// redirects to the console's Usage tab.
func TestConsoleServed(t *testing.T) {
	f := newFixture(t, false)
	f.cfg.AdminUI.Brand = `Acme <b>Models</b>`
	f.cfg.AdminUI.Nav = []NavLink{{Label: "Portal", Href: "/admin/portal/"}, {Label: "Away", Href: "https://elsewhere.example/"}}
	w := do(f.admin, "GET", "/admin/v1/ui/", admin("u1"), "")
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("page: %d %v", w.Code, w.Header())
	}
	page := w.Body.String()
	csp := w.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "style-src 'self'", "connect-src 'self'", "frame-ancestors 'none'", "form-action 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Errorf("CSP allows inline code: %q", csp)
	}
	for _, want := range []string{`role="tablist"`, `id="tab-overview"`, `id="tab-usage"`, `id="tab-workloads"`, `id="tab-limits"`,
		`<script src="console.js"`, `<link rel="stylesheet" href="console.css"`, "Acme &lt;b&gt;Models&lt;/b&gt;", `href="/admin/portal/"`,
		"Signed in as u1@example.com", `<meta name="badger-user" content="u1@example.com">`, `<dialog`} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	for _, bad := range []string{"elsewhere.example", "<script>", " style=", " onclick=", "http://", "https://"} {
		if strings.Contains(page, bad) {
			t.Errorf("page contains %q", bad)
		}
	}
	js := do(f.admin, "GET", "/admin/v1/ui/console.js", admin("u1"), "")
	if js.Code != 200 || !strings.HasPrefix(js.Header().Get("Content-Type"), "text/javascript") || !strings.Contains(js.Body.String(), `"use strict"`) {
		t.Fatalf("script: %d %v", js.Code, js.Header())
	}
	if strings.Contains(js.Body.String(), "innerHTML") || strings.Contains(js.Body.String(), "eval(") {
		t.Fatal("the script parses strings as markup or code")
	}
	css := do(f.admin, "GET", "/admin/v1/ui/console.css", admin("u1"), "")
	if css.Code != 200 || !strings.HasPrefix(css.Header().Get("Content-Type"), "text/css") || !strings.Contains(css.Body.String(), "prefers-color-scheme") {
		t.Fatalf("styles: %d %v", css.Code, css.Header())
	}
	if w := do(f.admin, "GET", "/admin/v1/ui/usage", admin("u1"), ""); w.Code != 302 || w.Header().Get("Location") != "./#usage" {
		t.Fatalf("old usage page: %d %v", w.Code, w.Header())
	}
	if w := do(f.admin, "GET", "/admin/v1/ui", admin("u1"), ""); w.Code != 302 || w.Header().Get("Location") != "ui/" {
		t.Fatalf("console without its slash: %d %v", w.Code, w.Header())
	}
	if w := do(f.admin, "GET", "/admin/v1/ui/nothing.js", admin("u1"), ""); w.Code != 404 {
		t.Fatalf("unknown asset: %d", w.Code)
	}
	for _, p := range []string{"/admin/v1/ui/", "/admin/v1/ui/console.js", "/admin/v1/ui/console.css", "/admin/v1/ui/usage"} {
		if w := do(f.admin, "GET", p, with(admin("u2"), "x-broker-role", "user"), ""); w.Code != 403 {
			t.Errorf("non-admin %s: %d", p, w.Code)
		}
		if w := do(f.admin, "GET", p, map[string]string{}, ""); w.Code != 401 {
			t.Errorf("anonymous %s: %d", p, w.Code)
		}
		if w := do(f.edge, "GET", p, map[string]string{"x-broker-principal": "alice@example.com"}, ""); w.Code == 200 {
			t.Errorf("edge listener served %s", p)
		}
	}
}
