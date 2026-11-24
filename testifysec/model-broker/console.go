package broker

import (
	_ "embed"
	"html"
	"io"
	"net/http"
	"strings"
)

// The shared Badger theme, a byte-identical copy of testifysec/branding/theme/theme.css. Inlined,
// so the pages load nothing from anywhere.
//
//go:embed theme.css
var themeCSS string

// The admin console (console.html, console.js, console.css): one page with five tabs, its script
// and its styles, served from the broker so the page loads nothing from anywhere else and runs no
// inline code. See docs/design/planned/broker-admin-console.md.
var (
	//go:embed console.html
	consoleHTML string
	//go:embed console.js
	consoleJS string
	//go:embed console.css
	consoleStyles string

	consoleCSS = themeCSS + "\n" + consoleStyles
)

const consoleCSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' blob:; " +
	"form-action 'none'; frame-ancestors 'none'; base-uri 'none'"

// sameOriginPath reports whether href is a path on this origin: it starts with one "/" and
// carries nothing a browser rewrites into another host. Browsers read "\" as "/" and drop tabs and
// newlines, so "/\host" and "/\t/host" would leave the origin; any backslash, control character
// or space is refused.
func sameOriginPath(href string) bool {
	if len(href) < 1 || href[0] != '/' || strings.HasPrefix(href, "//") {
		return false
	}
	for _, c := range href {
		if c == '\\' || c <= ' ' || c == 0x7f {
			return false
		}
	}
	return true
}

// adminHeader is the console's top bar: the configured brand, the configured links to sibling admin
// pages, and who is signed in. A link whose href is not a same-origin path is dropped.
func adminHeader(brand string, nav []NavLink, user string) string {
	if brand == "" {
		brand = "Model broker"
	}
	var b strings.Builder
	b.WriteString(`<header class="topbar"><span class="brand">` + html.EscapeString(brand) + `</span>`)
	if len(nav) > 0 {
		b.WriteString("<nav>")
		for _, l := range nav {
			if !sameOriginPath(l.Href) {
				continue
			}
			cur := ""
			if h := strings.TrimRight(l.Href, "/"); strings.HasSuffix(h, "/ui") || strings.HasSuffix(h, "/ui/usage") {
				cur = ` aria-current="page"`
			}
			b.WriteString(`<a href="` + html.EscapeString(l.Href) + `"` + cur + `>` + html.EscapeString(l.Label) + `</a>`)
		}
		b.WriteString("</nav>")
	}
	b.WriteString(`<span class="spacer"></span>`)
	if user != "" {
		b.WriteString(`<span class="who">Signed in as ` + html.EscapeString(user) + `</span>`)
	}
	b.WriteString("</header>")
	return b.String()
}

// classificationBanner is the deployment's marking as the workspace app shows it: one line at the
// top of the page and one at the bottom (console.css keeps its colours in both modes).
func classificationBanner(marking string) string {
	return `<div class="classification-banner" role="note" aria-label="Data marking">` + html.EscapeString(marking) + `</div>`
}

// consoleRoutes serves the console at GET /admin/v1/ui/ on the admin listener, behind the admin
// check every admin route has. Redirects are relative, so they hold behind the edge's prefix.
func (b *Broker) consoleRoutes(mux *http.ServeMux) {
	relative := func(to string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", to)
			w.WriteHeader(http.StatusFound)
		}
	}
	asset := func(contentType, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", contentType)
			io.WriteString(w, body)
		}
	}
	mux.HandleFunc("GET /admin/v1/ui", relative("ui/"))
	// The usage page the console replaced: its bookmarks and nav links open the Usage tab.
	mux.HandleFunc("GET /admin/v1/ui/usage", relative("./#usage"))
	mux.HandleFunc("GET /admin/v1/ui/console.js", asset("text/javascript; charset=utf-8", consoleJS))
	mux.HandleFunc("GET /admin/v1/ui/console.css", asset("text/css; charset=utf-8", consoleCSS))
	mux.HandleFunc("GET /admin/v1/ui/{$}", func(w http.ResponseWriter, r *http.Request) {
		_, user, _ := b.AdminIdentity(r) // the name self-change detection compares (quota.go)
		page := strings.Replace(consoleHTML, "<!--HEADER-->", adminHeader(b.cfg.AdminUI.Brand, b.cfg.AdminUI.Nav, user), 1)
		page = strings.ReplaceAll(page, "<!--BANNER-->", classificationBanner(b.cfg.Ceiling().Banner))
		page = strings.Replace(page, "<!--USER-->", html.EscapeString(user), 1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", consoleCSP)
		io.WriteString(w, page)
	})
}
