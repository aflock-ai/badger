package broker

import (
	"regexp"
	"strings"
	"testing"

	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
)

// The console carries the deployment's marking, its configured ceiling, as a banner at the top and
// the bottom of the page, the same as the workspace app.
func TestConsoleClassificationBanner(t *testing.T) {
	f := newFixture(t, false)
	for _, banner := range []string{"SECRET", "SECRET//REL TO USA, GBR", "UNCLASSIFIED//FGI GBR"} {
		label, err := pgdb.ParseLabel(banner)
		if err != nil {
			t.Fatal(err)
		}
		f.cfg.CeilingMarking, f.cfg.ceiling = banner, label
		page := do(f.admin, "GET", "/admin/v1/ui/", admin("u1"), "").Body.String()
		want := `<div class="classification-banner" role="note" aria-label="Data marking">` + label.Banner + `</div>`
		if n := strings.Count(page, want); n != 2 {
			t.Fatalf("%q: banner appears %d times, want 2 (top and bottom):\n%s", banner, n, page)
		}
		body := page[strings.Index(page, "<body>")+len("<body>"):]
		if !strings.HasPrefix(body, want) || !strings.HasSuffix(strings.TrimSpace(body), want+"</body></html>") {
			t.Fatalf("%q: banner is not the first and last thing on the page", banner)
		}
	}
	if got := classificationBanner(`A<b>&"`); got != `<div class="classification-banner" role="note" aria-label="Data marking">A&lt;b&gt;&amp;&#34;</div>` {
		t.Fatalf("banner text is not escaped: %s", got)
	}
}

// The banner keeps the workspace app's colours in light and dark mode: the console's stylesheet
// sets them outside any colour-scheme rule.
func TestConsoleBannerColours(t *testing.T) {
	rule := regexp.MustCompile(`(?s)\.classification-banner\s*\{[^}]*\}`).FindString(consoleCSS)
	for _, want := range []string{"background: #243746", "color: #fff"} {
		if !strings.Contains(rule, want) {
			t.Fatalf("banner rule %q lacks %q", rule, want)
		}
	}
}

// Nothing the console serves names a vendor or chat service, or points off the deployment.
func TestConsoleNoExternalLinksOrVendorNames(t *testing.T) {
	f := newFixture(t, false)
	external := regexp.MustCompile(`(?i)\b(?:https?:)?//[a-z0-9.-]+\.[a-z]{2,}`)
	for _, p := range []string{"/admin/v1/ui/", "/admin/v1/ui/console.js", "/admin/v1/ui/console.css"} {
		body := do(f.admin, "GET", p, admin("u1"), "").Body.String()
		// The only absolute URL the script needs is the SVG namespace, an identifier no browser fetches.
		body = strings.ReplaceAll(body, `"http://www.w3.org/2000/svg"`, "")
		if m := external.FindString(body); m != "" {
			t.Errorf("%s links off the deployment: %q", p, m)
		}
		for _, word := range []string{"testifysec", "discord"} {
			if strings.Contains(strings.ToLower(body), word) {
				t.Errorf("%s names %q", p, word)
			}
		}
	}
}
