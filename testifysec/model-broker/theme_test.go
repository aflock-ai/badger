package broker

import (
	"os"
	"strings"
	"testing"
)

// The embedded theme must match the canonical one, and the console's styles must carry it.
func TestThemeMatchesBranding(t *testing.T) {
	want, err := os.ReadFile("../branding/theme/theme.css")
	if os.IsNotExist(err) {
		t.Skip("canonical theme not in this checkout")
	}
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != themeCSS {
		t.Fatal("model-broker/theme.css differs from branding/theme/theme.css; run branding/theme/sync.sh")
	}
	if !strings.HasPrefix(consoleCSS, themeCSS) || !strings.Contains(consoleCSS, "var(--c-accent)") {
		t.Fatal("the console's styles do not start with the theme")
	}
}

// The header shows the configured brand and same-origin links, escaped, and never an off-site link.
func TestAdminHeader(t *testing.T) {
	h := adminHeader("Badger <admin>", []NavLink{{"Data sources", "/admin/sources"}, {"Usage", "/broker/admin/v1/ui/usage"}, {"Console", "/broker/admin/v1/ui/"},
		{"Evil", "javascript:alert(1)"}, {"Off", "//example.com/x"}, {"Abs", "https://example.com/"},
		{"Slash", "/\\example.com/x"}, {"Tab", "/\t/example.com/x"}, {"Newline", "/\n/example.com/x"},
		{"Space", " //example.com/x"}, {"Del", "/\x7f/example.com"}}, "carol<b>")
	for _, want := range []string{"Badger &lt;admin&gt;", `href="/admin/sources"`, `href="/broker/admin/v1/ui/usage" aria-current="page"`, `href="/broker/admin/v1/ui/" aria-current="page"`, "Signed in as carol&lt;b&gt;"} {
		if !strings.Contains(h, want) {
			t.Fatalf("header lacks %q: %s", want, h)
		}
	}
	for _, bad := range []string{"javascript:", "example.com"} {
		if strings.Contains(h, bad) {
			t.Fatalf("header kept %q: %s", bad, h)
		}
	}
	if !strings.Contains(adminHeader("", nil, ""), ">Model broker<") {
		t.Fatal("no default brand")
	}
}
