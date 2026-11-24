package web

import (
	"os"
	"strings"
	"testing"

	"github.com/aflock-ai/badger/testifysec/portal/internal/auth"
	"github.com/aflock-ai/badger/testifysec/portal/internal/users"
)

// The embedded theme must match the canonical one, so the portal never drifts from the other pages.
func TestThemeMatchesBranding(t *testing.T) {
	want, err := os.ReadFile("../../../branding/theme/theme.css")
	if os.IsNotExist(err) {
		t.Skip("canonical theme not in this checkout")
	}
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != themeCSS {
		t.Fatal("portal/internal/web/theme.css differs from branding/theme/theme.css; run branding/theme/sync.sh")
	}
}

// The approver queue names a user by subject, as the users table does, not by internal id.
func TestQueueShowsSubject(t *testing.T) {
	var b strings.Builder
	err := usersPage.Execute(&b, map[string]any{"Theme": theme, "Principal": auth.Principal{Name: "carol"},
		"Users":    []users.User{{ID: "u-1", Subject: "bob@example.com"}},
		"Pending":  []users.Request{{ID: "rr-1", UserID: "u-1"}, {ID: "rr-2", UserID: "u-gone"}},
		"Subjects": map[string]string{"u-1": "bob@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	queue := b.String()[strings.Index(b.String(), "Waiting for an approver"):]
	if !strings.Contains(queue, "bob@example.com") || strings.Contains(queue, ">u-1<") {
		t.Fatal("queue does not show the subject")
	}
	if !strings.Contains(queue, "<code>u-gone</code>") {
		t.Fatal("an unknown user id is not shown as an id")
	}
}
