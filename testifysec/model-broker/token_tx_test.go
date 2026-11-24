package broker

import (
	"strings"
	"testing"
	"time"
)

// A token's issue and its audit record are written in one transaction on one connection, so
// issuing works however small the pool is (with one connection it used to wait on itself).
func TestTokenIssueOnASingleConnection(t *testing.T) {
	f := newFixture(t, true)
	f.db.SetMaxOpenConns(1)
	start := time.Now()
	w := do(f.provision, "POST", "/provision/v1/tokens", map[string]string{"Authorization": "Bearer prov-key"},
		`{"workspace":"ws-one","principal":"alice@example.com"}`)
	if w.Code != 201 || time.Since(start) > 5*time.Second {
		t.Fatalf("issue on a one-connection pool: %d after %v", w.Code, time.Since(start))
	}
	if !strings.Contains(f.superText(`SELECT string_agg(record, ' ') FROM broker.audit`), `"token_issue"`) {
		t.Fatal("no audit record for the issue")
	}
}
