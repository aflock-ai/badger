package main

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	broker "github.com/aflock-ai/badger/testifysec/model-broker"
)

func TestMain(m *testing.M) {
	// The scratch Postgres the database tests use (BADGER_TEST_PG) may be reached without TLS;
	// nothing else is.
	if u, err := url.Parse(os.Getenv("BADGER_TEST_PG")); err == nil && u.Hostname() != "" {
		h := u.Hostname()
		plaintextHost = func(host string) bool { return host == h }
	}
	os.Exit(m.Run())
}

// A service connection to another host without authenticated TLS stops the service before it
// connects, with the fix in the message.
func TestOpenDatabaseRefusesPlaintextToAnotherHost(t *testing.T) {
	dir := t.TempDir()
	cfg, err := broker.LoadConfig(writeConfig(t, dir, "https://model.example.com/a", ""))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"disable", "prefer", "require"} {
		os.WriteFile(filepath.Join(dir, "dsn"), []byte("postgres://svc@db.example.internal:5432/b?sslmode="+mode+"\n"), 0o600)
		db, err := openDatabase(context.Background(), cfg)
		if err == nil {
			db.Close()
			t.Fatalf("sslmode=%s to another host: started", mode)
		}
		if !strings.Contains(err.Error(), "sslmode=verify-full") {
			t.Fatalf("sslmode=%s: %v, want the fix named", mode, err)
		}
	}
}
