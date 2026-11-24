// jade:ring local
package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCollectorCannotAcknowledgeWithMalformedOrPartialResponse(t *testing.T) {
	for _, reply := range []string{"null", `{"partialSuccess":null}`, `{"PartialSuccess":{}}`, `{"partialSuccess":{"RejectedLogRecords":"1"}}`, `{"partialSuccess":{"rejectedLogRecords":"1"}}`, `{"partialSuccess":{"errorMessage":"failed"}}`, `{"partialSuccess":{"rejectedLogRecords":"1","rejectedLogRecords":"0"}}`, `{"partialSuccess":{},"PartialSuccess":null}`} {
		t.Run(reply, func(t *testing.T) {
			c := Config{Spool: privateTemp(t), MaxRecords: 4, MaxOfflineSeconds: 60, CollectorURL: "https://collector.test/v1/logs"}
			if err := os.Chmod(c.Spool, 0700); err != nil {
				t.Fatal(err)
			}
			s, err := openSpool(c)
			if err != nil {
				t.Fatal(err)
			}
			r, err := s.begin(1)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.finish(r, "completed", 200, 1); err != nil {
				t.Fatal(err)
			}
			g := &Gateway{config: c, spool: s, client: &http.Client{Transport: transport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBufferString(reply))}, nil
			})}}
			if g.exportOne(context.Background()) == nil {
				t.Fatal("malformed collector response deleted evidence")
			}
			if _, err = os.Stat(filepath.Join(c.Spool, r.ID+".json")); err != nil {
				t.Fatal("evidence lost", err)
			}
		})
	}
}

func TestTerminalDiskFailureStopsNewActionsAndRetainsStart(t *testing.T) {
	c := Config{Spool: privateTemp(t), MaxRecords: 4, MaxOfflineSeconds: 60}
	_ = os.Chmod(c.Spool, 0700)
	s, err := openSpool(c)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.begin(1)
	if err != nil {
		t.Fatal(err)
	}
	// Replace the destination path with a directory to force a real atomic-rename failure,
	// while retaining the on-disk start bytes under another name for inspection.
	name := filepath.Join(c.Spool, r.ID+".json")
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(name); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(name, 0700); err != nil {
		t.Fatal(err)
	}
	if s.finish(r, "completed", 200, 1) == nil {
		t.Fatal("terminal failure ignored")
	}
	if _, err = s.begin(1); err == nil {
		t.Fatal("admitted after audit fault")
	}
	if !bytes.Contains(data, []byte(`"outcome":"started"`)) {
		t.Fatal("start not persisted")
	}
}

func TestSpoolRejectsLinksOversizeAndUnexpectedEntries(t *testing.T) {
	for _, kind := range []string{"symlink", "oversize", "unexpected"} {
		t.Run(kind, func(t *testing.T) {
			c := Config{Spool: privateTemp(t), MaxRecords: 2}
			_ = os.Chmod(c.Spool, 0700)
			name := filepath.Join(c.Spool, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json")
			switch kind {
			case "symlink":
				if err := os.Symlink("/etc/passwd", name); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err := os.WriteFile(name, make([]byte, 4097), 0600); err != nil {
					t.Fatal(err)
				}
			case "unexpected":
				if err := os.WriteFile(filepath.Join(c.Spool, "unknown"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := openSpool(c); err == nil {
				t.Fatal("unsafe spool accepted")
			}
		})
	}
}

func TestOTLPHasDistinctStableStartAndTerminalIDs(t *testing.T) {
	r := Record{ID: "request", Started: time.Unix(1, 0), Finished: time.Unix(2, 0), Outcome: "completed"}
	a, b := otlp(r, "none"), otlp(r, "none")
	if !bytes.Equal(a, b) || !bytes.Contains(a, []byte("request/start")) || !bytes.Contains(a, []byte("request/terminal")) {
		t.Fatal("event identities are not stable and distinct")
	}
}

func TestInterruptedAtomicWritesRecoverWithoutLosingStartedAction(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial", true: "terminal"}[terminal], func(t *testing.T) {
			c := Config{Spool: privateTemp(t), MaxRecords: 2, MaxOfflineSeconds: 60}
			_ = os.Chmod(c.Spool, 0700)
			s, err := openSpool(c)
			if err != nil {
				t.Fatal(err)
			}
			if terminal {
				if _, err = s.begin(1); err != nil {
					t.Fatal(err)
				}
			}
			f, err := os.CreateTemp(c.Spool, ".pending-")
			if err != nil {
				t.Fatal(err)
			}
			_, _ = f.Write([]byte(`{"unfinished":`))
			_ = f.Sync()
			_ = f.Close()
			recovered, err := openSpool(c)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = os.Lstat(f.Name()); !os.IsNotExist(err) {
				t.Fatal("uncommitted temporary not removed")
			}
			if terminal {
				r, ok := recovered.next()
				if !ok || r.Outcome != "incomplete-after-restart" {
					t.Fatal("start evidence lost")
				}
			} else if _, ok := recovered.next(); ok {
				t.Fatal("invented an admitted action")
			}
		})
	}
}

func TestSSETerminalRequiresCompleteEventAcrossArbitraryChunks(t *testing.T) {
	valid := []byte("data: {\"choices\":[]}\r\n\r\ndata: [DONE]\r\n\r\n")
	for split := 0; split <= len(valid); split++ {
		var s sseTerminal
		if !s.observe(valid[:split]) || !s.observe(valid[split:]) || !s.done {
			t.Fatalf("lost terminal at split %d", split)
		}
	}
	for _, raw := range []string{"data: [DONE]", "data: [DONE]\n", "data: {\"text\":\"[DONE]\"}\n\n", "data: [DONE]\ndata: extra\n\n"} {
		var s sseTerminal
		if !s.observe([]byte(raw)) || s.done {
			t.Fatal("false terminal", raw)
		}
	}
	var s sseTerminal
	if s.observe(bytes.Repeat([]byte{'x'}, 65537)) {
		t.Fatal("unbounded SSE line")
	}
}

func privateTemp(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}
