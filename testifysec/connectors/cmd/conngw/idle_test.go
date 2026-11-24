package main

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// idleMinutes is optional: absent is 30 minutes, 0 never closes an idle stream, negative is refused.
func TestIdleMinutesZeroMeansNever(t *testing.T) {
	lv := levels(t)
	write := func(extra string) string {
		p := t.TempDir() + "/c.json"
		c := `{"listen":":8443","certFile":"/c","keyFile":"/k","audience":"a","namespaces":["ws"],"labelsFile":"/var/lib/conngw/labels"` + extra +
			`,"hostDigest":"` + hostDigest + `","signers":{"vendor":"` + strings.Repeat("A", 43) + `="},"connectors":[{"name":"jira","bundle":"/plugins/jira","digest":"sha256:` + strings.Repeat("0", 64) +
			`","signer":"vendor","tokenPath":"/t","socket":"/run/conngw/p.sock","uid":61000,"gid":61000,"grants":[{"workspaces":["ws/a"]}],"classification":"` + lv[1] + `"}]}`
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for extra, want := range map[string]int{"": 30, `,"idleMinutes":0`: 0, `,"idleMinutes":1440`: 1440} {
		c, err := load(write(extra))
		if err != nil || *c.IdleMinutes != want {
			t.Fatalf("%q: %v %v, want %d", extra, err, c.IdleMinutes, want)
		}
	}
	if _, err := load(write(`,"idleMinutes":-1`)); err == nil {
		t.Fatal("negative idleMinutes accepted")
	}

	// With an idle of zero a quiet stream stays open.
	outR, outW := io.Pipe()
	var once sync.Once
	p := &process{in: nopCloser{io.Discard}, out: outR, stop: func() { once.Do(func() { _ = outW.Close() }) }}
	callerR, callerW := io.Pipe()
	s := &stream{ws: "ws/a", conn: mustSource(t, "low", lv[0]), labels: newLabels(), log: slog.New(slog.DiscardHandler), pending: map[string]bool{}}
	returned := make(chan struct{})
	go func() {
		s.relay(callerR, closer{close: func() { _ = callerR.Close() }}, p, time.Hour, 0)
		close(returned)
	}()
	select {
	case <-returned:
		t.Fatal("a quiet stream was closed with idle 0")
	case <-time.After(300 * time.Millisecond):
	}
	_ = callerW.Close()
	p.stop()
	<-returned
}

// With idle 0 the stream bounds still hold: past the per-workspace and per-pod caps a caller gets 429
// and no connector starts.
func TestStreamBoundsHoldWithoutAnIdleClose(t *testing.T) {
	testStreamBounds(t, 0)
}

// A workspace's label belongs to the pod, not to a stream: after it reads a higher connector and the
// stream closes, a new stream (a reconnect) to a lower connector is still refused.
func TestTheLabelOutlivesAReconnect(t *testing.T) {
	lv := levels(t)
	low, high := mustSource(t, "low", lv[0]), mustSource(t, "high", lv[2])
	l := newLabels()
	callHigh, closeHigh := session(t, l, "ws/a", high, &fake{})
	if got := callHigh(callID("1")); strings.Contains(got, "refused") {
		t.Fatalf("high call refused: %s", got)
	}
	closeHigh() // the stream ends: the bridge reconnects with a new one
	f := &fake{}
	callLow, closeLow := session(t, l, "ws/a", low, f)
	defer closeLow()
	if got := callLow(callID("2")); !strings.Contains(got, "refused by the connector gateway") {
		t.Fatalf("low call after a reconnect not refused: %s", got)
	}
	if len(f.methods()) != 0 {
		t.Fatalf("connector saw %v", f.methods())
	}
}
