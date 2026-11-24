package broker

import (
	"strings"
	"testing"
)

// A chat body over 1 MiB is refused with 413 before any decision or upstream call, for pipelines
// and for people; a body just under the cap is served.
func TestChatBodyCappedAtOneMiB(t *testing.T) {
	f := newFixture(t, false)
	body := func(n int) string {
		head, tail := `{"model":"model-a","messages":[{"role":"user","content":"`, `"}]}`
		return head + strings.Repeat("A", n-len(head)-len(tail)) + tail
	}
	pipeline := map[string]string{"x-broker-ci-claims": payload(nil)}
	person := map[string]string{"x-broker-principal": "alice@example.com"}
	for name, h := range map[string]map[string]string{"pipeline": pipeline, "person": person} {
		if w := do(f.edge, "POST", "/v1/chat/completions", h, body(1<<20+1)); w.Code != 413 {
			t.Fatalf("%s: over the cap: %d %s", name, w.Code, w.Body)
		}
	}
	if f.calls.Load() != 0 {
		t.Fatal("an oversized body reached the upstream")
	}
	if w := do(f.edge, "POST", "/v1/chat/completions", pipeline, body(1<<20)); w.Code != 200 {
		t.Fatalf("at the cap: %d %s", w.Code, w.Body)
	}
}
