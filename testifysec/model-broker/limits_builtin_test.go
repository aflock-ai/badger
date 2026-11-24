package broker

import (
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The console shows the managed agent's built-in limits as numbers. They are the agent's compiled
// values (packages/server/src/managed.ts, `limits`); this holds the broker's copy to them.
func TestBuiltInAgentLimitsMatchTheAgent(t *testing.T) {
	src, err := os.ReadFile("../../packages/server/src/managed.ts")
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)export const limits: ManagedLimits\.Limits = \{(.*?)\n\}`).FindSubmatch(src)
	if block == nil {
		t.Fatal("managed.ts no longer declares the compiled limits where this test looks")
	}
	field := func(name string) int {
		m := regexp.MustCompile(`\n\s*` + name + `:\s*([0-9_]+),`).FindSubmatch(block[1])
		if m == nil {
			t.Fatalf("managed.ts limits lack %s", name)
		}
		n, _ := strconv.Atoi(strings.ReplaceAll(string(m[1]), "_", ""))
		return n
	}
	want := map[string]int{"steps": field("steps"), "context": field("context"), "output": field("output"), "timeout_seconds": field("timeoutMs") / 1000}
	for k, v := range want {
		if builtInAgentLimits[k] != v {
			t.Errorf("built-in %s: broker says %d, the agent compiles %d", k, builtInAgentLimits[k], v)
		}
	}
	f := newFixture(t, false)
	var got struct {
		BuiltIn map[string]int `json:"built_in"`
	}
	json.Unmarshal(do(f.admin, "GET", "/admin/v1/quotas", admin("u1"), "").Body.Bytes(), &got)
	if len(got.BuiltIn) != 4 || got.BuiltIn["steps"] != want["steps"] || got.BuiltIn["timeout_seconds"] != want["timeout_seconds"] {
		t.Fatalf("GET quotas built_in = %v, want %v", got.BuiltIn, want)
	}
}

// The limit editor shows each model's price, so an admin can size a budget.
func TestConfigServesModelPrices(t *testing.T) {
	f := newFixture(t, false)
	f.b.up.usage.prices = map[string]Price{"model-a": {Input: 2.5, CachedInput: 0.25, Output: 10}}
	var got struct {
		Prices map[string]Price `json:"prices"`
	}
	json.Unmarshal(do(f.admin, "GET", "/admin/v1/config", admin("u1"), "").Body.Bytes(), &got)
	if p, ok := got.Prices["model-a"]; !ok || p.Input != 2.5 || p.Output != 10 || len(got.Prices) != 1 {
		t.Fatalf("prices %+v", got.Prices)
	}
}
