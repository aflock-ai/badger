package broker

import (
	"encoding/json"
	"os"
	"testing"
)

// The README's examples must load: the config as-is, the policy at a time inside its TTL.
func TestExamplesLoad(t *testing.T) {
	cfg, err := LoadConfig("examples/config.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile("examples/policy.json")
	var p Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	at := p.Entries[1].ExpiresAt.AddDate(0, 0, -7)
	if errs := cfg.Operator().Validate(&p, at); len(errs) != 0 {
		t.Fatal(errs)
	}
}
