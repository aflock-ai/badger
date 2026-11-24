package broker

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Editing a named-branch workload's branch changes its principal, and under the two-person rule the
// policy write only proposes the change: the workload still runs as its old principal, so that
// principal keeps its quota. Deleting the quota before the policy change takes effect would leave the running workload
// on the default limit, or on none.
func TestConsoleWorkloadPrincipalChangeKeepsQuotaUntilPolicyApplies(t *testing.T) {
	chrome := findChrome(t)
	f := newFixture(t, true)
	put(t, f, `"0"`, `{"principals":{"ci:group/sub/beta@feat/x-1":5},"comment":"beta-feature cap"}`)
	drive := waitThen(`tr[data-id="beta-feature"] button`, `x.click();$("wd-ref").value="feat/x-2";$("wd-reason").value="next branch";$("wd-save").click();`)
	dom := chromeRun(t, chrome, "--dump-dom", consoleServer(t, f, "u1", drive).URL+"/admin/v1/ui/#workloads")
	if !strings.Contains(dom, "Saved as proposal #") {
		t.Fatalf("the edit was not saved as a proposal: %s", dom[max(0, len(dom)-3000):])
	}
	if e := activeEntry(t, f, "beta-feature"); e.Ref != "feat/x-1" {
		t.Fatalf("the proposal took effect without approval: %+v", e)
	}
	if v := getQuotas(t, f); v.Principals["ci:group/sub/beta@feat/x-1"] != 5 {
		t.Fatalf("the running workload's quota was removed before its policy change applied: %+v", v.Principals)
	}
}

// When the policy write takes effect at once, the workload now runs as its new principal: the quota
// moves to it and the old principal's entry is removed, after the write, not before.
func TestConsoleWorkloadPrincipalChangeMovesQuotaOnceApplied(t *testing.T) {
	chrome := findChrome(t)
	f := newFixture(t, false)
	put(t, f, `"0"`, `{"principals":{"ci:group/alpha":5},"comment":"alpha cap"}`)
	drive := waitThen(`tr[data-id="alpha"] button`, `x.click();$("wd-project").value="group/alpha-two";$("wd-reason").value="moved project";$("wd-save").click();`)
	dom := chromeRun(t, chrome, "--dump-dom", consoleServer(t, f, "u1", drive).URL+"/admin/v1/ui/#workloads")
	if !strings.Contains(dom, "Saved as policy version 2.") || strings.Contains(dom, "was not removed") {
		t.Fatalf("the edit was not saved cleanly: %s", dom[max(0, len(dom)-3000):])
	}
	if e := activeEntry(t, f, "alpha"); e.ProjectPath != "group/alpha-two" {
		t.Fatalf("the edit did not apply: %+v", e)
	}
	if v := getQuotas(t, f).Principals; v["ci:group/alpha-two"] != 5 || len(v) != 1 {
		t.Fatalf("quota after the move: %+v", v)
	}
}

// Editing something unrelated keeps a workload's exact expiry: the date field shows only the day,
// and saving it as 23:59:59 of that day would extend the workload (or bring back one that expired
// earlier that day).
func TestConsoleWorkloadEditKeepsExactExpiry(t *testing.T) {
	chrome := findChrome(t)
	f := newFixture(t, false)
	exp := time.Now().UTC().Add(72 * time.Hour).Truncate(time.Hour)
	if exp.Hour() == 23 {
		exp = exp.Add(-time.Hour)
	}
	body := policyBody(t, f, func(es []Entry) []Entry {
		for i := range es {
			if es[i].ID == "alpha" {
				es[i].ExpiresAt = &exp
			}
		}
		return es
	})
	if w := do(f.admin, "PUT", "/admin/v1/policy", with(admin("u1"), "If-Match", `"1"`), body); w.Code != 201 {
		t.Fatalf("set expiry: %d %s", w.Code, w.Body)
	}
	drive := waitThen(`tr[data-id="alpha"] button`, `x.click();$("wd-users").value="alice, bob";$("wd-reason").value="add bob";$("wd-save").click();`)
	dom := chromeRun(t, chrome, "--dump-dom", consoleServer(t, f, "u1", drive).URL+"/admin/v1/ui/#workloads")
	if !strings.Contains(dom, "Saved as policy version 3.") {
		t.Fatalf("the edit was not saved: %s", dom[max(0, len(dom)-3000):])
	}
	e := activeEntry(t, f, "alpha")
	if !strings.Contains(strings.Join(e.TriggerUsers, ","), "bob") {
		t.Fatalf("the edit did not apply: %+v", e)
	}
	if e.ExpiresAt == nil || !e.ExpiresAt.Equal(exp) {
		t.Fatalf("expiry changed by an unrelated edit: got %v, want %v", e.ExpiresAt, exp)
	}
}

// activeEntry is the entry with this id in the broker's active policy.
func activeEntry(t *testing.T, f *fixture, id string) Entry {
	t.Helper()
	for _, e := range f.b.store.Active().Entries {
		if e.ID == id {
			return e
		}
	}
	b, _ := json.Marshal(f.b.store.Active().Entries)
	t.Fatalf("no entry %q in %s", id, b)
	return Entry{}
}
