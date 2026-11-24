package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/badger/testifysec/connectors/marking"
)

func parsed(t *testing.T, banner string) marking.Marking {
	t.Helper()
	m, err := marking.Parse(banner)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func openedLabels(t *testing.T) (*labels, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "labels")
	if err := initLabels(path, marking.Current()); err != nil {
		t.Fatal(err)
	}
	l, err := openLabels(path, marking.Current())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.file.Close() })
	return l, path
}

// A registered workspace never rises above its ceiling: the raise is refused and the label is
// unchanged. A new workspace's ceiling is the profile's floor.
func TestARegisteredWorkspaceNeverRisesAboveItsCeiling(t *testing.T) {
	lv := levels(t)
	l, _ := openedLabels(t)
	ceiling, err := l.register("ns/a", "owner-1", parsed(t, lv[0]))
	if err != nil || marking.Banner(ceiling) != lv[0] {
		t.Fatalf("register: %v %q", err, marking.Banner(ceiling))
	}
	if _, err := l.raise("ns/a", parsed(t, lv[0])); err != nil {
		t.Fatalf("a raise to the floor: %v", err)
	}
	if _, err := l.raise("ns/a", parsed(t, lv[1])); err == nil {
		t.Fatal("a raise above the ceiling succeeded")
	}
	if label, ok := l.allows("ns/a", parsed(t, lv[0])); !ok || marking.Banner(label) != lv[0] {
		t.Fatalf("label changed by a refused raise: %q", marking.Banner(label))
	}
	if _, ok := l.withinCeiling("ns/a", parsed(t, lv[1])); ok {
		t.Fatal("withinCeiling allows a call above the ceiling")
	}
	// An unregistered workspace behaves as before (laptop and pilot paths).
	if _, err := l.raise("ns/legacy", parsed(t, lv[2])); err != nil {
		t.Fatalf("legacy raise: %v", err)
	}
}

// Registration keeps a workspace's existing label: its ceiling is the join of the floor and what it
// has read, so a workspace that already read higher content keeps that level and goes no further.
func TestRegisteringALabelledWorkspaceKeepsItsLevel(t *testing.T) {
	lv := levels(t)
	l, _ := openedLabels(t)
	if _, err := l.raise("ns/a", parsed(t, lv[1])); err != nil {
		t.Fatal(err)
	}
	ceiling, err := l.register("ns/a", "owner-1", parsed(t, lv[0]))
	if err != nil || marking.Banner(ceiling) != lv[1] {
		t.Fatalf("ceiling %q %v", marking.Banner(ceiling), err)
	}
	if _, err := l.register("ns/a", "owner-1", parsed(t, lv[0])); err != nil {
		t.Fatalf("register is idempotent for the same owner: %v", err)
	}
	if _, err := l.register("ns/a", "owner-2", parsed(t, lv[0])); err == nil {
		t.Fatal("a second owner registered the same workspace")
	}
}

// A fork starts at its parent's label with the ceiling the user agreed to; the parent's label and
// ceiling are unchanged, and the fork rises only as far as its own ceiling.
func TestAForkLeavesItsParentUnchanged(t *testing.T) {
	lv := levels(t)
	l, path := openedLabels(t)
	if _, err := l.register("ns/p", "owner-1", parsed(t, lv[0])); err != nil {
		t.Fatal(err)
	}
	if _, err := l.raise("ns/p", parsed(t, lv[0])); err != nil {
		t.Fatal(err)
	}
	label, err := l.fork("ns/p", "ns/c", "owner-1", parsed(t, lv[1]))
	if err != nil || marking.Banner(label) != lv[0] {
		t.Fatalf("fork: %v %q", err, marking.Banner(label))
	}
	if _, err := l.raise("ns/c", parsed(t, lv[1])); err != nil {
		t.Fatalf("the fork's agreed raise: %v", err)
	}
	if _, err := l.raise("ns/c", parsed(t, lv[2])); err == nil {
		t.Fatal("the fork rose above its ceiling")
	}
	pl, _, _, pc, _ := l.describe("ns/p")
	if marking.Banner(pl) != lv[0] || marking.Banner(pc) != lv[0] {
		t.Fatalf("parent changed: label %q ceiling %q", marking.Banner(pl), marking.Banner(pc))
	}
	// Everything survives a restart.
	l.file.Close()
	again, err := openLabels(path, marking.Current())
	if err != nil {
		t.Fatal(err)
	}
	defer again.file.Close()
	cl, labelled, owner, cc, registered := again.describe("ns/c")
	if !labelled || !registered || owner != "owner-1" || marking.Banner(cl) != lv[1] || marking.Banner(cc) != lv[1] {
		t.Fatalf("fork after restart: %q %v %q %q %v", marking.Banner(cl), labelled, owner, marking.Banner(cc), registered)
	}
	if pl, _, _, _, _ := again.describe("ns/p"); marking.Banner(pl) != lv[0] {
		t.Fatalf("parent after restart: %q", marking.Banner(pl))
	}
}

func TestAForkIsRefusedUnlessEverythingChecks(t *testing.T) {
	lv := levels(t)
	l, _ := openedLabels(t)
	if _, err := l.register("ns/p", "owner-1", parsed(t, lv[0])); err != nil {
		t.Fatal(err)
	}
	if _, err := l.raise("ns/p", parsed(t, lv[0])); err != nil {
		t.Fatal(err)
	}
	if _, err := l.raise("ns/used", parsed(t, lv[0])); err != nil {
		t.Fatal(err)
	}
	if _, err := l.register("ns/other", "owner-2", parsed(t, lv[0])); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		parent, child, owner string
		ceiling              string
	}{
		"unregistered parent":      {"ns/x", "ns/c", "owner-1", lv[1]},
		"another owner's parent":   {"ns/p", "ns/c", "owner-2", lv[1]},
		"child already labelled":   {"ns/p", "ns/used", "owner-1", lv[1]},
		"child already registered": {"ns/p", "ns/other", "owner-1", lv[1]},
		"child is the parent":      {"ns/p", "ns/p", "owner-1", lv[1]},
	} {
		if _, err := l.fork(tc.parent, tc.child, tc.owner, parsed(t, tc.ceiling)); err == nil {
			t.Errorf("%s: fork accepted", name)
		}
	}
	// A ceiling below the parent's label would be a write down.
	if _, err := l.raise("ns/high", parsed(t, lv[2])); err != nil {
		t.Fatal(err)
	}
	if _, err := l.register("ns/high", "owner-1", parsed(t, lv[0])); err != nil {
		t.Fatal(err)
	}
	if _, err := l.fork("ns/high", "ns/c2", "owner-1", parsed(t, lv[1])); err == nil {
		t.Error("a fork with a ceiling below its parent's label was accepted")
	}
	if _, _, _, _, registered := l.describe("ns/c"); registered {
		t.Error("a refused fork left a record")
	}
}

// The ceiling and owner records fail closed on load like labels do.
func TestWorkspaceRecordsFailClosed(t *testing.T) {
	lv := levels(t)
	dir := t.TempDir()
	reg := `{"workspace":"ns/a","owner":"o1","ceiling":"` + lv[0] + `"}`
	for name, content := range map[string]string{
		"owner without ceiling": `{"workspace":"ns/a","owner":"o1"}`,
		"ceiling without owner": `{"workspace":"ns/a","ceiling":"` + lv[0] + `"}`,
		"second owner":          reg + "\n" + `{"workspace":"ns/a","owner":"o2","ceiling":"` + lv[0] + `"}`,
		"other ceiling":         reg + "\n" + `{"workspace":"ns/a","owner":"o1","ceiling":"` + lv[1] + `"}`,
		"label above ceiling":   reg + "\n" + `{"workspace":"ns/a","label":"` + lv[1] + `"}`,
		"bad owner":             `{"workspace":"ns/a","owner":"o 1","ceiling":"` + lv[0] + `"}`,
		"empty record":          `{"workspace":"ns/a"}`,
	} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		if err := os.WriteFile(p, []byte(labelsHeader+"\n"+content+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if l, err := openLabels(p, marking.Current()); err == nil {
			l.file.Close()
			t.Errorf("%s: accepted", name)
		}
	}
}

// Marking names come from configuration: a SECRET-high deployment forks the same way.
func TestCeilingsWorkAtEveryLevel(t *testing.T) {
	lv := levels(t)
	l, _ := openedLabels(t)
	top := lv[len(lv)-1]
	if _, err := l.register("ns/p", "o", parsed(t, lv[0])); err != nil {
		t.Fatal(err)
	}
	for i, banner := range lv[1:] {
		child := "ns/c" + string(rune('a'+i))
		if _, err := l.fork("ns/p", child, "o", parsed(t, banner)); err != nil {
			t.Fatalf("%s: %v", banner, err)
		}
		if _, err := l.raise(child, parsed(t, banner)); err != nil {
			t.Fatalf("%s: raise: %v", banner, err)
		}
	}
	if _, err := l.fork("ns/p", "ns/top", "o", parsed(t, top)); err != nil {
		t.Fatal(err)
	}
}
