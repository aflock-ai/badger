package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/badger/testifysec/connectors/marking"
)

// A workspace's label survives a restart: it is in the labels file before the answer is passed on.
func TestLabelsSurviveARestart(t *testing.T) {
	lv := levels(t)
	low, high := mustSource(t, "low", lv[0]).marking, mustSource(t, "high", lv[2]).marking
	path := filepath.Join(t.TempDir(), "labels")
	if err := initLabels(path, marking.Current()); err != nil {
		t.Fatal(err)
	}
	if err := initLabels(path, marking.Current()); err == nil {
		t.Fatal("init replaced an existing labels file")
	}
	l, err := openLabels(path, marking.Current())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.raise("ns/a", high); err != nil {
		t.Fatal(err)
	}
	if _, err := l.raise("ns/a", low); err != nil { // no change, nothing appended
		t.Fatal(err)
	}
	l.file.Close()
	again, err := openLabels(path, marking.Current())
	if err != nil {
		t.Fatal(err)
	}
	if label, ok := again.allows("ns/a", low); ok || marking.Banner(label) != lv[2] {
		t.Fatalf("label after restart: %q allows low %v", marking.Banner(label), ok)
	}
	if _, ok := again.allows("ns/b", low); !ok {
		t.Fatal("another workspace inherited a label")
	}
	b, _ := os.ReadFile(path)
	if strings.Count(string(b), "\n") != 2 {
		t.Fatalf("file: %q", b)
	}
}

// Without a labels file, or with one the pod cannot fully read, it refuses rather than starting with
// every label empty. Only a torn last record is dropped, and the file is cut back to whole records.
func TestLabelsFileFailsClosed(t *testing.T) {
	lv := levels(t)
	dir := t.TempDir()
	if _, err := openLabels(filepath.Join(dir, "absent"), marking.Current()); err == nil {
		t.Fatal("a missing labels file was accepted")
	}
	write := func(content string) string {
		p := filepath.Join(dir, "labels")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	record := `{"workspace":"ns/a","label":"` + lv[2] + `"}`
	for name, content := range map[string]string{
		"empty":          "",
		"no header":      record + "\n",
		"torn header":    labelsHeader,
		"bad record":     labelsHeader + "\n{\"workspace\":\"ns/a\"\n" + record + "\n",
		"unknown field":  labelsHeader + "\n" + `{"workspace":"ns/a","label":"` + lv[0] + `","x":1}` + "\n",
		"bad marking":    labelsHeader + "\n" + `{"workspace":"ns/a","label":"` + lv[2] + `//NOT A TOKEN"}` + "\n",
		"no workspace":   labelsHeader + "\n" + `{"label":"` + lv[2] + `"}` + "\n",
		"two on a line":  labelsHeader + "\n" + `{"workspace":"ns/a","label":"` + lv[0] + `"}{"workspace":"ns/a","label":"` + lv[2] + `"}` + "\n",
		"trailing text":  labelsHeader + "\n" + record + ` x` + "\n",
		"bad workspace":  labelsHeader + "\n" + `{"workspace":"a","label":"` + lv[2] + `"}` + "\n",
		"workspace path": labelsHeader + "\n" + `{"workspace":"ns/a/b","label":"` + lv[2] + `"}` + "\n",
		"other version":  `{"conngw-labels":2}` + "\n" + record + "\n",
		"lowered label":  labelsHeader + "\n" + record + "\n" + `{"workspace":"ns/a","label":"` + lv[0] + `"}` + "\n",
		"unknown token":  labelsHeader + "\n" + `{"workspace":"ns/a","label":"` + lv[2] + `//ZZ"}` + "\n",
	} {
		if _, err := openLabels(write(content), marking.Current()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	p := write(labelsHeader + "\n" + record + "\n" + `{"workspace":"ns/b","la`)
	l, err := openLabels(p, marking.Current())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := l.allows("ns/a", mustSource(t, "low", lv[0]).marking); ok {
		t.Fatal("whole record lost")
	}
	if _, err := l.raise("ns/b", mustSource(t, "low", lv[0]).marking); err != nil {
		t.Fatal(err)
	}
	l.file.Close()
	if _, err := openLabels(p, marking.Current()); err != nil {
		t.Fatalf("file after a torn record and an append: %v", err)
	}
}

// Once the file cannot be written, no answer is passed on again until a restart reads the file
// back: not a retry at the same marking, not another workspace's. After the restart the label that
// was never written is absent, and nothing that carried it was released.
func TestAFailedWriteStopsEveryLaterRelease(t *testing.T) {
	lv := levels(t)
	high := mustSource(t, "high", lv[2]).marking
	path := filepath.Join(t.TempDir(), "labels")
	if err := initLabels(path, marking.Current()); err != nil {
		t.Fatal(err)
	}
	l, err := openLabels(path, marking.Current())
	if err != nil {
		t.Fatal(err)
	}
	l.file.Close() // the disk goes away
	if _, err := l.raise("ns/a", high); err == nil {
		t.Fatal("a raise that was not written succeeded")
	}
	for _, ws := range []string{"ns/a", "ns/b"} {
		if _, err := l.raise(ws, high); err == nil {
			t.Fatalf("%s: a later raise succeeded after a failed write", ws)
		}
	}
	// In memory the label stays raised, so calls to lower connectors are still refused.
	if _, ok := l.allows("ns/a", mustSource(t, "low", lv[0]).marking); ok {
		t.Fatal("label dropped in memory")
	}
	again, err := openLabels(path, marking.Current())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := again.raise("ns/a", high); err != nil {
		t.Fatalf("after a restart: %v", err)
	}
	again.file.Close()
	final, err := openLabels(path, marking.Current())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := final.allows("ns/a", mustSource(t, "low", lv[0]).marking); ok {
		t.Fatal("label written after the restart not restored")
	}
}

// One conngw owns a labels file: a second on the same file refuses while the first holds it, and
// starts once the first has stopped.
func TestOneOwnerPerLabelsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "labels")
	if err := initLabels(path, marking.Current()); err != nil {
		t.Fatal(err)
	}
	first, err := openLabels(path, marking.Current())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openLabels(path, marking.Current()); err == nil || !strings.Contains(err.Error(), "another conngw holds it") {
		t.Fatalf("second owner: %v", err)
	}
	first.file.Close() // the first process exits
	second, err := openLabels(path, marking.Current())
	if err != nil {
		t.Fatalf("after the first stopped: %v", err)
	}
	second.file.Close()
}
