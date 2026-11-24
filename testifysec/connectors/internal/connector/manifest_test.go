package connector

import (
	"encoding/json"
	"testing"

	"github.com/aflock-ai/badger/testifysec/connectors/internal/bundle"
)

// The manifest lists every tool, write tools included and marked, without a client, a token or a
// classification: it describes the binary, not a deployment.
func TestManifestListsEveryToolAndMarksWrites(t *testing.T) {
	b, err := Manifest(testSpec)
	if err != nil {
		t.Fatal(err)
	}
	var m bundle.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	m.Digest = bundle.Digest([]byte("x")) // pack adds it
	b, _ = json.Marshal(m)
	if _, err := bundle.Parse(b); err != nil {
		t.Fatalf("manifest does not parse as a bundle manifest: %v", err)
	}
	if m.Name != testSpec.Name || m.Version != testSpec.Version {
		t.Fatalf("%+v", m)
	}
	writes := map[string]bool{}
	for _, tl := range m.Tools {
		writes[tl.Name] = tl.Write
	}
	for _, tl := range testSpec.Tools(nil) {
		if w, ok := writes[tl.Name]; !ok || w != tl.Write {
			t.Errorf("tool %s: in manifest %v, write %v", tl.Name, ok, w)
		}
	}
	var raw map[string]any
	_ = json.Unmarshal(b, &raw)
	if _, ok := raw["classification"]; ok {
		t.Fatal("a manifest must not carry a classification")
	}
}
