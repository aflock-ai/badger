// jade:ring local
package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestManagedPortablePaths(t *testing.T) {
	for _, p := range []string{"file", "nested/a&b/result.bin", ".config/file", "space name"} {
		if !managedPath(p) {
			t.Fatal(p)
		}
	}
	for _, p := range []string{"../x", "/x", "a//b", "a/../b", ".git/x", "a/.GiT", "git~1/config", "nul.txt", "a/COM0", "a/lpt9.txt", "a.", "a ", "a\\b", "a:b", "a\x00", "é"} {
		if managedPath(p) {
			t.Fatal(p)
		}
	}
	for _, pair := range [][2]string{{"A/x", "a/y"}, {"a", "a/b"}, {"a/b", "a"}, {"a/b", "a/b"}} {
		var set pathSet
		if !set.add(pair[0], true) || set.add(pair[1], true) {
			t.Fatal(pair)
		}
	}
}

func TestManagedRecursiveSnapshot(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "nested/a&b"), 0700); err != nil {
		t.Fatal(err)
	}
	raw := []byte{0, 255, 128, 10}
	file := filepath.Join(dir, "nested/a&b/run.bin")
	if err := os.WriteFile(file, raw, 0700); err != nil {
		t.Fatal(err)
	}
	files, err := captureManaged(dir)
	if err != nil || len(files) != 1 {
		t.Fatalf("%+v %v", files, err)
	}
	f := files[0]
	if f.Path != "nested/a&b/run.bin" || f.Size != 4 || f.SHA256 != sum(raw) || !f.Executable || f.ContentBase64 != base64.StdEncoding.EncodeToString(raw) {
		t.Fatal(f)
	}
	if err := os.Symlink(file, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := captureManaged(dir); err == nil {
		t.Fatal("symlink exported")
	}
}

func TestManagedInputContentAndManifest(t *testing.T) {
	file := managedFile{Path: "a&b", SHA256: sum([]byte("x")), Size: 1, Executable: true, ContentBase64: "eA=="}
	files, _ := json.Marshal([]managedFile{file})
	request, _ := json.Marshal(managedRequest{Prompt: "hello", TimeoutSeconds: 2})
	j := job{Request: request, Materials: files}
	if err := decodeManaged(&j); err != nil {
		t.Fatal(err)
	}
	descriptor := `[{"path":"a\u0026b","sha256":"` + sum([]byte("x")) + `","size":1,"executable":true}]`
	if descriptionHash(j.ManagedFiles) != sum([]byte(descriptor)) {
		t.Fatal("descriptor bytes differ")
	}
	file.ContentBase64 = "eQ=="
	j.Materials, _ = json.Marshal([]managedFile{file})
	if decodeManaged(&j) == nil {
		t.Fatal("tampered bytes admitted")
	}
}

func TestManagedMalformedUnicode(t *testing.T) {
	for _, raw := range []string{`{"prompt":"\ud800","timeoutSeconds":2}`, `{"prompt":"\udc00","timeoutSeconds":2}`} {
		j := job{Request: json.RawMessage(raw), Materials: json.RawMessage(`[]`)}
		if decodeManaged(&j) == nil {
			t.Fatal("lossy Unicode accepted")
		}
	}
}
