// jade:ring local
package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"runtime"
	"testing"
)

type testEntry struct {
	name        string
	data        []byte
	mode        os.FileMode
	compression uint16
}

func archiveFixture(t *testing.T, entries []testEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: entry.compression}
		header.SetMode(entry.mode)
		file, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = file.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func specFixture(t *testing.T) (payloadSpec, []testEntry) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	entries := []testEntry{{"data/config.json", []byte{0, 255, 1}, 0400, zip.Store}, {"runner", raw, 0500, zip.Store}}
	spec := payloadSpec{Schema: "testifysec.hardened-code.single-executable/v1", OS: runtime.GOOS, Arch: runtime.GOARCH, Entry: "runner", Product: "TestifySec Hardened Code", Command: "hardened-code", Version: "fixture", UpstreamVersion: "fixture", Attribution: "Built on OpenCode", InputManifestSHA256: digest([]byte("fixture"))}
	for _, entry := range entries {
		spec.Files = append(spec.Files, fileSpec{Name: entry.name, SHA256: digest(entry.data), Size: int64(len(entry.data)), Mode: uint32(entry.mode)})
	}
	spec.PayloadSHA256 = digest(archiveFixture(t, entries))
	return spec, entries
}

func TestMaterializedPayload(t *testing.T) {
	spec, entries := specFixture(t)
	root, _, clean, err := privateDirectory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := clean(true); err != nil {
			t.Error(err)
		}
	})
	if err = materialize(root, spec, archiveFixture(t, entries)); err != nil {
		t.Fatal(err)
	}
	raw, err := root.ReadFile("data/config.json")
	if err != nil || !bytes.Equal(raw, entries[0].data) {
		t.Fatal("exact non-UTF8 bytes not retained")
	}
	if err = root.Chmod("data/config.json", 0600); err != nil {
		t.Fatal(err)
	}
	if err = root.WriteFile("data/config.json", []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	if verifyMaterialized(root, spec) == nil {
		t.Fatal("changed extracted bytes accepted")
	}
}

func TestManifestRefusals(t *testing.T) {
	base, _ := specFixture(t)
	cases := []struct {
		name   string
		change func(*payloadSpec)
	}{
		{"other-os", func(s *payloadSpec) { s.OS = "unsupported" }},
		{"other-arch", func(s *payloadSpec) { s.Arch = "unsupported" }},
		{"entry-absent", func(s *payloadSpec) { s.Entry = "absent" }},
		{"entry-not-executable", func(s *payloadSpec) { s.Files[1].Mode = 0400 }},
		{"excess-mode", func(s *payloadSpec) { s.Files[1].Mode = 0755 }},
		{"negative-size", func(s *payloadSpec) { s.Files[0].Size = -1 }},
		{"excess-file", func(s *payloadSpec) { s.Files[0].Size = maxFile + 1 }},
		{"duplicate-file", func(s *payloadSpec) { s.Files = append(s.Files, s.Files[1]) }},
		{"path-traversal", func(s *payloadSpec) { s.Files[0].Name = "../escape" }},
		{"absolute-path", func(s *payloadSpec) { s.Files[0].Name = "/escape" }},
		{"windows-stream", func(s *payloadSpec) { s.Files[0].Name = "file:stream" }},
		{"windows-device", func(s *payloadSpec) { s.Files[0].Name = "NUL.txt" }},
		{"windows-trailing-dot", func(s *payloadSpec) { s.Files[0].Name = "file." }},
		{"case-directory-alias", func(s *payloadSpec) { s.Files[1].Name = "DATA/runner"; s.Entry = s.Files[1].Name }},
		{"prefix-collision", func(s *payloadSpec) {
			s.Files[0].Name = "runner"
			s.Files[1].Name = "runner/entry"
			s.Entry = s.Files[1].Name
		}},
		{"display-control", func(s *payloadSpec) { s.Product += "\x1b" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			spec := base
			spec.Files = append([]fileSpec{}, base.Files...)
			test.change(&spec)
			raw, err := json.Marshal(spec)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = manifest(raw, digest(raw)); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manifest(raw, digest(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err = manifest(raw, digest([]byte("other"))); err == nil {
		t.Fatal("wrong manifest digest accepted")
	}
}

func TestArchiveRefusals(t *testing.T) {
	base, original := specFixture(t)
	cases := []struct {
		name   string
		change func([]testEntry) []testEntry
	}{
		{"archive-traversal", func(e []testEntry) []testEntry { e[0].name = "../escape"; return e }},
		{"archive-symlink", func(e []testEntry) []testEntry { e[0].mode = os.ModeSymlink | 0400; return e }},
		{"archive-setuid", func(e []testEntry) []testEntry { e[1].mode = os.ModeSetuid | 0500; return e }},
		{"archive-directory", func(e []testEntry) []testEntry { e[0].mode = os.ModeDir | 0400; return e }},
		{"archive-compression", func(e []testEntry) []testEntry { e[0].compression = zip.Deflate; return e }},
		{"archive-unlisted", func(e []testEntry) []testEntry { return append(e, testEntry{"extra", []byte("x"), 0400, zip.Store}) }},
		{"archive-duplicate", func(e []testEntry) []testEntry { return append(e, e[0]) }},
		{"archive-wrong-digest", func(e []testEntry) []testEntry { e[0].data = []byte{2, 3, 4}; return e }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			entries := test.change(append([]testEntry{}, original...))
			raw := archiveFixture(t, entries)
			spec := base
			spec.PayloadSHA256 = digest(raw)
			root, _, clean, err := privateDirectory()
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := clean(true); err != nil {
					t.Error(err)
				}
			}()
			if materialize(root, spec, raw) == nil {
				t.Fatal("invalid archive accepted")
			}
		})
	}
}

func TestTargetRejectsNonNativeEntry(t *testing.T) {
	if executableTarget(bytes.NewReader([]byte("#!/bin/sh\nexit 0\n")), runtime.GOOS, runtime.GOARCH) == nil {
		t.Fatal("script accepted as native entry")
	}
}

func TestDeclaredPluginAssetPaths(t *testing.T) {
	for _, name := range []string{"approved-plugins/@scope/codex-oauth/index.js", ".opencode/plugins/oauth.js", "node_modules/.cache/asset.wasm"} {
		if !portableName(name) {
			t.Fatalf("safe declared plugin asset refused: %s", name)
		}
	}
	for _, name := range []string{".git/config", "plugins/../../escape", "plugins/NUL.txt", "plugins/."} {
		if portableName(name) {
			t.Fatalf("unsafe plugin asset accepted: %s", name)
		}
	}
}
