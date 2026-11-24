package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/badger/testifysec/connectors/internal/bundle"
)

const image = "sha256:abababababababababababababababababababababababababababababababab"

// keygen, manifest, pack and verify make a bundle the gateway's loader accepts; sign makes a signature the
// gateway's profile check accepts.
func TestPackProducesAnAdmissibleBundle(t *testing.T) {
	dir := t.TempDir()
	if err := run([]string{"keygen", "-out", filepath.Join(dir, "vendor")}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "vendor.key")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("private key: %v %v", err, fi)
	}
	// A plugin that prints its manifest with --manifest, as sdk.Main does.
	exe := filepath.Join(dir, "demo")
	m := `{"schema":1,"name":"demo","version":"1.0.0","tools":[{"name":"demo_get","description":"Get.","inputSchema":{"type":"object"}}]}`
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n[ \"$1\" = --manifest ] && echo '"+m+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	tools := filepath.Join(dir, "tools.json")
	if err := run([]string{"manifest", "-exe", exe, "-out", tools}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "bundle")
	if err := run([]string{"pack", "-manifest", tools, "-digest", image, "-key", filepath.Join(dir, "vendor.key"), "-out", out}); err != nil {
		t.Fatal(err)
	}
	pubB, _ := os.ReadFile(filepath.Join(dir, "vendor.pub"))
	pub, err := bundle.ParseKey(strings.TrimSpace(string(pubB)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := bundle.Load(out, pub)
	if err != nil || got.Digest != image || len(got.Tools) != 1 {
		t.Fatalf("packed bundle: %v %+v", err, got)
	}
	if _, err := os.Stat(filepath.Join(out, "plugin")); err == nil {
		t.Fatal("the executable was bundled: the vendor image carries it")
	}
	if err := run([]string{"verify", "-bundle", out, "-pub", filepath.Join(dir, "vendor.pub")}); err != nil {
		t.Fatal(err)
	}
	// pack refuses an existing output and a missing or malformed image digest; manifest refuses a
	// plugin that prints no manifest.
	for _, bad := range []string{"", "sha256:abc", "latest"} {
		if err := run([]string{"pack", "-manifest", tools, "-digest", bad, "-key", filepath.Join(dir, "vendor.key"), "-out", filepath.Join(dir, "b-"+bad)}); err == nil {
			t.Fatalf("packed with image %q", bad)
		}
	}
	if err := run([]string{"pack", "-manifest", tools, "-digest", image, "-key", filepath.Join(dir, "vendor.key"), "-out", out}); err == nil {
		t.Fatal("pack overwrote a bundle")
	}
	_ = os.WriteFile(exe, []byte("#!/bin/sh\necho nope\n"), 0o755)
	if err := run([]string{"manifest", "-exe", exe, "-out", filepath.Join(dir, "t2.json")}); err == nil {
		t.Fatal("wrote a manifest for a plugin that prints none")
	}

	profile := filepath.Join(dir, "profile.json")
	_ = os.WriteFile(profile, []byte(`{"x":1}`), 0o600)
	if err := run([]string{"sign", "-key", filepath.Join(dir, "vendor.key"), "-in", profile}); err != nil {
		t.Fatal(err)
	}
	sig, _ := os.ReadFile(profile + ".sig")
	if bundle.Verify(pub, []byte(`{"x":1}`), sig) != nil {
		t.Fatal("profile signature does not verify")
	}
}

// A bare -exe name is the file in the current directory, never a same-named program on PATH: the
// tool list must come from that binary.
func TestManifestRunsTheFileItIsGiven(t *testing.T) {
	dir := t.TempDir()
	if err := run([]string{"keygen", "-out", filepath.Join(dir, "vendor")}); err != nil {
		t.Fatal(err)
	}
	manifest := func(tool string) string {
		return "#!/bin/sh\n[ \"$1\" = --manifest ] && echo '{\"schema\":1,\"name\":\"demo\",\"version\":\"1.0.0\",\"tools\":[{\"name\":\"" + tool + "\",\"description\":\"d\",\"inputSchema\":{\"type\":\"object\"}}]}'\n"
	}
	work, elsewhere := filepath.Join(dir, "work"), filepath.Join(dir, "path")
	for _, d := range []string{work, elsewhere} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(work, "plugin"), []byte(manifest("real_tool")), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(elsewhere, "plugin"), []byte(manifest("impostor_tool")), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", elsewhere+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Chdir(work)
	out := filepath.Join(dir, "tools.json")
	if err := run([]string{"manifest", "-exe", "plugin", "-out", out}); err != nil {
		t.Fatal(err)
	}
	m, _ := os.ReadFile(out)
	if !strings.Contains(string(m), "real_tool") || strings.Contains(string(m), "impostor_tool") {
		t.Fatalf("manifest %s", m)
	}
}

// manifest runs --manifest from a private copy of the bytes it read, never from the given path, so
// replacing the file while pack runs cannot pair one binary's tool list with another's digest.
func TestManifestRunsAPrivateCopy(t *testing.T) {
	dir := t.TempDir()
	if err := run([]string{"keygen", "-out", filepath.Join(dir, "vendor")}); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "plugin")
	// Run from its own path, it declares a tool the bundled bytes would not be checked against.
	script := "#!/bin/sh\nt=copy_tool\n[ \"$0\" = '" + exe + "' ] && t=path_tool\n" +
		"[ \"$1\" = --manifest ] && echo '{\"schema\":1,\"name\":\"demo\",\"version\":\"1.0.0\",\"tools\":[{\"name\":\"'$t'\",\"description\":\"d\",\"inputSchema\":{\"type\":\"object\"}}]}'\n"
	if err := os.WriteFile(exe, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "tools.json")
	if err := run([]string{"manifest", "-exe", exe, "-out", out}); err != nil {
		t.Fatal(err)
	}
	m, _ := os.ReadFile(out)
	if !strings.Contains(string(m), "copy_tool") {
		t.Fatalf("pack ran the given path, not its copy: %s", m)
	}
}

// pack never runs plugin code, so a hostile plugin never runs beside the signing key: it refuses
// -exe outright, and the plugin given there is never started.
func TestPackNeverRunsThePlugin(t *testing.T) {
	dir := t.TempDir()
	if err := run([]string{"keygen", "-out", filepath.Join(dir, "vendor")}); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "ran")
	exe := filepath.Join(dir, "plugin")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\ntouch '"+marker+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	tools := filepath.Join(dir, "tools.json")
	_ = os.WriteFile(tools, []byte(`{"schema":1,"name":"demo","version":"1","tools":[]}`), 0o644)
	err := run([]string{"pack", "-exe", exe, "-manifest", tools, "-digest", image, "-key", filepath.Join(dir, "vendor.key"), "-out", filepath.Join(dir, "b")})
	if err == nil || !strings.Contains(err.Error(), "does not run the plugin") {
		t.Fatalf("pack took -exe: %v", err)
	}
	if err := run([]string{"pack", "-manifest", tools, "-digest", image, "-key", filepath.Join(dir, "vendor.key"), "-out", filepath.Join(dir, "b")}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("pack ran the plugin")
	}
}
