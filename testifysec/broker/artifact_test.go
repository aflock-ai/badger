// jade:ring local

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func artifactTar(t *testing.T, headers ...tar.Header) []byte {
	t.Helper()
	var raw bytes.Buffer
	writer := tar.NewWriter(&raw)
	if err := writer.WriteHeader(&tar.Header{Name: "workspace/", Typeflag: tar.TypeDir, Mode: 01777}); err != nil {
		t.Fatal(err)
	}
	for _, h := range headers {
		if err := writer.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := writer.Write(bytes.Repeat([]byte{255}, int(h.Size))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return raw.Bytes()
}
func decodeArtifact(t *testing.T, artifact *artifactEnvelope) workspaceBundle {
	t.Helper()
	if artifact == nil {
		t.Fatal("missing artifact")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(artifact.PayloadBase64)
	if err != nil || hash(payload) != artifact.SHA256 {
		t.Fatal("artifact exact-byte digest mismatch")
	}
	var bundle workspaceBundle
	if err := json.Unmarshal(payload, &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.FinalManifestSHA256 != artifact.FinalManifestSHA256 || hash(marshal(bundle.Files)) != bundle.FinalManifestSHA256 {
		t.Fatal("manifest digest mismatch")
	}
	for _, file := range bundle.Changes {
		content, err := base64.StdEncoding.Strict().DecodeString(file.ContentBase64)
		if err != nil || int64(len(content)) != file.Size || hash(content) != file.SHA256 {
			t.Fatal("file exact-byte digest mismatch")
		}
	}
	return bundle
}
func TestArtifactRetainsExactChangesAndRemovals(t *testing.T) {
	initial := []material{{Path: "delete", SHA256: hash([]byte("old")), Size: 3}, {Path: "unchanged", SHA256: hash([]byte{255}), Size: 1}}
	raw := artifactTar(t, tar.Header{Name: "workspace/unchanged", Typeflag: tar.TypeReg, Mode: 0644, Size: 1}, tar.Header{Name: "workspace/binary", Typeflag: tar.TypeReg, Mode: 0755, Size: 2})
	artifact, err := captureArtifact(context.Background(), bytes.NewReader(raw), initial, limits{WorkspaceFiles: 10, WorkspaceBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	bundle := decodeArtifact(t, artifact)
	if len(bundle.Changes) != 1 || bundle.Changes[0].Path != "binary" || !bundle.Changes[0].Executable || len(bundle.Removed) != 1 || bundle.Removed[0] != "delete" || bundle.MaterialsSHA256 != hash(marshal(initial)) {
		t.Fatalf("wrong changes: %+v", bundle)
	}
}
func TestArtifactRejectsAmbiguousAndSpecialArchives(t *testing.T) {
	regular := func(name string) tar.Header { return tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0644} }
	cases := map[string][]tar.Header{
		"traversal":          {regular("workspace/../escape")},
		"absolute":           {regular("/workspace/escape")},
		"dot-component":      {regular("workspace/a/./x")},
		"backslash":          {regular(`workspace/a\b`)},
		"git":                {regular("workspace/.GiT/config")},
		"git-ntfs":           {regular("workspace/git~1/config")},
		"git-hfs":            {regular("workspace/.g\u200cit/config")},
		"trailing-dot":       {regular("workspace/.git./config")},
		"alternate-stream":   {regular("workspace/a:b")},
		"duplicate":          {regular("workspace/a"), regular("workspace/a")},
		"case-alias":         {regular("workspace/A"), regular("workspace/a")},
		"prefix-file-first":  {regular("workspace/a"), regular("workspace/a/b")},
		"prefix-child-first": {regular("workspace/a/b"), regular("workspace/a")},
		"prefix-case":        {regular("workspace/A/b"), regular("workspace/a/c")},
		"symlink":            {{Name: "workspace/link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}},
		"hardlink":           {{Name: "workspace/link", Typeflag: tar.TypeLink, Linkname: "workspace/a"}},
		"fifo":               {{Name: "workspace/pipe", Typeflag: tar.TypeFifo}},
		"device":             {{Name: "workspace/dev", Typeflag: tar.TypeChar}},
		"setuid":             {{Name: "workspace/setuid", Typeflag: tar.TypeReg, Mode: 04755}},
		"xattr":              {{Name: "workspace/xattr", Typeflag: tar.TypeReg, Xattrs: map[string]string{"user.test": "value"}}},
	}
	for name, headers := range cases {
		t.Run(name, func(t *testing.T) {
			artifact, err := captureArtifact(context.Background(), bytes.NewReader(artifactTar(t, headers...)), nil, limits{WorkspaceFiles: 10, WorkspaceBytes: 1024})
			if err == nil || artifact != nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
}
func TestArtifactBudgetsAndTrailer(t *testing.T) {
	for _, test := range []struct {
		name   string
		raw    []byte
		limits limits
	}{
		{"entries", artifactTar(t, tar.Header{Name: "workspace/a", Typeflag: tar.TypeReg}, tar.Header{Name: "workspace/b", Typeflag: tar.TypeReg}), limits{WorkspaceFiles: 1, WorkspaceBytes: 10}},
		{"bytes", artifactTar(t, tar.Header{Name: "workspace/a", Typeflag: tar.TypeReg, Size: 11}), limits{WorkspaceFiles: 1, WorkspaceBytes: 10}},
		{"changed-content", artifactTar(t, tar.Header{Name: "workspace/a", Typeflag: tar.TypeReg, Size: artifactContentLimit + 1}), limits{WorkspaceFiles: 1, WorkspaceBytes: 1 << 20}},
		{"trailer", append(artifactTar(t), []byte("hidden")...), limits{WorkspaceFiles: 1, WorkspaceBytes: 10}},
		{"missing-terminator", artifactTar(t)[:512], limits{WorkspaceFiles: 1, WorkspaceBytes: 10}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := captureArtifact(context.Background(), bytes.NewReader(test.raw), nil, test.limits); err == nil {
				t.Fatal("budget or trailer accepted")
			}
		})
	}
}
