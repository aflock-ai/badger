package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"path"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const responseLimit = 2 << 20
const artifactContentLimit = 256 << 10
const artifactPayloadLimit = 768 << 10

type changedFile struct {
	material
	ContentBase64 string `json:"contentBase64"`
}
type workspaceBundle struct {
	Schema              string        `json:"schema"`
	MaterialsSHA256     string        `json:"materialsSha256"`
	FinalManifestSHA256 string        `json:"finalManifestSha256"`
	Files               []material    `json:"files"`
	Changes             []changedFile `json:"changes"`
	Removed             []string      `json:"removed"`
}
type artifactEnvelope struct {
	Schema              string `json:"schema"`
	Scope               string `json:"scope"`
	PayloadBase64       string `json:"payloadBase64"`
	SHA256              string `json:"sha256"`
	MaterialsSHA256     string `json:"materialsSha256"`
	FinalManifestSHA256 string `json:"finalManifestSha256"`
	ChangedFiles        int    `json:"changedFiles"`
	RemovedFiles        int    `json:"removedFiles"`
}

// Output is a portable repository artifact, not a filesystem restore archive.
// Reject ambiguous names before they can reach a different host filesystem.
func artifactPath(name string) bool {
	if name == "" || len(name) > 1024 || !utf8.ValidString(name) || path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.ContainsAny(name, `\:*?"<>|`) {
		return false
	}
	parts := strings.Split(name, "/")
	if len(parts) > 32 {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > 255 || strings.TrimRight(part, ". ") != part {
			return false
		}
		for _, r := range part {
			if r > 127 || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				return false
			}
		}
		lower := strings.ToLower(part)
		if lower == ".git" || strings.HasPrefix(lower, "git~") {
			return false
		}
		// Windows device names remain aliases even with filename extensions.
		stem, _, _ := strings.Cut(lower, ".")
		if stem == "con" || stem == "prn" || stem == "aux" || stem == "nul" || len(stem) == 4 && (strings.HasPrefix(stem, "com") || strings.HasPrefix(stem, "lpt")) && stem[3] >= '0' && stem[3] <= '9' {
			return false
		}
	}
	return true
}

// capBuffer retains at most the remaining changed-content budget plus one byte.
// Unchanged large files can be hashed without allocating their entire contents.
type capBuffer struct {
	bytes.Buffer
	remaining int
}

type countReader struct {
	reader io.Reader
	bytes  int64
}

func (r *countReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.bytes += int64(n)
	return n, err
}

func (b *capBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if len(p) > b.remaining {
		p = p[:b.remaining]
	}
	b.Buffer.Write(p)
	b.remaining -= len(p)
	return n, nil
}

func captureArtifact(ctx context.Context, source io.Reader, initial []material, limits limits) (*artifactEnvelope, error) {
	// Budget tar framing as well as regular-file content. This also bounds PAX
	// metadata and padding, which the tar reader otherwise consumes internally.
	bounded := &io.LimitedReader{R: source, N: limits.WorkspaceBytes + int64(limits.WorkspaceFiles+1)*4096 + 10240}
	counted := &countReader{reader: bounded}
	reader := tar.NewReader(counted)
	before := make(map[string]material, len(initial))
	for _, item := range initial {
		before[item.Path] = item
	}
	bundle := workspaceBundle{Schema: "testifysec.hardened-opencode.workspace-bundle/v1", MaterialsSHA256: hash(marshal(initial)), Files: []material{}, Changes: []changedFile{}, Removed: []string{}}
	seen := map[string]bool{}
	canonical := map[string]string{}
	requiredDirectories := map[string]bool{}
	var total int64
	entries, changedBytes := 0, 0
	rootSeen := false
	var lastSize int64
	for {
		if err := ctx.Err(); err != nil {
			return nil, deny("artifact_timeout", "Workspace capture deadline exceeded")
		}
		beforeHeader := counted.bytes
		header, err := reader.Next()
		if err == io.EOF {
			// archive/tar also accepts EOF without a terminator. Export must not:
			// a daemon-side walk error could otherwise look like file deletions.
			if counted.bytes-beforeHeader < (512-lastSize%512)%512+1024 {
				return nil, deny("unsafe_artifact", "Incomplete archive terminator")
			}
			break
		}
		if err != nil {
			return nil, deny("unsafe_artifact", "Malformed workspace archive")
		}
		lastSize = header.Size
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA && header.Typeflag != tar.TypeDir || header.Linkname != "" || header.Mode&06000 != 0 || header.Size < 0 || header.Typeflag == tar.TypeDir && header.Size != 0 {
			return nil, deny("unsafe_artifact", "Workspace archive contains links, special files or privileged modes")
		}
		for key := range header.PAXRecords {
			if key != "path" && key != "size" && key != "mtime" && key != "atime" && key != "ctime" {
				return nil, deny("unsafe_artifact", "Unsupported archive metadata")
			}
		}
		if len(header.Xattrs) != 0 {
			return nil, deny("unsafe_artifact", "Extended attributes are not portable artifacts")
		}
		name := header.Name
		if header.Typeflag == tar.TypeDir {
			name = strings.TrimSuffix(name, "/")
		}
		if name == "workspace" {
			if rootSeen || header.Typeflag != tar.TypeDir {
				return nil, deny("unsafe_artifact", "Invalid archive root")
			}
			rootSeen = true
			continue
		}
		if !rootSeen || !strings.HasPrefix(name, "workspace/") {
			return nil, deny("unsafe_artifact", "Archive path is outside workspace")
		}
		name = strings.TrimPrefix(name, "workspace/")
		if !artifactPath(name) {
			return nil, deny("unsafe_artifact", "Unsafe or ambiguous artifact path")
		}
		entries++
		if entries > limits.WorkspaceFiles {
			return nil, deny("artifact_limit", "Final workspace entry budget exceeded")
		}
		key := strings.ToLower(name)
		if _, found := seen[key]; found {
			return nil, deny("unsafe_artifact", "Duplicate or case-colliding artifact path")
		}
		parts := strings.Split(name, "/")
		for i := range parts {
			prefix := strings.Join(parts[:i+1], "/")
			folded := strings.ToLower(prefix)
			if previous, exists := canonical[folded]; exists && previous != prefix {
				return nil, deny("unsafe_artifact", "Case-colliding artifact prefix")
			}
			canonical[folded] = prefix
			if len(canonical) > limits.WorkspaceFiles {
				return nil, deny("artifact_limit", "Final artifact prefix budget exceeded")
			}
			if i != len(parts)-1 {
				if directory, found := seen[folded]; found && !directory {
					return nil, deny("unsafe_artifact", "File/directory prefix collision")
				}
				requiredDirectories[folded] = true
			}
		}
		isDirectory := header.Typeflag == tar.TypeDir
		if requiredDirectories[key] && !isDirectory {
			return nil, deny("unsafe_artifact", "File/directory prefix collision")
		}
		seen[key] = isDirectory
		if isDirectory {
			continue
		}
		if header.Size > limits.WorkspaceBytes-total {
			return nil, deny("artifact_limit", "Final workspace byte budget exceeded")
		}
		total += header.Size
		content := capBuffer{remaining: artifactContentLimit - changedBytes + 1}
		digest := sha256.New()
		if _, err = io.CopyN(io.MultiWriter(digest, &content), reader, header.Size); err != nil {
			return nil, deny("unsafe_artifact", "Truncated regular file")
		}
		item := material{Path: name, SHA256: hex.EncodeToString(digest.Sum(nil)), Size: header.Size, Executable: header.Mode&0111 != 0}
		bundle.Files = append(bundle.Files, item)
		if old, found := before[name]; !found || old != item {
			if header.Size > int64(artifactContentLimit-changedBytes) {
				return nil, deny("artifact_limit", "Changed file contents exceed export budget")
			}
			changedBytes += int(header.Size)
			bundle.Changes = append(bundle.Changes, changedFile{material: item, ContentBase64: base64.StdEncoding.EncodeToString(content.Bytes())})
		}
		delete(before, name)
	}
	if !rootSeen || bounded.N <= 0 {
		return nil, deny("artifact_limit", "Missing archive root or exhausted archive budget")
	}
	// Consume only zero tar padding. Hidden appended archives/data are rejected;
	// the raw stream bound also prevents unbounded end padding.
	var padding [4096]byte
	for {
		n, err := bounded.Read(padding[:])
		for _, value := range padding[:n] {
			if value != 0 {
				return nil, deny("unsafe_artifact", "Trailing archive data")
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, deny("artifact_unavailable", "Workspace archive stream failed")
		}
	}
	if bounded.N <= 0 {
		return nil, deny("artifact_limit", "Archive framing exceeds budget")
	}
	sort.Slice(bundle.Files, func(i, j int) bool { return bundle.Files[i].Path < bundle.Files[j].Path })
	sort.Slice(bundle.Changes, func(i, j int) bool { return bundle.Changes[i].Path < bundle.Changes[j].Path })
	for name := range before {
		bundle.Removed = append(bundle.Removed, name)
	}
	sort.Strings(bundle.Removed)
	bundle.FinalManifestSHA256 = hash(marshal(bundle.Files))
	payload := marshal(bundle)
	if len(payload) > artifactPayloadLimit {
		return nil, deny("artifact_limit", "Artifact envelope exceeds export budget")
	}
	return &artifactEnvelope{Schema: "testifysec.hardened-opencode.workspace-artifact/v1", Scope: "regular-files-only", PayloadBase64: base64.StdEncoding.EncodeToString(payload), SHA256: hash(payload), MaterialsSHA256: bundle.MaterialsSHA256, FinalManifestSHA256: bundle.FinalManifestSHA256, ChangedFiles: len(bundle.Changes), RemovedFiles: len(bundle.Removed)}, nil
}
