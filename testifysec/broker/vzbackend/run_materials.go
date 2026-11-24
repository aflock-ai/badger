package vzbackend

import (
	"encoding/base64"
	"encoding/json"
	"path"
	"strings"
)

// Mirrors the portable regular-file contract of vm/guest/managed.go. It does
// not accept filesystem references, symlinks, full modes or empty directories.
func runPath(name string) bool {
	if name == "" || len(name) > 1024 || path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.ContainsAny(name, `\:*?"<>|`) {
		return false
	}
	parts := strings.Split(name, "/")
	if len(parts) > 32 {
		return false
	}
	for _, part := range parts {
		if !runPathPart(part) {
			return false
		}
	}
	return true
}
func runPathPart(part string) bool {
	if part == "" || part == "." || part == ".." || len(part) > 255 || strings.TrimRight(part, ". ") != part {
		return false
	}
	for _, r := range part {
		if r < 32 || r >= 127 {
			return false
		}
	}
	lower := strings.ToLower(part)
	if lower == ".git" || strings.HasPrefix(lower, "git~") {
		return false
	}
	stem, _, _ := strings.Cut(lower, ".")
	return !runDevice(stem)
}
func runDevice(stem string) bool {
	if stem == "con" || stem == "prn" || stem == "aux" || stem == "nul" {
		return true
	}
	return len(stem) == 4 && (strings.HasPrefix(stem, "com") || strings.HasPrefix(stem, "lpt")) && stem[3] >= '0' && stem[3] <= '9'
}

type runPaths struct {
	names map[string]string
	files map[string]bool
}

func (p *runPaths) add(name string) bool {
	if !runPath(name) {
		return false
	}
	if p.names == nil {
		p.names = map[string]string{}
		p.files = map[string]bool{}
	}
	parts := strings.Split(name, "/")
	for i := range parts {
		prefix := strings.Join(parts[:i+1], "/")
		key := strings.ToLower(prefix)
		if prior, ok := p.names[key]; ok && (prior != prefix || p.files[key] || i == len(parts)-1) {
			return false
		}
		p.names[key] = prefix
		if i == len(parts)-1 {
			p.files[key] = true
		}
	}
	return len(p.names) <= runEntriesLimit
}
func validateMaterials(files []RunMaterial) error {
	if files == nil || len(files) > runFilesLimit {
		return refused("run_materials")
	}
	var paths runPaths
	previous := ""
	var total int64
	for _, f := range files {
		if f.Path <= previous || !paths.add(f.Path) || !hexDigest.MatchString(f.SHA256) || f.Size < 0 || f.Size > runFileLimit || len(f.ContentBase64) > base64.StdEncoding.EncodedLen(runFileLimit) {
			return refused("run_materials")
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(f.ContentBase64)
		if err != nil || base64.StdEncoding.EncodeToString(raw) != f.ContentBase64 || int64(len(raw)) != f.Size || hash(raw) != f.SHA256 {
			return refused("run_material_bytes")
		}
		total += f.Size
		if total > runMaterialLimit {
			return refused("run_material_bounds")
		}
		previous = f.Path
	}
	return nil
}

type materialDescriptor struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
	Executable bool   `json:"executable"`
}

func materialManifest(files []RunMaterial) string {
	descriptions := make([]materialDescriptor, 0, len(files))
	for _, f := range files {
		descriptions = append(descriptions, materialDescriptor{f.Path, f.SHA256, f.Size, f.Executable})
	}
	raw, _ := json.Marshal(descriptions)
	return hash(raw)
}
