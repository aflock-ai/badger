// Command packaging runs one fixed, embedded native entrypoint.
// It packages binaries; it is not a sandbox or a privileged service installer.
package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

//go:embed assets/manifest.json
var embeddedManifest []byte

//go:embed assets/payload.dat
var embeddedPayload []byte

var manifestDigest string

const maxPayload = 768 << 20
const maxFile = 256 << 20
const maxFiles = 256

type fileSpec struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
}

type payloadSpec struct {
	Schema              string     `json:"schema"`
	OS                  string     `json:"os"`
	Arch                string     `json:"arch"`
	Entry               string     `json:"entry"`
	Product             string     `json:"product"`
	Command             string     `json:"command"`
	Version             string     `json:"version"`
	UpstreamVersion     string     `json:"upstreamVersion"`
	Attribution         string     `json:"attribution"`
	PayloadSHA256       string     `json:"payloadSha256"`
	InputManifestSHA256 string     `json:"inputManifestSha256"`
	Files               []fileSpec `json:"files"`
}

var simple = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var component = regexp.MustCompile(`^[A-Za-z0-9_@.-]{1,128}$`)
var shaPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func portableName(name string) bool {
	if name == "" || len(name) > 512 || path.Clean(name) != name || strings.HasPrefix(name, "/") {
		return false
	}
	parts := strings.Split(name, "/")
	if len(parts) > 8 {
		return false
	}
	for _, part := range parts {
		if !component.MatchString(part) || part == "." || part == ".." || strings.EqualFold(part, ".git") || strings.TrimRight(part, ". ") != part {
			return false
		}
		stem, _, _ := strings.Cut(strings.ToLower(part), ".")
		if stem == "con" || stem == "prn" || stem == "aux" || stem == "nul" || stem == "clock$" || len(stem) == 4 && (strings.HasPrefix(stem, "com") || strings.HasPrefix(stem, "lpt")) && stem[3] >= '0' && stem[3] <= '9' {
			return false
		}
	}
	return true
}

func manifest(raw []byte, expected string) (payloadSpec, error) {
	var spec payloadSpec
	if len(raw) > 128<<10 || !shaPattern.MatchString(expected) || digest(raw) != expected {
		return spec, errors.New("manifest integrity")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&spec); err != nil {
		return spec, errors.New("manifest schema")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return spec, errors.New("manifest trailing data")
	}
	if spec.Schema != "testifysec.hardened-code.single-executable/v1" || spec.OS != runtime.GOOS || spec.Arch != runtime.GOARCH || !portableName(spec.Entry) || !shaPattern.MatchString(spec.PayloadSHA256) || !shaPattern.MatchString(spec.InputManifestSHA256) || len(spec.Files) == 0 || len(spec.Files) > maxFiles {
		return spec, errors.New("manifest target or bounds")
	}
	if !simple.MatchString(spec.Command) || len(spec.Product) == 0 || len(spec.Product) > 128 || len(spec.Version) == 0 || len(spec.Version) > 64 || len(spec.UpstreamVersion) > 64 || len(spec.Attribution) > 256 {
		return spec, errors.New("manifest display bounds")
	}
	for _, s := range []string{spec.Product, spec.Version, spec.UpstreamVersion, spec.Attribution} {
		if strings.ContainsAny(s, "\x00\r\n\x1b") {
			return spec, errors.New("manifest display controls")
		}
	}
	seen := map[string]bool{}
	aliases := map[string]string{}
	last := ""
	total := int64(0)
	entry := false
	for _, file := range spec.Files {
		if !portableName(file.Name) || file.Name <= last || !shaPattern.MatchString(file.SHA256) || file.Size < 0 || file.Size > maxFile || (file.Mode != 0400 && file.Mode != 0500) {
			return spec, errors.New("manifest file")
		}
		last = file.Name
		total += file.Size
		if total > maxPayload {
			return spec, errors.New("payload byte budget")
		}
		parts := strings.Split(file.Name, "/")
		for i := 1; i <= len(parts); i++ {
			prefix := strings.Join(parts[:i], "/")
			lower := strings.ToLower(prefix)
			if previous, exists := aliases[lower]; exists && previous != prefix {
				return spec, errors.New("case alias")
			}
			aliases[lower] = prefix
			if seen[prefix] {
				return spec, errors.New("file directory collision")
			}
		}
		seen[file.Name] = true
		if file.Name == spec.Entry {
			entry = file.Mode == 0500
		}
	}
	if !entry {
		return spec, errors.New("missing executable entry")
	}
	return spec, nil
}

func executableTarget(raw io.ReaderAt, targetOS, targetArch string) error {
	switch targetOS {
	case "darwin":
		file, err := macho.NewFile(raw)
		if err == nil && file.Type == macho.TypeExec && (targetArch == "arm64" && file.Cpu == macho.CpuArm64 || targetArch == "amd64" && file.Cpu == macho.CpuAmd64) {
			return nil
		}
	case "linux":
		file, err := elf.NewFile(raw)
		if err == nil && (file.Type == elf.ET_EXEC || file.Type == elf.ET_DYN) && (targetArch == "arm64" && file.Machine == elf.EM_AARCH64 || targetArch == "amd64" && file.Machine == elf.EM_X86_64) {
			return nil
		}
	case "windows":
		file, err := pe.NewFile(raw)
		if err == nil && file.Characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE != 0 && file.Characteristics&pe.IMAGE_FILE_DLL == 0 && (targetArch == "arm64" && file.Machine == pe.IMAGE_FILE_MACHINE_ARM64 || targetArch == "amd64" && file.Machine == pe.IMAGE_FILE_MACHINE_AMD64) {
			return nil
		}
	}
	return errors.New("payload executable target mismatch")
}

func materialize(root *os.Root, spec payloadSpec, payload []byte) error {
	if len(payload) > maxPayload+1<<20 || digest(payload) != spec.PayloadSHA256 {
		return errors.New("payload integrity")
	}
	archive, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil || len(archive.File) != len(spec.Files) {
		return errors.New("payload archive")
	}
	for i, file := range archive.File {
		expected := spec.Files[i]
		if file.Name != expected.Name || file.Method != zip.Store || file.Mode() != os.FileMode(expected.Mode) || file.UncompressedSize64 != uint64(expected.Size) || file.CompressedSize64 != uint64(expected.Size) {
			return errors.New("payload entry")
		}
		if parent := path.Dir(file.Name); parent != "." {
			if err = root.MkdirAll(parent, 0700); err != nil {
				return err
			}
		}
		input, err := file.Open()
		if err != nil {
			return err
		}
		output, err := root.OpenFile(file.Name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			input.Close()
			return err
		}
		hash := sha256.New()
		size, copyErr := io.Copy(io.MultiWriter(output, hash), io.LimitReader(input, expected.Size+1))
		err = errors.Join(copyErr, input.Close(), output.Sync(), output.Close())
		if err != nil || size != expected.Size || hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
			return errors.New("materialized file integrity")
		}
		if err = root.Chmod(file.Name, os.FileMode(expected.Mode)); err != nil {
			return err
		}
	}
	return verifyMaterialized(root, spec)
}

func verifyMaterialized(root *os.Root, spec payloadSpec) error {
	for _, expected := range spec.Files {
		before, err := root.Lstat(expected.Name)
		if err != nil || !before.Mode().IsRegular() || before.Size() != expected.Size {
			return errors.New("materialized file type")
		}
		file, err := root.Open(expected.Name)
		if err != nil {
			return err
		}
		current, err := file.Stat()
		if err != nil || !os.SameFile(before, current) {
			file.Close()
			return errors.New("materialized file changed")
		}
		hash := sha256.New()
		size, err := io.Copy(hash, io.LimitReader(file, expected.Size+1))
		if err != nil || size != expected.Size || hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
			file.Close()
			return errors.New("materialized file digest")
		}
		if expected.Name == spec.Entry {
			if err = executableTarget(file, spec.OS, spec.Arch); err != nil {
				file.Close()
				return err
			}
		}
		if err = file.Close(); err != nil {
			return err
		}
	}
	return nil
}

// cleanupSafe is an observed lifecycle result, never inferred from a kill
// request or from the entrypoint's exit status alone.
type supervisor func(*exec.Cmd) (code int, cleanupSafe bool, err error)

func launch() (int, error) { return launchWith(os.Args, supervise) }

func launchWith(args []string, run supervisor) (code int, failure error) {
	spec, err := manifest(embeddedManifest, manifestDigest)
	if err != nil {
		return 2, err
	}
	if len(args) == 2 {
		switch args[1] {
		case "--help":
			fmt.Printf("%s\n\nUsage: %s < request.json\n       %s --help\n       %s --version\n\nOne executable contains the selected native runtime payload.\nThe configured protected execution backend is still required.\n%s\n", spec.Product, spec.Command, spec.Command, spec.Command, spec.Attribution)
			return 0, nil
		case "--version":
			fmt.Printf("%s %s\nOpenCode %s\nTarget %s/%s\n%s\n", spec.Product, spec.Version, spec.UpstreamVersion, spec.OS, spec.Arch, spec.Attribution)
			return 0, nil
		}
	}
	if len(args) != 1 {
		return 2, errors.New("unsupported invocation")
	}
	root, directory, clean, err := privateDirectory()
	if err != nil {
		return 2, err
	}
	cleanupSafe := true // No process has been started yet.
	defer func() {
		if err := clean(cleanupSafe); err != nil {
			code = 2
			failure = errors.Join(failure, errors.New("payload cleanup failed"))
		}
		if !cleanupSafe {
			code = 2
			failure = errors.Join(failure, errors.New("payload retained: process cleanup incomplete"))
		}
	}()
	if err = materialize(root, spec, embeddedPayload); err != nil {
		return 2, err
	}
	if err = root.Mkdir("scratch", 0700); err != nil {
		return 2, err
	}
	command := exec.Command(filepath.Join(directory, filepath.FromSlash(spec.Entry)))
	command.Dir = directory
	command.Env, err = childEnvironment(filepath.Join(directory, "scratch"))
	if err != nil {
		return 2, err
	}
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	cleanupSafe = false
	code, cleanupSafe, failure = run(command)
	return code, failure
}

func main() {
	code, err := launch()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Hardened Code packaged runtime unavailable")
	}
	os.Exit(code)
}
