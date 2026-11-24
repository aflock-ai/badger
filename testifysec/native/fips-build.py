# jade:ring local
"""Build and exercise a pinned Go FIPS-module candidate; never certify or install."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile


# CMVP #5247 Security Policy, June 12, 2026, section 11.1 (pages 97–99).
# Exact snapshots, never the moving latest/certified/inprocess aliases.
APPROVED_SNAPSHOTS = {
    "v1.0.0-c2097c7c": "daf3614e0406f67ae6323c902db3f953a1effb199142362a039e7526dfb9368b",
    "v1.0.1": "0a9bfccef9f8011257e3303788d3420dee2677b2ceafc38b81450cc60799d007",
}
POLICY_URL = "https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5247.pdf"
CERTIFICATE_URL = "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    with Path(path).open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def library_probe(arguments):
    """An isolated build-time Python process loads the actual native C ABI."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if len(arguments) != 3:
        raise SystemExit("internal library probe requires library, fixtures and module")
    library_path, fixtures, module = arguments
    library = ctypes.CDLL(library_path)
    library.RookeryABIVersion.restype = ctypes.c_uint32
    library.RookeryFIPSStatus.restype = ctypes.c_void_p
    library.RookeryFree.argtypes = [ctypes.c_void_p]
    library.RookeryVerify.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    library.RookeryVerify.restype = ctypes.c_void_p

    def consume(pointer):
        if not pointer:
            raise RuntimeError("native allocation missing")
        try:
            return json.loads(ctypes.string_at(pointer))
        finally:
            library.RookeryFree(pointer)

    status = consume(library.RookeryFIPSStatus())
    if (library.RookeryABIVersion() != 1 or not status["enabled"]
            or status["moduleVersion"] != module.split("-", 1)[0]
            or status["settings"].get("GOFIPS140") != module):
        raise RuntimeError("actual shared library FIPS mode/module does not match pin")
    checks = []
    for name, expected in (("valid", True), ("invalid", False)):
        raw = (Path(fixtures) / (name + ".json")).read_bytes()
        buffer = ctypes.create_string_buffer(raw)
        answer = consume(library.RookeryVerify(buffer, len(raw)))
        if answer.get("ok") is not expected or answer.get("abiVersion") != 1:
            raise RuntimeError("actual C ABI signature verification result mismatch")
        if expected:
            import base64
            payload = base64.b64decode(json.loads(raw)["envelope"]["payload"], validate=True)
            if answer.get("payloadSha256") != digest(payload):
                raise RuntimeError("verified payload digest mismatch")
        checks.append({"name": "c-abi-" + name + "-signature", "passed": True})
    print(json.dumps({"status": status, "checks": checks}))


STATUS_SOURCE = r'''
import (
    "crypto/fips140"
    "encoding/json"
    "runtime/debug"
)
const expectedModule = PIN_MODULE
const expectedVersion = PIN_VERSION
type modeStatus struct {
    Enabled bool `json:"enabled"`
    ModuleVersion string `json:"moduleVersion"`
    GoVersion string `json:"goVersion"`
    Settings map[string]string `json:"settings"`
}
func fipsStatus() modeStatus {
    info, ok := debug.ReadBuildInfo()
    if !ok { panic("native FIPS build information unavailable") }
    settings := map[string]string{}
    for _, setting := range info.Settings { settings[setting.Key] = setting.Value }
    return modeStatus{fips140.Enabled(), fips140.Version(), info.GoVersion, settings}
}
func requireFIPS() modeStatus {
    status := fipsStatus()
    if !status.Enabled || status.ModuleVersion != expectedVersion || status.Settings["GOFIPS140"] != expectedModule {
        panic("native FIPS mode or exact cryptographic module mismatch")
    }
    return status
}
'''


ROOKERY_MODULE = "github.com/aflock-ai/rookery/attestation"
ROOKERY_PACKAGES = ("cryptoutil", "dsse")


def rookery_sources(run):
    """The published Rookery attestation sources this build compiles, from the offline module cache.

    The module is extracted first (GOPROXY is off, so only an already cached download qualifies);
    an empty or missing directory, or a package with no Go sources, refuses the build rather than
    hashing nothing."""
    run(["go", "mod", "download", ROOKERY_MODULE])
    listed = run(["go", "list", "-mod=readonly", "-m", "-f", "{{.Dir}}", ROOKERY_MODULE]).stdout.decode().strip()
    directory = Path(listed) if listed else None
    if directory is None or not directory.is_absolute() or not directory.is_dir():
        raise RuntimeError("Rookery attestation module is not extracted in the offline module cache: " + repr(listed))
    paths = []
    for package in ROOKERY_PACKAGES:
        found = sorted((directory / package).glob("*.go"))
        if not found:
            raise RuntimeError("Rookery attestation package has no Go sources: " + package)
        paths += found
    return directory, paths


def sources(module):
    common = STATUS_SOURCE.replace("PIN_MODULE", json.dumps(module)).replace(
        "PIN_VERSION", json.dumps(module.split("-", 1)[0]))
    guard = '''package main
/*
#include <stdlib.h>
*/
import "C"
''' + common + '''
func init() { requireFIPS() }
//export RookeryFIPSStatus
func RookeryFIPSStatus() *C.char {
    raw, err := json.Marshal(requireFIPS())
    if err != nil { panic("native FIPS status encoding failed") }
    return C.CString(string(raw))
}
'''
    probe = '''package main
import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha256"
    "os"
)
''' + common + '''
func main() {
    status := requireFIPS()
    key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil { panic(err) }
    message := sha256.Sum256([]byte("synthetic FIPS build probe"))
    signature, err := ecdsa.SignASN1(rand.Reader, key, message[:])
    if err != nil || !ecdsa.VerifyASN1(&key.PublicKey, message[:], signature) { panic("synthetic ECDSA failed") }
    message[0] ^= 1
    if ecdsa.VerifyASN1(&key.PublicKey, message[:], signature) { panic("tampered ECDSA accepted") }
    if err := json.NewEncoder(os.Stdout).Encode(status); err != nil { panic(err) }
}
'''
    return guard, probe


def verify_unpacked(snapshot, cache, module):
    """Check the actual cached source used by Go, not just the bundled ZIP."""
    base = Path(cache) / ("golang.org/fips140@" + module)
    if not base.is_dir() or base.is_symlink():
        raise RuntimeError("Go did not unpack the requested module snapshot")
    expected = {}
    prefix = "golang.org/fips140@" + module + "/"
    with zipfile.ZipFile(snapshot) as archive:
        for item in archive.infolist():
            if item.is_dir():
                continue
            if not item.filename.startswith(prefix):
                raise RuntimeError("unexpected snapshot layout")
            relative = item.filename[len(prefix):]
            if relative in expected or ".." in Path(relative).parts:
                raise RuntimeError("ambiguous snapshot path")
            expected[relative] = digest(archive.read(item))
    observed = {}
    for path in base.rglob("*"):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("unpacked module contains an alias/special file")
        observed[path.relative_to(base).as_posix()] = file_digest(path)
    if observed != expected:
        raise RuntimeError("unpacked Go cryptographic module differs from the approved ZIP")
    return {"directory": str(base), "files": len(expected),
            "inventorySha256": digest(json.dumps(expected, sort_keys=True, separators=(",", ":")).encode())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", required=True, type=Path)
    parser.add_argument("--expected-go-version", default="go1.26.5")
    parser.add_argument("--module", choices=tuple(APPROVED_SNAPSHOTS), default="v1.0.0-c2097c7c")
    parser.add_argument("--output", required=True, type=Path, help="new isolated build directory")
    parser.add_argument("--qualification-record", type=Path, help="optional supplied evidence reference; never treated as approval")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    repo = root.parents[1]
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report_path = output / "fips-build-report.json"
    report = {"schema": "testifysec.hardened-opencode.fips-build/v1", "passed": False,
              "startedUnix": int(time.time()), "requestedModule": args.module,
              "releaseQualified": False, "productFIPSComplianceClaim": False,
              "deploymentQualification": "not-assessed", "checks": [],
              "sources": {"goDocumentation": "https://go.dev/doc/security/fips140",
                          "certificate": CERTIFICATE_URL, "securityPolicy": POLICY_URL,
                          "reviewedOn": "2026-09-08"},
              "limitations": [
                  "Build-time synthetic evidence only; no installation, deployment, release signing or qualification.",
                  "A validated cryptographic module does not certify Bun, Rookery, OpenCode or the whole product.",
                  "Deployment must establish approved operating environment, algorithm/key use, entropy, custody and lifecycle requirements.",
                  "Other crypto implementations and network/TLS paths remain outside this component probe.",
                  "The generated guarded library is a candidate; existing managed bundles must be rebuilt against its exact digest.",
                  "Qualification records are hashed references only; this harness never grants a compliance claim.",
              ]}
    try:
        go = args.go.resolve(strict=True)
        if not go.is_file() or not os.access(go, os.X_OK):
            raise RuntimeError("explicit executable Go toolchain required")
        # No inherited GOFLAGS, GODEBUG, GOENV, compiler overrides, dynamic loader
        # injection or automatic toolchain/dependency network provisioning.
        env = {"PATH": str(go.parent) + ":/usr/bin:/bin:/usr/sbin:/sbin",
               "HOME": str(Path.home()), "GOENV": "off", "GOTOOLCHAIN": "local",
               "GOWORK": "off", "GOFIPS140": args.module, "GOFLAGS": "",
               "GOEXPERIMENT": "", "CGO_ENABLED": "1", "GOPROXY": "off", "GOSUMDB": "off",
               "GOMAXPROCS": "4", "LANG": "C", "TMPDIR": str(output),
               "GOCACHE": str(Path(tempfile.gettempdir()) / "hc-fips-build-cache")}

        def run(command, *, cwd=root, environment=env, timeout=300, expect=0):
            process = subprocess.run([str(v) for v in command], cwd=cwd, env=environment,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            if (expect == 0 and process.returncode != 0) or (expect != 0 and process.returncode == 0):
                raise RuntimeError("command failed: " + str(command[0]) + " " + str(command[1:4])
                                   + "\n" + process.stderr[-4000:].decode(errors="replace"))
            return process

        settings = json.loads(run([go, "env", "-json", "GOVERSION", "GOROOT", "GOHOSTOS", "GOHOSTARCH",
                                   "GOOS", "GOARCH", "GOFIPS140", "CGO_ENABLED", "CC", "CXX", "GOEXPERIMENT",
                                   "GOFLAGS", "GOTOOLCHAIN", "GOWORK", "GOPROXY", "GOSUMDB", "GOCACHE", "GOMODCACHE"]).stdout)
        report["toolchain"] = {"executable": str(go), "sha256": file_digest(go), "settings": settings}
        report["host"] = {"system": platform.system(), "release": platform.release(), "machine": platform.machine()}
        if settings["GOVERSION"] != args.expected_go_version or not settings["GOVERSION"].startswith("go1.26."):
            raise RuntimeError("actual Go toolchain does not match explicit Go 1.26 version pin")
        if settings["GOOS"] not in ("linux", "darwin") or settings["GOOS"] != settings["GOHOSTOS"] or settings["GOARCH"] != settings["GOHOSTARCH"]:
            raise RuntimeError("this harness requires a native Linux/Darwin build and execution")
        snapshot = Path(settings["GOROOT"]) / "lib/fips140" / (args.module + ".zip")
        if not snapshot.is_file():
            raise RuntimeError("requested approved snapshot missing from provisioned toolchain: " + str(snapshot))
        if file_digest(snapshot) != APPROVED_SNAPSHOTS[args.module]:
            raise RuntimeError("Go snapshot differs from exact NIST Security Policy SHA256")
        report["snapshot"] = {"path": str(snapshot), "sha256": file_digest(snapshot), "cmvpCertificate": 5247}
        report["checks"].append({"name": "nist-snapshot-digest", "passed": True})
        report["compiler"] = run([settings["CC"], "--version"]).stdout.decode().strip()
        report["revision"] = run(["git", "rev-parse", "HEAD"]).stdout.decode().strip()
        report["worktreeDirty"] = bool(run(["git", "-c", "core.fsmonitor=false", "status", "--porcelain"]).stdout)
        source_paths = list(root.glob("*.go")) + [root / "go.mod", root / "go.sum", Path(__file__).resolve()]
        rookery, rookery_paths = rookery_sources(run)
        source_paths += rookery_paths
        source_names = {(str(p.relative_to(repo)) if p.is_relative_to(repo) else "rookery-attestation/" + str(p.relative_to(rookery))): p
                        for p in sorted(source_paths)}
        source_hashes = {name: file_digest(p) for name, p in source_names.items()}
        report["sourceFiles"] = source_hashes
        if args.qualification_record is not None:
            record = args.qualification_record.resolve(strict=True)
            if not record.is_file() or record.stat().st_size > 1 << 20:
                raise RuntimeError("qualification reference must be a bounded regular file")
            report["qualificationRecord"] = {"sha256": file_digest(record), "status": "provided-unvalidated"}
        guard, probe = sources(args.module)
        guard_path = output / "fips_guard.go"
        probe_path = output / "fips_probe.go"
        guard_path.write_text(guard)
        probe_path.write_text(probe)
        overlay = output / "overlay.json"
        overlay.write_text(json.dumps({"Replace": {str(root / "fips_candidate_generated.go"): str(guard_path)}}))
        report["generatedSources"] = {p.name: file_digest(p) for p in (guard_path, probe_path, overlay)}
        # Cause Go to select/unpack the frozen snapshot, then check every actual
        # cached source file against the NIST-bound ZIP before any compilation.
        run([go, "list", "crypto/fips140"])
        report["unpackedModule"] = verify_unpacked(snapshot, settings["GOMODCACHE"], args.module)
        library_name = "librookery.dylib" if settings["GOOS"] == "darwin" else "librookery.so"
        library = output / library_name
        executable = output / "fips-probe"
        flags = ["-mod=readonly", "-trimpath", "-p=2"]
        library_command = [go, "build", *flags, "-overlay", overlay, "-buildmode=c-shared", "-o", library, "."]
        probe_command = [go, "build", *flags, "-o", executable, probe_path]
        report["buildCommands"] = [[str(v) for v in command] for command in (library_command, probe_command)]
        run(library_command)
        run(probe_command)
        report["buildInfo"] = {}
        for artifact in (library, executable):
            metadata = run([go, "version", "-m", "-json", artifact]).stdout
            info = json.loads(metadata)
            build = {s["Key"]: s["Value"] for s in info["Settings"]}
            if build.get("GOFIPS140") != args.module or info.get("GoVersion") != args.expected_go_version:
                raise RuntimeError("artifact build metadata does not use exact pinned module/toolchain")
            report["buildInfo"][artifact.name] = info
        clean_runtime = {"PATH": "/usr/bin:/bin", "HOME": str(output), "TMPDIR": str(output), "LANG": "C"}
        mode = json.loads(run([executable], cwd=output, environment=clean_runtime).stdout)
        if not mode["enabled"] or mode["moduleVersion"] != args.module.split("-", 1)[0] or mode["settings"].get("GOFIPS140") != args.module:
            raise RuntimeError("actual probe did not activate the exact requested module")
        report["probe"] = mode
        report["checks"].append({"name": "native-mode-version-and-ecdsa-probe", "passed": True})
        fixtures = output / "fixtures"
        test_env = dict(env, ROOKERY_TEST_FIXTURES=str(fixtures))
        tested = run([go, "test", *flags, "-overlay", overlay, "-count=1", "-json", "."], environment=test_env)
        (output / "native-tests.jsonl").write_bytes(tested.stdout)
        report["tests"] = []
        for line in tested.stdout.splitlines():
            event = json.loads(line)
            if event.get("Test") and event.get("Action") in ("pass", "fail", "skip"):
                report["tests"].append({"name": event["Test"], "status": event["Action"]})
        if not report["tests"] or any(test["status"] != "pass" for test in report["tests"]):
            raise RuntimeError("native verification tests were absent, failed or skipped")
        child = [sys.executable, "-I", Path(__file__).resolve(), "_library-probe", library, fixtures, args.module]
        result = json.loads(run(child, cwd=output, environment=clean_runtime).stdout)
        report["libraryProbe"] = result["status"]
        report["checks"] += result["checks"]
        disabled = dict(clean_runtime, GODEBUG="fips140=off")
        for name, command in (("native-probe", [executable]), ("shared-library", child)):
            refused = run(command, cwd=output, environment=disabled, expect=1)
            if b"native FIPS mode or exact cryptographic module mismatch" not in refused.stderr:
                raise RuntimeError("disabled-mode negative failed for an unrelated reason")
            report["checks"].append({"name": name + "-runtime-off-refused", "passed": True})
        verify_unpacked(snapshot, settings["GOMODCACHE"], args.module)
        if any(file_digest(source_names[path]) != value for path, value in source_hashes.items()):
            raise RuntimeError("source changed during component build")
        report["artifacts"] = {p.name: {"sha256": file_digest(p), "size": p.stat().st_size}
                               for p in (library, output / (Path(library_name).stem + ".h"), executable)}
        report["passed"] = True
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report["failure"] = str(error)
    finally:
        report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "report": str(report_path), "releaseQualified": False}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "_library-probe":
        library_probe(sys.argv[2:])
    else:
        raise SystemExit(main())
