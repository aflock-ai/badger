# jade:ring local
"""Compile unchanged legacy consumers against real, local native admission bundles."""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import time


_MODULES = ("broker", "gateway", "platform")
_GO_INPUTS = {".go", ".mod", ".sum", ".c", ".h", ".s", ".S"}
_TEST_NAME = "TestAflockLegacyProfileConsumer"


def _sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sources(root):
    result = {}
    for module in _MODULES:
        for path in sorted((root / module).rglob("*")):
            if path.suffix not in _GO_INPUTS:
                continue
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError("consumer source must be regular")
            # This harness stages source files only; do not silently omit a
            # future embedded asset from its compilation/provenance closure.
            if path.suffix == ".go" and b"//go:embed" in path.read_bytes():
                raise ValueError("consumer embedded assets need explicit staging")
            result[str(path.relative_to(root))] = _sha(path)
    if not all(module + "/go.mod" in result for module in _MODULES):
        raise ValueError("consumer modules unavailable")
    return result


def _copy_regular(source, target, expected, mode, limit):
    before = source.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise ValueError("fixture input must be a bounded regular file")
    if _sha(source) != expected:
        raise ValueError("fixture source digest mismatch")
    shutil.copyfile(source, target)
    target.chmod(mode)
    after = source.lstat()
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or _sha(source) != expected or _sha(target) != expected):
        raise ValueError("fixture input changed during copy")


def _run(argv, cwd, env, log, timeout):
    """Retain bounded local diagnostics; require child exit and pipe EOF."""
    process = subprocess.Popen([str(arg) for arg in argv], cwd=cwd, env=env,
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, start_new_session=True)
    selector = selectors.DefaultSelector()
    os.set_blocking(process.stdout.fileno(), False)
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    total = 0
    completed = False
    try:
        with log.open("xb") as stream:
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise TimeoutError("consumer command or output-drain deadline")
                for key, _ in selector.select(.05):
                    raw = os.read(key.fileobj.fileno(), 65536)
                    if not raw:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(raw)
                    if total > 1024 * 1024:
                        raise ValueError("consumer command output limit")
                    stream.write(raw)
            process.wait(timeout=max(.01, deadline - time.monotonic()))
        if process.returncode != 0:
            raise RuntimeError("consumer command failed; inspect retained bounded log")
        completed = True
    finally:
        try:
            if not completed:
                # A child can retain the output pipe after its leader exits.
                # Terminate our session's group on any incomplete run as well.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
        finally:
            process.stdout.close()
            selector.close()


_COMMON_TEST = r'''// jade:ring local
package main

import (
    "bytes"
    "context"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "os"
    "os/exec"
    "testing"
    "time"
)

type aflockLegacyCase struct {
    Executable string `json:"executable"`
    ExecutableSHA256 string `json:"executableSha256"`
    Envelope string `json:"envelope"`
    PayloadSHA256 string `json:"payloadSha256"`
    TenantID string `json:"tenantId"`
}

func aflockLegacyInputs(t *testing.T) map[string]aflockLegacyCase {
    t.Helper()
    raw, err := os.ReadFile(os.Getenv("AFLOCK_LEGACY_CONSUMER_CASES"))
    if err != nil { t.Fatal("protected fixture configuration unavailable") }
    var cases map[string]aflockLegacyCase
    if json.Unmarshal(raw, &cases) != nil || len(cases) != 2 { t.Fatal("invalid fixture configuration") }
    return cases
}

func aflockNativeControl(t *testing.T, input aflockLegacyCase, version int) []byte {
    t.Helper()
    envelope, err := os.ReadFile(input.Envelope)
    if err != nil || len(envelope) == 0 || len(envelope) > 65536 { t.Fatal("invalid fixture envelope") }
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    command := exec.CommandContext(ctx, input.Executable)
    command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
    command.Dir = t.TempDir()
    command.Stdin = bytes.NewReader(envelope)
    command.WaitDelay = time.Second
    raw, err := command.Output()
    if err != nil { t.Fatal("native positive control did not admit") }
    var result struct {
        SchemaVersion int `json:"schemaVersion"`
        Admitted bool `json:"admitted"`
        Scope string `json:"scope"`
        PayloadSHA256 string `json:"payloadSha256"`
        EnvelopeSHA256 string `json:"envelopeSha256"`
        Profile struct {
            TenantID string `json:"tenantId"`
            Backend json.RawMessage `json:"backend"`
        } `json:"profile"`
    }
    hash := sha256.Sum256(envelope)
    if json.Unmarshal(raw, &result) != nil || result.SchemaVersion != version || !result.Admitted ||
        result.Scope != "profile-admission-only" || result.PayloadSHA256 != input.PayloadSHA256 ||
        result.EnvelopeSHA256 != hex.EncodeToString(hash[:]) || result.Profile.TenantID != input.TenantID {
        t.Fatal("native positive control returned unbound or incorrect contract")
    }
    if (version == 2) != (len(result.Profile.Backend) != 0) { t.Fatal("native backend contract mismatch") }
    return envelope
}

func TestAflockLegacyProfileConsumer(t *testing.T) {
    cases := aflockLegacyInputs(t)
    for index, name := range []string{"v1", "v2"} {
        t.Run(name, func(t *testing.T) {
            input, ok := cases[name]
            if !ok { t.Fatal("missing fixture case") }
            envelope := aflockNativeControl(t, input, index + 1)
            _ = envelope
__CONSUMER__
        })
    }
}
'''

_BROKER_TEST = r'''            result, err := verifyAdmission(context.Background(), policy{
                AdmissionExecutable: input.Executable, AdmissionSHA256: input.ExecutableSHA256,
                ProfileSHA256: input.PayloadSHA256,
            }, string(envelope))
            if name == "v1" {
                if err != nil || result != input.PayloadSHA256 { t.Fatal("legacy broker v1 control failed") }
            } else {
                // Require the output-contract refusal after successful native
                // admission, not an unavailable executable or bad signature.
                if err == nil || result != "" || err.Error() != "profile_denied: Native verifier returned invalid admission" {
                    t.Fatal("legacy broker did not strictly refuse v2 native output")
                }
            }'''

_GATEWAY_TEST = r'''            expiry, err := checkProfile(context.Background(), Config{
                SignedProfileFile: input.Envelope, AdmissionExecutable: input.Executable,
                AdmissionSHA256: input.ExecutableSHA256, ProfileDigest: input.PayloadSHA256, Tenant: input.TenantID,
            })
            if name == "v1" {
                if err != nil || !expiry.After(time.Now()) { t.Fatal("legacy gateway v1 control failed") }
            } else {
                if err == nil || !expiry.IsZero() || err.Error() != "invalid profile admission" {
                    t.Fatal("legacy gateway did not strictly refuse v2 native output")
                }
            }'''


def run_legacy_consumers(repo_root, output, go, cases):
    """Return a retained report for actual v1 acceptance and strict v2 refusal.

    repo_root is the OpenCode root. output must not already exist. Each v1/v2
    case supplies bundle, envelope, payloadSha256 and tenantId. The supplied
    native bundles contain only local fixture trust; no service is started.
    """
    if os.name != "posix":
        raise ValueError("legacy Unix consumer harness requires a POSIX host")
    if set(cases) != {"v1", "v2"}:
        raise ValueError("exact v1/v2 cases required")
    repo_root, output, go = Path(repo_root).resolve(), Path(output).resolve(), Path(go).resolve(strict=True)
    output.mkdir(mode=0o700)
    root = repo_root / "testifysec"
    before = _sources(root)
    native_before = {}
    own_source = Path(__file__).resolve()
    report = {"schema": "testifysec.aflock.legacy-profile-consumers-uat/v1", "passed": False,
              "sourceFiles": before, "harnessSha256": _sha(own_source), "goSha256": _sha(go),
              "cases": [], "checks": [], "generatedTests": {}, "binaries": {}, "logs": {},
              "report": str(output / "report.json"),
              "scope": "Actual existing broker/gateway admission functions and native local signed fixtures only; no engine, HTTP listener, provider or platform request. Public fixture hashes are build evidence, not independent deployment authorization."}

    def check(name, condition):
        report["checks"].append({"name": name, "passed": bool(condition)})
        if not condition:
            raise AssertionError(name)

    try:
        stage = output / "source"
        for name, expected in before.items():
            destination = stage / name
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _copy_regular(root / name, destination, expected, 0o600, 4 * 1024 * 1024)
        configuration = {}
        for name in ("v1", "v2"):
            case = cases[name]
            if set(case) != {"bundle", "envelope", "payloadSha256", "tenantId"}:
                raise ValueError("unexpected fixture fields")
            if not re.fullmatch(r"[0-9a-f]{64}", case["payloadSha256"]) or not isinstance(case["tenantId"], str):
                raise ValueError("invalid expected profile binding")
            bundle = Path(case["bundle"]).resolve(strict=True)
            manifest_path = bundle / "manifest.json"
            native_before[str(manifest_path)] = _sha(manifest_path)
            manifest = json.loads(manifest_path.read_bytes())
            files = manifest["files"]
            if not 1 <= len(files) <= 16 or "hardened-admission" not in files:
                raise ValueError("native admission bundle manifest required")
            directory = output / name
            directory.mkdir(mode=0o700)
            for filename, expected in files.items():
                if Path(filename).name != filename or filename in (".", "..") or not re.fullmatch(r"[0-9a-f]{64}", expected):
                    raise ValueError("invalid native manifest entry")
                source = bundle / filename
                native_before[str(source)] = expected
                _copy_regular(source, directory / filename, expected, 0o700 if filename in ("hardened-admission", "hardened-runtime") else 0o600, 256 * 1024 * 1024)
            envelope_source = Path(case["envelope"]).resolve(strict=True)
            envelope_hash = _sha(envelope_source)
            native_before[str(envelope_source)] = envelope_hash
            _copy_regular(envelope_source, directory / "profile.json", envelope_hash, 0o600, 65536)
            configuration[name] = {"executable": str(directory / "hardened-admission"),
                                   "executableSha256": files["hardened-admission"],
                                   "envelope": str(directory / "profile.json"),
                                   "payloadSha256": case["payloadSha256"], "tenantId": case["tenantId"]}
        config = output / "cases.json"
        config.write_text(json.dumps(configuration, separators=(",", ":")) + "\n")
        config.chmod(0o600)
        report["caseConfigSha256"] = _sha(config)
        report["nativeInputFiles"] = native_before
        report["stagedFixtureFiles"] = {str(path.relative_to(output)): _sha(path)
                                        for name in ("v1", "v2") for path in sorted((output / name).iterdir())}
        env = {"PATH": str(go.parent) + ":/usr/bin:/bin", "HOME": str(output), "TMPDIR": str(output),
               "GOWORK": "off", "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off",
               "CGO_ENABLED": "0", "GOMAXPROCS": "2", "GOCACHE": str(output / "gocache"),
               "AFLOCK_LEGACY_CONSUMER_CASES": str(config), "LANG": "C"}
        for module, body in (("broker", _BROKER_TEST), ("gateway", _GATEWAY_TEST)):
            generated = stage / module / "aflock_legacy_consumer_uat_test.go"
            generated.write_text(_COMMON_TEST.replace("__CONSUMER__", body))
            report["generatedTests"][module] = _sha(generated)
            executable = output / (module + "-consumer.test")
            build_log = output / (module + "-build.log")
            _run([go, "test", "-mod=readonly", "-c", "-p", "1", "-trimpath", "-buildvcs=false", "-o", executable, "."],
                 stage / module, env, build_log, 180)
            report["binaries"][module] = {"path": str(executable), "sha256": _sha(executable)}
            test_log = output / (module + "-test.log")
            _run([executable, "-test.run=^" + _TEST_NAME + "$", "-test.v", "-test.timeout=40s"],
                 stage / module, env, test_log, 50)
            lines = test_log.read_text().splitlines()
            for name in ("v1", "v2"):
                passed = sum(line.strip().startswith("--- PASS: " + _TEST_NAME + "/" + name + " (") for line in lines) == 1
                check(module + "-" + name + "-actual-consumer", passed)
                report["cases"].append({"consumer": module, "contract": name, "passed": passed,
                                        "nativeAdmissionAccepted": True, "consumerAccepted": name == "v1"})
        check("exact-four-consumer-cases", len(report["cases"]) == 4)
        check("staged-consumer-source-unchanged", all(_sha(stage / name) == value for name, value in before.items()))
        check("original-consumer-source-unchanged", _sources(root) == before)
        check("native-fixtures-unchanged", all(_sha(Path(name)) == value for name, value in native_before.items()))
        check("staged-fixtures-unchanged", all(_sha(output / name) == value for name, value in report["stagedFixtureFiles"].items()))
        check("generated-tests-unchanged", all(_sha(stage / module / "aflock_legacy_consumer_uat_test.go") == value for module, value in report["generatedTests"].items()))
        check("test-executables-unchanged", all(_sha(Path(value["path"])) == value["sha256"] for value in report["binaries"].values()))
        check("harness-compiler-and-case-config-unchanged", _sha(own_source) == report["harnessSha256"]
              and _sha(go) == report["goSha256"] and _sha(config) == report["caseConfigSha256"])
        report["passed"] = True
    except (OSError, ValueError, RuntimeError, AssertionError, subprocess.SubprocessError) as error:
        report["error"] = type(error).__name__ + ": " + str(error)[:240]
    finally:
        report["logs"] = {path.name: {"sha256": _sha(path), "bytes": path.stat().st_size}
                          for path in sorted(output.glob("*.log"))}
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report
