# jade:ring local
"""Native v1/v2 admission compatibility; retained public synthetic fixtures only."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


parser = argparse.ArgumentParser()
parser.add_argument("--go", required=True)
parser.add_argument("--bun", required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parent
output = args.output.resolve()
output.mkdir(mode=0o700)
env = dict(os.environ, GOWORK="off", GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off", GOFLAGS="-mod=readonly")
checks = []
manifests = {}
logs = {}
report = {"schema": "testifysec.hardened-code.profile-compatibility-uat/v1", "scope": "profile-admission-only",
          "startedAt": datetime.now(timezone.utc).isoformat(), "assertions": checks,
          "builds": manifests, "logs": logs, "passed": False,
          "limitations": [
              "Synthetic SPKI signer and non-executable backend manifest; no platform authentication, activation, revocation or publish.",
              "V2 proves a signed manifest reference equals protected build assignment. It does not inspect a manifest, authorize VM startup or measure hardware.",
              "Legacy broker/gateway checks are isolated actual function tests; no engine, provider or service execution.",
              "Legacy pushgate v1 refusal is source inventory only in this harness; its end-to-end workflow is not exercised here.",
              "No upstream initialization, runtime package installation, VM boot, persistent rollback state, or production preflight is enabled.",
              "OS time and protected installation/loader custody remain assumptions; no same-user isolation or FIPS/ALPS/IL6 qualification.",
              "Hashes identify observed source and executable path bytes, not running-image or hardware measurements; reports are unsigned local observations.",
          ]}


def check(name, passed, **details):
    checks.append({"id": name, "passed": bool(passed), **details})
    if not passed:
        raise AssertionError(name)


def run(name, command, cwd=root, data=None, expected=0):
    result = subprocess.run(command, cwd=cwd, env=env, input=data, capture_output=True, timeout=600)
    stdout = output / (name + ".stdout.log")
    stderr = output / (name + ".stderr.log")
    stdout.write_bytes(result.stdout)
    stderr.write_bytes(result.stderr)
    logs[name] = {"stdoutSha256": sha(result.stdout), "stderrSha256": sha(result.stderr), "exitCode": result.returncode}
    if result.returncode != expected:
        raise RuntimeError(name + " failed; inspect retained log")
    return result


def verify_sources(manifest):
    return (all(sha((root / path).read_bytes()) == value for path, value in manifest["sourceFiles"].items())
            and all(sha((root.parent / "native" / path).read_bytes()) == value for path, value in manifest["nativeBuild"]["sourceFiles"].items())
            and all(sha(Path(path).read_bytes()) == value for path, value in manifest["nativeGoInputs"]["files"].items())
            and all(sha(Path(tool["path"]).read_bytes()) == tool["sha256"] for tool in manifest["buildTools"].values()))


try:
    run("fixtures", [args.go, "run", str(root / "fixtures-v2.go"), str(output / "fixtures")], cwd=root.parent / "native")
    fixtures = output / "fixtures"
    check("same-signer-and-common-assignment", (lambda a, b: a == {k: v for k, v in b.items() if k != "backend"} | {"schemaVersion": 1})(
        json.loads((fixtures / "trust-v1.json").read_bytes()), json.loads((fixtures / "trust-v2.json").read_bytes())))
    for version in (1, 2):
        bundle = output / ("bundle-v" + str(version))
        run("build-v" + str(version), ["python3", str(root / "build.py"), "--go", args.go, "--bun", args.bun,
                                      "--trust", str(fixtures / ("trust-v" + str(version) + ".json")), "--output", str(bundle)])
        manifest = json.loads((bundle / "manifest.json").read_bytes())
        manifests[str(version)] = {"manifestSha256": sha((bundle / "manifest.json").read_bytes()), "manifest": manifest}
        check("build-v" + str(version) + "-inputs", verify_sources(manifest)
              and manifest["profileVersion"] == version
              and manifest["trustSha256"] == sha((fixtures / ("trust-v" + str(version) + ".json")).read_bytes())
              and all(sha((bundle / path).read_bytes()) == value for path, value in manifest["files"].items()))
    trust = json.loads((fixtures / "trust-v2.json").read_bytes())
    check("synthetic-manifest-pin", trust["backend"]["manifestSha256"] == sha((fixtures / "backend-manifest.json").read_bytes())
          and manifests["2"]["manifest"]["assignment"]["backend"] == trust["backend"])
    home = output / "foreign-cwd"
    home.mkdir(mode=0o700)
    (home / "poison.js").write_text('throw new Error("untrusted preload ran")\n')
    (home / ".env").write_text("MANAGED_TRUST=attacker\nMANAGED_PROFILE_VERSION=1\n")
    (home / "bunfig.toml").write_text('preload = ["./poison.js"]\n')
    runtime_env = {"HOME": str(home), "PATH": "/nonexistent", "TMPDIR": str(home),
                   "BUN_OPTIONS": "--preload " + str(home / "poison.js"), "NODE_OPTIONS": "--require " + str(home / "poison.js"),
                   "MANAGED_TRUST": json.dumps({**trust, "schemaVersion": 1}), "MANAGED_PROFILE_VERSION": "1",
                   "MANAGED_BACKEND_KIND": "linux-docker/v1", "MANAGED_BACKEND_MANIFEST_SHA256": "0" * 64}
    decisions = {}

    def admit(label, version, raw, reason=None, extra=None, launcher=False):
        result = subprocess.run([str(output / ("bundle-v" + str(version)) / "hardened-admission"), *(extra or [])],
                                input=raw, capture_output=True, env=runtime_env, cwd=home, timeout=30)
        try:
            decision = json.loads(result.stdout)
        except (ValueError, UnicodeDecodeError):
            decision = {}
        passed = result.returncode == (0 if reason is None else 1) and decision.get("schemaVersion") == version
        passed = passed and decision.get("scope") == "profile-admission-only" and decision.get("admitted") is (reason is None)
        if launcher:
            passed = result.returncode == 2 and not result.stdout and b"unavailable" in result.stderr
        elif reason is not None:
            passed = passed and decision.get("reason") == reason and set(decision) == {"schemaVersion", "scope", "admitted", "reason"}
        else:
            manifest = manifests[str(version)]["manifest"]
            payload = base64.b64decode(json.loads(raw)["payload"], validate=True)
            keys = {"profileId", "tenantId", "deploymentId", "sequence", "notBefore", "expiresAt"}
            passed = (passed and decision.get("envelopeSha256") == sha(raw) and decision.get("payloadSha256") == sha(payload)
                      and decision.get("trustSha256") == manifest["trustSha256"]
                      and decision.get("nativeSha256") == next(value for key, value in manifest["files"].items() if key.startswith("librookery"))
                      and isinstance(decision.get("signerKeyIds"), list) and len(decision["signerKeyIds"]) == 1
                      and set(decision) == {"schemaVersion", "admitted", "scope", "profile", "envelopeSha256", "payloadSha256", "signerKeyIds", "trustSha256", "nativeSha256"}
                      and set(decision.get("profile", {})) == (keys | {"backend"} if version == 2 else keys))
            if version == 2:
                passed = passed and decision["profile"]["backend"] == trust["backend"]
        decisions[label] = decision
        check(label, passed, inputSha256=sha(raw), outputSha256=sha(result.stdout), stderrSha256=sha(result.stderr),
              exitCode=result.returncode, decision=decision)

    expected = {"valid-v2": None, "tampered": "profile-signature-invalid", "wrong-key": "profile-signature-invalid",
                "expired": "profile-time-invalid", "future": "profile-time-invalid", "wrong-tenant": "assignment-mismatch",
                "rollback": "profile-rollback", "wrong-backend": "unsupported-backend", "wrong-pin": "backend-assignment-mismatch",
                "uppercase-pin": "invalid-backend-pin", "short-pin": "invalid-backend-pin", "missing-backend": "invalid-schema",
                "null-backend": "invalid-schema", "extra-backend": "invalid-schema", "unknown-field": "invalid-schema",
                "duplicate-backend": "duplicate-json-key", "rounded-version": "invalid-json-number", "rounded-sequence": "invalid-json-number",
                "weakened-controls": "unsupported-controls", "type1-schema2": "unsupported-profile-type",
                "type2-schema1": "unsupported-profile-version", "unsupported-version": "unsupported-profile-version", "unsupported-type": "unsupported-profile-type"}
    for name, reason in expected.items():
        admit("v2-" + name, 2, (fixtures / (name + ".json")).read_bytes(), reason)
    valid1 = (fixtures / "valid-v1.json").read_bytes()
    valid2 = (fixtures / "valid-v2.json").read_bytes()
    admit("v1-valid", 1, valid1)
    admit("v1-refuses-v2", 1, valid2, "admission-unavailable")
    admit("v2-refuses-v1", 2, valid1, "unsupported-profile-type")
    admit("v1-refuses-type1-schema2", 1, (fixtures / "type1-schema2.json").read_bytes(), "invalid-schema")
    admit("v1-refuses-type2-schema1", 1, (fixtures / "type2-schema1.json").read_bytes(), "admission-unavailable")
    check("same-verified-signer-across-contracts", decisions["v1-valid"]["signerKeyIds"] == decisions["v2-valid-v2"]["signerKeyIds"])
    for key, value in (("publicKeys", trust["publicKeys"]), ("schemaVersion", 1), ("backend", trust["backend"])):
        admit("envelope-refuses-" + key, 2, json.dumps({**json.loads(valid2), key: value}).encode(), "invalid-schema")
    admit("envelope-duplicate-version", 2, b'{"payloadType":"attacker",' + valid2[1:], "duplicate-json-key")
    admit("argv-cannot-choose-version", 2, valid2, extra=["--profile-version", "1"], launcher=True)
    admit("argv-cannot-enable-run", 2, valid2, extra=["run"], launcher=True)
    raw_trust = (fixtures / "trust-v2.json").read_bytes()
    invalid_trust = {
        "cross-version": json.dumps({**trust, "schemaVersion": 1}).encode(),
        "unsupported-version": json.dumps({**trust, "schemaVersion": 3}).encode(),
        "missing-backend": json.dumps({k: v for k, v in trust.items() if k != "backend"}).encode(),
        "null-backend": json.dumps({**trust, "backend": None}).encode(),
        "wrong-kind": json.dumps({**trust, "backend": {**trust["backend"], "kind": "linux-docker/v1"}}).encode(),
        "uppercase-pin": json.dumps({**trust, "backend": {**trust["backend"], "manifestSha256": "A" * 64}}).encode(),
        "unknown-backend-field": json.dumps({**trust, "backend": {**trust["backend"], "override": True}}).encode(),
        "duplicate-key": raw_trust.replace(b'"kind":', b'"kind":"darwin-vz/v1","\\u006bind":'),
        "rounded-version": raw_trust.replace(b'"schemaVersion":2', b'"schemaVersion":2.00000000000000001'),
        "rounded-floor": raw_trust.replace(b'"minimumSequence":10', b'"minimumSequence":9.999999999999999999'),
        "threshold-too-high": json.dumps({**trust, "threshold": 2}).encode(),
    }
    for name, raw in invalid_trust.items():
        result = subprocess.run([args.bun, str(root / "validate-trust.ts")], input=raw, capture_output=True, env=env, cwd=root, timeout=30)
        check("build-trust-refuses-" + name, result.returncode != 0, inputSha256=sha(raw), outputSha256=sha(result.stdout), stderrSha256=sha(result.stderr))
    rejected_output = output / "must-not-build-legacy-host"
    result = subprocess.run(["python3", str(root.parent / "runtime/build-host.py"), "--go", "/nonexistent/go", "--bun", "/nonexistent/bun",
                             "--trust", str(fixtures / "trust-v2.json"), "--broker-socket", "/nonexistent/broker.sock", "--workspace", "fixture",
                             "--output", str(rejected_output)], capture_output=True, env=env, timeout=30)
    check("legacy-host-refuses-v2-before-tools-or-output", result.returncode != 0 and not rejected_output.exists()
          and b"Legacy managed host requires version 1 trust" in result.stderr and b"FileNotFoundError" not in result.stderr,
          sourceSha256=sha((root.parent / "runtime/build-host.py").read_bytes()), stderrSha256=sha(result.stderr))
    spec = importlib.util.spec_from_file_location("legacy_consumers", root / "legacy-consumers.py")
    consumers = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(consumers)
    report["legacyConsumers"] = consumers.run_legacy_consumers(root.parent.parent, output / "consumers", args.go, {
        "v" + str(version): {"bundle": output / ("bundle-v" + str(version)), "envelope": fixtures / ("valid-v" + str(version) + ".json"),
                            "payloadSha256": sha(base64.b64decode(json.loads((fixtures / ("valid-v" + str(version) + ".json")).read_bytes())["payload"])),
                            "tenantId": trust["tenantId"]} for version in (1, 2)})
    check("legacy-consumer-native-controls", report["legacyConsumers"]["passed"])
    run("schema-tests", [args.bun, "test", "profile.test.ts", "profile-v2.test.ts"])
    run("legacy-v1-regression", ["python3", str(root / "uat.py"), "--go", args.go, "--bun", args.bun, "--report", str(output / "legacy-v1-report.json")])
    legacy = json.loads((output / "legacy-v1-report.json").read_bytes())
    report["legacyV1"] = {"reportSha256": sha((output / "legacy-v1-report.json").read_bytes()), "checks": len(legacy["assertions"])}
    check("legacy-v1-regression", all(item["passed"] for item in legacy["assertions"]) and len(legacy["assertions"]) == 29)
    for version in (1, 2):
        manifest = manifests[str(version)]["manifest"]
        check("final-v" + str(version) + "-source-and-artifact-binding", verify_sources(manifest)
              and all(sha((output / ("bundle-v" + str(version)) / name).read_bytes()) == value for name, value in manifest["files"].items()))
    report["fixtures"] = {path.name: sha(path.read_bytes()) for path in sorted(fixtures.iterdir()) if path.is_file()}
    report["passed"] = all(item["passed"] for item in checks)
except Exception as error:
    report["error"] = str(error)
finally:
    report["finishedAt"] = datetime.now(timezone.utc).isoformat()
    report["checkCount"] = len(checks)
    destination = output / "report.json"
    destination.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "checks": len(checks), "report": str(destination), "sha256": sha(destination.read_bytes()),
                      "error": report.get("error")}))
raise SystemExit(0 if report["passed"] else 1)
