# jade:ring local
"""HC-02: compiled native admission exercised with real ephemeral DSSE fixtures."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--go", default="go")
parser.add_argument("--bun", default="bun")
parser.add_argument("--report", required=True, type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parent
assertions = []

def digest(data):
    return hashlib.sha256(data).hexdigest()

with tempfile.TemporaryDirectory(prefix="hardened-admission-uat-") as temp:
    work = Path(temp)
    fixtures = work / "fixtures"
    bundle = work / "bundle"
    subprocess.run([args.go, "run", str(root / "fixtures.go"), str(fixtures)], cwd=root.parent / "native",
                   env=dict(os.environ, GOWORK="off"), check=True)
    subprocess.run(["python3", str(root / "build.py"), "--go", args.go, "--bun", args.bun,
                    "--trust", str(fixtures / "trust.json"), "--output", str(bundle)], check=True)
    manifest = json.loads((bundle / "manifest.json").read_text())
    home = work / "agent-home"
    home.mkdir()
    # Deliberately hostile ambient configuration must not become managed authority.
    (work / ".env").write_text("MANAGED_TRUST=attacker\nROOKERY_LIBRARY_SHA256=attacker\n")
    (work / "bunfig.toml").write_text('preload = ["./poison.js"]\n')
    (work / "poison.js").write_text('throw new Error("untrusted preload ran")\n')
    (work / "package.json").write_text('{"name":"untrusted","type":"module"}\n')
    runtime = {"PATH": "/nonexistent", "HOME": str(home), "TMPDIR": str(work),
               "MANAGED_TRUST": "attacker", "ROOKERY_LIBRARY_SHA256": "attacker",
               "BUN_OPTIONS": "--preload " + str(work / "poison.js"),
               "NODE_OPTIONS": "--require " + str(work / "poison.js")}

    def check(name, data, reason=None, extra_args=None, launcher_refusal=False):
        result = subprocess.run([str(bundle / "hardened-admission"), *(extra_args or [])], input=data,
                                capture_output=True, cwd=work, env=runtime, timeout=30)
        try:
            decision = json.loads(result.stdout)
        except (json.JSONDecodeError, UnicodeDecodeError):
            decision = {}
        passed = result.returncode == (0 if reason is None else 1) and decision.get("scope") == "profile-admission-only"
        if launcher_refusal:
            passed = result.returncode == 2 and result.stdout == b"" and b"unavailable" in result.stderr
        elif reason is None:
            passed = passed and decision.get("admitted") is True and decision.get("envelopeSha256") == digest(data)
            passed = passed and decision.get("trustSha256") == manifest["trustSha256"]
            passed = passed and decision.get("profile", {}).get("sequence") == 10
            passed = passed and decision.get("payloadSha256") == digest(base64.b64decode(json.loads(data)["payload"]))
            passed = passed and len(decision.get("signerKeyIds", [])) == 1
        else:
            passed = passed and decision.get("admitted") is False and decision.get("reason") == reason
        assertions.append({"id": "HC-02." + name, "passed": bool(passed), "inputSha256": digest(data),
                           "outputSha256": digest(result.stdout), "exitCode": result.returncode, "decision": decision})

    expected = {
        "valid": None,
        "tampered": "profile-signature-invalid", "wrong-key": "profile-signature-invalid",
        "expired": "profile-time-invalid", "not-yet-valid": "profile-time-invalid",
        "wrong-tenant": "assignment-mismatch", "wrong-deployment": "assignment-mismatch", "wrong-profile": "assignment-mismatch",
        "rollback": "profile-rollback", "unknown-field": "invalid-schema", "unknown-control": "invalid-schema",
        "duplicate-payload": "duplicate-json-key", "unsupported-version": "unsupported-profile-version",
        "weakened-controls": "unsupported-controls", "fractional-sequence": "invalid-json-number", "invalid-utf8": "admission-unavailable",
        "rounded-sequence": "invalid-json-number", "rounded-schema-version": "invalid-json-number",
        "exponent-sequence": "invalid-json-number", "unsafe-sequence": "invalid-json-number", "negative-zero": "invalid-json-number",
    }
    for name, reason in expected.items():
        check(name, (fixtures / (name + ".json")).read_bytes(), reason)
    valid = (fixtures / "valid.json").read_bytes()
    check("empty", b"", "admission-unavailable")
    check("oversize", b"x" * (512 * 1024 + 1), "admission-unavailable")
    check("duplicate-envelope", b'{"payloadType":"attacker",' + valid[1:], "duplicate-json-key")
    check("no-run-command", valid, extra_args=["run", "sh", "-c", "true"], launcher_refusal=True)
    check("no-preload-command", valid, extra_args=["--preload", str(work / "poison.js")], launcher_refusal=True)
    injected = json.loads(valid)
    injected["publicKeys"] = json.loads((fixtures / "trust.json").read_text())["publicKeys"]
    check("request-trust-injection", json.dumps(injected).encode(), "invalid-schema")
    library = next(name for name in manifest["files"] if name.startswith("librookery"))
    original_library = (bundle / library).read_bytes()
    (bundle / library).write_bytes(b"unapproved native verifier")
    check("library-substitution", valid, "admission-unavailable")
    (bundle / library).write_bytes(original_library)
    (bundle / "hardened-runtime").write_bytes(b"unapproved runtime")
    check("runtime-substitution", valid, launcher_refusal=True)
    report = {
        "story": "HC-02", "timestamp": datetime.now(timezone.utc).isoformat(), "runtime": manifest,
        "manifestSha256": digest((bundle / "manifest.json").read_bytes()), "assertions": assertions,
        "limitations": [
            "Local synthetic SPKI roots and profiles; no platform login, signer ceremony, activation or revocation.",
            "Admission-only component; no upstream OpenCode initialization, model calls or tool execution.",
            "Build-provisioned rollback floor; no persistent highest-seen counter or rollback-resistant hardware state.",
            "Expiry uses the operating-system clock and assumes protected, correctly synchronized time.",
            "Protected installation and loader environment required; same-user or privileged tampering is not isolated.",
            "Launcher uses a fixed system PATH; no external npm, Node, Go or Bun runtime is needed. No network-containment claim.",
            "Only the native launcher is a supported entrypoint; deployment must prevent privileged direct-runtime invocation.",
            "No FIPS, ALPS or IL6 qualification claim.",
        ],
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    raise SystemExit(0 if all(item["passed"] for item in assertions) else 1)
