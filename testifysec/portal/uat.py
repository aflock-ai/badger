# jade:ring local
"""Portal-signed profiles through the compiled native admission (managed/build.py bundle).

The portal's Go tests reproduce admission; this runs the real hardened-admission executable on
envelopes the portal's issuer signed, with the trust input the portal exports compiled in.
"""
import argparse
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


with tempfile.TemporaryDirectory(prefix="portal-admission-uat-") as temp:
    work = Path(temp)
    fixtures, bundle = work / "fixtures", work / "bundle"
    subprocess.run([args.go, "run", "./cmd/portal-uat-fixtures", str(fixtures)], cwd=root,
                   env=dict(os.environ, GOWORK="off"), check=True)
    subprocess.run(["python3", str(root.parent / "managed" / "build.py"), "--go", args.go, "--bun", args.bun,
                    "--trust", str(fixtures / "trust.json"), "--output", str(bundle)], check=True)
    home = work / "home"
    home.mkdir()

    def check(name, reason=None):
        data = (fixtures / (name + ".json")).read_bytes()
        result = subprocess.run([str(bundle / "hardened-admission")], input=data, capture_output=True, cwd=work,
                                env={"PATH": "/nonexistent", "HOME": str(home), "TMPDIR": str(work)}, timeout=30)
        try:
            decision = json.loads(result.stdout)
        except (json.JSONDecodeError, UnicodeDecodeError):
            decision = {}
        passed = result.returncode == (0 if reason is None else 1) and decision.get("scope") == "profile-admission-only"
        if reason is None:
            version = json.loads((fixtures / (name + ".version.json")).read_text())
            passed = passed and decision.get("admitted") is True
            # The digests the broker pins and binds must be the ones the portal recorded.
            passed = passed and decision.get("payloadSha256") == version["payloadSha256"]
            passed = passed and decision.get("envelopeSha256") == version["envelopeSha256"] == digest(data)
            passed = passed and decision.get("signerKeyIds") == sorted(version["signerKeyIds"])
            passed = passed and decision.get("profile", {}).get("sequence") == version["sequence"]
        else:
            passed = passed and decision.get("admitted") is False and decision.get("reason") == reason
        assertions.append({"id": "PORTAL-UAT." + name, "passed": bool(passed), "inputSha256": digest(data),
                           "exitCode": result.returncode, "decision": decision})

    check("current")
    check("previous", "profile-rollback")
    check("tampered", "profile-signature-invalid")
    check("wrong-key", "profile-signature-invalid")
    check("wrong-deployment", "assignment-mismatch")
    report = {"story": "portal-admission", "assertions": assertions,
              "limitations": ["Ephemeral portal keys and a local build; no enclave CA, activation record or device pull."]}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    raise SystemExit(0 if all(item["passed"] for item in assertions) else 1)
