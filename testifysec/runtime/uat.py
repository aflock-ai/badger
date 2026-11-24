# jade:ring local
"""Native admission -> native broker -> real upstream OpenCode -> scripted local model."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument("--go", default="go")
parser.add_argument("--bun", default="bun")
parser.add_argument("--worker", required=True, type=Path)
parser.add_argument("--image", required=True)
parser.add_argument("--engine-socket", required=True)
parser.add_argument("--report", required=True, type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parent
assertions = []
env = dict(os.environ, GOWORK="off")
digest = lambda value: hashlib.sha256(value).hexdigest()
with tempfile.TemporaryDirectory(prefix="hc-runtime-uat-") as temporary:
    work = Path(temporary).resolve()
    fixtures = work / "fixtures"
    host = work / "host"
    source = work / "source"
    toolpack = work / "toolpack"
    source.mkdir()
    toolpack.mkdir()
    shutil.copy2(args.worker, toolpack / "opencode-worker")
    subprocess.run([args.go, "run", str(root.parent / "managed/fixtures.go"), str(fixtures)],
                   cwd=root.parent / "native", env=env, check=True)
    socket = work / "broker.sock"
    subprocess.run(["python3", str(root / "build-host.py"), "--go", args.go, "--bun", args.bun,
                    "--trust", str(fixtures / "trust.json"), "--broker-socket", str(socket),
                    "--workspace", "runtime-uat", "--output", str(host)], check=True)
    subprocess.run([args.go, "build", "-trimpath", "-o", str(work / "broker"), "."],
                   cwd=root.parent / "broker", env=env, check=True)
    valid = json.loads((fixtures / "valid.json").read_text())
    profile_digest = digest(base64.b64decode(valid["payload"]))
    manifest = json.loads((host / "manifest.json").read_text())
    policy = {
        "schema": "testifysec.hardened-opencode.broker-policy/v1", "listenSocket": str(socket),
        "dockerSocket": args.engine_socket, "image": args.image, "workspace": {"id": "runtime-uat", "source": str(source)},
        "limits": {"timeoutSeconds": 60, "outputBytes": 1048576, "workspaceBytes": 1048576, "workspaceFiles": 100,
                   "memoryMiB": 1024, "workspaceMiB": 256},
        "allowedUIDs": [os.getuid()], "developmentAllowSameUID": True, "toolpack": str(toolpack),
        "admissionExecutable": str(host / "hardened-admission"), "admissionSha256": manifest["files"]["hardened-admission"],
        "profileSha256": profile_digest,
    }
    policy_file = work / "policy.json"
    policy_file.write_text(json.dumps(policy))
    policy_file.chmod(0o600)
    with (work / "broker.log").open("wb") as logs:
        broker = subprocess.Popen([str(work / "broker"), "serve", "--config", str(policy_file)], stdout=logs, stderr=logs)
        try:
            deadline = time.monotonic() + 5
            while not socket.exists() and broker.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            if not socket.exists():
                raise RuntimeError("broker did not start: " + (work / "broker.log").read_text())
            for name in ("valid", "expired", "wrong-key", "duplicate-payload"):
                request = {"schema": "testifysec.hardened-opencode.run/v1", "profile": json.loads((fixtures / (name + ".json")).read_text()),
                           "prompt": "Write result.txt and run its test."}
                raw = json.dumps(request).encode()
                result = subprocess.run([str(host / "hardened-code")], input=raw, capture_output=True, timeout=85,
                                        cwd=source, env={"PATH": "/nonexistent", "BUN_OPTIONS": "--preload /does-not-exist.js"})
                try:
                    output = json.loads(result.stdout)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    output = {}
                if name == "valid":
                    observation = output.get("broker", {})
                    passed = result.returncode == 0 and observation.get("status") == "completed" and observation.get("cleanup") is True
                    passed = passed and observation.get("profileSha256") == profile_digest and "HARNESS_TEST_PASSED" in observation.get("output", "")
                else:
                    passed = result.returncode == 1 and output.get("status") == "unavailable" and "broker" not in output
                assertions.append({"id": name, "passed": bool(passed), "exitCode": result.returncode, "inputSha256": digest(raw),
                                   "outputSha256": digest(result.stdout), "result": output})
        finally:
            broker.terminate()
            try:
                broker.wait(timeout=5)
            except subprocess.TimeoutExpired:
                broker.kill()
                broker.wait()
    report = {"story": "HC-03-managed-native-journey", "timestamp": datetime.now(timezone.utc).isoformat(),
              "hostBuild": manifest, "workerSha256": digest(args.worker.read_bytes()), "brokerSha256": digest((work / "broker").read_bytes()),
              "policySha256": digest(policy_file.read_bytes()), "assertions": assertions,
              "limitations": ["Real native host/broker/upstream execution with a scripted provider, not a live model or platform session.",
                              "Same-UID development host; this harness does not qualify production peer isolation or ALPS 3.",
                              "Worker edits remain ephemeral; output export and safe host application are not implemented."]}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"report": str(args.report), "passed": sum(item["passed"] for item in assertions), "checks": len(assertions)}))
    raise SystemExit(0 if all(item["passed"] for item in assertions) else 1)
