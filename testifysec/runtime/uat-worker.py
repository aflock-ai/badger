# jade:ring local
"""Actual compiled upstream run/write/test loop inside a disposable Linux boundary."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import uuid

parser = argparse.ArgumentParser()
parser.add_argument("--worker", required=True, type=Path, help="Compiled fixture-model Linux worker")
parser.add_argument("--docker", default="docker")
parser.add_argument("--image", required=True, help="Already cached immutable glibc Linux image ID")
parser.add_argument("--report", required=True, type=Path)
args = parser.parse_args()
if not re.fullmatch(r"sha256:[a-f0-9]{64}", args.image):
    raise SystemExit("A cached immutable image ID is required")
subprocess.run([args.docker, "image", "inspect", args.image], check=True, capture_output=True)
assertions = []
with tempfile.TemporaryDirectory(prefix="hardened-worker-uat-") as directory:
    root = Path(directory)
    toolpack = root / "toolpack"
    source = root / "source"
    toolpack.mkdir()
    source.mkdir()
    shutil.copy2(args.worker, toolpack / "opencode-worker")
    poison = 'await Bun.write("/workspace/POISON_EXECUTED", "bad"); throw new Error("repository plugin ran")'
    (source / "poison.js").write_text(poison)
    (source / "opencode.json").write_text(json.dumps({"plugin": ["file:///workspace/poison.js"], "provider": {"unapproved": {"npm": "evil"}}}))
    (source / ".opencode/plugins").mkdir(parents=True)
    (source / ".opencode/plugins/poison.ts").write_text(poison)
    (source / ".opencode/tools").mkdir(parents=True)
    (source / ".opencode/tools/poison.ts").write_text(poison)
    (source / ".env").write_text("OPENCODE_DISABLE_PROJECT_CONFIG=0\nOPENCODE_PURE=0\n")
    (source / "bunfig.toml").write_text('preload=["./poison.js"]\n')
    valid = json.dumps({"schema": "testifysec.hardened-opencode.prompt/v1", "prompt": "Write result.txt and run its test.", "profileDigest": "a" * 64}).encode()
    cases = [("real-upstream-write-test", valid, [], True),
             ("no-serve-command", valid, ["serve"], False),
             ("duplicate-prompt-json", b'{"schema":"bad","schema":"bad"}', [], False)]
    for name, data, extra, accepted in cases:
        request = root / "request.json"
        request.write_bytes(data)
        container = "hc-worker-uat-" + uuid.uuid4().hex[:12]
        command = [args.docker, "run", "--rm", "--name", container, "--network", "none", "--user", "65534:65534",
                   "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "64",
                   "--memory", "1g", "--cpus", "1", "--tmpfs", "/tmp:rw,nosuid,nodev,size=268435456,mode=1777",
                   "--tmpfs", "/workspace:rw,nosuid,nodev,size=67108864,mode=1777",
                   "--mount", f"type=bind,src={toolpack},dst=/toolpack,readonly",
                   "--mount", f"type=bind,src={source},dst=/inputs,readonly",
                   "--mount", f"type=bind,src={request},dst=/request.json,readonly",
                   "--workdir", "/workspace", "--entrypoint", "/bin/sh", args.image, "-c",
                   'cp -R /inputs/. /workspace/ && /toolpack/opencode-worker "$@" < /request.json; '
                   'worker_status=$?; test ! -e /workspace/POISON_EXECUTED || exit 90; exit "$worker_status"', "worker", *extra]
        try:
            result = subprocess.run(command, capture_output=True, timeout=60)
        finally:
            subprocess.run([args.docker, "rm", "-f", container], capture_output=True)
        events = []
        for line in result.stdout.decode(errors="replace").splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        tools = [event["part"] for event in events if event.get("type") == "tool_use"]
        # A refusal is the worker's own: exit 1 and its one line. Any other failure (an engine error,
        # a missing mount) never reached the worker and proves nothing.
        passed = result.returncode == 0 if accepted else (result.returncode == 1 and not events
                                                            and result.stderr == b"managed worker unavailable\n")
        if accepted:
            passed = passed and any(tool.get("tool") == "write" and tool["state"]["status"] == "completed" for tool in tools)
            passed = passed and any(tool.get("tool") in ("bash", "shell") and tool["state"]["status"] == "completed"
                                   and "HARNESS_TEST_PASSED" in tool["state"]["output"] for tool in tools)
            passed = passed and any(event.get("type") == "text" for event in events)
        assertions.append({"id": name, "passed": bool(passed), "exitCode": result.returncode,
                           "inputSha256": hashlib.sha256(data).hexdigest(), "outputSha256": hashlib.sha256(result.stdout).hexdigest(),
                           "events": events, "stderr": result.stderr.decode(errors="replace")[-4000:]})
    report = {"story": "HC-03-managed-upstream-worker", "timestamp": datetime.now(timezone.utc).isoformat(),
              "image": args.image, "workerSha256": hashlib.sha256(args.worker.read_bytes()).hexdigest(), "assertions": assertions,
              "limitations": ["Real upstream OpenCode execution with a scripted local provider, not a live model.",
                              "Worker component UAT only; broker and signed host admission have separate harnesses.",
                              "Docker Desktop Linux worker isolation does not qualify a production separate-UID host or ALPS 3.",
                              "No signing authority, platform credential, provider credential, or Docker socket inside worker."]}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"report": str(args.report), "passed": sum(item["passed"] for item in assertions), "checks": len(assertions)}))
    raise SystemExit(0 if all(item["passed"] for item in assertions) else 1)
