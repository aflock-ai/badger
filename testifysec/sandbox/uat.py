#!/usr/bin/env python3
# jade:ring local
"""Real local Docker UAT; uses only an existing image and disposable fixtures."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid

from broker import Engine, Rejected, encoded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", default=shutil.which("docker"))
    parser.add_argument("--engine-socket", required=True)
    parser.add_argument("--image", required=True, help="Cached immutable sha256 image ID; Alpine/busybox tooling required")
    parser.add_argument("--out", default=str(Path(__file__).parent / ".cache" / "local-uat.json"))
    args = parser.parse_args()
    directory = Path(__file__).resolve().parent
    report = {"schema": "testifysec.hardened-opencode.sandbox-uat/v1",
              "startedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "claim": "HC-03 local execution adapter only; ALPS not assessed",
              "checks": [], "receipts": [], "attempts": []}
    report["sourceHashes"] = {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
                              for name in ("broker.py", "uat.py", "README.md")}
    # Read-only revision evidence; no git executes in the fixture workspace.
    report["revision"] = subprocess.check_output(["git", "-C", str(directory), "rev-parse", "HEAD"], text=True).strip()
    report["dirtyPaths"] = subprocess.check_output(
        ["git", "-C", str(directory), "status", "--porcelain", "--untracked-files=all", "--", "."], text=True).splitlines()

    def check(name, passed, detail):
        report["checks"].append({"name": name, "passed": bool(passed), "detail": detail})
        print(("PASS " if passed else "FAIL ") + name, flush=True)
        if not passed:
            raise AssertionError(name + ": " + detail)

    try:
        with tempfile.TemporaryDirectory(prefix="hc-sandbox-uat-") as temporary:
            root = Path(temporary).resolve()
            workspace = root / "source"
            workspace.mkdir()
            (workspace / "hello.txt").write_text("original\n")
            (workspace / ".git" / "hooks").mkdir(parents=True)
            (workspace / ".git" / "config").write_text("SYNTHETIC UNTRUSTED GIT CONFIG\n")
            (workspace / ".git" / "hooks" / "pre-commit").write_text("exit 91\n")
            secret = root / "controller-secret"
            secret.write_text("HC_SYNTHETIC_CONTROLLER_SECRET\n")
            secret.chmod(0o600)
            administrative = root / "admin"
            administrative.mkdir(mode=0o700)
            policy_path = administrative / "policy.json"
            policy = {"schema": "testifysec.hardened-opencode.sandbox-policy/v1",
                      "dockerBinary": args.docker, "engineSocket": args.engine_socket, "image": args.image,
                      "workspace": {"id": "uat", "source": str(workspace)},
                      "limits": {"timeoutSeconds": 5, "outputBytes": 8192, "workspaceBytes": 1048576, "workspaceFiles": 100}}

            def write_policy(value):
                policy_path.write_bytes(encoded(value))
                policy_path.chmod(0o600)

            write_policy(policy)
            engine = Engine(policy, administrative)
            report["runtime"] = engine.preflight()

            def run(command="true", changes=None, raw=None, override_policy=None):
                value = {"schema": "testifysec.hardened-opencode.exec/v1", "workspace": "uat", "command": "set -eu\n" + command}
                value.update(changes or {})
                request_path = root / "request.json"
                request_path.write_bytes(raw if raw is not None else encoded(value))
                write_policy(override_policy or policy)
                result = subprocess.run([shutil.which("python3"), str(directory / "broker.py"),
                                         "--policy", str(policy_path), "--request", str(request_path)],
                                        capture_output=True, timeout=40,
                                        env={**os.environ, "HC_TEST_CONTROLLER_SECRET": "SYNTHETIC_INHERITED_SECRET"})
                try:
                    response = json.loads(result.stdout)
                except (ValueError, UnicodeError) as error:
                    raise AssertionError("Adapter did not return structured result: " + result.stderr.decode()) from error
                if result.returncode != (0 if response["status"] == "completed" else 1):
                    raise AssertionError("Adapter exit status contradicts its response")
                report["attempts"].append({"requestSha256": hashlib.sha256(request_path.read_bytes()).hexdigest(),
                                           "policySha256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
                                           "status": response["status"], "code": response.get("code"),
                                           "exitCode": response.get("exitCode")})
                if response["status"] == "completed":
                    # Full receipts bind source contents, command, output, policy and runtime.
                    report["receipts"].append(response)
                return response

            check("host-secret-positive-control", secret.read_text() == "HC_SYNTHETIC_CONTROLLER_SECRET\n",
                  "The disposable host secret is readable before entering the worker boundary")
            response = run("test \"$(cat hello.txt)\" = original && printf changed >hello.txt && test ! -e .git && printf workspace-ok")
            check("workspace-edit-and-git-metadata-exclusion", response.get("exitCode") == 0 and response.get("output") == "workspace-ok",
                  "Worker reads and edits its snapshot; agent-authored .git metadata is absent")
            check("daemon-logging-disabled-with-live-output", response.get("containerConfiguration", {}).get("logDriver") == "none"
                  and response.get("output") == "workspace-ok",
                  "Engine reports logging driver none while bounded live attachment captures command output")
            check("original-checkout-unchanged", (workspace / "hello.txt").read_text() == "original\n"
                  and (workspace / ".git" / "hooks" / "pre-commit").read_text() == "exit 91\n",
                  "No writes or hooks execute in the original checkout; output export is deliberately not implemented")
            response = run("test \"$(id -u)\" = 65534 && grep -q '^CapEff:[[:space:]]*0000000000000000$' /proc/self/status "
                           "&& grep -q '^NoNewPrivs:[[:space:]]*1$' /proc/self/status && printf nonroot-ok")
            check("nonroot-capabilities-and-no-new-privileges", response.get("exitCode") == 0 and response.get("output") == "nonroot-ok",
                  "Worker observes uid 65534, zero effective capabilities and NoNewPrivs")
            response = run(f"test -z \"${{HC_TEST_CONTROLLER_SECRET-}}\" && test ! -S '{args.engine_socket}' "
                           f"&& test ! -S /var/run/docker.sock && if cat '{secret}' >/dev/null 2>&1; then exit 7; fi; "
                           "test -z \"${HC_TEST_CONTROLLER_SECRET-}\" && printf secret-denied")
            check("controller-secret-environment-and-engine-socket-isolation", response.get("exitCode") == 0
                  and response.get("output") == "secret-denied",
                  "Actual synthetic host-file read is refused; controller env and engine socket are absent")
            response = run("if touch /hc-root-write 2>/tmp/denial; then exit 7; fi; "
                           "grep -q 'Read-only file system' /tmp/denial && printf root-denied")
            check("read-only-root-refusal", response.get("exitCode") == 0 and response.get("output") == "root-denied",
                  "Write fails specifically with read-only-filesystem error")
            response = run("if dd if=/dev/zero of=/workspace/quota bs=1048576 count=65 2>/tmp/denial; then exit 7; fi; "
                           "grep -q 'No space left on device' /tmp/denial && printf quota-denied")
            check("workspace-storage-quota-refusal", response.get("exitCode") == 0 and response.get("output") == "quota-denied",
                  "Workspace tmpfs refuses writes beyond 64 MiB; no host mount is writable")

            # Private Docker-bridge echo fixture. No published host port or public endpoint.
            endpoint = "hc-uat-net-" + uuid.uuid4().hex
            try:
                engine.call(["run", "--pull", "never", "--detach", "--name", endpoint,
                             "--read-only", "--log-driver", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true",
                             "--user", "65534:65534", "--pids-limit", "16", "--memory", "32m",
                             "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=1m,mode=1777", "--entrypoint", "/bin/sh",
                             args.image, "-c", "exec nc -lk -p 43891 -e /bin/cat"])
                address = engine.call(["inspect", "--format", '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', endpoint]).decode().strip()
                control = b""
                for attempt in range(10):
                    try:
                        control = engine.call(["exec", endpoint, "/bin/sh", "-c", f"printf HC_NETWORK_CONTROL | nc -w 1 {address} 43891"])
                        break
                    except Rejected:
                        time.sleep(0.1)
                check("network-endpoint-positive-control", control == b"HC_NETWORK_CONTROL",
                      "Same-image nc reaches a disposable private-bridge echo endpoint before isolation")
                response = run(f"if nc -v -w 1 {address} 43891 </dev/null >/tmp/body 2>/tmp/denial; then exit 7; fi; "
                               "grep -Eq 'Network (is )?unreachable|No route to host' /tmp/denial || { cat /tmp/denial; exit 8; }; printf network-denied")
                check("network-none-refuses-reachable-endpoint", response.get("exitCode") == 0
                      and response.get("output") == "network-denied",
                      "Actual connection fails for lack of a route, not missing tools or a dead endpoint")
            finally:
                engine.call(["rm", "--force", endpoint])

            response = run(changes={"mounts": [str(secret)]})
            check("caller-cannot-add-mounts", response.get("code") == "invalid_schema", "Unknown request fields fail before engine access")
            response = run(changes={"workspace": "unassigned"})
            check("unassigned-workspace-refused", response.get("code") == "workspace_denied", "Worker cannot select a filesystem path")
            response = run(raw=b'{"schema":"one","schema":"two"}')
            check("duplicate-json-key-refused", response.get("code") == "invalid_json", "Ambiguous requests fail closed")
            response = run(raw=b'{"schema":"testifysec.hardened-opencode.exec/v1","workspace":"uat","command":"\\ud800"}')
            check("unpaired-unicode-surrogate-refused", response.get("code") == "invalid_json",
                  "The exact JSON escape \\ud800 produces a structured refusal instead of an encoding traceback")
            response = run(override_policy={**policy, "image": "alpine:latest"})
            check("mutable-image-refused", response.get("code") == "unapproved_image", "Tags cannot select a runtime")
            response = run(override_policy={**policy, "image": "sha256:" + "0" * 64})
            check("missing-image-refused-without-pull", response.get("code") == "engine_unavailable", "Local inspection fails; image fetching is absent")
            response = run(override_policy={**policy, "engineSocket": str(root / "absent.sock")})
            check("missing-engine-refused-without-host-fallback", response.get("code") == "engine_unavailable", "Host execution is never substituted")
            entry_policy = {**policy, "limits": {**policy["limits"], "workspaceFiles": 10}}
            try:
                for index in range(100):
                    (workspace / f"budget-{index:03}").write_bytes(b"")
                response = run(override_policy=entry_policy)
                entry_label = "io.testifysec.hardened.policy=" + hashlib.sha256(encoded(entry_policy)).hexdigest()
                events = engine.call(["events", "--since", "60s", "--until", datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                      "--filter", "label=" + entry_label, "--filter", "event=start", "--format", '{{json .}}'])
                check("workspace-entry-budget-refused-before-start", response.get("code") == "workspace_limit" and not events.strip(),
                      "100 entries exceed a 10-entry policy; no start event exists for this invocation's unique policy digest")
            finally:
                for index in range(100):
                    (workspace / f"budget-{index:03}").unlink()
            (workspace / "escape").symlink_to(secret)
            try:
                response = run()
                check("workspace-symlink-refused", response.get("code") == "unsafe_workspace", "Snapshot refuses the link before launch")
            finally:
                (workspace / "escape").unlink()
            os.link(secret, workspace / "hardlink")
            try:
                response = run()
                check("workspace-hardlink-refused", response.get("code") == "unsafe_workspace", "No host secret can be smuggled through a hardlink")
            finally:
                (workspace / "hardlink").unlink()
            response = run("sleep 20", changes={"timeoutSeconds": 1})
            check("timeout-kills-worker", response.get("code") == "execution_timeout", "Policy timeout terminates and removes the entire worker container")
            response = run("yes synthetic-output")
            check("output-limit-kills-worker", response.get("code") == "output_limit", "Excess output cannot consume unbounded controller memory")
            response = run("exit 23")
            check("command-failure-preserved", response.get("exitCode") == 23, "Command failure remains distinct from broker admission failure")
            label = "io.testifysec.hardened.policy=" + hashlib.sha256(encoded(policy)).hexdigest()
            active = engine.call(["ps", "-a", "--filter", "label=" + label, "--format", '{{.Names}}']).decode().splitlines()
            # No unrelated container is removed: names are captured before cleanup, never bulk-deleted.
            check("no-worker-containers-remain", not active, "All worker containers created by this isolated UAT were removed")
            report["cleanup"] = "fixture containers and private files removed"
    except (AssertionError, Rejected, OSError, subprocess.SubprocessError) as error:
        report["failure"] = str(error)
    report["passed"] = bool(report["checks"]) and all(item["passed"] for item in report["checks"]) and "failure" not in report
    report["limitations"] = [
        "Development Python adapter; no packaged native distribution or upstream tool routing yet.",
        "Docker Desktop Linux VM fixture only; no production host, kernel-escape or hardware-attestation qualification.",
        "Local broker uid owns policy; a malicious same-uid host process can alter it. Separate-user daemon provisioning and authenticated requests remain required.",
        "Output reports are unsigned; no independent trace, test semantics, SPIFFE principal, platform session or ALPS grade is asserted.",
        "Workspace edits are disposable and never exported; source symlinks/hardlinks/special files are intentionally unsupported.",
        "Image and Docker daemon are trusted administrator inputs; Docker socket is never granted to the worker.",
        "Network is entirely disabled; approved gateway egress and every upstream executable/file capability remain follow-on integration work.",
    ]
    output = Path(args.out).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(str(output), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
