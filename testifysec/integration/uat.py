# jade:ring local
"""Real native host/broker/OpenCode plus separate native gateway; local fixtures only."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid

parser = argparse.ArgumentParser()
parser.add_argument("--go", default="go")
parser.add_argument("--bun", default="bun")
parser.add_argument("--worker", type=Path, required=True, help="Production gateway-mode Linux worker, not fixture-mode")
parser.add_argument("--image", required=True, help="Cached immutable glibc Linux image ID")
parser.add_argument("--engine-socket", required=True)
parser.add_argument("--report", type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parent
checks = []
digest = lambda data: hashlib.sha256(data).hexdigest()
env = dict(os.environ, GOWORK="off", CGO_ENABLED="0")
linux = dict(env, GOOS="linux", GOARCH="arm64")
prefix = "hc-gateway-" + uuid.uuid4().hex[:12]
container = prefix + "-service"
volumes = [prefix + "-socket", prefix + "-state"]


def edit_test_completed(output):
    """The worker's own tool results, not its echoed inputs: the bash call's command text also contains the marker."""
    tools = []
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and event.get("type") == "tool_use":
            tools.append(event["part"])
    return (any(tool.get("tool") == "write" and tool["state"]["status"] == "completed" for tool in tools)
            and any(tool.get("tool") in ("bash", "shell") and tool["state"]["status"] == "completed"
                    and "HARNESS_TEST_PASSED" in tool["state"].get("output", "") for tool in tools))


def docker(*arguments, **kwargs):
    return subprocess.run(["docker", "--host", "unix://" + args.engine_socket, *arguments], capture_output=True, check=True, **kwargs)


def check(name, condition):
    checks.append({"id": name, "passed": bool(condition)})
    if not condition:
        raise AssertionError(name)


with tempfile.TemporaryDirectory(prefix="hc-gateway-journey-") as temporary:
    work = Path(temporary).resolve()
    for name in ("source", "toolpack", "tools", "fixture"):
        (work / name).mkdir(mode=0o700)
    # Directories mounted for a UID65534 worker may be traversed; none contains credentials.
    (work / "toolpack").chmod(0o755)
    (work / "tools").chmod(0o755)
    shutil.copy2(args.worker, work / "toolpack/opencode-worker")
    docker("image", "inspect", args.image)
    subprocess.run([args.go, "build", "-trimpath", "-o", str(work / "tools/hardened-gateway"), "."], cwd=root.parent / "gateway", env=linux, check=True)
    subprocess.run([args.go, "build", "-trimpath", "-o", str(work / "tools/fixture-services"), str(root / "fixture_services.go")], env=linux, check=True)
    subprocess.run([args.go, "run", str(root.parent / "managed/fixtures.go"), str(work / "profiles")], cwd=root.parent / "native", env=dict(os.environ, GOWORK="off"), check=True)
    broker_socket = work / "broker.sock"
    subprocess.run(["python3", str(root.parent / "runtime/build-host.py"), "--go", args.go, "--bun", args.bun,
                    "--trust", str(work / "profiles/trust.json"), "--broker-socket", str(broker_socket),
                    "--workspace", "integration-uat", "--output", str(work / "host")], check=True)
    subprocess.run([args.go, "build", "-trimpath", "-o", str(work / "broker"), "."], cwd=root.parent / "broker", env=env, check=True)
    profile = json.loads((work / "profiles/valid.json").read_text())
    profile_digest = digest(base64.b64decode(profile["payload"]))
    host_manifest = json.loads((work / "host/manifest.json").read_text())
    gateway_config = {
        "schema": "testifysec.hardened-opencode.gateway/v1", "socket": "/gateway/gateway.sock", "spool": "/private/spool",
        "providerURL": "http://127.0.0.1:8090/v1/chat/completions", "providerTokenFile": "/private/provider.token",
        "collectorURL": "http://127.0.0.1:8090/v1/logs", "collectorTokenFile": "", "model": "approved",
        "tenant": "fixture-tenant", "session": prefix, "agent": "spiffe://fixture.test/tenant/example/agent/example",
        "profileDigest": profile_digest, "maxRecords": 32, "maxOfflineSeconds": 60, "timeoutSeconds": 30,
        "developmentLoopback": True,
    }
    (work / "fixture/config.json").write_text(json.dumps(gateway_config))
    (work / "fixture/provider.token").write_text("synthetic-provider-credential")
    broker = None
    broker_log = (work / "broker.log").open("wb")
    observations = {}
    result = {}
    try:
        for volume in volumes:
            docker("volume", "create", "--label", "testifysec.uat=" + prefix, volume)
        docker("run", "--rm", "--network", "none", "--mount", f"type=volume,src={volumes[0]},dst=/gateway",
               "--mount", f"type=volume,src={volumes[1]},dst=/private", "--mount", f"type=bind,src={work / 'fixture'},dst=/inputs,readonly",
               "--entrypoint", "/bin/sh", args.image, "-c",
               "cp /inputs/config.json /inputs/provider.token /private/ && mkdir /private/spool && chown -R 65534:65534 /private /gateway && chmod 700 /private /private/spool /gateway && chmod 600 /private/config.json /private/provider.token")
        docker("run", "--detach", "--name", container, "--network", "none", "--read-only", "--user", "65534:65534",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "128m", "--pids-limit", "64",
               "--log-driver", "none", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
               "--mount", f"type=volume,src={volumes[0]},dst=/gateway", "--mount", f"type=volume,src={volumes[1]},dst=/private",
               "--mount", f"type=bind,src={work / 'tools'},dst=/tools,readonly", "--entrypoint", "/tools/fixture-services", args.image)
        ready = False
        for _ in range(100):
            ready = subprocess.run(["docker", "--host", "unix://" + args.engine_socket, "exec", container, "/bin/sh", "-c", "test -S /gateway/gateway.sock"], capture_output=True).returncode == 0
            if ready:
                break
            time.sleep(0.05)
        check("separate-native-gateway-ready", ready)
        policy = {
            "schema": "testifysec.hardened-opencode.broker-policy/v1", "listenSocket": str(broker_socket),
            "dockerSocket": args.engine_socket, "image": args.image, "workspace": {"id": "integration-uat", "source": str(work / "source")},
            "limits": {"timeoutSeconds": 60, "outputBytes": 1048576, "workspaceBytes": 1048576, "workspaceFiles": 100, "memoryMiB": 1024, "workspaceMiB": 256},
            "allowedUIDs": [os.getuid()], "developmentAllowSameUID": True, "toolpack": str(work / "toolpack"),
            "gatewayVolume": volumes[0], "admissionExecutable": str(work / "host/hardened-admission"),
            "admissionSha256": host_manifest["files"]["hardened-admission"], "profileSha256": profile_digest,
        }
        policy_file = work / "policy.json"
        policy_file.write_text(json.dumps(policy))
        policy_file.chmod(0o600)
        broker = subprocess.Popen([str(work / "broker"), "serve", "--config", str(policy_file)], stdout=broker_log, stderr=broker_log)
        for _ in range(100):
            if broker_socket.exists() or broker.poll() is not None:
                break
            time.sleep(0.05)
        check("native-broker-ready", broker_socket.exists())
        request = {"schema": "testifysec.hardened-opencode.run/v1", "profile": profile, "prompt": "Write result.txt and run its test."}
        call = subprocess.run([str(work / "host/hardened-code")], input=json.dumps(request).encode(), capture_output=True, timeout=85, cwd=work / "source", env={"PATH": "/nonexistent", "BUN_OPTIONS": "--preload /bad.js"})
        result = json.loads(call.stdout)
        execution = result.get("broker", {})
        check("upstream-edit-test-through-native-gateway", call.returncode == 0 and edit_test_completed(execution.get("output", "")))
        check("production-worker-path", '"fixtureModel":false' in execution.get("output", ""))
        for _ in range(60):
            docker("cp", container + ":/private/observations.json", str(work / "observations.json"))
            observations = json.loads((work / "observations.json").read_text())
            batches = observations.get("auditBatches") or []  # null until the first export arrives
            logs = [entry for batch in batches for resource in batch["resourceLogs"] for scope in resource["scopeLogs"] for entry in scope["logRecords"]]
            if len(logs) >= observations["providerRequests"] * 2:
                break
            time.sleep(0.1)
        check("all-model-requests-audited", observations["providerRequests"] >= 3 and len(logs) == observations["providerRequests"] * 2)
        check("provider-credential-held-by-gateway", all(observations["credentialIsolated"]))
        check("audit-profile-correlation", all({"key": "profile.sha256", "value": {"stringValue": profile_digest}} in event["attributes"] for event in logs))
        check("worker-cleanup-observed", execution.get("cleanup") is True)
    finally:
        if broker is not None:
            broker.terminate()
            broker.wait(timeout=8)
        broker_log.close()
        subprocess.run(["docker", "--host", "unix://" + args.engine_socket, "rm", "-f", container], capture_output=True)
        for volume in volumes:
            subprocess.run(["docker", "--host", "unix://" + args.engine_socket, "volume", "rm", volume], capture_output=True)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps({"story": "native-upstream-audited-gateway", "assertions": checks, "observations": observations,
            "result": result, "hostBuild": host_manifest, "workerSha256": digest(args.worker.read_bytes()),
            "gatewaySha256": digest((work / "tools/hardened-gateway").read_bytes()), "brokerSha256": digest((work / "broker").read_bytes()),
            "sourceHashes": {p.name: digest(p.read_bytes()) for p in root.iterdir() if p.is_file()},
            "limitations": ["Synthetic local model/collector; no cloud requests.", "Same-UID macOS host development; not managed Linux or ALPS qualification.", "Platform-authenticated session and reviewed persistent editing remain separate phases."]}, indent=2) + "\n")
    print(f"native audited journey: {len(checks)} passed")
