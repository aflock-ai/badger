# jade:ring local
"""Offline Linux build and separate-UID native host/broker/gateway UAT."""
import argparse
import base64
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid


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


def sha(data):
    return hashlib.sha256(data).hexdigest()


# build-host.py and native/wrap.py also read the product branding, VERSION and the CLI's upstream version.
BUILD_SOURCE_FILES = ["testifysec/branding/product.json", "VERSION", "packages/cli/package.json"]
BUILD_SOURCE_DIRECTORIES = ["testifysec/" + d for d in ("native", "managed", "runtime", "broker", "gateway", "platform")]


def bound_audit_complete(observations):
    """Whether every provider call the fixture bound has both its start and terminal audit events. Events for
    requests that never reached the provider (a busy refusal, say) do not count toward it."""
    seen = set()
    for batch in observations["auditBatches"]:
        for entry in (e for resource in batch["resourceLogs"] for scope in resource["scopeLogs"] for e in scope["logRecords"]):
            attributes = {a["key"]: a["value"]["stringValue"] for a in entry["attributes"]}
            seen.add((attributes["request.id"], attributes["event.id"].removeprefix(attributes["request.id"] + "/")))
    return all((request_id, phase) in seen for request_id in observations["requestIds"] for phase in ("start", "terminal"))


def copy_build_sources(repo, snapshot):
    """Copy the selected build sources into the snapshot and return their digests; any symlink is refused."""
    copied = {}
    for selected in (*BUILD_SOURCE_DIRECTORIES, *BUILD_SOURCE_FILES):
        root = repo / selected
        for p in ([root] if root.is_file() or root.is_symlink() else sorted(root.rglob("*"))):
            if any(part in (".cache", "dist", "node_modules", "__pycache__") for part in p.parts):
                continue
            if p.is_symlink():
                raise RuntimeError("build snapshot refuses source symlinks: " + str(p))
            if not p.is_file():
                continue
            relative = p.relative_to(repo)
            destination = snapshot / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            data = p.read_bytes()
            destination.write_bytes(data)
            copied[str(relative)] = sha(data)
    return copied


def write_json(path, value, mode=0o600):
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(mode)


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=100):
        super().__init__("local", timeout=timeout)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def local_request(path, method, target, body=None, timeout=100):
    connection = UnixConnection(path, timeout=timeout)
    try:
        connection.request(method, target, body=body, headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        raw = response.read(4 << 20)
        return response.status, json.loads(raw) if raw else None
    finally:
        connection.close()


def inside(config_path):
    c = json.loads(Path(config_path).read_text())
    work, source, shared = Path(c["work"]), Path(c["source"]), Path(c["shared"])
    code = source / "testifysec"
    evidence = Path("/evidence")
    report = {"schema": "testifysec.hardened-opencode.linux-uat/v1", "passed": False,
              "releaseQualified": False, "checks": [], "build": {}, "result": {},
              "boundaries": {"controllerOS": sys.platform, "brokerUID": 0, "callerUID": 65533,
                             "gatewayUID": 65534, "workerUID": 65534,
                             "gatewayProfileAdmission": "development-bypass; broker independently verifies signed profile",
                             "gatewayIdentitySource": "administrator-provisioned-development-fixture"}}
    processes, logs = [], []
    provider = None
    observations = {"providerRequests": 0, "requestIds": [], "credentialIsolated": [], "auditBatches": [],
                    "requestSeconds": [], "auditBatchSeconds": [], "providerCalls": []}
    observations_lock = threading.Lock()
    environment = dict(os.environ, GOWORK="off", GOTOOLCHAIN="local", GOMAXPROCS="4",
                       GOPROXY="file:///cached-modules/cache/download", GOSUMDB="off",
                       GOMODCACHE=str(work / "modules"), GOCACHE=str(work / "go-cache"), GOFLAGS="-p=2",
                       PATH="/usr/local/go/bin:/usr/bin:/bin", TMPDIR="/tmp")

    def check(name, condition):
        report["checks"].append({"id": name, "passed": bool(condition)})
        if not condition:
            raise RuntimeError(name)

    def run(arguments, cwd=None, **kwargs):
        return subprocess.run(arguments, cwd=cwd, env=environment, check=True, capture_output=True, timeout=600, **kwargs)

    def launch(arguments, name, user=0, group=0, env=None):
        log = (work / (name + ".log")).open("wb")
        logs.append(log)
        process = subprocess.Popen(arguments, stdout=log, stderr=log, cwd=work,
                                   env=env or {"PATH": "/usr/bin:/bin", "TMPDIR": str(shared / "scratch")},
                                   user=user, group=group, extra_groups=[])
        processes.append((name, process))
        return process

    def await_socket(path, process):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and process.poll() is None:
            if path.is_socket():
                return True
            time.sleep(0.02)
        return False

    try:
        check("linux-root-fixture", sys.platform == "linux" and os.getuid() == 0)
        work.chmod(0o755)
        for name in ("profiles", "host", "source", "gateway-private"):
            (work / name).mkdir(mode=0o700)
        for name in ("host", "source"):
            (work / name).chmod(0o755)
        (shared / "scratch").mkdir(mode=0o700)
        (shared / "toolpack").mkdir(mode=0o755)
        report["boundaries"]["sharedInputsLinuxUID"] = shared.stat().st_uid
        report["build"]["go"] = run(["go", "version"]).stdout.decode().strip()
        report["build"]["bun"] = run(["/tools/bun", "--version"]).stdout.decode().strip()
        report["build"]["gcc"] = run(["gcc", "-dumpfullversion"]).stdout.decode().strip()
        report["build"]["machine"] = os.uname().machine
        run(["go", "run", str(code / "managed/fixtures.go"), str(work / "profiles")], cwd=code / "native")
        broker_socket = work / "broker.sock"
        run(["python3", str(code / "runtime/build-host.py"), "--go", "/usr/local/go/bin/go", "--bun", "/tools/bun",
             "--trust", str(work / "profiles/trust.json"), "--broker-socket", str(broker_socket),
             "--workspace", "linux-uat", "--output", str(work / "host")])
        report["hostBuild"] = json.loads((work / "host/manifest.json").read_text())
        check("native-linux-rookery-and-bun-host-built", report["hostBuild"]["admissionBuild"]["platform"] == "linux" and
              "librookery.so" in report["hostBuild"]["files"])
        for name in ("broker", "gateway"):
            run(["go", "build", "-trimpath", "-o", str(work / ("hardened-" + name)), "."], cwd=code / name)
        shutil.copy2("/worker/opencode-worker", shared / "toolpack/opencode-worker")
        (work / "source/baseline.txt").write_bytes(b"unchanged baseline\n")
        (work / "source/poison.js").write_text('await Bun.write("/tmp/HOST_POISON", "bad"); throw new Error("autoload");')
        (work / "source/bunfig.toml").write_text('preload=["./poison.js"]\n')
        baseline = {p.name: sha(p.read_bytes()) for p in (work / "source").iterdir()}
        profile = json.loads((work / "profiles/valid.json").read_text())
        profile_digest = sha(base64.b64decode(profile["payload"], validate=True))
        private = work / "gateway-private"
        os.chown(private, 65534, 65534)
        (private / "spool").mkdir(mode=0o700)
        os.chown(private / "spool", 65534, 65534)
        gateway_root = Path("/gateway")
        gateway_root.chmod(0o700)
        os.chown(gateway_root, 65534, 65534)

        class Fixture(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if length > 2 << 20:
                    self.send_error(413)
                    return
                body = json.loads(self.rfile.read(length))
                started = []
                if self.path == "/v1/chat/completions":
                    # The gateway writes a durable start before its one-active-request check, so a request it is
                    # about to refuse as busy can briefly sit beside the one in flight. Wait for that start to
                    # finish, then bind this call to the single request still in flight.
                    settle = time.monotonic() + 2
                    while True:
                        started = [json.loads(p.read_text()) for p in (private / "spool").glob("*.json")]
                        started = [r for r in started if r.get("outcome") == "started" and r.get("profileDigest") == profile_digest and r.get("session") == c["name"]]
                        if len(started) == 1 or time.monotonic() > settle:
                            break
                        time.sleep(0.02)
                with observations_lock:
                    if self.path == "/v1/logs":
                        observations["auditBatches"].append(body)
                        observations["auditBatchSeconds"].append(time.monotonic())
                        data, content_type = b"{}", "application/json"
                    elif self.path == "/v1/chat/completions":
                        observations["providerRequests"] += 1
                        number = observations["providerRequests"]
                        # What each model call is for, so a refused one can be named: tools offered, tool results so far,
                        # and the start of its system prompt (a title request offers no tools).
                        system = next((m.get("content") for m in body.get("messages", []) if m.get("role") == "system"), "") or ""
                        observations["providerCalls"].append({"tools": len(body.get("tools", [])),
                                                              "toolResults": sum(m.get("role") == "tool" for m in body.get("messages", [])),
                                                              "system": (system if isinstance(system, str) else json.dumps(system))[:120]})
                        if len(started) != 1:
                            self.send_error(500, "provider request lacks one durable bound start")
                            return
                        observations["requestIds"].append(started[0]["id"])
                        observations["requestSeconds"].append(time.monotonic())
                        observations["credentialIsolated"].append(self.headers.get("Authorization") == "Bearer synthetic-linux-provider")
                        names = {t["function"]["name"] for t in body.get("tools", [])}
                        # OpenCode 2.0's write tool names its target `path`, 1.x's `filePath`: follow the advertised one.
                        target = "path" if any(t["function"]["name"] == "write" and "path" in t["function"].get("parameters", {}).get("properties", {})
                                               for t in body.get("tools", [])) else "filePath"
                        if body.get("model") != "approved" or names & {"task", "webfetch", "websearch", "lsp", "skill", "question"}:
                            self.send_error(400)
                            return
                        results = sum(m.get("role") == "tool" for m in body["messages"])
                        operation, arguments = "", {}
                        if results == 0 and "write" in names:
                            operation, arguments = "write", {target: "/workspace/result.txt", "content": "hardened-worker-verified\n"}
                        elif results == 1 and names & {"bash", "shell"}:
                            operation = "bash" if "bash" in names else "shell"
                            arguments = {"command": "test \"$(cat result.txt)\" = hardened-worker-verified && printf 'HARNESS_TEST_PASSED\\n'",
                                         "description": "Check generated file", "timeout": 10000}
                        if operation:
                            delta = {"role": "assistant", "tool_calls": [{"index": 0, "id": "call-" + str(number), "type": "function",
                                     "function": {"name": operation, "arguments": json.dumps(arguments)}}]}
                        else:
                            delta = {"role": "assistant", "content": "Managed file and test journey completed."}
                        chunks = [{"id": "fixture-" + str(number), "object": "chat.completion.chunk", "created": 1, "model": "approved",
                                   "choices": [{"index": 0, "delta": d, "finish_reason": f}]}
                                  for d, f in ((delta, None), ({}, "tool_calls" if operation else "stop"))]
                        data = b"".join(b"data: " + json.dumps(event).encode() + b"\n\n" for event in chunks) + b"data: [DONE]\n\n"
                        content_type = "text/event-stream"
                    else:
                        self.send_error(404)
                        return
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        provider = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
        threading.Thread(target=provider.serve_forever, daemon=True).start()
        endpoint = "http://127.0.0.1:" + str(provider.server_port)
        (private / "provider.token").write_text("synthetic-linux-provider")
        gateway_config = {"schema": "testifysec.hardened-opencode.gateway/v1", "socket": "/gateway/gateway.sock", "spool": str(private / "spool"),
                          "providerURL": endpoint + "/v1/chat/completions", "providerTokenFile": str(private / "provider.token"),
                          "collectorURL": endpoint + "/v1/logs", "collectorTokenFile": "", "model": "approved", "tenant": "synthetic-linux-tenant",
                          "session": c["name"], "agent": "spiffe://fixture.test/tenant/example/agent/example", "profileDigest": profile_digest,
                          "maxRecords": 32, "maxOfflineSeconds": 60, "timeoutSeconds": 30, "developmentLoopback": True}
        write_json(private / "config.json", gateway_config)
        for name in ("provider.token", "config.json"):
            (private / name).chmod(0o600)
            os.chown(private / name, 65534, 65534)
        gateway = launch([str(work / "hardened-gateway"), "--config", str(private / "config.json")], "gateway", 65534, 65534,
                         {"PATH": "/nonexistent", "TMPDIR": "/tmp"})
        check("separate-uid-native-gateway-ready", await_socket(gateway_root / "gateway.sock", gateway))
        policy = {"schema": "testifysec.hardened-opencode.broker-policy/v1", "listenSocket": str(broker_socket), "dockerSocket": "/engine.sock",
                  "image": c["workerImage"], "workspace": {"id": "linux-uat", "source": str(work / "source")},
                  "limits": {"timeoutSeconds": 60, "outputBytes": 1048576, "workspaceBytes": 1048576, "workspaceFiles": 100,
                             "memoryMiB": 1024, "workspaceMiB": 256}, "allowedUIDs": [65533], "developmentAllowSameUID": False,
                  "toolpack": str(shared / "toolpack"), "gatewayVolume": c["gatewayVolume"],
                  "admissionExecutable": str(work / "host/hardened-admission"),
                  "admissionSha256": report["hostBuild"]["files"]["hardened-admission"], "profileSha256": profile_digest}
        write_json(work / "policy.json", policy)
        broker = launch([str(work / "hardened-broker"), "serve", "--config", str(work / "policy.json")], "broker")
        check("linux-production-peer-gate-ready", await_socket(broker_socket, broker))
        status, denied = local_request(broker_socket, "POST", "/v1/execute", b"{}")
        check("unassigned-uid-zero-refused", status == 403 and denied.get("code") == "unauthorized_peer")
        for name in ("valid", "expired", "wrong-key", "duplicate-payload"):
            before = observations["providerRequests"]
            request = {"schema": "testifysec.hardened-opencode.run/v1", "profile": json.loads((work / "profiles" / (name + ".json")).read_text()),
                       "prompt": "Write result.txt and run its test."}
            call = subprocess.run([str(work / "host/hardened-code")], input=json.dumps(request).encode(), capture_output=True,
                                  cwd=work / "source", timeout=85, user=65533, group=65533, extra_groups=[],
                                  env={"PATH": "/nonexistent", "BUN_OPTIONS": "--preload /does-not-exist.js", "NODE_OPTIONS": "--require /does-not-exist.js"})
            output = json.loads(call.stdout)
            if name != "valid":
                check("native-profile-" + name + "-refused", call.returncode == 1 and output.get("status") == "unavailable" and
                      "broker" not in output and observations["providerRequests"] == before)
                continue
            report["result"] = output
            execution = output.get("broker", {})
            if call.returncode != 0:
                diagnostic = subprocess.run([str(work / "host/hardened-admission")], input=json.dumps(profile).encode(), capture_output=True,
                                            user=65533, group=65533, extra_groups=[], timeout=10, env={"PATH": "/nonexistent"})
                report["admissionDiagnostic"] = {"exitCode": diagnostic.returncode, "stdout": diagnostic.stdout.decode(errors="replace"),
                                                 "stderr": diagnostic.stderr.decode(errors="replace")}
                broker_request = {"schema": "testifysec.hardened-opencode.exec/v1", "workspace": "linux-uat", "command": "/toolpack/opencode-worker",
                                  "timeoutSeconds": 60, "profileEnvelope": json.dumps(profile),
                                  "stdin": json.dumps({"schema": "testifysec.hardened-opencode.prompt/v1", "prompt": request["prompt"], "profileDigest": profile_digest})}
                write_json(work / "diagnostic-request.json", broker_request, 0o644)
                diagnostic = subprocess.run([str(work / "hardened-broker"), "execute", "--socket", str(broker_socket), "--request", str(work / "diagnostic-request.json")],
                                            capture_output=True, user=65533, group=65533, extra_groups=[], timeout=85, env={"PATH": "/nonexistent"})
                report["brokerDiagnostic"] = {"exitCode": diagnostic.returncode, "stdout": diagnostic.stdout.decode(errors="replace"),
                                              "stderr": diagnostic.stderr.decode(errors="replace")}
            check("real-upstream-edit-test-via-linux-host-and-gateway", call.returncode == 0 and execution.get("status") == "completed" and
                  execution.get("exitCode") == 0 and edit_test_completed(execution.get("output", "")))
            check("linux-kernel-authenticated-distinct-caller", execution.get("callerUid") == 65533 and
                  execution.get("assurance") == "linux-kernel-peer-uid; not-assessed" and execution.get("cleanup") is True)
            check("production-gateway-worker-mode", '"fixtureModel":false' in execution.get("output", ""))
            artifact = execution.get("artifact", {})
            payload = base64.b64decode(artifact.get("payloadBase64", ""), validate=True)
            bundle = json.loads(payload)
            changes = {f["path"]: base64.b64decode(f["contentBase64"], validate=True) for f in bundle["changes"]}
            check("exact-edit-retained-after-worker-cleanup", sha(payload) == artifact.get("sha256") and
                  changes.get("result.txt") == b"hardened-worker-verified\n" and all(sha(changes[f["path"]]) == f["sha256"] for f in bundle["changes"]))
            compact = lambda value: json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
            final_files = {f["path"]: f for f in bundle["files"]}
            initial_files = {f["path"]: f for f in execution["materials"]}
            applied = dict(initial_files)
            for removed in bundle["removed"]:
                applied.pop(removed)
            for changed in bundle["changes"]:
                applied[changed["path"]] = {k: changed[k] for k in ("path", "sha256", "size", "executable")}
            check("artifact-manifests-and-diff-consistent", sha(compact(execution["materials"])) == execution["materialsSha256"] == bundle["materialsSha256"] == artifact["materialsSha256"] and
                  sha(compact(bundle["files"])) == bundle["finalManifestSha256"] == artifact["finalManifestSha256"] and applied == final_files and
                  len(changes) == len(bundle["changes"]) == artifact["changedFiles"] and len(bundle["removed"]) == artifact["removedFiles"] and
                  all(len(changes[f["path"]]) == f["size"] for f in bundle["changes"]))
        check("host-checkout-unchanged", baseline == {p.name: sha(p.read_bytes()) for p in (work / "source").iterdir()})
        check("ambient-bun-preload-did-not-execute", not Path("/tmp/HOST_POISON").exists())
        deadline = time.monotonic() + 8
        events = []
        while time.monotonic() < deadline:
            with observations_lock:
                events = [entry for batch in observations["auditBatches"] for resource in batch["resourceLogs"]
                          for scope in resource["scopeLogs"] for entry in scope["logRecords"]]
                count = observations["providerRequests"]
            if len(events) >= count * 2:
                break
            time.sleep(0.05)
        # Late and absent are different findings: keep the 8 s bar, but keep listening a while longer and
        # record, per provider call, when each audit event arrived, so a failure says which one it was.
        window_closed = time.monotonic()
        grace = window_closed + 30
        while time.monotonic() < grace:
            with observations_lock:
                if bound_audit_complete(observations):
                    break
            time.sleep(0.05)
        with observations_lock:
            arrivals = {}
            for batch, received in zip(observations["auditBatches"], observations["auditBatchSeconds"]):
                for entry in (e for resource in batch["resourceLogs"] for scope in resource["scopeLogs"] for e in scope["logRecords"]):
                    attributes = {a["key"]: a["value"]["stringValue"] for a in entry["attributes"]}
                    arrivals.setdefault((attributes["request.id"], attributes["event.id"].removeprefix(attributes["request.id"] + "/")),
                                        (received, entry["body"]["stringValue"]))
            calls = list(zip(observations["requestIds"], observations["requestSeconds"]))
        timing = []
        for request_id, called in calls:
            row = {"requestId": request_id}
            for phase in ("start", "terminal"):
                arrived = arrivals.get((request_id, phase))
                row[phase] = None if arrived is None else {"latencyMs": round((arrived[0] - called) * 1000),
                                                           "withinWindow": arrived[0] <= window_closed, "outcome": arrived[1]}
            timing.append(row)
        found = [row[phase] for row in timing for phase in ("start", "terminal") if row[phase] is not None]
        report["providerCalls"] = observations["providerCalls"]
        report["auditTiming"] = {"windowSeconds": 8, "graceSeconds": 30, "expected": 2 * len(timing),
                                 "withinWindow": sum(item["withinWindow"] for item in found),
                                 "late": sum(not item["withinWindow"] for item in found),
                                 "absent": 2 * len(timing) - len(found),
                                 "maxLatencyMs": max((item["latencyMs"] for item in found), default=None), "calls": timing,
                                 "unmatched": [{"requestId": key[0], "phase": key[1], "outcome": value[1]} for key, value in sorted(arrivals.items())
                                               if key[0] not in {request_id for request_id, _ in calls}]}
        # The managed build serializes its model calls, so the gateway never has to refuse one as busy.
        check("no-model-call-refused-as-busy", not any(item["outcome"] == "request-denied" for item in report["auditTiming"]["unmatched"]))
        expected_ids = observations["requestIds"]
        audited = {}
        for event in events:
            attributes = {a["key"]: a["value"]["stringValue"] for a in event["attributes"]}
            request_id = attributes["request.id"]
            phase = attributes["event.id"].removeprefix(request_id + "/")
            key = (request_id, phase)
            if key in audited or len(attributes) != len(event["attributes"]):
                raise RuntimeError("duplicate audit event or attribute")
            audited[key] = event["body"]["stringValue"]
        expected = {(request_id, phase): outcome for request_id in expected_ids
                    for phase, outcome in (("start", "started"), ("terminal", "provider-stream-ended"))}
        check("all-provider-calls-have-bound-start-and-terminal-audit", count >= 3 and len(expected_ids) == len(set(expected_ids)) == count and audited == expected)
        check("provider-credential-only-gateway", all(observations["credentialIsolated"]))
        check("audit-profile-binding", all({"key": "profile.sha256", "value": {"stringValue": profile_digest}} in event["attributes"] for event in events))
        denied_read = subprocess.run(["/bin/sh", "-c", 'test ! -r "$1" && test ! -r /engine.sock', "fixture", str(private / "provider.token")],
                                     user=65533, group=65533, extra_groups=[], capture_output=True)
        check("caller-cannot-read-gateway-secret-or-docker-socket", denied_read.returncode == 0)
        report["observations"] = observations
        report["policySha256"] = sha((work / "policy.json").read_bytes())
        report["passed"] = True
    except Exception as error:
        report["failure"] = type(error).__name__ + ": " + str(error)
        if isinstance(error, subprocess.CalledProcessError):
            report["failureOutput"] = (error.stderr or b"").decode(errors="replace")[-6000:]
    finally:
        for name, process in reversed(processes):
            try:
                process.terminate()
                exit_code = process.wait(timeout=40)
                report.setdefault("serviceExitCodes", {})[name] = exit_code
                if exit_code != 0:
                    report["passed"] = False
                    report["shutdownFailure"] = name + " exited unsuccessfully: " + str(exit_code)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                report["passed"] = False
                report["failure"] = name + " failed bounded service shutdown"
            except OSError as error:
                report["passed"] = False
                report["shutdownFailure"] = name + ": " + str(error)
        if provider:
            provider.shutdown()
            provider.server_close()
        for log in logs:
            log.close()
        for name in ("broker", "gateway"):
            path = work / (name + ".log")
            if path.exists():
                report[name + "Log"] = path.read_text(errors="replace")[-4000:]
        evidence.mkdir(exist_ok=True)
        report["binarySHA256"] = {}
        for path in [work / "hardened-broker", work / "hardened-gateway", *list((work / "host").glob("*"))]:
            if path.is_file():
                shutil.copy2(path, evidence / path.name)
                report["binarySHA256"][path.name] = sha(path.read_bytes())
        write_json(evidence / "inside-report.json", report, 0o644)
    return 0 if report["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inside", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--engine-socket", type=Path)
    parser.add_argument("--build-image")
    parser.add_argument("--image", help="Already cached immutable glibc Linux worker image ID")
    parser.add_argument("--bun", type=Path, help="Cached matching Linux Bun executable")
    parser.add_argument("--module-cache", type=Path, help="Cached Go module directory; read-only local file proxy")
    parser.add_argument("--worker", type=Path, help="Compiled production gateway-mode Linux upstream worker")
    parser.add_argument("--worker-manifest", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.inside:
        return inside(args.inside)
    required = ("engine_socket", "build_image", "image", "bun", "module_cache", "worker", "worker_manifest", "report")
    if any(getattr(args, name) is None for name in required):
        parser.error("all documented outer harness arguments are required")
    if not all(re.fullmatch(r"sha256:[0-9a-f]{64}", value) for value in (args.image, args.build_image)):
        parser.error("both images must be immutable cached sha256 IDs")
    root = Path(__file__).resolve().parent
    repo = root.parents[1]
    report_path = args.report.resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    evidence = report_path.with_suffix(".artifacts")
    if evidence.exists():
        raise SystemExit("refusing to overwrite existing artifact directory: " + str(evidence))
    evidence.mkdir(mode=0o700)
    report = {"schema": "testifysec.hardened-opencode.linux-uat/v1", "passed": False, "releaseQualified": False,
              "buildImage": args.build_image, "workerImage": args.image, "startedUnix": int(time.time()),
              "limitations": ["Docker Desktop Linux controller/worker fixture; not native-host installation or kernel qualification.",
                              "Go/Bun/C tooling is used only while building; shipped native components need none of those installations.",
                              "Synthetic locally signed profiles and scripted provider/collector; no production credentials or external API traffic.",
                              "Gateway uses explicit development loopback and provisioned attribution; authenticated platform sessions have separate HC04 evidence.",
                              "UID separation is observed inside the controller container; Docker daemon and controller root remain trusted.",
                              "Unsigned local build/UAT observations do not establish release authenticity, FIPS, IL6, ALPS or hardware attestation."]}
    name = "hc-linux-" + uuid.uuid4().hex[:12]
    volumes = [name + "-state", name + "-gateway"]
    created_volumes, container_attempted = [], False

    def docker(*arguments, check=True, **kwargs):
        return subprocess.run([args.docker, "--host", "unix://" + str(args.engine_socket.resolve()), *arguments],
                              capture_output=True, check=check, timeout=kwargs.pop("timeout", 30), **kwargs)

    def cleanup_resource(resource, volume=False):
        target = "/v1.47/volumes/" + resource if volume else "/v1.47/containers/" + resource + "/json"
        try:
            status, value = local_request(args.engine_socket, "GET", target, timeout=30)
            if status == 404:
                return {"resource": resource, "removed": True, "observedAbsent": True}
            if status != 200:
                raise RuntimeError("resource inspection failed: " + str(status))
            actual_name = value.get("Name") if volume else value.get("Name", "").removeprefix("/")
            labels = value.get("Labels", {}) if volume else value.get("Config", {}).get("Labels", {})
            if actual_name != resource or labels.get("testifysec.uat") != name:
                return {"resource": resource, "removed": False, "error": "ownership labels mismatch; not removed"}
            if volume:
                deletion = target
            else:
                if not re.fullmatch(r"[0-9a-f]{64}", value["Id"]):
                    raise RuntimeError("invalid owned container ID")
                deletion = "/v1.47/containers/" + value["Id"] + "?force=1&v=1"
            status, _ = local_request(args.engine_socket, "DELETE", deletion, timeout=30)
            if status not in (204, 404):
                raise RuntimeError("resource deletion failed: " + str(status))
            status, _ = local_request(args.engine_socket, "GET", target, timeout=30)
            absent = status == 404
            return {"resource": resource, "removed": absent, "observedAbsent": absent}
        except Exception as error:
            return {"resource": resource, "removed": False, "error": str(error)}

    try:
        for image_id in (args.build_image, args.image):
            docker("image", "inspect", image_id)
        manifest = json.loads(args.worker_manifest.read_text())
        report["workerManifest"] = manifest
        report["workerSHA256"] = sha(args.worker.read_bytes())
        if manifest.get("component") != "hardened-opencode-worker" or manifest.get("fixtureModel") is not False or \
                manifest.get("binarySha256") != report["workerSHA256"] or not str(manifest.get("target", "")).startswith("bun-linux-"):
            raise RuntimeError("worker manifest must bind the supplied production gateway-mode Linux binary")
        for source_name, expected in manifest.get("sourceFiles", {}).items():
            path = repo / source_name
            if Path(source_name).is_absolute() or ".." in Path(source_name).parts or path.is_symlink() or not path.is_file() or sha(path.read_bytes()) != expected:
                raise RuntimeError("worker source manifest does not match this checkout: " + source_name)
        report["bunSHA256"] = sha(args.bun.read_bytes())
        report["revision"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
        report["worktreeDirty"] = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=repo))
        snapshot = evidence / "source"
        # Rookery attestation is a published module; it comes from --module-cache, not from source.
        report["sourceFiles"] = copy_build_sources(repo, snapshot)
        # This isolated commit identifies copied source bytes; it is not a signed
        # repository commit or a claim that the checkout was clean.
        for command in (["init", "--quiet"], ["add", "."], ["-c", "user.name=Local Linux UAT", "-c", "user.email=uat@invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "commit", "--quiet", "-m", "Local selected-source build snapshot"]):
            subprocess.run(["git", *command], cwd=snapshot, check=True, capture_output=True)
        report["buildSnapshotRevision"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=snapshot, text=True).strip()
        report["buildSnapshotScope"] = "Unsigned isolated selected-source fixture commit; original repository revision and dirty state are separate fields"
        for volume in volumes:
            created_volumes.append(volume)
            docker("volume", "create", "--label", "testifysec.uat=" + name, volume)
        work = json.loads(docker("volume", "inspect", volumes[0]).stdout)[0]["Mountpoint"]
        if not work.startswith("/var/lib/docker/volumes/") or len(work + "/broker.sock") >= 104:
            raise RuntimeError("unsupported daemon volume path for protected Unix socket: " + work)
        shared = evidence / "shared-inputs"
        shared.mkdir(mode=0o700)
        configuration = {"name": name, "work": work, "source": "/source", "shared": str(shared), "workerImage": args.image, "gatewayVolume": volumes[1]}
        write_json(evidence / "input.json", configuration, 0o644)
        container_arguments = ["create", "--name", name, "--label", "testifysec.uat=" + name, "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL",
                               "--cap-add", "CHOWN", "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "DAC_OVERRIDE", "--cap-add", "KILL",
                               "--security-opt", "no-new-privileges", "--pids-limit", "256", "--memory", "3g", "--cpus", "4", "--log-driver", "none",
                               "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=1g,mode=1777",
                               "--mount", "type=volume,src=" + volumes[0] + ",dst=" + work,
                               "--mount", "type=volume,src=" + volumes[1] + ",dst=/gateway",
                               "--mount", "type=bind,src=" + str(snapshot) + ",dst=/source,readonly",
                               "--mount", "type=bind,src=" + str(evidence) + ",dst=/evidence",
                               "--mount", "type=bind,src=" + str(shared) + ",dst=" + str(shared),
                               "--mount", "type=bind,src=" + str(args.bun.resolve()) + ",dst=/tools/bun,readonly",
                               "--mount", "type=bind,src=" + str(args.module_cache.resolve()) + ",dst=/cached-modules,readonly",
                               "--mount", "type=bind,src=" + str(args.worker.resolve()) + ",dst=/worker/opencode-worker,readonly",
                               "--mount", "type=bind,src=" + str(args.engine_socket.resolve()) + ",dst=/engine.sock",
                               "--env", "GIT_CONFIG_COUNT=1", "--env", "GIT_CONFIG_KEY_0=safe.directory", "--env", "GIT_CONFIG_VALUE_0=/source",
                               "--entrypoint", "/usr/bin/python3", args.build_image,
                               "/source/testifysec/runtime/uat-linux.py", "--inside", "/evidence/input.json"]
        report["containerCommand"] = container_arguments
        container_attempted = True
        container_id = docker(*container_arguments).stdout.decode().strip()
        if not re.fullmatch(r"[0-9a-f]{64}", container_id):
            raise RuntimeError("invalid created fixture container ID")
        result = docker("start", "--attach", container_id, check=False, timeout=900)
        report["controllerExitCode"] = result.returncode
        report["controllerStderr"] = result.stderr.decode(errors="replace")[-4000:]
        if (evidence / "inside-report.json").exists():
            report["linux"] = json.loads((evidence / "inside-report.json").read_text())
        report["passed"] = result.returncode == 0 and report.get("linux", {}).get("passed") is True
        report["buildSnapshotUnchanged"] = all(sha((snapshot / source_name).read_bytes()) == expected for source_name, expected in copied.items())
        report["passed"] = report["passed"] and report["buildSnapshotUnchanged"]
        if not report["passed"]:
            report["failure"] = report.get("linux", {}).get("failure", "Linux controller did not produce a passing report")
    except Exception as error:
        report["failure"] = type(error).__name__ + ": " + str(error)
        if isinstance(error, subprocess.CalledProcessError):
            report["failureOutput"] = (error.stderr or b"").decode(errors="replace")[-6000:]
    finally:
        cleanup = []
        if container_attempted:
            cleanup.append(cleanup_resource(name))
        for volume in reversed(created_volumes):
            cleanup.append(cleanup_resource(volume, volume=True))
        report["fixtureCleanup"] = cleanup
        if any(not item["removed"] for item in cleanup):
            report["passed"] = False
            report["cleanupFailure"] = "Owned fixture resource removal failed; inspect listed names only"
        write_json(report_path, report, 0o644)
    print(json.dumps({"passed": report["passed"], "checks": len(report.get("linux", {}).get("checks", [])), "report": str(report_path)}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
