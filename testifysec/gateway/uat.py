# jade:ring local
"""Exercise a real compiled gateway with local provider/OTLP collectors, no cloud calls."""
import argparse
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("gateway", timeout=10)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--go", default="go")
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    checks = []
    state = {"provider": [], "collector": [], "mode": "valid", "collect": False, "partial": False}

    class Fixture(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if self.path == "/v1/logs":
                state["collector"].append(json.loads(body))
                self.send_response(200 if state["collect"] else 503)
                self.end_headers()
                self.wfile.write(b'{"partialSuccess":{"rejectedLogRecords":"1"}}' if state["partial"] else b"{}")
                return
            state["provider"].append({"body": json.loads(body), "headers": dict(self.headers)})
            mode = state["mode"]
            if mode == "hold":
                time.sleep(5)
            if mode == "redirect":
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/trap")
                self.end_headers()
                return
            self.send_response(401 if mode == "error" else 200)
            self.send_header("Set-Cookie", "provider-secret-cookie")
            self.end_headers()
            content = b'data: {"choices":[]}\n\ndata: [DONE]\n\n' if mode == "stream" else b'{"choices":[{"message":{"content":"fixture reply"}}]}'
            if mode == "truncated":
                content = b'data: {"choices":[]}\n\n'
            if mode == "error":
                content = b"secret-provider-error"
            try:
                self.wfile.write(content)
            except BrokenPipeError:
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    processes = []

    def check(name, condition):
        checks.append({"id": name, "passed": bool(condition)})
        if not condition:
            raise AssertionError(name)

    def until(predicate, timeout=6):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if predicate():
                return True
            time.sleep(0.025)
        return False

    with tempfile.TemporaryDirectory(prefix="hc-gateway-", dir="/private/tmp" if Path("/private/tmp").exists() else None) as temp:
        base = Path(temp)
        binary = base / "hardened-gateway"
        subprocess.run([args.go, "build", "-trimpath", "-o", str(binary), "."], cwd=root, check=True)
        log = (base / "service.log").open("wb")
        config = {
            "schema": "testifysec.hardened-opencode.gateway/v1", "socket": str(base / "gateway.sock"),
            "spool": str(base / "spool"), "providerURL": f"http://127.0.0.1:{server.server_port}/v1/chat/completions",
            "providerTokenFile": str(base / "provider.token"), "collectorURL": f"http://127.0.0.1:{server.server_port}/v1/logs",
            "collectorTokenFile": "", "model": "approved", "tenant": "fixture-tenant", "session": "fixture-session",
            "agent": "spiffe://fixture.test/tenant/fixture-tenant/agent/fixture-agent", "profileDigest": "a" * 64,
            "maxRecords": 16, "maxOfflineSeconds": 60, "timeoutSeconds": 10, "developmentLoopback": True,
        }
        spool = Path(config["spool"])
        spool.mkdir(mode=0o700)
        token = Path(config["providerTokenFile"])
        token.write_text("synthetic-provider-credential")
        token.chmod(0o600)
        config_path = base / "config.json"

        def start(custom=None):
            config_path.write_text(json.dumps(custom or config))
            config_path.chmod(0o600)
            proc = subprocess.Popen([str(binary), "--config", str(config_path)], stdout=log, stderr=log, env={"PATH": "/usr/bin:/bin"})
            processes.append(proc)
            if not until(lambda: proc.poll() is not None or Path(config["socket"]).exists()):
                raise AssertionError("startup timeout")
            return proc

        def stop(proc, crash=False):
            if proc.poll() is None:
                proc.kill() if crash else proc.terminate()
                proc.wait(timeout=8)
            Path(config["socket"]).unlink(missing_ok=True)

        def call(payload=None, path="/v1/chat/completions", headers=None):
            if payload is None:
                payload = {"model": "approved", "messages": [{"role": "user", "content": "synthetic-private-prompt"}]}
            body = json.dumps(payload).encode() if isinstance(payload, dict) else payload
            connection = UnixHTTP(config["socket"])
            connection.request("POST", path, body, {"Content-Type": "application/json", **(headers or {})})
            response = connection.getresponse()
            result = response.status, response.read(), dict(response.headers)
            connection.close()
            return result

        try:
            proc = start()
            check("native-startup", proc.poll() is None)
            status, data, headers = call(headers={"Authorization": "Bearer hostile-worker-token", "X-Agent-ID": "forged", "X-Provider-URL": "http://trap"})
            check("approved-provider-call", status == 200 and b"fixture reply" in data)
            forwarded = state["provider"][-1]["headers"]
            check("credential-and-header-isolation", forwarded.get("Authorization") == "Bearer synthetic-provider-credential" and "X-Agent-ID" not in forwarded and "X-Provider-URL" not in forwarded and "Set-Cookie" not in headers)
            before = len(state["provider"])
            for name, payload, path, expected in [
                ("wrong-model", {"model": "evil", "messages": [{}]}, "/v1/chat/completions", 403),
                ("duplicate-model", b'{"model":"evil","model":"approved","messages":[{}]}', "/v1/chat/completions", 400),
                ("escaped-duplicate", b'{"model":"evil","mo\\u0064el":"approved","messages":[{}]}', "/v1/chat/completions", 400),
                ("case-alias", {"model": "approved", "Model": "evil", "messages": [{}]}, "/v1/chat/completions", 400),
                ("unknown-provider-option", {"model": "approved", "baseURL": "http://trap", "messages": [{}]}, "/v1/chat/completions", 400),
                ("destination-query", None, "/v1/chat/completions?target=http://trap", 400),
                ("unsupported-api", None, "/v1/files", 400),
                ("request-size", b"x" * (1024 * 1024 + 1), "/v1/chat/completions", 413),
            ]:
                check(name, call(payload, path)[0] == expected)
            check("denials-never-forwarded", len(state["provider"]) == before)
            state["mode"] = "redirect"
            check("redirect-refused", call()[0] == 502 and len(state["provider"]) == before + 1)
            state["mode"] = "error"
            status, data, _ = call()
            check("provider-error-redacted", status == 502 and b"secret-provider-error" not in data)
            state["mode"] = "stream"
            check("stream-completes", b"[DONE]" in call({"model": "approved", "messages": [{}], "stream": True})[1])
            state["mode"] = "valid"
            for _ in range(4):
                check("bounded-outage-continues-" + str(_), call()[0] == 200)
            before = len(state["provider"])
            check("audit-capacity-fails-before-side-effect", call()[0] == 503 and len(state["provider"]) == before)
            records = [json.loads(p.read_text()) for p in spool.glob("*.json")]
            check("durable-terminal-records", len(records) == 16 and all(r["outcome"] != "started" for r in records))
            check("denied-requests-audited", sum(r["outcome"] == "request-denied" for r in records) == 8)
            all_spool = "".join(p.read_text() for p in spool.glob("*.json"))
            check("audit-excludes-secrets-and-payloads", all(secret not in all_spool for secret in ["synthetic-provider-credential", "synthetic-private-prompt", "hostile-worker-token", "secret-provider-error"]))
            state["collect"], state["partial"] = True, True
            check("partial-otlp-refusal-retains-evidence", until(lambda: len(state["collector"]) > 0) and len(list(spool.glob("*.json"))) == 16)
            stop(proc)
            state["partial"] = False
            proc = start()
            check("restart-replays-durable-audit", until(lambda: len(list(spool.glob("*.json"))) == 0))
            exported = [record for batch in state["collector"] for resource in batch["resourceLogs"] for scope in resource["scopeLogs"] for record in scope["logRecords"]]
            attrs = [[{a["key"]: a["value"]["stringValue"]} for a in item["attributes"]] for item in exported]
            check("otlp-correlated-provisioned-identity", len(exported) >= 32 and all({"identity.source": "administrator-provisioned"} in a for a in attrs))
            state["collect"] = False
            state["mode"] = "truncated"
            try:
                call({"model": "approved", "messages": [{}], "stream": True})
                interrupted = False
            except (OSError, http.client.HTTPException):
                interrupted = True
            check("truncated-stream-aborts-and-is-audited", interrupted and until(lambda: any(json.loads(p.read_text())["outcome"] == "response-interrupted" for p in spool.glob("*.json"))))
            state["mode"] = "hold"
            caller_errors = []
            def pending():
                try:
                    call()
                except (OSError, http.client.HTTPException) as error:
                    caller_errors.append(type(error).__name__)
            request_thread = threading.Thread(target=pending, daemon=True)
            request_thread.start()
            check("start-persisted-before-provider-completes", until(lambda: any(json.loads(p.read_text())["outcome"] == "started" for p in spool.glob("*.json"))))
            stop(proc, crash=True)
            state["mode"] = "valid"
            before = len(state["provider"])
            proc = start()
            check("crash-recovered-without-replaying-model-call", any(json.loads(p.read_text())["outcome"] == "incomplete-after-restart" for p in spool.glob("*.json")) and len(state["provider"]) == before)
            stop(proc)
            wrong = dict(config, session="different-session")
            proc = start(wrong)
            check("cross-session-spool-refused", proc.wait(timeout=5) != 0)
            stop(proc)
            config["maxOfflineSeconds"] = 1
            time.sleep(1.05)
            proc = start()
            before = len(state["provider"])
            check("offline-age-bound", call()[0] == 503 and len(state["provider"]) == before)
            stop(proc)
            wrong = dict(config, developmentLoopback=False)
            proc = start(wrong)
            check("production-cleartext-refused", proc.wait(timeout=5) != 0)
            stop(proc)
        finally:
            for proc in processes:
                stop(proc)
            server.shutdown()
            log.close()
            try:
                revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
                dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=root, text=True))
            except subprocess.CalledProcessError:
                revision, dirty = "unknown", True
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps({
                "schema": "testifysec.hardened-opencode.gateway-uat/v1", "revision": revision,
                "worktreeDirty": dirty, "binarySha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "sourceFiles": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.glob("*")) if p.suffix in (".go", ".py")},
                "assertions": checks, "providerRequests": len(state["provider"]),
                "scope": "local native gateway, synthetic provider and OTLP collector; provisioned identity only",
                "releaseQualified": False,
            }, indent=2) + "\n")
        print(f"gateway UAT: {len(checks)} passed")


if __name__ == "__main__":
    main()
