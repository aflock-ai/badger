# jade:ring local
"""Build native client and exercise the real platform session HTTP handler offline."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--gateway", action="store_true", help="Also exercise the compiled model gateway against the real platform handler")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    monorepo = root.parents[3]
    if not (monorepo / "judge-api/cmd/server/cmd/handlers_agent_session.go").is_file():
        # Parked: the platform handler this exercised is not available to this repository. The client is
        # covered by client_test.go and the synthetic cmd/session-platform-fixture; see README.md.
        raise SystemExit("platform UAT parked: the agent-session handler is not available; see testifysec/platform/README.md")
    report = {"schema": "testifysec.hardened-opencode.platform-uat/v1", "passed": False,
              "scope": "native client plus real platform HTTP handler and synthetic ent/SQLite enrollment",
              "releaseQualified": False, "tests": [], "startedUnix": int(time.time())}
    environment = dict(os.environ, GOWORK="off", GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off", GOMAXPROCS="4")
    source_paths = list(root.rglob("*.go")) + [root / "go.mod", Path(__file__).resolve()]
    source_paths += [monorepo / "judge-api/cmd/server/cmd" / name for name in
                     ("handlers_agent_session.go", "handlers_agent_session_test.go", "handlers_agent_exchange.go", "routes.go")]
    if args.gateway:
        source_paths += list((root.parent / "gateway").glob("*.go")) + [root.parent / "gateway/go.mod"]
        report["scope"] += "; compiled model gateway, synthetic provider and collector"
    report["sourceFiles"] = {str(p.relative_to(monorepo)): hashlib.sha256(p.read_bytes()).hexdigest()
                             for p in sorted(source_paths)}
    report["revision"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    report["worktreeDirty"] = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=root, text=True))

    def run_tests(cwd, selection=()):
        process = subprocess.run([args.go, "test", "-p", "2", "-count=1", "-timeout=8m", "-json", *selection],
                                 cwd=cwd, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in process.stdout.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("Action") in ("pass", "fail", "skip") and event.get("Test"):
                report["tests"].append({"id": event["Test"], "status": event["Action"],
                                        "package": event.get("Package")})
        if process.returncode:
            raise RuntimeError("Go tests failed: " + process.stderr[-4000:] + process.stdout[-8000:])

    try:
        with tempfile.TemporaryDirectory(prefix="hc-platform-uat-") as temporary:
            binary = Path(temporary) / "hardened-session-check"
            subprocess.run([args.go, "build", "-p", "2", "-trimpath", "-o", str(binary), "./cmd/hardened-session-check"],
                           cwd=root, env=dict(environment, CGO_ENABLED="0"), check=True)
            report["clientSha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
            run_tests(root, ("./...",))
            environment["HC_PLATFORM_CLIENT"] = str(binary)
            selection = "^TestAgentSession"
            if args.gateway:
                gateway = Path(temporary) / "hardened-gateway"
                subprocess.run([args.go, "build", "-p", "2", "-trimpath", "-o", str(gateway), "."],
                               cwd=root.parent / "gateway", env=dict(environment, CGO_ENABLED="0"), check=True)
                report["gatewaySha256"] = hashlib.sha256(gateway.read_bytes()).hexdigest()
                environment["HC_PLATFORM_GATEWAY"] = str(gateway)
                run_tests(root.parent / "gateway", ("-run", "^TestGatewayPlatform", "."))
                selection = "^(TestAgentSession|TestPlatformGatewayNativeUAT)"
            run_tests(monorepo / "judge-api", ("-run", selection, "./cmd/server/cmd"))
            if not any(t["id"] == "TestAgentSessionNativeClientUAT" and t["status"] == "pass" for t in report["tests"]):
                raise RuntimeError("real platform handler/native client UAT did not run")
            if args.gateway and not any(t["id"] == "TestPlatformGatewayNativeUAT" and t["status"] == "pass" for t in report["tests"]):
                raise RuntimeError("real platform handler/native gateway integration did not run")
            if any(t["status"] != "pass" for t in report["tests"]):
                raise RuntimeError("test failed or was skipped")
            if report["sourceFiles"] != {str(p.relative_to(monorepo)): hashlib.sha256(p.read_bytes()).hexdigest()
                                         for p in sorted(source_paths)}:
                raise RuntimeError("selected source files changed while building or testing")
            report["passed"] = True
    except (OSError, subprocess.SubprocessError, RuntimeError) as error:
        report["failure"] = str(error)
    finally:
        report["limitations"] = [
            "Synthetic enrolled principals and TLS roots; no live credentials or production mutations.",
            "Checks authenticate possession of the existing agent refresh bearer; no hardware proof or mTLS SVID.",
            "Historical enrollment AAL and human delegation reference are not current human presence.",
            "Identity and enrollment scope grant no model, tool, signing, upload or activation authority.",
            "A live check is a point-in-time observation, not a revocation-proof lease or offline authorization.",
            "Source hashes cover the selected adapter, gateway and handler files, not the full transitive monorepo build closure.",
        ]
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "tests": len(report["tests"]), "report": str(args.report)}))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
