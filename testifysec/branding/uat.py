# jade:ring local
"""Exercise compiled branding, the native launcher boundary, and the real worker."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import uuid


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, **kwargs):
    return subprocess.run(command, capture_output=True, timeout=180, **kwargs)


def required(command, **kwargs):
    result = run(command, **kwargs)
    if result.returncode:
        raise RuntimeError(f"build/check failed: {command[0]}: {result.stderr.decode(errors='replace')[-4000:]}")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--go", required=True)
    parser.add_argument("--bun", required=True)
    parser.add_argument("--worker", required=True, type=Path, help="Freshly compiled fixture-model worker")
    parser.add_argument("--image", required=True, help="Already cached immutable Linux image ID")
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    repo = root.parent.parent
    product = json.loads((root / "product.json").read_text())
    version = (repo / "VERSION").read_text().strip()
    upstream = json.loads((repo / "packages/cli/package.json").read_text())["version"]
    worker_manifest = json.loads(Path(str(args.worker) + ".manifest.json").read_text())
    files = ["VERSION", "LICENSE", "packages/cli/src/brand.ts", "packages/cli/src/index.ts",
             "packages/server/src/managed.ts", "testifysec/native/wrap.py",
             "testifysec/native/launcher/main.go", "testifysec/runtime/build-host.py",
             "testifysec/runtime/build-worker.ts", "testifysec/runtime/worker.ts"]
    files += [str(path.relative_to(repo)) for path in root.iterdir() if path.is_file()]
    report = {"story": "Badger compiled branding", "timestamp": datetime.now(timezone.utc).isoformat(),
              "revision": required(["git", "rev-parse", "HEAD"], cwd=repo).stdout.decode().strip(),
              "worktreeDirty": bool(required(["git", "status", "--porcelain"], cwd=repo).stdout),
              "sourceFiles": {file: digest(repo / file) for file in sorted(files)},
              "product": product, "version": version, "upstreamVersion": upstream,
              "assertions": [], "artifacts": {}, "workerManifest": worker_manifest,
              "limitations": ["Branding is display metadata, not authentication, isolation, or qualification.",
                              "The worker uses a local scripted model; no live provider or paid API is exercised.",
                              "Internal executable names, package identifiers, protocol schemas and upstream licenses remain unchanged."]}

    def check(name, passed, **details):
        report["assertions"].append({"id": name, "passed": bool(passed), **details})

    environment = dict(os.environ, GOWORK="off", GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off", CGO_ENABLED="0")
    try:
        with tempfile.TemporaryDirectory(prefix="hardened-branding-uat-") as directory:
            temp = Path(directory)
            fixture = temp / "fixture.go"
            fixture.write_text('package main\nimport("encoding/json";"os")\nfunc main(){json.NewEncoder(os.Stdout).Encode(map[string]any{"runtimeStarted":true,"args":os.Args[1:],"env":os.Environ()})}\n')
            runtime = temp / "fixture-runtime"
            required([args.go, "build", "-o", str(runtime), str(fixture)], env=environment)
            launcher = temp / product["command"]
            internal = temp / "internal-verifier"
            for path, flags in ((launcher, ["--brand-product"]), (internal, [])):
                required(["python3", str(root.parent / "native/wrap.py"), "--go", args.go,
                          "--runtime", str(runtime), "--output", str(path), *flags], env=environment)
                report["artifacts"][path.name] = digest(path)
            poison = dict(environment, BUN_OPTIONS="--preload /not-present/poison.ts",
                          NODE_OPTIONS="--require /not-present/poison.js", HARDENED_BUILD="false",
                          PROVIDER_API_KEY="UAT_SENTINEL_NOT_A_CREDENTIAL")
            runtime.rename(temp / "runtime-absent")
            result = run([str(launcher), "--help"], env=poison)
            check("native-help-without-runtime", result.returncode == 0 and product["name"] in result.stdout.decode()
                  and f'Usage: {product["command"]} < request.json' in result.stdout.decode()
                  and product["attribution"] in result.stdout.decode(), output=result.stdout.decode())
            result = run([str(launcher), "--version"], env=poison)
            expected = f'{product["name"]} {version}\nOpenCode {upstream}\n{product["attribution"]}\n'
            check("native-version-without-runtime", result.returncode == 0 and result.stdout.decode() == expected,
                  output=result.stdout.decode())
            result = run([str(launcher)], input=b"{}", env=poison)
            check("missing-runtime-execution-refused", result.returncode != 0 and not result.stdout)
            (temp / "runtime-absent").rename(runtime)
            for flags in (["--help", "--version"], ["--help=anything"], ["--version=anything"], ["-h"], ["-v"],
                          ["run"], ["--preload", "poison.ts"], ["--help", "--preload", "poison.ts"]):
                result = run([str(launcher), *flags], env=poison)
                check("native-refuses-" + "-".join(flags), result.returncode != 0 and not result.stdout)
            for flag in ("--help", "--version"):
                result = run([str(internal), flag], env=poison)
                check("internal-verifier-refuses-" + flag, result.returncode != 0 and not result.stdout)
            result = run([str(launcher)], input=b"{}", env=poison)
            actual = json.loads(result.stdout)
            check("native-execution-sanitizes-environment", result.returncode == 0 and actual["runtimeStarted"]
                  and actual["args"] == [] and sorted(actual["env"]) == ["LANG=C", "PATH=/usr/bin:/bin", "TMPDIR=/tmp"])
            runtime.write_bytes(runtime.read_bytes() + b"changed")
            result = run([str(launcher)], input=b"{}", env=poison)
            check("changed-runtime-refused", result.returncode != 0 and not result.stdout)

            probes = {}
            for mode in ("true", "false", "unset"):
                binary = temp / ("branding-" + mode)
                command = [args.bun, str(root / "build-probe.ts"), str(binary), version, mode]
                required(command, cwd=root)
                result = required([str(binary)], env=dict(environment, HARDENED_BUILD="0" if mode == "true" else "1"))
                probes[mode] = json.loads(result.stdout)
                report["artifacts"][binary.name] = digest(binary)
            current = probes["true"]
            license = (repo / "LICENSE").read_text()
            check("compiled-hardened-command-and-version", current["enabled"] and current["name"] == product["name"]
                  and current["command"] == product["command"]
                  and current["description"] == f'{product["name"]} command line interface'
                  and current["version"] == f"{version} (OpenCode fixture-upstream)"
                  and current["about"] == f'{product["name"]} {version}\nOpenCode fixture-upstream\n{product["attribution"]}\n\n{license}',
                  observation={key: value for key, value in current.items() if key != "about"})
            # The managed profile is display-named by the product; its IDs and bundled route are fixed.
            check("compiled-provider-display-only", current["provider"] == product["providerName"]
                  and current["model"] == product["modelName"] and current["modelID"] == "managed/approved"
                  and current["providers"] == ["managed"] and current["package"] == "@opencode/ai/providers/openai-compatible")
            upstream_view = {key: probes["unset"][key] for key in ("enabled", "name", "command", "description", "version", "about")}
            check("upstream-branding-preserved", probes["false"] == probes["unset"] and upstream_view == {
                      "enabled": False, "name": "OpenCode", "command": "opencode",
                      "description": "OpenCode command line interface", "version": "fixture-upstream",
                      "about": f"fixture-upstream\n\n{license}"},
                  observation={key: value for key, value in upstream_view.items() if key != "about"})

            check("worker-manifest-matches-current-sources", digest(args.worker) == worker_manifest["binarySha256"]
                  and worker_manifest["fixtureModel"] is True and worker_manifest["product"] == {**product, "version": version}
                  and all(digest(root.parent.parent / file) == value for file, value in worker_manifest["sourceFiles"].items()))
            worker_report = temp / "worker.json"
            result = run(["python3", str(root.parent / "runtime/uat-worker.py"), "--worker", str(args.worker),
                          "--docker", args.docker, "--image", args.image, "--report", str(worker_report)])
            report["workerUAT"] = json.loads(worker_report.read_text())
            observations = report["workerUAT"]["assertions"]
            check("real-upstream-worker-write-test-and-refusals", result.returncode == 0
                  and len(observations) == 3 and all(item["passed"] for item in observations))
            starts = [event for item in observations for event in item.get("events", []) if event.get("type") == "managed_worker_start"]
            check("real-worker-reports-product", len(starts) == 1 and starts[0].get("product") == product["name"]
                  and starts[0].get("scope") == "untrusted-worker")
            for flag in ("--help", "--version", "--preload"):
                name = "hc-branding-" + uuid.uuid4().hex[:16]
                command = [args.docker, "run", "--rm", "--pull", "never", "--name", name,
                           "--network", "none", "--user", "65534:65534", "--read-only", "--cap-drop", "ALL",
                           "--security-opt", "no-new-privileges", "--pids-limit", "64", "--memory", "1g", "--cpus", "1",
                           "--log-driver", "none", "--workdir", "/workspace",
                           "--mount", f"type=bind,src={args.worker.resolve()},dst=/worker,readonly",
                           "--entrypoint", "/worker", args.image, flag]
                try:
                    result = run(command)
                finally:
                    run([args.docker, "rm", "--force", name])
                check("worker-refuses-" + flag, result.returncode != 0 and not result.stdout
                      and b"managed worker unavailable" in result.stderr)
    except Exception as error:
        report["error"] = str(error)
        check("harness-completed", False)
    check("source-hashes-still-match", all(digest(repo / file) == value for file, value in report["sourceFiles"].items()))
    report["passed"] = all(item["passed"] for item in report["assertions"])
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"report": str(args.report), "passed": sum(item["passed"] for item in report["assertions"]),
                      "checks": len(report["assertions"]), "success": report["passed"]}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
