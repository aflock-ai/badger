#!/usr/bin/env python3
# jade:ring local
"""Build/probe UAT, never VM execution UAT. Python/Go are build tools only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone

SOURCE = Path(__file__).resolve().parent
TARGETS = [
    ("darwin", "arm64"), ("darwin", "amd64"),
    ("linux", "arm64"), ("linux", "amd64"), ("windows", "amd64"),
]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources():
    return sorted(path for path in SOURCE.rglob("*") if path.is_file()
                  and (path.suffix in (".go", ".m", ".md", ".py") or path.name == "go.mod")
                  and "__pycache__" not in path.parts)


def snapshot():
    return {str(path.relative_to(SOURCE)): digest(path) for path in sources()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path,
                        help="new directory for local build/test artifacts")
    args = parser.parse_args()
    compiler = args.go.resolve(strict=True)
    output = args.output_directory.absolute()
    output.mkdir(mode=0o700)  # Never overwrite a previous run or follow its final symlink.
    build_tmp = output / "build-tmp"
    build_tmp.mkdir(mode=0o700)
    before = snapshot()
    report = {"schema": "testifysec.hardened-opencode.execution-uat/v1",
              "startedAt": datetime.now(timezone.utc).isoformat(),
              "status": "running", "sourceFiles": before,
              "compiler": {"path": str(compiler), "sha256": digest(compiler)},
              "host": {"system": platform.system(), "machine": platform.machine(),
                       "release": platform.release()},
              "builds": [], "checks": [], "backendRuntimeTested": False,
              "qualification": "not-qualified", "hardwareAttestation": False,
              "scope": "local-native-probe-and-negative-UAT;cross-builds-are-unrun"}
    env = {"PATH": str(compiler.parent) + ":/usr/bin:/bin:/usr/sbin:/sbin",
           "HOME": os.environ.get("HOME", ""), "GOTOOLCHAIN": "local", "GOWORK": "off",
           "GOPROXY": "off", "GOSUMDB": "off", "GOFLAGS": "", "GOMAXPROCS": "4", "TMPDIR": str(build_tmp),
           "GOCACHE": str(Path(os.environ.get("GOCACHE", output / "gocache")).absolute())}
    # Build inputs are private copied bytes, not mutable shared worktree paths.
    with tempfile.TemporaryDirectory(prefix="execution-source-", dir=output) as temporary:
        staged = Path(temporary)
        for name, expected in before.items():
            destination = staged / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(SOURCE / name, destination)
            if digest(destination) != expected:
                raise RuntimeError("source changed while staging: " + name)

        def command(arguments, name, environment=env, expected=0):
            result = subprocess.run(arguments, cwd=staged, env=environment, capture_output=True,
                                    timeout=240, check=False)
            log = output / (name + ".log")
            log.write_bytes(result.stdout + b"\n--- STDERR ---\n" + result.stderr)
            report["checks"].append({"name": name, "exitCode": result.returncode,
                                     "expectedExitCode": expected, "log": log.name,
                                     "logSha256": digest(log)})
            if result.returncode != expected:
                raise RuntimeError("UAT failed: " + name + "; inspect " + str(log))
            return result

        try:
            compiler_env = json.loads(command([str(compiler), "env", "-json", "GOHOSTOS", "GOHOSTARCH", "GOVERSION"], "toolchain").stdout)
            report["compiler"].update(compiler_env)
            local = (compiler_env["GOHOSTOS"], compiler_env["GOHOSTARCH"])
            native_env = dict(env, CGO_ENABLED="1" if local[0] == "darwin" else "0",
                              GOOS=local[0], GOARCH=local[1])
            native_tests = command([str(compiler), "test", "-mod=readonly", "-p", "2", "-count=1", "-json", "./..."],
                                   "native-tests", native_env)
            events = [json.loads(line) for line in native_tests.stdout.splitlines() if line]
            report["nativeTestPasses"] = sum(event.get("Action") == "pass" and "Test" in event for event in events)
            suffix = ".exe" if local[0] == "windows" else ""
            native = output / ("hardened-execution-native" + suffix)
            command([str(compiler), "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", str(native), "./cmd/hardened-execution"],
                    "native-build", native_env)
            native_digest = digest(native)
            report["builds"].append({"target": "/".join(local), "variant": "native-framework" if local[0] == "darwin" else "stdlib",
                                     "path": native.name, "sha256": native_digest, "probeExecuted": True,
                                     "vmExecuted": False})
            # Customer-facing probe has no helper search path, stdin or ambient
            # runtime settings. No shell, codesign, Docker or runtime is invoked.
            runtime_env = {"PATH": "/nonexistent"} if local[0] != "windows" else {}
            inspected = command([str(native), "inspect"], "native-inspect", runtime_env)
            observed = json.loads(inspected.stdout)
            if observed["executionAllowed"] is not False or observed["target"]["qualification"] != "not-qualified":
                raise RuntimeError("native probe authorized execution")
            report["nativeObservation"] = observed
            command([str(native), "preflight"], "native-refusal", runtime_env, 3)
            matrix = json.loads(command([str(native), "matrix"], "matrix", runtime_env).stdout)
            actual_targets = [(item["os"], item["arch"]) for item in matrix["proposedTargets"]]
            if actual_targets != TARGETS:
                raise RuntimeError("target matrix drift")
            for name, argv in [("no-launch", ["execute"]), ("no-host-command", ["/bin/sh"]),
                               ("no-force", ["preflight", "--force"]),
                               ("no-docker-fallback", ["preflight", "--backend=docker"]),
                               ("no-remote-fallback", ["preflight", "--backend=remote"])]:
                command([str(native)] + argv, name, runtime_env, 2)
            injected = dict(runtime_env, HARDENED_EXECUTION_BACKEND="unconfined", HARDENED_EXECUTION_FORCE="1",
                            BUN_OPTIONS="--preload=/not-present.js", NODE_OPTIONS="--require=/not-present.js")
            refused = json.loads(command([str(native), "preflight"], "no-ambient-override", injected, 3).stdout)
            if refused["executionAllowed"] is not False:
                raise RuntimeError("environment bypassed refusal")
            if digest(native) != native_digest:
                raise RuntimeError("native executable pathname changed during UAT")
            # These are compile checks only. No cross-built binary is executed.
            for goos, arch in TARGETS + [("windows", "arm64")]:
                cross = dict(env, CGO_ENABLED="0", GOOS=goos, GOARCH=arch)
                filename = "hardened-execution-" + goos + "-" + arch + (".exe" if goos == "windows" else "")
                binary = output / filename
                command([str(compiler), "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", str(binary), "./cmd/hardened-execution"],
                        "build-" + goos + "-" + arch, cross)
                command([str(compiler), "test", "-mod=readonly", "-c", "-o", str(output / (filename + ".test")), "."],
                        "compile-tests-" + goos + "-" + arch, cross)
                report["builds"].append({"target": goos + "/" + arch, "variant": "stdlib",
                                         "proposedTarget": (goos, arch) in TARGETS,
                                         "path": filename, "sha256": digest(binary),
                                         "probeExecuted": False, "vmExecuted": False})
            if local[0] == "darwin":
                command([str(compiler), "test", "-mod=readonly", "-p", "2", "-count=1", "-json", "./..."],
                        "native-nocgo-tests", dict(native_env, CGO_ENABLED="0"))
            if snapshot() != before:
                raise RuntimeError("source changed during UAT; report is not attributable")
            report["status"] = "passed"
        except Exception:
            report["status"] = "failed"
            raise
        finally:
            report["finishedAt"] = datetime.now(timezone.utc).isoformat()
            (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "report": str(output / "report.json"),
                      "sha256": digest(output / "report.json")}, indent=2))


if __name__ == "__main__":
    main()
