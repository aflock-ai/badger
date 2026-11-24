# jade:ring local
"""Actual one-executable custody/launch UAT; target builds are labeled separately."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import tempfile
import uuid

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
MARKER = b"PACKAGING_EXACT_BYTES\x00\xff"
FIXTURE = r'''package main
import("encoding/json";"fmt";"io";"os";"time")
func main(){
 input,_:=io.ReadAll(os.Stdin); data,err:=os.ReadFile("data.bin"); if err!=nil{os.Exit(80)}
 cwd,_:=os.Getwd(); info,_:=os.Stat(cwd)
 json.NewEncoder(os.Stdout).Encode(map[string]any{"cwd":cwd,"data":data,"mode":uint32(info.Mode().Perm()),"args":os.Args[1:],"env":os.Environ()})
 if string(input)=="sleep"{fmt.Fprintln(os.Stdout,"READY");time.Sleep(60*time.Second)}
 if string(input)=="exit7"{os.Exit(7)}
}'''


def digest(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def command(argv, **kwargs):
    return subprocess.run(argv, capture_output=True, timeout=240, **kwargs)


def required(argv, **kwargs):
    result = command(argv, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{argv[0]} failed: {result.stderr.decode(errors='replace')[-3000:]}")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--go", required=True)
    parser.add_argument("--native-bundle", required=True, type=Path)
    parser.add_argument("--image", required=True, help="Already cached immutable Linux image ID")
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    host_os = {"Darwin": "darwin", "Linux": "linux"}.get(platform.system())
    host_arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64"}.get(platform.machine())
    if not host_os or not host_arch:
        raise SystemExit("This UAT driver currently requires a native macOS/Linux host")
    image = json.loads(required([args.docker, "image", "inspect", args.image]).stdout)[0]
    if image["Id"] != args.image or image["Os"] != "linux" or image["Architecture"] not in ("arm64", "amd64"):
        raise SystemExit("An exact cached Linux image ID and supported architecture are required")
    env = {**os.environ, "GOTOOLCHAIN": "local", "GOWORK": "off", "GOPROXY": "off", "GOSUMDB": "off", "CGO_ENABLED": "0"}
    source_files = {str(path.relative_to(REPO)): digest(path) for path in HERE.rglob("*") if path.is_file() and "__pycache__" not in path.parts}
    product = json.loads((HERE.parent / "branding/product.json").read_text())["name"].encode()
    report = {"story": "Single-executable payload packaging", "timestamp": datetime.now(timezone.utc).isoformat(),
              "revision": required(["git", "rev-parse", "HEAD"], cwd=REPO).stdout.decode().strip(),
              "worktreeDirty": bool(required(["git", "status", "--porcelain"], cwd=REPO).stdout),
              "sourceFiles": source_files, "checks": [], "targets": {}, "image": args.image,
              "releaseQualified": False,
              "limitations": ["Packaging only; complete automatic sandbox/backend provisioning is not implemented.",
                              "Current real managed host still requires its protected broker/gateway; existing worker backend requires a Linux engine.",
                              "Windows targets are compiled only; ACL, process/job, DLL and lifecycle controls need actual Windows UAT.",
                              "Private extraction does not isolate the launching account, administrator or kernel; no ALPS/FIPS/IL6 claim.",
                              "Docker is used only as this Linux UAT runner; no public image pull or model request occurs."]}

    def check(name, passed, **details):
        report["checks"].append({"id": name, "passed": bool(passed), **details})

    def build(source, entry, target, output):
        required(["python3", str(HERE / "build.py"), "--go", args.go, "--input", str(source), "--entry", entry,
                  "--target", target, "--output", str(output)], env=env)
        return json.loads(Path(str(output) + ".manifest.json").read_text())

    def linux_run(binary, executable_tmp=True):
        name = "hc-package-" + uuid.uuid4().hex[:16]
        argv = [args.docker, "run", "--rm", "--pull", "never", "--name", name, "-i", "--network", "none",
                "--user", "65534:65534", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--log-driver", "none", "--pids-limit", "64", "--memory", "512m", "--cpus", "1",
                "--tmpfs", "/tmp:rw,"+("exec" if executable_tmp else "noexec")+",nosuid,nodev,size=134217728,mode=1777",
                "--mount", f"type=bind,src={binary},dst=/product,readonly", "--entrypoint", "/product", args.image]
        try:
            return command(argv, input=b"normal")
        finally:
            command([args.docker, "rm", "--force", name])

    try:
        with tempfile.TemporaryDirectory(prefix="hc-package-uat-") as directory:
            temp = Path(directory)
            source = temp / "fixture.go"
            source.write_text(FIXTURE)
            built = {}
            for system in ("darwin", "linux", "windows"):
                for arch in ("amd64", "arm64"):
                    target = system + "-" + arch
                    bundle = temp / target
                    bundle.mkdir()
                    entry = "fixture.exe" if system == "windows" else "fixture"
                    required([args.go, "build", "-p=2", "-trimpath", "-o", str(bundle / entry), str(source)],
                             env={**env, "GOOS": system, "GOARCH": arch})
                    (bundle / "data.bin").write_bytes(MARKER)
                    (bundle / "manifest.json").write_text(json.dumps({"files": {entry: digest(bundle / entry), "data.bin": digest(bundle / "data.bin")}}))
                    binary = temp / (target + (".exe" if system == "windows" else ".bin"))
                    manifest = build(bundle, entry, target, binary)
                    built[target] = binary
                    report["targets"][target] = {"compiled": True, "executed": False, "binarySha256": digest(binary),
                                                  "manifestSha256": manifest["manifestSha256"], "payloadSha256": manifest["manifest"]["payloadSha256"]}
                    check("compile-"+target, manifest["target"] == target and manifest["binarySha256"] == digest(binary))
                    shutil.rmtree(bundle)  # Runtime must not need its original input directory.
            native = built[host_os+"-"+host_arch]
            poison = {"PATH": "/nonexistent", "TMPDIR": "/not-present", "HOME": "/not-present",
                      "BUN_OPTIONS": "--preload /poison.ts", "NODE_OPTIONS": "--require /poison.js", "PROVIDER_KEY": "UAT_SENTINEL"}
            result = command([str(native)], input=b"normal", env=poison)
            observation = json.loads(result.stdout)
            import base64
            check("native-single-file-launch-without-input-bundle", result.returncode == 0
                  and base64.b64decode(observation["data"]) == MARKER and observation["args"] == []
                  and observation["mode"] == 0o700 and not Path(observation["cwd"]).exists(), observation=observation)
            check("native-environment-sanitized", len(observation["env"]) == 4
                  and not any("BUN_OPTIONS" in value or "NODE_OPTIONS" in value or "PROVIDER_KEY" in value for value in observation["env"]))
            report["targets"][host_os+"-"+host_arch]["executed"] = True
            for flag in ("--help", "--version"):
                result = command([str(native), flag], env=poison)
                check("packaged-"+flag, result.returncode == 0 and product in result.stdout, output=result.stdout.decode())
            for flags in (["run"], ["--preload", "evil"], ["--help", "--version"], ["--version=x"]):
                result = command([str(native), *flags], env=poison)
                check("refuse-"+"-".join(flags), result.returncode != 0 and not result.stdout)
            result = command([str(native)], input=b"exit7", env=poison)
            check("entry-exit-code-preserved", result.returncode == 7 and not Path(json.loads(result.stdout)["cwd"]).exists())
            process = subprocess.Popen([str(native)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=poison)
            process.stdin.write(b"sleep")
            process.stdin.close()
            observation = json.loads(process.stdout.readline())
            if process.stdout.readline() != b"READY\n":
                process.kill(); process.wait(); raise RuntimeError("signal fixture did not start")
            process.send_signal(signal.SIGTERM)
            process.wait(timeout=15)
            check("signal-stops-entry-and-removes-payload", process.returncode == 143 and not Path(observation["cwd"]).exists())
            linux = built["linux-"+image["Architecture"]]
            result = linux_run(linux)
            if result.returncode:
                raise RuntimeError("Linux packaged fixture failed: " + result.stderr.decode(errors="replace")[-2000:])
            observation = json.loads(result.stdout)
            check("linux-single-file-launch", result.returncode == 0 and observation["mode"] == 0o700
                  and base64.b64decode(observation["data"]) == MARKER and observation["args"] == [], observation=observation)
            report["targets"]["linux-"+image["Architecture"]]["executed"] = True
            result = linux_run(linux, False)
            check("linux-noexec-policy-refused-without-fallback", result.returncode == 2 and not result.stdout
                  and b"packaged runtime unavailable" in result.stderr)
            raw = linux.read_bytes()
            if raw.count(MARKER) != 1:
                raise RuntimeError("corruption fixture is not uniquely located")
            corrupt = temp / "corrupt-linux"
            corrupt.write_bytes(raw.replace(MARKER, b"X"+MARKER[1:]))
            corrupt.chmod(0o755)
            result = linux_run(corrupt)
            check("linux-corrupt-embedded-payload-refused", result.returncode == 2 and not result.stdout
                  and b"packaged runtime unavailable" in result.stderr)
            actual = temp / "actual-hardened-code"
            actual_manifest = build(args.native_bundle.resolve(), "hardened-code", host_os+"-"+host_arch, actual)
            result = command([str(actual)], input=b"{}", env=poison)
            actual_output = json.loads(result.stdout)
            check("actual-bundled-managed-host-runs", result.returncode == 1 and actual_output.get("status") == "unavailable"
                  and actual_output.get("schema") == "testifysec.hardened-opencode.run-result/v1")
            report["actualHostPackage"] = actual_manifest
            check("actual-host-no-qualification-claim", actual_manifest["runtimeVerified"] is False and actual_manifest["releaseQualified"] is False)
            test = required([args.go, "test", "-count=1", "-json", "./..."], cwd=HERE, env=env)
            events = [json.loads(line) for line in test.stdout.splitlines() if line.startswith(b"{")]
            passes = [item["Test"] for item in events if item.get("Action") == "pass" and item.get("Test")]
            check("native-materialization-negative-tests", bool(passes) and not any(item.get("Action") in ("fail", "skip") for item in events), cases=passes)
            lifecycle = ["normal", "exit7", "descendant", "cancel", "unobserved-exit", "kill-failure", "group-drain-failure", "group-permission-failure", "pipe-drain-failure"]
            check("native-observed-cleanup-fixtures", all("TestLaunchCleanupRequiresObservedLifecycle/" + name in passes for name in lifecycle),
                  cases=lifecycle, scope="Actual POSIX native fixtures; five lifecycle faults injected through test-only Go dependencies. Windows remains compile-only.")
    except Exception as error:
        report["error"] = str(error)
        check("harness-completed", False)
    check("sources-unchanged-during-uat", all(digest(REPO / name) == expected for name, expected in source_files.items()))
    report["passed"] = all(item["passed"] for item in report["checks"])
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps({"report": str(args.report), "passed": sum(item["passed"] for item in report["checks"]),
                      "checks": len(report["checks"]), "success": report["passed"]}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
