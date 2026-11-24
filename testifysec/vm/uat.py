#!/usr/bin/env python3
# jade:ring local
"""Actual local macOS VZ boot/run/stop UAT; never production admission."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time

SOURCE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--worker", type=Path, help="Optional compiled fixture-model Linux arm64 OpenCode worker")
    parser.add_argument("--image", help="Exact cached Debian image ID for the optional worker input extraction")
    args = parser.parse_args()
    if bool(args.worker) != bool(args.image):
        parser.error("--worker and --image must be supplied together")
    output = args.output.absolute()
    output.mkdir(mode=0o700)
    report = {"schema": "testifysec.vm-uat/v2", "status": "running", "cases": [], "checks": [],
              "scope": "actual VZ VM, static synthetic worker, local developer ad-hoc entitlement",
              "releaseQualified": False, "admissionIntegrated": False, "gatewayIntegrated": False}

    def check(name, condition):
        report["checks"].append({"name": name, "passed": bool(condition)})
        if not condition:
            raise RuntimeError("UAT failed: " + name)

    def build(target, mode="edit", reuse=None, worker_root=None):
        command = ["python3", "-B", str(SOURCE / "build.py"), "--go", str(args.go), "--output", str(target), "--mode", mode]
        if reuse:
            command += ["--reuse", str(reuse)]
            if not worker_root: command += ["--mke2fs", "/nonexistent/no-image-builder"]
        if worker_root:
            command += ["--worker-root", str(worker_root)]
        result = subprocess.run(command, capture_output=True, timeout=240)
        if result.returncode:
            raise RuntimeError("fixture build failed: " + result.stderr.decode(errors="replace"))

    def run_case(name, target, expected, configuration=None, terminate=False, memory=512, protocol_fault=False):
        config = target / "config.json"
        if configuration:
            value = json.loads(config.read_text()); value.update(configuration)
            config = target / "case-config.json"; config.write_text(json.dumps(value)); config.chmod(0o600)
        start = time.monotonic()
        host_binary = target / ("hc-vm-uat" if protocol_fault else "hc-vm")
        process = subprocess.Popen([str(host_binary), str(config)], env={"PATH": "/nonexistent"},
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            if terminate:
                time.sleep(0.5)
                process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=35)
        except BaseException:
            process.kill(); process.communicate(timeout=10); raise
        value = json.loads(stdout) if stdout else None
        record = {"name": name, "exitCode": process.returncode, "elapsedSeconds": time.monotonic() - start,
                  "hostSha256": digest(host_binary), "configSha256": digest(config),
                  "buildManifestSha256": digest(target / "manifest.json"),
                  "stdoutSha256": hashlib.sha256(stdout).hexdigest(), "stderrSha256": hashlib.sha256(stderr).hexdigest(),
                  "observation": value}
        report["cases"].append(record)
        check(name + "-exit", process.returncode == expected)
        if expected != 2:
            check(name + "-actual-start-and-stop", value["started"] is True and value["stopped"] is True)
            check(name + "-bounded-no-host-sharing", value["configuredCPUs"] == 1 and value["configuredMemoryMiB"] == memory
                  and value["networkDevices"] == 0 and value["sharedDirectories"] == 0 and value["writableHostDisks"] == 0
                  and value["serialBytes"] <= 262144 and value["jobPort"] == 17001 and value["jobConnections"] <= 1)
            check(name + "-job-admission-closed-and-transport-drained", value["jobAdmissionClosed"] is True
                  and value["jobTransportDrained"] is True)
        else:
            check(name + "-no-vm-observation", not stdout)
        if expected == 0:
            current = json.loads(config.read_bytes())
            check(name + "-full-job-binding", value["jobSent"] is True and value["jobConnections"] == 1
                  and value["guestResult"]["jobValidated"] is True
                  and value["guestResult"]["nonce"] == value["bootNonce"]
                  and value["guestResult"]["binding"] == current["binding"]
                  and value["guestResult"]["jobSha256"] == current["jobSha256"])
        return value

    try:
        base = output / "build"
        build(base)
        manifest = json.loads((base / "manifest.json").read_text())
        report["buildManifest"] = manifest
        report["buildManifestSha256"] = digest(base / "manifest.json")
        positive = run_case("edit-test-capture", base, 0)
        guest = positive["guestResult"]
        check("actual-regular-artifact-and-test", guest["passed"] is True and guest["rootReadonly"] is True
              and guest["workerUid"] == 65534 and guest["pid"] == 1
              and guest["files"] == {"result.txt": base64.b64encode(b"vm-fixture-verified\n").decode()}
              and "WORKER_UID=65534 HARNESS_TEST_PASSED" in guest["output"])
        for mode, failure in (("timeout", "worker-deadline"), ("overflow", "worker-output-limit"), ("symlink", "nonregular-artifact"), ("descendant", "worker-drain-deadline")):
            with tempfile.TemporaryDirectory(prefix="case-", dir=output) as temporary:
                target = Path(temporary) / "build"; build(target, mode, base)
                reuse_manifest = json.loads((target / "manifest.json").read_bytes())
                check(mode + "-same-immutable-image-no-mke2fs", reuse_manifest["imageReused"] is True
                      and reuse_manifest["rootDisk"] == manifest["rootDisk"]
                      and not (target / "root.ext4").exists() and "mke2fs" not in reuse_manifest["tools"])
                observation = run_case(mode, target, 3)
                check(mode + "-precise-refusal", observation["guestResult"]["error"] == failure and not observation["passed"])
                if mode == "timeout":
                    observation = run_case("host-deadline", target, 3, {"timeoutSeconds": 1})
                    check("host-deadline-confirmed-stop", observation["error"] == "host-deadline" and not observation["passed"])
                    observation = run_case("SIGTERM", target, 3, terminate=True)
                    check("SIGTERM-confirmed-stop", observation["error"] == "cancelled" and not observation["passed"])
            check(mode + "-owned-scratch-removed", not Path(temporary).exists())
        second = run_case("same-job-fresh-boot-nonce", base, 0)
        check("fresh-nonce-per-boot", second["bootNonce"] != positive["bootNonce"])
        for fault, failure in (("replay-nonce", "job-envelope-binding"), ("duplicate-frame", "job-frame-extra-or-no-eof"),
                               ("oversize-frame", "job-frame-size"), ("truncated-frame", "job-frame-truncated"),
                               ("hold-open", "job-frame-extra-or-no-eof")):
            changes = {"fixtureFault": fault}
            if fault == "replay-nonce": changes["fixtureReplayNonce"] = positive["bootNonce"]
            observation = run_case(fault, base, 3, changes, protocol_fault=True)
            if fault == "replay-nonce":
                check("exact-prior-frame-replay-refused", observation["jobFrameSha256"] == positive["jobFrameSha256"] and observation["bootNonce"] != positive["bootNonce"])
            check(fault + "-precise-protocol-refusal", observation["guestResult"].get("error") == failure
                  and not observation["passed"] and observation["guestResult"].get("files") == {} and observation["guestResult"].get("jobValidated") is False)
        run_case("normal-host-refuses-fault-config", base, 2, {"fixtureFault":"duplicate-frame"})
        closed = run_case("connection-after-admission-close", base, 3, {"fixtureFault":"closed-job-admission"}, protocol_fault=True)
        check("closed-admission-refuses-actual-connection-before-sender", closed["error"] == "fixture-job-admission-closed"
              and closed["jobConnectionsRefusedAfterClose"] == 1 and closed["jobConnections"] == 0
              and closed["jobFrameSha256"] is None and closed["jobSent"] is False and not closed["passed"])
        run_case("old-config-version-refused", base, 2, {"schema":"testifysec.vm-config/v1"})
        original = json.loads((base / "config.json").read_bytes())
        run_case("unknown-binding-field-refused", base, 2, {"binding":dict(original["binding"], extra="refuse")})
        with tempfile.TemporaryDirectory(prefix="oversize-config-", dir=output) as temporary:
            oversized = Path(temporary)/"config.json"; oversized.write_bytes(b" "*4097); oversized.chmod(0o600)
            refused = subprocess.run([str(base/"hc-vm"),str(oversized)],env={"PATH":"/nonexistent"},capture_output=True,timeout=5)
            check("bounded-config-read-before-decode", refused.returncode == 2 and not refused.stdout)
        original_job = json.loads((base / "job.json").read_bytes())
        compact = lambda v: json.dumps(v, separators=(",", ":")).encode()
        sha = lambda b: hashlib.sha256(b).hexdigest()
        def job_case(name, job, expected_error, binding=None, raw=None):
            with tempfile.TemporaryDirectory(prefix="job-", dir=output) as temporary:
                path = Path(temporary) / "job.json"; path.write_bytes(raw if raw is not None else compact(job)); path.chmod(0o600)
                changes = {"jobFile":str(path), "jobSha256":digest(path)}
                if binding is not None: changes["binding"] = binding
                observation = run_case(name, base, 0 if expected_error is None else 3, changes)
                if expected_error is not None:
                    check(name+"-job-refused-before-workload", observation["guestResult"].get("error") == expected_error
                          and observation["guestResult"].get("files") == {} and not observation["passed"])
                return observation
        for field in ("requestSha256", "profileSha256", "sessionId", "materialsSha256", "backendSha256"):
            job = json.loads(json.dumps(original_job)); job["binding"][field] = "f" * (32 if field=="sessionId" else 64)
            job_case("wrong-"+field, job, "job-assignment-binding")
        job = json.loads(json.dumps(original_job)); job["request"]["prompt"] = "changed request"
        job_case("request-content-digest", job, "job-content-binding")
        job_case("duplicate-job-key", original_job, "job-assignment-binding", raw=compact(original_job).replace(b'"schema":',b'"schema":"other","schema":',1))
        job_case("unknown-job-field", dict(original_job, unknown=True), "job-assignment-binding")
        job_case("null-job-field", dict(original_job, schema=None), "job-assignment-binding")
        material_bytes = b"seed from bounded session input\n"
        materials = [{"path":"seed.txt", "contentBase64":base64.b64encode(material_bytes).decode(), "sha256":sha(material_bytes)}]
        job = json.loads(json.dumps(original_job)); job["materials"] = materials
        job["binding"]["materialsSha256"] = sha(compact(materials))
        seeded = job_case("bounded-session-materials", job, None, job["binding"])
        check("materials-and-edits-retained", seeded["guestResult"]["files"] == {"seed.txt":base64.b64encode(material_bytes).decode(), "result.txt":base64.b64encode(b"vm-fixture-verified\n").decode()})
        for name, records, failure in [
            ("traversal-material", [dict(materials[0],path="../escape")], "job-material-path"),
            ("git-material", [dict(materials[0],path=".GiT")], "job-material-path"),
            ("duplicate-material", materials+materials, "job-material-path"),
            ("bad-material-bytes", [dict(materials[0],sha256="0"*64)], "job-material-bytes"),
            ("wide-materials", [dict(materials[0],path=f"file{i}") for i in range(17)], "job-materials"),
        ]:
            changed=json.loads(json.dumps(original_job));changed["materials"]=records
            changed["binding"]["materialsSha256"]=sha(compact(records))
            job_case(name,changed,failure,changed["binding"])
        run_case("wrong-kernel-digest", base, 2, {"kernelSha256": "0" * 64})
        run_case("wrong-root-digest", base, 2, {"rootDiskSha256": "0" * 64})
        run_case("resource-limit", base, 2, {"cpus": 2})
        if args.worker:
            worker_sha = digest(args.worker)
            worker_inputs = output / "worker-inputs"
            extracted = subprocess.run(["python3", "-B", str(SOURCE / "extract-worker.py"), "--worker", str(args.worker),
                                        "--image", args.image, "--output", str(worker_inputs)], capture_output=True, timeout=120)
            check("cached-worker-input-extraction", extracted.returncode == 0)
            extraction = json.loads((worker_inputs / "manifest.json").read_text())
            report["workerInputs"] = extraction
            report["workerInputsManifestSha256"] = digest(worker_inputs / "manifest.json")
            check("no-container-execution-and-owned-cleanup", extraction["containerStarted"] is False and extraction["ownedContainerRemoved"] is True)
            target = output / "worker-build"
            build(target, "worker", base, worker_inputs / "root")
            observation = run_case("actual-upstream-worker", target, 0, memory=1024)
            guest = observation["guestResult"]
            events = [json.loads(line) for line in guest["output"].splitlines() if line.strip()]
            tools = [event["part"] for event in events if event.get("type") == "tool_use"]
            check("actual-upstream-write", any(item.get("tool") == "write" and item["state"]["status"] == "completed" for item in tools))
            check("actual-upstream-shell-test", any(item.get("tool") in ("bash", "shell") and item["state"]["status"] == "completed"
                  and "HARNESS_TEST_PASSED" in item["state"]["output"] for item in tools))
            check("actual-upstream-artifact", guest["files"] == {"result.txt": base64.b64encode(b"hardened-worker-verified\n").decode()})
            check("fixture-provider-scope", any(event.get("type") == "managed_worker_start" and event.get("fixtureModel") is True
                  and event.get("scope") == "untrusted-worker" for event in events)
                  and observation["admissionIntegrated"] is False and observation["gatewayIntegrated"] is False)
            check("worker-input-unchanged", digest(args.worker) == worker_sha and digest(target / "root/toolpack/opencode-worker") == worker_sha)
            check("worker-root-disk-unchanged", digest(Path(json.loads((target / "config.json").read_text())["rootDisk"])) == json.loads((target / "manifest.json").read_text())["rootDiskSha256"])
        check("root-disk-unchanged", digest(Path(manifest["rootDisk"])) == manifest["rootDiskSha256"])
        check("host-binary-unchanged", digest(base / "hc-vm") == manifest["binaries"]["hc-vm"])
        check("source-snapshot-unchanged", all(digest(SOURCE / name) == sha for name, sha in manifest["sourceFiles"].items()))
        report["status"] = "passed"
    except BaseException:
        report["status"] = "failed"
        raise
    finally:
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "checks": len(report["checks"]), "report": str(output / "report.json"),
                      "sha256": digest(output / "report.json")}))


if __name__ == "__main__":
    main()
