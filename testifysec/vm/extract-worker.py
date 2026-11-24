#!/usr/bin/env python3
"""Copy selected bytes from a cached image without starting its container."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import uuid


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", default="/usr/local/bin/docker")
    # Only a local daemon: DOCKER_HOST is not read, so the environment cannot point this at a remote one.
    parser.add_argument("--socket", default=f"unix://{Path.home()}/.docker/run/docker.sock")
    parser.add_argument("--image", required=True)
    parser.add_argument("--worker", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    if not args.socket.startswith("unix:///"):
        parser.error("--socket must be a local unix:// socket")
    return args


def absent(returncode, stderr, name):
    """Whether `docker inspect NAME` reported NAME absent. Docker 29 prints "error: no such object: NAME",
    earlier CLIs capitalise the prefix; only the prefix may differ in case, the name must match verbatim."""
    prefix = "error: no such object: "
    text = stderr.decode(errors="replace").strip()
    return returncode == 1 and text[:len(prefix)].lower() == prefix and text[len(prefix):] == name


def main():
    args = parse_args()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image):
        raise SystemExit("exact cached image ID required")
    output = args.output.absolute(); output.mkdir(mode=0o700)
    root = output / "root"; root.mkdir()
    docker_config = output / "docker-config"; docker_config.mkdir(mode=0o700)
    cli = [args.docker, "--host", args.socket]
    tool_sha256 = digest(args.docker)
    source_sha256 = digest(__file__)

    def docker(*arguments, check=True):
        value = subprocess.run(cli + list(arguments), capture_output=True, timeout=60,
                               env={"PATH": "/usr/bin:/bin", "DOCKER_CONFIG": str(docker_config)})
        if check and value.returncode:
            raise RuntimeError("cached image extraction command failed: " + arguments[0])
        return value

    def inspect_owned(name):
        value = docker("inspect", name, check=False)
        if value.returncode == 0:
            return json.loads(value.stdout)[0]
        if absent(value.returncode, value.stderr, name):
            return None
        raise RuntimeError("extraction cleanup unavailable; absence not established")

    image = json.loads(docker("image", "inspect", args.image).stdout)[0]
    if image["Id"] != args.image or image["Os"] != "linux" or image["Architecture"] != "arm64":
        raise RuntimeError("image assignment mismatch")
    worker_manifest = json.loads(Path(str(args.worker) + ".manifest.json").read_text())
    expected_worker = digest(args.worker)
    if worker_manifest["target"] != "bun-linux-arm64" or worker_manifest["fixtureModel"] is not True or worker_manifest["binarySha256"] != expected_worker:
        raise RuntimeError("exact fixture-model worker required")
    nonce = uuid.uuid4().hex
    name = "hc-vm-input-" + nonce
    entries = {}
    try:
        docker("create", "--pull=never", "--name", name, "--label", "io.testifysec.vm.fixture=" + nonce,
               "--network", "none", "--read-only", "--cap-drop", "ALL", "--entrypoint", "/bin/false", args.image)
        files = {"/bin/sh": "bin/sh", "/bin/bash": "bin/bash", "/usr/bin/cat": "usr/bin/cat", "/usr/bin/env": "usr/bin/env"}
        for library in ("libc.so.6", "libpthread.so.0", "libdl.so.2", "libm.so.6", "libgcc_s.so.1", "libtinfo.so.6"):
            files["/usr/lib/aarch64-linux-gnu/" + library] = "lib/aarch64-linux-gnu/" + library
        files["/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"] = "lib/ld-linux-aarch64.so.1"
        for source, destination in files.items():
            data = docker("cp", "-L", name + ":" + source, "-").stdout
            if len(data) > 32 * 1024 * 1024:
                raise RuntimeError("selected library archive too large")
            with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                members = archive.getmembers()
                if len(members) != 1 or not members[0].isfile() or members[0].size > 16 * 1024 * 1024:
                    raise RuntimeError("expected exactly one bounded regular file")
                body = archive.extractfile(members[0]).read()
            target = root / destination; target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body); target.chmod(0o755)
            entries[destination] = {"imagePath": source, "sha256": digest(target)}
        # The ELF interpreter is also a DT_NEEDED dependency of the compiled
        # worker. Provide identical regular bytes at its library search path.
        loader = root / "lib/ld-linux-aarch64.so.1"
        duplicate = root / "lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"
        shutil.copyfile(loader, duplicate); duplicate.chmod(0o755)
        entries[str(duplicate.relative_to(root))] = {"imagePath": "/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1", "sha256": digest(duplicate)}
        target = root / "toolpack/opencode-worker"; target.parent.mkdir()
        shutil.copyfile(args.worker, target); target.chmod(0o755)
        if digest(target) != expected_worker or digest(args.worker) != expected_worker:
            raise RuntimeError("worker changed during staging")
        entries["toolpack/opencode-worker"] = {"source": str(args.worker), "sha256": expected_worker}
    finally:
        item = inspect_owned(name)
        if item is not None:
            if item["Config"]["Labels"].get("io.testifysec.vm.fixture") != nonce or item["State"]["Running"]:
                raise RuntimeError("uncertain extraction container ownership/state; refusing cleanup")
            docker("rm", item["Id"])
    if inspect_owned(name) is not None:
        raise RuntimeError("extraction container remains")
    if digest(args.docker) != tool_sha256 or digest(__file__) != source_sha256:
        raise RuntimeError("selected extraction tool/source changed")
    report = {"schema": "testifysec.vm-worker-inputs/v1", "image": args.image, "files": entries,
              "workerBuildManifest": worker_manifest, "containerStarted": False, "ownedContainerRemoved": True,
              "dockerExecutableSha256": tool_sha256, "extractorSourceSha256": source_sha256,
              "scope": "cached development input extraction, no runtime Docker dependency, not authenticated release provenance"}
    (output / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"root": str(root), "manifestSha256": digest(output / "manifest.json")}))


if __name__ == "__main__":
    main()
