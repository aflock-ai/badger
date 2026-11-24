#!/usr/bin/env python3
"""Local HC-03 scaffold: constrained Docker execution, never a signing API.

This development adapter requires Python. It is not the shipping native service,
does not establish agent identity, and makes no ALPS qualification claim.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import tempfile
import time
import uuid


class Rejected(Exception):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise Rejected("invalid_json", "Duplicate JSON object key")
        result[key] = value
    return result


def parse(data):
    if len(data) > 65536:
        raise Rejected("invalid_json", "JSON input exceeds 64 KiB")
    try:
        value = json.loads(data, object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        # JSON escapes can represent lone surrogates that cannot cross UTF-8 or
        # filesystem boundaries. Reject them in every key/value before admission.
        pending = [value]
        while pending:
            item = pending.pop()
            if type(item) is str:
                item.encode("utf-8")
            elif type(item) is dict:
                pending.extend(item.keys())
                pending.extend(item.values())
            elif type(item) is list:
                pending.extend(item)
        return value
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Rejected("invalid_json", "Invalid JSON input") from error


def fields(value, required, optional=()):
    if type(value) is not dict or not set(required) <= value.keys() or value.keys() - set(required) - set(optional):
        raise Rejected("invalid_schema", "Missing or unknown object fields")


def bounded(value, low, high, name):
    if type(value) is not int or not low <= value <= high:
        raise Rejected("invalid_schema", f"Invalid {name}")
    return value


def absolute(value):
    if type(value) is not str or not value.startswith("/") or "\x00" in value:
        raise Rejected("invalid_schema", "Expected absolute path")
    return Path(value)


def within(path, root):
    return path == root or root in path.parents


def open_directory(path):
    """Resolve each component without following links; never trust realpath alone."""
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            if part in (".", ".."):
                raise Rejected("unsafe_path", "Dot path components are prohibited")
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def read_policy(filename):
    path = absolute(filename)
    descriptor = open_directory(path.parent)
    try:
        parent = os.fstat(descriptor)
        if parent.st_uid != os.getuid() or parent.st_mode & 0o022:
            raise Rejected("unsafe_policy", "Policy directory must be broker-owned and not writable by others")
        handle = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        try:
            metadata = os.fstat(handle)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
                raise Rejected("unsafe_policy", "Policy must be a private broker-owned regular file")
            data = os.read(handle, 65537)
        finally:
            os.close(handle)
    finally:
        os.close(descriptor)
    value = parse(data)
    fields(value, ("schema", "dockerBinary", "engineSocket", "image", "workspace", "limits"))
    if value["schema"] != "testifysec.hardened-opencode.sandbox-policy/v1":
        raise Rejected("invalid_schema", "Unsupported policy schema")
    if type(value["image"]) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", value["image"]):
        raise Rejected("unapproved_image", "Policy must select an immutable local image ID")
    fields(value["workspace"], ("id", "source"))
    if type(value["workspace"]["id"]) is not str or not re.fullmatch(r"[a-z0-9-]{1,64}", value["workspace"]["id"]):
        raise Rejected("invalid_schema", "Invalid workspace ID")
    source = absolute(value["workspace"]["source"])
    if source == Path("/") or within(path, source):
        raise Rejected("unsafe_policy", "Policy must be outside the workspace")
    limits = value["limits"]
    fields(limits, ("timeoutSeconds", "outputBytes", "workspaceBytes", "workspaceFiles"))
    bounded(limits["timeoutSeconds"], 1, 60, "timeout")
    bounded(limits["outputBytes"], 1024, 1048576, "output limit")
    bounded(limits["workspaceBytes"], 1, 67108864, "workspace byte limit")
    bounded(limits["workspaceFiles"], 1, 10000, "workspace file limit")
    absolute(value["dockerBinary"])
    absolute(value["engineSocket"])
    return value, digest(data)


def request(value, policy):
    fields(value, ("schema", "workspace", "command"), ("timeoutSeconds",))
    if value["schema"] != "testifysec.hardened-opencode.exec/v1":
        raise Rejected("invalid_schema", "Unsupported request schema")
    if value["workspace"] != policy["workspace"]["id"]:
        raise Rejected("workspace_denied", "Workspace is not assigned to this policy")
    command = value["command"]
    if type(command) is not str or not command or "\x00" in command or len(command.encode()) > 8192:
        raise Rejected("invalid_schema", "Invalid command")
    timeout = value.get("timeoutSeconds", policy["limits"]["timeoutSeconds"])
    bounded(timeout, 1, policy["limits"]["timeoutSeconds"], "request timeout")
    return command, timeout


def identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def snapshot(source, destination, limits):
    """Private byte snapshot; no host git, symlinks, hardlinks, devices or sockets."""
    files = []
    size = 0
    entries = 0

    def copy(directory, target, prefix, depth):
        nonlocal size, entries
        if depth > 64:
            raise Rejected("unsafe_workspace", "Workspace nesting exceeds limit")
        before = os.fstat(directory)
        names = []
        # Reserve the global budget before materializing or sorting a directory.
        # Even excluded .git entries consume budget; traversal is always bounded.
        with os.scandir(directory) as scan:
            for item in scan:
                entries += 1
                if entries > limits["workspaceFiles"]:
                    raise Rejected("workspace_limit", "Workspace entry count exceeds policy limit")
                names.append(item.name)
        for name in sorted(names):
            if name == ".git":
                continue
            metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
            relative = prefix + name
            if stat.S_ISDIR(metadata.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                try:
                    if (metadata.st_dev, metadata.st_ino) != (os.fstat(child).st_dev, os.fstat(child).st_ino):
                        raise Rejected("workspace_changed", "Workspace changed during snapshot")
                    (target / name).mkdir(mode=0o777)
                    (target / name).chmod(0o777)
                    copy(child, target / name, relative + "/", depth + 1)
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise Rejected("unsafe_workspace", "Workspace contains a link or non-regular file")
            if len(files) >= limits["workspaceFiles"] or size + metadata.st_size > limits["workspaceBytes"]:
                raise Rejected("workspace_limit", "Workspace exceeds policy limits")
            handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                opened = os.fstat(handle)
                if identity(opened) != identity(metadata) or opened.st_nlink != 1 or not stat.S_ISREG(opened.st_mode):
                    raise Rejected("workspace_changed", "Workspace changed during snapshot")
                content = bytearray()
                while True:
                    chunk = os.read(handle, min(65536, limits["workspaceBytes"] - size - len(content) + 1))
                    if not chunk:
                        break
                    content.extend(chunk)
                    if size + len(content) > limits["workspaceBytes"]:
                        raise Rejected("workspace_limit", "Workspace exceeds policy limits")
                if identity(os.fstat(handle)) != identity(opened):
                    raise Rejected("workspace_changed", "Workspace changed during snapshot")
            finally:
                os.close(handle)
            (target / name).write_bytes(content)
            mode = 0o777 if opened.st_mode & 0o111 else 0o666
            (target / name).chmod(mode)
            size += len(content)
            files.append({"path": relative, "size": len(content), "sha256": digest(content), "executable": bool(mode & 0o111)})
        if identity(os.fstat(directory)) != identity(before):
            raise Rejected("workspace_changed", "Workspace changed during snapshot")

    descriptor = open_directory(source)
    try:
        destination.mkdir(mode=0o777)
        destination.chmod(0o777)
        copy(descriptor, destination, "", 0)
    finally:
        os.close(descriptor)
    return {"sha256": digest(encoded(files)), "files": files, "bytes": size, "gitMetadata": "excluded"}


def capture(argv, env, timeout, limit):
    process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, start_new_session=True)
    started = time.monotonic()
    output = bytearray()
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        while selector.get_map():
            if time.monotonic() - started > timeout:
                raise Rejected("execution_timeout", "Execution exceeded policy time limit")
            for key, _ in selector.select(timeout=0.05):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output.extend(chunk)
                if len(output) > limit:
                    raise Rejected("output_limit", "Execution exceeded policy output limit")
        return process.wait(timeout=max(0.1, timeout - (time.monotonic() - started))), bytes(output)
    except subprocess.TimeoutExpired as error:
        raise Rejected("execution_timeout", "Execution exceeded policy time limit") from error
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()


class Engine:
    def __init__(self, policy, home):
        self.policy = policy
        self.argv = [policy["dockerBinary"], "--host", "unix://" + policy["engineSocket"]]
        self.env = {"HOME": str(home), "DOCKER_CONFIG": str(home), "PATH": "/usr/bin:/bin"}

    def call(self, args, timeout=15, limit=1048576):
        code, output = capture(self.argv + args, self.env, timeout, limit)
        if code:
            raise Rejected("engine_unavailable", "Local container operation failed; no host fallback")
        return output

    def preflight(self):
        try:
            info = parse(self.call(["info", "--format", '{{json .}}']))
            image = parse(self.call(["image", "inspect", self.policy["image"]]))[0]
        except (IndexError, KeyError, TypeError) as error:
            raise Rejected("engine_unavailable", "Invalid local engine response") from error
        if info.get("OSType") != "linux" or image.get("Os") != "linux" or image.get("Id") != self.policy["image"]:
            raise Rejected("unapproved_image", "Expected exact approved Linux image")
        if "name=seccomp,profile=builtin" not in info.get("SecurityOptions", []):
            raise Rejected("engine_unavailable", "Engine must report its built-in seccomp profile")
        if image.get("Config", {}).get("Volumes"):
            raise Rejected("unapproved_image", "Image-declared volumes are prohibited")
        for item in image.get("Config", {}).get("Env", []):
            if item.split("=", 1)[0] not in {"PATH", "HOME", "TMPDIR", "LANG"}:
                raise Rejected("unapproved_image", "Image contains an unapproved environment variable")
        return {"serverVersion": info["ServerVersion"], "kernel": info["KernelVersion"],
                "os": info["OSType"], "architecture": image["Architecture"], "image": image["Id"],
                "securityOptions": info["SecurityOptions"]}


def boundary(image, workspace, name, command, policy_sha):
    return ["create", "--pull", "never", "--name", name, "--read-only", "--network", "none", "--log-driver", "none",
            "--label", "io.testifysec.hardened.policy=" + policy_sha,
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--pids-limit", "64",
            "--memory", "128m", "--memory-swap", "128m", "--cpus", "1", "--user", "65534:65534", "--ipc", "private",
            "--ulimit", "nofile=256:256", "--ulimit", "core=0:0", "--restart", "no",
            "--env", "HOME=/tmp/home", "--env", "PATH=/usr/bin:/bin", "--env", "TMPDIR=/tmp",
            "--env", "LANG=C", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
            "--tmpfs", "/workspace:rw,nosuid,nodev,size=64m,mode=1777",
            "--mount", f"type=bind,src={workspace},dst=/inputs,readonly,bind-propagation=rprivate",
            "--workdir", "/workspace", "--entrypoint", "/bin/sh", image, "-c",
            'cp -R /inputs/. /workspace/ && exec /bin/sh -c "$1"', "hc-worker", command]


def execute(policy_path, raw_request):
    policy, policy_sha = read_policy(str(policy_path))
    value = parse(raw_request)
    command, timeout = request(value, policy)
    # Scratch is outside the worker-authored source and removed after every run.
    with tempfile.TemporaryDirectory(prefix="hc-sandbox-") as temporary:
        root = Path(temporary).resolve()
        if within(root, absolute(policy["workspace"]["source"])):
            raise Rejected("unsafe_policy", "Broker scratch cannot reside in the workspace")
        engine = Engine(policy, root)
        observed = engine.preflight()
        material = snapshot(absolute(policy["workspace"]["source"]), root / "workspace", policy["limits"])
        name = "hc-sandbox-" + uuid.uuid4().hex
        argv = boundary(policy["image"], root / "workspace", name, command, policy_sha)
        cleanup = False
        try:
            container = engine.call(argv).decode().strip()
            if not re.fullmatch(r"[0-9a-f]{64}", container):
                raise Rejected("engine_unavailable", "Invalid container ID")
            # Inspect the concrete engine object before starting repository code.
            details = parse(engine.call(["inspect", container]))[0]
            host = details["HostConfig"]
            if not (host["ReadonlyRootfs"] and host["NetworkMode"] == "none"
                    and host["CapDrop"] == ["ALL"] and not host["Privileged"]
                    and "no-new-privileges=true" in host["SecurityOpt"]
                    and details["Config"]["User"] == "65534:65534"
                    and host["PidMode"] == "" and not host.get("Devices")
                    and host["PidsLimit"] == 64 and host["Memory"] == 134217728
                    and host["MemorySwap"] == 134217728 and host["NanoCpus"] == 1000000000
                    and host["IpcMode"] == "private"
                    and host["LogConfig"]["Type"] == "none"
                    and host["Tmpfs"] == {"/tmp": "rw,noexec,nosuid,nodev,size=16m,mode=1777",
                                          "/workspace": "rw,nosuid,nodev,size=64m,mode=1777"}
                    and len(details["Mounts"]) == 1
                    and details["Mounts"][0]["Source"] == str(root / "workspace")
                    and details["Mounts"][0]["Destination"] == "/inputs"
                    and not details["Mounts"][0]["RW"]):
                raise Rejected("boundary_mismatch", "Engine did not establish the required boundary")
            code, output = capture(engine.argv + ["start", "--attach", container], engine.env,
                                   timeout, policy["limits"]["outputBytes"])
            state = parse(engine.call(["inspect", "--format", '{{json .State}}', container]))
            if state["Running"] or state["ExitCode"] != code or state.get("OOMKilled") or state.get("Error"):
                raise Rejected("execution_failed", "Container did not finish cleanly")
            normalized = boundary(policy["image"], "<private-snapshot>", "<run-id>", "<request-command>", policy_sha)
            result = {"schema": "testifysec.hardened-opencode.exec-result/v1", "status": "completed",
                      "exitCode": code, "output": output.decode("utf-8", errors="replace"),
                      "outputSha256": digest(output), "policySha256": policy_sha,
                      "requestSha256": digest(raw_request), "materials": material,
                      "runtime": observed, "boundary": normalized, "boundarySha256": digest(encoded(normalized)),
                      "containerConfiguration": {"logDriver": host["LogConfig"]["Type"],
                                                 "networkMode": host["NetworkMode"],
                                                 "readonlyRootfs": host["ReadonlyRootfs"],
                                                 "writableHostMounts": sum(bool(mount["RW"]) for mount in details["Mounts"])},
                      "assurance": "local-container-fixture; not-assessed"}
        finally:
            # Names are generated by this invocation; never remove unrelated containers.
            engine.call(["rm", "--force", name])
            cleanup = True
        result["cleanup"] = cleanup
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--request", required=True)
    args = parser.parse_args()
    try:
        with open(args.request, "rb") as handle:
            result = execute(args.policy, handle.read(65537))
    except (Rejected, OSError) as error:
        result = {"status": "rejected", "code": getattr(error, "code", "io_failure"), "message": str(error)}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
