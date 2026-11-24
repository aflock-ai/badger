#!/usr/bin/env python3
"""Export fixed backend bytes for independent native verification; never boot a VM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

SCHEMA = "testifysec.aflock.vz-backend/v1"
ROLES = {"host": ("hc-vm", 64 * 1024 * 1024, 0o500),
         "kernel": ("kernel", 128 * 1024 * 1024, 0o400),
         "rootDisk": ("root.ext4", 2 * 1024 * 1024 * 1024, 0o400),
         "provenance": ("build.json", 256 * 1024, 0o400)}


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate metadata key")
        value[key] = item
    return value


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def source(directory, name, maximum):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size <= 0
                or before.st_size > maximum or before.st_mode & 0o7022
                or before.st_uid not in (0, os.getuid())):
            raise ValueError("unsafe or oversized build input")
        return descriptor, before
    except BaseException:
        os.close(descriptor)
        raise


def bounded_bytes(directory, name, maximum):
    descriptor, before = source(directory, name, maximum)
    try:
        raw = bytearray()
        while len(raw) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) != before.st_size or len(raw) > maximum or identity(os.fstat(descriptor)) != identity(before):
            raise ValueError("changed build metadata")
        return bytes(raw)
    finally:
        os.close(descriptor)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def export(build, output):
    if os.name != "posix":
        raise ValueError("backend preparation currently requires POSIX")
    build = Path(build).absolute()
    output = Path(output).absolute()
    # These are build-administrator inputs. Held directory/file descriptors keep
    # copying on the opened object; this is not protection against its owner.
    source_directory = os.open(build, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    parent = None
    destination = None
    created = None
    made = False
    written = []
    complete = False
    try:
        raw_build = bounded_bytes(source_directory, "manifest.json", ROLES["provenance"][1])
        metadata = json.loads(raw_build, object_pairs_hook=unique)
        raw_config = bounded_bytes(source_directory, "config.json", 4096)
        config = json.loads(raw_config, object_pairs_hook=unique)
        if not isinstance(metadata, dict) or not isinstance(config, dict) or not isinstance(metadata.get("binaries"), dict):
            raise ValueError("invalid build metadata object")
        if (metadata.get("schema") != "testifysec.vm-build/v2"
                or config.get("schema") != "testifysec.vm-config/v3"
                or metadata.get("configSha256") != sha(raw_config)
                or metadata.get("protocolFaultInjection") != "separate hc-vm-uat binary only"
                or metadata.get("releaseQualified") is not False
                or metadata.get("binaries", {}).get("hc-vm") == metadata.get("binaries", {}).get("hc-vm-uat")):
            raise ValueError("normal V3 development build required")
        fault_host = metadata["binaries"].get("hc-vm-uat")
        if not isinstance(fault_host, str) or len(fault_host) != 64 or any(c not in "0123456789abcdef" for c in fault_host):
            raise ValueError("normal/fault build distinction missing")
        expected = {"host": metadata["binaries"]["hc-vm"], "kernel": metadata["kernelSha256"],
                    "rootDisk": metadata["rootDiskSha256"], "provenance": sha(raw_build)}
        if (config.get("kernelSha256") != expected["kernel"] or config.get("rootDiskSha256") != expected["rootDisk"]
                or any(not isinstance(value, str) or len(value) != 64
                       or any(c not in "0123456789abcdef" for c in value) for value in expected.values())):
            raise ValueError("invalid observed build bindings")
        parent_path = output.parent.resolve(strict=True)
        parent = os.open(parent_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        owner = os.fstat(parent)
        if owner.st_uid not in (0, os.getuid()) or (owner.st_mode & 0o022 and not (owner.st_uid == 0 and owner.st_mode & stat.S_ISVTX)):
            raise ValueError("unsafe output parent")
        os.mkdir(output.name, 0o700, dir_fd=parent)
        made = True
        destination = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        created = os.fstat(destination)
        descriptors = {}
        for role, (name, maximum, mode) in ROLES.items():
            origin = "manifest.json" if role == "provenance" else name
            descriptor, before = source(source_directory, origin, maximum)
            target = None
            try:
                target = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=destination)
                written.append(name)
                digest = hashlib.sha256()
                count = 0
                while True:
                    chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - count))
                    if not chunk:
                        break
                    count += len(chunk)
                    if count > maximum:
                        raise ValueError("build input grew beyond bound")
                    digest.update(chunk)
                    remaining = memoryview(chunk)
                    while remaining:
                        size = os.write(target, remaining)
                        if size <= 0:
                            raise OSError("short output write")
                        remaining = remaining[size:]
                if (count != before.st_size or identity(os.fstat(descriptor)) != identity(before)
                        or digest.hexdigest() != expected[role]):
                    raise ValueError("build bytes changed or do not match observed build")
                os.fchmod(target, mode)
                os.fsync(target)
                descriptors[role] = {"sha256": digest.hexdigest(), "size": count}
            finally:
                os.close(descriptor)
                if target is not None:
                    os.close(target)
        manifest = {"schema": SCHEMA, "kind": "darwin-vz/v1", "hostTarget": "darwin-arm64",
                    "guestTarget": "linux-arm64", "jobSchema": "testifysec.vm-job/v3",
                    "resultSchema": "testifysec.vm-result/v3", "relayProtocol": "HCMDL2", "files": descriptors}
        raw = json.dumps(manifest, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
        descriptor = os.open("backend.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=destination)
        written.append("backend.json")
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        # Publish the manifest last and leave all payload files read-only.
        os.fchmod(destination, 0o500)
        os.fsync(destination)
        current = os.stat(output.name, dir_fd=parent, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (created.st_dev, created.st_ino):
            raise ValueError("output directory changed")
        complete = True
        return {"schema": "testifysec.aflock.vz-backend-export/v1", "directory": str(parent_path / output.name),
                "manifestSha256": sha(raw), "files": descriptors, "buildConfigSha256": sha(raw_config),
                "vmExecuted": False, "releaseQualified": False, "admissionIntegrated": False}
    finally:
        cleanup_error = RuntimeError("unconfirmed new directory custody") if made and created is None else None
        if created is not None and not complete:
            try:
                os.fchmod(destination, 0o700)
                for name in reversed(written):
                    os.unlink(name, dir_fd=destination)
                current = os.stat(output.name, dir_fd=parent, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != (created.st_dev, created.st_ino):
                    raise ValueError("output cleanup custody changed")
                os.rmdir(output.name, dir_fd=parent)
            except (OSError, ValueError) as error:
                cleanup_error = error
        for descriptor in (destination, parent, source_directory):
            if descriptor is not None:
                os.close(descriptor)
        if cleanup_error is not None:
            raise RuntimeError("export refused; owned output cleanup incomplete") from cleanup_error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", required=True, type=Path, help="Retained V3 build directory with fixed local inputs")
    parser.add_argument("--output", required=True, type=Path, help="Fresh directory under a trusted private or root-sticky parent")
    args = parser.parse_args()
    try:
        result = export(args.build, args.output)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        print(json.dumps({"schema": "testifysec.aflock.vz-backend-export/v1", "exported": False,
                          "error": str(error), "vmExecuted": False}))
        raise SystemExit(1)
    print(json.dumps({"exported": True, **result}))


if __name__ == "__main__":
    main()
