#!/usr/bin/env python3
"""Embed a previously built, pinned native bundle into one target executable."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
TARGETS = {f"{system}-{arch}" for system in ("darwin", "linux", "windows") for arch in ("arm64", "amd64")}
MAX_FILE = 256 << 20
MAX_PAYLOAD = 768 << 20


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def portable(name):
    if not isinstance(name, str) or len(name) > 512 or len(name.split("/")) > 8:
        return False
    for part in name.split("/"):
        stem = part.lower().split(".")[0]
        if not re.fullmatch(r"[A-Za-z0-9_@.-]{1,128}", part) or part in (".", "..") or part.lower() == ".git" or part.endswith(".") or stem in {"con", "prn", "aux", "nul"} or re.fullmatch(r"(?:com|lpt)[0-9]", stem):
            return False
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--go", required=True)
    parser.add_argument("--input", required=True, type=Path, help="Native bundle directory with a files/SHA256 manifest.json")
    parser.add_argument("--entry", required=True, help="Exact relative native executable to launch; no argv forwarding")
    parser.add_argument("--target", required=True, choices=sorted(TARGETS))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    source = args.input.resolve(strict=True)
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("output must be a new file")
    output.parent.mkdir(parents=True, exist_ok=True)
    opened = os.open(source / "manifest.json", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(opened, "rb") as read:
        info = os.fstat(read.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 2 << 20:
            raise ValueError("input manifest must be a bounded single-link regular file")
        raw = read.read((2 << 20)+1)
        if len(raw) > 2 << 20:
            raise ValueError("input manifest too large")
    origin = json.loads(raw, object_pairs_hook=unique)
    files = origin.get("files")
    if not isinstance(files, dict) or not files or len(files) >= 256 or args.entry not in files or "manifest.json" in files:
        raise ValueError("bounded explicit input file manifest required")
    files = {**files, "manifest.json": hashlib.sha256(raw).hexdigest()}
    aliases, names = {}, set(files)
    for name, expected in files.items():
        if not portable(name) or not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected):
            raise ValueError("invalid input file name or digest")
        parts = name.split("/")
        for count in range(1, len(parts)+1):
            prefix = "/".join(parts[:count])
            if prefix.lower() in aliases and aliases[prefix.lower()] != prefix or count < len(parts) and prefix in names:
                raise ValueError("input path alias or prefix collision")
            aliases[prefix.lower()] = prefix
    product = json.loads((HERE.parent / "branding/product.json").read_bytes())
    version = (REPO / "VERSION").read_text().strip()
    upstream = json.loads((HERE.parent.parent / "packages/cli/package.json").read_bytes())["version"]
    source_files = [*HERE.glob("*.go"), HERE / "go.mod", Path(__file__).resolve(), HERE.parent / "branding/product.json",
                    REPO / "VERSION", HERE.parent.parent / "packages/cli/package.json"]
    source_hashes = {str(path.relative_to(REPO)): digest(path) for path in source_files}
    with tempfile.TemporaryDirectory(prefix="hardened-package-build-") as directory:
        stage = Path(directory)
        (stage / "assets").mkdir()
        for path in [*HERE.glob("*.go"), HERE / "go.mod"]:
            shutil.copyfile(path, stage / path.name)
            if digest(stage / path.name) != source_hashes[str(path.relative_to(REPO))]:
                raise ValueError("launcher source changed")
        entries, total = [], 0
        with zipfile.ZipFile(stage / "assets/payload.dat", "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
            for name, expected in sorted(files.items()):
                path = source / name
                before = path.lstat()
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_FILE:
                    raise ValueError("input file is not a bounded single-link regular file")
                total += before.st_size
                if total > MAX_PAYLOAD:
                    raise ValueError("payload exceeds byte budget")
                mode = 0o500 if name == args.entry or before.st_mode & 0o111 else 0o400
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | mode) << 16
                opened = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
                with os.fdopen(opened, "rb") as read:
                    actual = os.fstat(read.fileno())
                    if (before.st_dev, before.st_ino) != (actual.st_dev, actual.st_ino) or not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1:
                        raise ValueError("input file changed before read")
                    hashed, copied = hashlib.sha256(), 0
                    with archive.open(info, "w") as write:
                        while chunk := read.read(1 << 20):
                            copied += len(chunk)
                            if copied > before.st_size:
                                raise ValueError("input file grew")
                            hashed.update(chunk)
                            write.write(chunk)
                    if copied != before.st_size or hashed.hexdigest() != expected:
                        raise ValueError("input file digest mismatch")
                entries.append({"name": name, "sha256": expected, "size": copied, "mode": mode})
        target_os, arch = args.target.split("-")
        manifest = {"schema": "testifysec.hardened-code.single-executable/v1", "os": target_os, "arch": arch,
                    "entry": args.entry, "product": product["name"], "command": product["command"], "version": version,
                    "upstreamVersion": upstream, "attribution": product["attribution"],
                    "payloadSha256": digest(stage / "assets/payload.dat"), "inputManifestSha256": hashlib.sha256(raw).hexdigest(),
                    "files": entries}
        encoded = (json.dumps(manifest, separators=(",", ":"), sort_keys=True) + "\n").encode()
        (stage / "assets/manifest.json").write_bytes(encoded)
        env = {**os.environ, "GOTOOLCHAIN": "local", "GOWORK": "off", "GOPROXY": "off", "GOSUMDB": "off",
               "CGO_ENABLED": "0", "GOOS": target_os, "GOARCH": arch}
        command = [args.go, "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-p=2", "-ldflags",
                   "-X main.manifestDigest=" + hashlib.sha256(encoded).hexdigest(), "-o", str(stage / "packaged"), "."]
        subprocess.run(command, cwd=stage, env=env, check=True)
        if any(digest(REPO / name) != expected for name, expected in source_hashes.items()):
            raise ValueError("source input changed during packaging")
        # Create exclusively: no replacement of an existing customer executable.
        with (stage / "packaged").open("rb") as source_stream, output.open("xb") as target:
            shutil.copyfileobj(source_stream, target)
        output.chmod(0o755)
    report = {"schema": "testifysec.hardened-code.packaging-build/v1", "target": args.target,
              "binarySha256": digest(output), "manifest": manifest, "manifestSha256": hashlib.sha256(encoded).hexdigest(),
              "sourceFiles": source_hashes, "go": subprocess.check_output([args.go, "version"], text=True).strip(),
              "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
              "worktreeDirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=REPO)),
              "runtimeVerified": False, "releaseQualified": False,
              "limitations": ["Packaging does not install or qualify a sandbox backend, protected service identity or release signature.",
                              "Existing managed worker execution still requires the configured protected broker and Linux engine.",
                              "Target compilation is not proof that the payload runs on that operating system."]}
    Path(str(output) + ".manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"binary": str(output), "target": args.target, "sha256": report["binarySha256"], "runtimeVerified": False}))


if __name__ == "__main__":
    main()
