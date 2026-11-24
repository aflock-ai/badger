"""Build a version-selected admission bundle with protected public assignment."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--go", default="go")
parser.add_argument("--bun", default="bun")
parser.add_argument("--trust", type=Path, help="Build administrator's public trust/assignment JSON")
parser.add_argument("--output", type=Path)
parser.add_argument("--list-shared", action="store_true", help="Print the shared files staged beside managed/ and exit")
args = parser.parse_args()
root = Path(__file__).resolve().parent


def import_closure(start):
    """The shared files start reaches through relative imports, as paths under testifysec/."""
    seen, pending = set(), [start]
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        if name.startswith("../") or posixpath.isabs(name):
            raise SystemExit(f"Shared import leaves testifysec/: {name}")
        seen.add(name)
        if name.endswith(".ts"):
            for ref in re.findall(r'\bfrom\s+"(\.\.?/[^"]+)"', (root.parent / name).read_text()):
                path = posixpath.normpath(posixpath.join(posixpath.dirname(name), ref))
                pending.append(path[:-3] + ".ts" if path.endswith(".js") else path)
    return tuple(sorted(seen))


# Profile v3 parses markings with the shared lattice, its schemes and token tables; every file
# marking.ts imports is staged at the same path relative to managed/ and hashed like every other input.
shared_names = import_closure("marking/marking.ts")
if args.list_shared:
    print("\n".join(shared_names))
    raise SystemExit(0)
if args.trust is None or args.output is None:
    parser.error("--trust and --output are required")
native_root = root.parent / "native"
output = args.output.resolve()
env = dict(os.environ, GOWORK="off", CGO_ENABLED="1", GOFLAGS="-mod=readonly")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def selected(directory, suffixes):
    return {str(path.relative_to(directory)): digest(path.read_bytes())
            for path in sorted(directory.rglob("*"))
            if path.is_file() and path.suffix in suffixes and "dist" not in path.parts}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate trust key")
        result[key] = value
    return result


def go_inputs():
    raw = subprocess.check_output([args.go, "list", "-deps", "-json", "."], cwd=native_root, env=env, text=True)
    decoder = json.JSONDecoder()
    files = set()
    while raw.strip():
        package, end = decoder.raw_decode(raw.lstrip())
        raw = raw.lstrip()[end:]
        if package.get("Standard"):
            continue
        directory = Path(package["Dir"])
        for field in ("GoFiles", "CgoFiles", "CFiles", "CXXFiles", "MFiles", "HFiles", "FFiles", "SFiles", "SysoFiles", "EmbedFiles"):
            files.update(directory / name for name in package.get(field, []))
        module = package.get("Module", {})
        module = module.get("Replace", module)
        if module.get("GoMod"):
            go_mod = Path(module["GoMod"])
            files.add(go_mod)
            if go_mod.with_suffix(".sum").exists():
                files.add(go_mod.with_suffix(".sum"))
    return {str(path): digest(path.read_bytes()) for path in sorted(files)}


trust_bytes = args.trust.read_bytes()
if len(trust_bytes) > 256 * 1024:
    raise SystemExit("Trust configuration too large")
source_files = selected(root, (".go", ".ts", ".py", ".md"))
native_sources = selected(native_root, (".go", ".ts", ".py", ".mod", ".sum"))
shared = lambda: {name: digest((root.parent / name).read_bytes()) for name in shared_names}
shared_sources = shared()
build_tools = {tool: {"path": str(Path(shutil.which(path) or path).resolve()),
                      "sha256": digest(Path(shutil.which(path) or path).read_bytes())}
               for tool, path in (("go", args.go), ("bun", args.bun))}
with tempfile.TemporaryDirectory(prefix="hardened-admission-build-") as temp:
    stage = Path(temp) / "source"
    managed = stage / "managed"
    managed.mkdir(parents=True)
    (stage / "native").mkdir()
    # Compile copies whose exact bytes were hashed, then reject changed source
    # inputs before publishing the manifest. These snapshots are attribution,
    # not a reproducible-build or protected-installation claim.
    for name, expected in source_files.items():
        raw = (root / name).read_bytes()
        if digest(raw) != expected:
            raise SystemExit("Managed input changed while staging")
        target = managed / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    binding = (native_root / "binding.ts").read_bytes()
    if digest(binding) != native_sources["binding.ts"]:
        raise SystemExit("Native binding changed while staging")
    (stage / "native/binding.ts").write_bytes(binding)
    for name, expected in shared_sources.items():
        raw = (root.parent / name).read_bytes()
        if digest(raw) != expected:
            raise SystemExit("Shared input changed while staging")
        (stage / name).parent.mkdir(parents=True, exist_ok=True)
        (stage / name).write_bytes(raw)
    # Validate original tokens before Python can round a noncanonical number.
    subprocess.run([args.bun, str(managed / "validate-trust.ts")], input=trust_bytes, check=True, cwd=managed)
    trust = json.loads(trust_bytes, object_pairs_hook=unique_object)
    inputs = go_inputs()
    native_output = Path(temp) / "native-output"
    subprocess.run(["python3", str(native_root / "build.py"), "--go", args.go, "--bun", args.bun,
                    "--output", str(native_output)], check=True, env=env)
    native = json.loads((native_output / "manifest.json").read_text())
    if native["sourceFiles"] != native_sources:
        raise SystemExit("Native input changed during compilation")
    name = next(file for file in native["files"] if file.startswith("librookery"))
    native_digest = native["files"][name]
    output.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(native_output / name, output / name)
    subprocess.run([
        args.bun, "build", "--compile", "--no-compile-autoload-dotenv", "--no-compile-autoload-bunfig",
        "--no-compile-autoload-package-json", "--no-compile-autoload-tsconfig", "--reject-unresolved",
        "--define", "ROOKERY_LIBRARY_SHA256=" + json.dumps(native_digest),
        "--define", "ROOKERY_LIBRARY_NAME=" + json.dumps(name),
        "--define", "MANAGED_TRUST=" + json.dumps(trust, separators=(",", ":")),
        "--define", "MANAGED_TRUST_SHA256=" + json.dumps(digest(trust_bytes)),
        "--outfile", str(output / "hardened-runtime"), str(managed / "admission-cli.ts"),
    ], cwd=managed, check=True)
    subprocess.run(["python3", str(native_root / "wrap.py"), "--go", args.go,
                    "--runtime", str(output / "hardened-runtime"), "--output", str(output / "hardened-admission")], check=True, env=env)
if selected(root, (".go", ".ts", ".py", ".md")) != source_files or selected(native_root, (".go", ".ts", ".py", ".mod", ".sum")) != native_sources or shared() != shared_sources:
    raise SystemExit("Admission source changed during build")
if go_inputs() != inputs:
    raise SystemExit("Native Go input changed during build")
if any(digest(Path(tool["path"]).read_bytes()) != tool["sha256"] for tool in build_tools.values()):
    raise SystemExit("Build tool changed during build")
manifest = {
    "schema": 1, "component": "hardened-opencode-profile-admission", "scope": "profile-admission-only",
    "profileVersion": trust["schemaVersion"],
    "acceptedPayloadType": "application/vnd.testifysec.hardened-opencode.profile.v" + str(trust["schemaVersion"]) + "+json",
    "revision": native["revision"], "platform": native["platform"], "architecture": native["architecture"],
    "worktreeDirty": native["worktreeDirty"], "nativeBuild": native,
    "sourceFiles": source_files,
    "sharedSourceFiles": shared_sources,
    "nativeGoInputs": {"scope": "selected non-standard Go package files and module inputs; excludes system compiler/SDK and standard-library source", "files": inputs},
    "go": native["go"], "bun": native["bun"], "trustSha256": digest(trust_bytes),
    "buildTools": build_tools,
    "assignment": {key: trust[key] for key in ("tenantId", "deploymentId", "profileId", "minimumSequence")},
    "files": {file: digest((output / file).read_bytes()) for file in (name, "hardened-runtime", "hardened-admission")},
    "releaseQualified": False,
}
if trust["schemaVersion"] == 2:
    manifest["assignment"]["backend"] = trust["backend"]
(output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(output / "manifest.json")
