"""Compile the native managed host; upstream OpenCode remains inside its worker."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--go", default="go")
parser.add_argument("--bun", default="bun")
parser.add_argument("--trust", required=True, type=Path)
parser.add_argument("--broker-socket", required=True, type=Path)
parser.add_argument("--workspace", required=True)
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parent
output = args.output.resolve()
if not args.broker_socket.is_absolute() or not args.workspace or len(args.workspace) > 64:
    raise SystemExit("Administrator must provision an absolute broker socket and bounded workspace ID")
trust_bytes = args.trust.read_bytes()
try:
    selected = json.loads(trust_bytes)
except (ValueError, UnicodeDecodeError):
    raise SystemExit("Legacy managed host requires version 1 trust")
if not isinstance(selected, dict) or type(selected.get("schemaVersion")) is not int or selected["schemaVersion"] != 1:
    raise SystemExit("Legacy managed host requires version 1 trust; VZ admission is not runtime integration")
output.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix="hardened-host-build-") as temp:
    trust_input = Path(temp) / "trust.json"
    trust_input.write_bytes(trust_bytes)
    subprocess.run(["python3", str(root.parent / "managed/build.py"), "--go", args.go, "--bun", args.bun,
                    "--trust", str(trust_input), "--output", temp], check=True)
    admission = json.loads((Path(temp) / "manifest.json").read_text())
    library = next(name for name in admission["files"] if name.startswith("librookery"))
    for name in admission["files"]:
        shutil.copy2(Path(temp) / name, output / name)
    trust = json.loads(trust_bytes)
    defines = {
        "MANAGED_TRUST": trust, "MANAGED_TRUST_SHA256": admission["trustSha256"],
        "ROOKERY_LIBRARY_NAME": library, "ROOKERY_LIBRARY_SHA256": admission["files"][library],
        "RUNTIME_BROKER_SOCKET": str(args.broker_socket), "RUNTIME_WORKSPACE_ID": args.workspace,
    }
    command = [args.bun, "build", "--compile", "--no-compile-autoload-dotenv", "--no-compile-autoload-bunfig",
               "--no-compile-autoload-package-json", "--no-compile-autoload-tsconfig", "--reject-unresolved"]
    for name, value in defines.items():
        command += ["--define", name + "=" + json.dumps(value)]
    command += ["--outfile", str(output / "hardened-host-runtime"), str(root / "host.ts")]
    subprocess.run(command, check=True, cwd=root)
subprocess.run(["python3", str(root.parent / "native/wrap.py"), "--go", args.go,
                "--runtime", str(output / "hardened-host-runtime"), "--output", str(output / "hardened-code"),
                "--brand-product"], check=True)
manifest = {
    "schema": 1, "component": "hardened-opencode-managed-host", "admissionBuild": admission,
    "brokerSocket": str(args.broker_socket), "workspace": args.workspace,
    "product": {**json.loads((root.parent / "branding/product.json").read_text()),
                "version": (root.parent.parent / "VERSION").read_text().strip()},
    "upstreamVersion": json.loads((root.parent.parent / "packages/cli/package.json").read_text())["version"],
    "files": {name: hashlib.sha256((output / name).read_bytes()).hexdigest()
              for name in (*admission["files"], "hardened-host-runtime", "hardened-code")},
    "sourceFiles": {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in sorted(root.iterdir()) if path.is_file() and path.suffix in (".py", ".ts")},
    "brandingSourceFiles": {str(path.relative_to(root.parent.parent)): hashlib.sha256(path.read_bytes()).hexdigest()
                            for path in (root.parent / "branding/product.json", root.parent.parent / "VERSION",
                                         root.parent.parent / "packages/cli/package.json",
                                         root.parent / "native/wrap.py", root.parent / "native/launcher/main.go")},
    "releaseQualified": False,
}
(output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(output / "manifest.json")
