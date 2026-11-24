"""Build the native component bundle; no install, signing or publication."""
import argparse
import hashlib
import json
import platform
from pathlib import Path
import subprocess
import os

parser = argparse.ArgumentParser()
parser.add_argument("--go", default="go")
parser.add_argument("--bun", default="bun")
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parent
output = args.output.resolve()
output.mkdir(parents=True, exist_ok=True)
system = platform.system()
if system not in ("Darwin", "Linux"):
    raise SystemExit("Only native Darwin/Linux component builds supported")
name = "librookery.dylib" if system == "Darwin" else "librookery.so"
env = dict(os.environ, GOWORK="off", CGO_ENABLED="1")
subprocess.run([args.go, "build", "-trimpath", "-buildmode=c-shared", "-o", str(output / name), "."], cwd=root, env=env, check=True)
digest = hashlib.sha256((output / name).read_bytes()).hexdigest()
subprocess.run([
    args.bun, "build", "--compile", "--no-compile-autoload-dotenv", "--no-compile-autoload-bunfig",
    "--no-compile-autoload-package-json", "--no-compile-autoload-tsconfig", "--reject-unresolved",
    "--define", "ROOKERY_LIBRARY_SHA256=" + json.dumps(digest),
    "--define", "ROOKERY_LIBRARY_NAME=" + json.dumps(name),
    "--outfile", str(output / "rookery-runtime"), str(root / "verify-cli.ts"),
], cwd=root, check=True)
subprocess.run(["python3", str(root / "wrap.py"), "--go", args.go, "--runtime", str(output / "rookery-runtime"), "--output", str(output / "rookery-verify")], check=True)
manifest = {
    "schema": 1, "component": "rookery-native-verifier", "abiVersion": 1,
    "platform": system.lower(), "architecture": platform.machine(),
    "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
    "worktreeDirty": bool(subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=root)),
    "sourceFiles": {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob("*")) if p.is_file() and p.suffix in (".go", ".ts", ".py", ".mod", ".sum") and "dist" not in p.parts},
    "go": subprocess.check_output([args.go, "version"], cwd=root, env=env, text=True).strip(),
    "bun": subprocess.check_output([args.bun, "--version"], text=True).strip(),
    "files": {f: hashlib.sha256((output / f).read_bytes()).hexdigest() for f in (name, "rookery-runtime", "rookery-verify")},
    "releaseQualified": False,
}
(output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(output / "manifest.json")
