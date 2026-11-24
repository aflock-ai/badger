"""Build a native environment-sanitizing launcher for a compiled stdin-only CLI."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--go", default="go")
parser.add_argument("--runtime", required=True, type=Path)
parser.add_argument("--output", required=True, type=Path)
parser.add_argument("--brand-product", action="store_true", help="Embed fixed customer help/version; internal verification CLIs stay stdin-only")
args = parser.parse_args()
runtime = args.runtime.resolve()
output = args.output.resolve()
if runtime.parent != output.parent or runtime == output or not runtime.name.replace("-", "").isalnum():
    raise SystemExit("runtime and launcher must be distinct sibling files with simple names")
digest = hashlib.sha256(runtime.read_bytes()).hexdigest()
flags = f"-X main.runtimeName={runtime.name} -X main.runtimeDigest={digest}"
if args.brand_product:
    source = Path(__file__).resolve().parent
    product = json.loads((source.parent / "branding/product.json").read_text())
    version = (source.parent.parent / "VERSION").read_text().strip()
    upstream = json.loads((source.parent.parent / "packages/cli/package.json").read_text())["version"]
    help_text = (
        f'{product["name"]}\n\n'
        f'Usage: {product["command"]} < request.json\n'
        f'       {product["command"]} --help\n'
        f'       {product["command"]} --version\n\n'
        'Accepts a signed profile and prompt as JSON on stdin.\n'
        'Execution requires the configured admission verifier and isolated broker.\n'
        'Help and version do not start a session or contact a provider.\n\n'
        f'{product["attribution"]}\n'
        'This build does not establish ALPS, FIPS or IL6 qualification.\n'
    )
    version_text = f'{product["name"]} {version}\nOpenCode {upstream}\n{product["attribution"]}\n'
    for name, value in (("helpBase64", help_text), ("versionBase64", version_text)):
        flags += f" -X main.{name}=" + base64.b64encode(value.encode()).decode()
subprocess.run([args.go, "build", "-trimpath", "-ldflags", flags, "-o", str(output), "./launcher"],
               cwd=Path(__file__).resolve().parent, env=dict(os.environ, GOWORK="off", CGO_ENABLED="0"), check=True)
