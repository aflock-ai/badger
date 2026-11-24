#!/usr/bin/env python3
"""Build the embedded native enrollment backend from canonical Cilock sources."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
MODULE = ROOT / 'subtrees/rookery/cilock'
if not (MODULE / 'enrollment').is_dir():
    # Parked: the cilock enrollment package this builds no longer exists in any reachable
    # source (public rookery or the current monorepo tree); see README.md.
    raise SystemExit('enrollment build parked: rookery/cilock/enrollment is not available; see testifysec/enrollment/README.md')
PACKAGES = ['./enrollment', './internal/auth', './cmd/hardened-enroll']

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def inventory(go, env):
    data = subprocess.check_output([go, 'list', '-mod=readonly', '-deps', '-test', '-json', *PACKAGES], cwd=MODULE, env=env, text=True)
    decoder = json.JSONDecoder()
    paths = {HERE / 'build.py', HERE / 'uat.py', MODULE / 'go.mod', MODULE / 'go.sum'}
    while data.strip():
        obj, end = decoder.raw_decode(data.lstrip())
        data = data.lstrip()[end:]
        directory = Path(obj.get('Dir', '/'))
        if directory.is_relative_to(ROOT):
            for key in ('GoFiles', 'CgoFiles', 'CFiles', 'HFiles', 'SFiles', 'EmbedFiles', 'TestGoFiles', 'XTestGoFiles'):
                for name in obj.get(key, []):
                    path = directory / name
                    if path.is_relative_to(ROOT) and path.is_file():
                        paths.add(path)
            module = obj.get('Module', {})
            module = module.get('Replace', module)
            if module.get('Dir'):
                for name in ('go.mod', 'go.sum'):
                    path = Path(module['Dir']) / name
                    if path.is_relative_to(ROOT) and path.is_file():
                        paths.add(path)
    return {str(path.relative_to(ROOT)): digest(path) for path in sorted(paths)}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--go', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--uat', action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, 'GOWORK':'off', 'GOTOOLCHAIN':'local', 'GOPROXY':'off', 'GOSUMDB':'off', 'CGO_ENABLED':'0', 'GOMAXPROCS':'4'}
    sources = inventory(args.go, env)
    subprocess.run([args.go, 'build', '-mod=readonly', '-p', '2', '-trimpath', '-buildvcs=false', '-o', str(output), './cmd/hardened-enroll'], cwd=MODULE, env=env, check=True)
    if args.uat:
        result = subprocess.run([args.go, 'test', '-mod=readonly', '-p', '2', '-count=1', '-json', *PACKAGES], cwd=MODULE, env=env, text=True, capture_output=True)
        output.with_suffix('.tests.jsonl').write_text(result.stdout + result.stderr)
        if result.returncode:
            raise SystemExit('canonical enrollment/auth tests failed; inspect local .tests.jsonl')
        subprocess.run(['python3', str(HERE / 'uat.py'), '--binary', str(output), '--report', str(output.with_suffix('.uat.json'))], check=True)
    if sources != inventory(args.go, env):
        raise SystemExit('source bytes changed during enrollment build/UAT; refusing manifest')
    manifest = {'schema':'testifysec.hardened-code.enrollment-build/v1', 'binarySha256':digest(output), 'goSha256':digest(Path(args.go)), 'sources':sources, 'runtimeDependencies':'native OS browser opener and platform HTTPS; no cilock/npm install', 'authenticity':'unsigned local build manifest; not release authorization', 'binaryMeasurement':'executable-path-readback-not-runtime-measurement'}
    output.with_suffix('.manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True)+'\n')
    print(json.dumps({'binary':str(output),'sha256':manifest['binarySha256'],'sourceFiles':len(sources)}))

if __name__ == '__main__':
    main()
