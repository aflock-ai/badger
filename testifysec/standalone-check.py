#!/usr/bin/env python3
"""Prove this checkout builds on its own, with no monorepo or rookery checkout beside it.

    python3 -I testifysec/standalone-check.py --go /path/to/go

Every Go module (each tracked go.mod) must vet and test using only this repository and
published modules; a replace directive that points outside the repository fails. Go source
outside a module must be a fixture listed in FIXTURES, vetted the way its harness builds it,
or a component listed by name in PARKED with the reason it cannot build here. Anything else
fails, as does a FIXTURES or PARKED entry that no longer exists. Python 3 stdlib only.
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Modules whose packages only build for Linux: vetted with GOOS=linux, tests not run here.
LINUX_ONLY = {"testifysec/vm/guest"}

# Single-file fixtures outside any module: (directory to run go from, GOOS), as their harness does.
FIXTURES = {
    "testifysec/commands/fixtures/fixture.go": (".", None),
    "testifysec/integration/fixture_services.go": (".", "linux"),
    "testifysec/managed/fixtures.go": ("testifysec/native", None),
    "testifysec/managed/fixtures-v2.go": ("testifysec/native", None),
    "testifysec/vm/fixtures/managed-worker.go": (".", "linux"),
}

# Not buildable from this repository. Named, never globbed, so the gap stays visible.
PARKED = {}


def tracked(pattern):
    out = subprocess.run(["git", "ls-files", "-z", pattern], cwd=ROOT, capture_output=True, check=True).stdout
    return sorted(p for p in out.decode().split("\0") if p)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--go", required=True)
    args = ap.parse_args()
    env = {**os.environ, "GOWORK": "off", "GOTOOLCHAIN": "local", "GOFLAGS": "-mod=readonly"}
    failures = []

    def go(name, argv, cwd, goos=None):
        result = subprocess.run([args.go, *argv], cwd=ROOT / cwd, capture_output=True, text=True,
                                env={**env, **({"GOOS": goos} if goos else {})})
        status = "ok  " if result.returncode == 0 else "FAIL"
        print(f"{status} {name}: go {' '.join(argv)}" + (f" (GOOS={goos})" if goos else ""), flush=True)
        if result.returncode:
            output = (result.stdout + result.stderr).strip().splitlines()
            # Name the failing tests, not just the module; a tail alone can miss them.
            tests = [line.strip() for line in output if line.lstrip().startswith(("--- FAIL", "FAIL\t", "panic:"))]
            failures.append(name + (" (" + ", ".join(t.removeprefix("--- FAIL: ").split(" (")[0] for t in tests if t.startswith("--- FAIL")) + ")"
                                    if any(t.startswith("--- FAIL") for t in tests) else ""))
            print("\n".join(tests + output[-8:]), flush=True)

    modules = sorted(str(Path(p).parent) for p in tracked("*go.mod"))
    for module in modules:
        edit = subprocess.run([args.go, "mod", "edit", "-json"], cwd=ROOT / module, capture_output=True, text=True, env=env, check=True)
        for replace in json.loads(edit.stdout).get("Replace") or []:
            target = replace["New"]["Path"]
            if target.startswith((".", "/")) and not (ROOT / module / target).resolve().is_relative_to(ROOT):
                failures.append(module)
                print(f"FAIL {module}: replace {replace['Old']['Path']} => {target} leaves the repository", flush=True)
        if module in LINUX_ONLY:
            go(module, ["vet", "./..."], module, "linux")
        else:
            go(module, ["vet", "./..."], module)
            go(module, ["test", "-count=1", "./..."], module)

    for path, (cwd, goos) in FIXTURES.items():
        if not (ROOT / path).is_file():
            failures.append(path)
            print(f"FAIL {path}: listed fixture no longer exists", flush=True)
            continue
        go(path, ["vet", str(ROOT / path)], cwd, goos)

    for directory, reason in PARKED.items():
        if not (ROOT / directory).is_dir():
            failures.append(directory)
            print(f"FAIL {directory}: parked component no longer exists; drop it from PARKED", flush=True)
        else:
            print(f"skip {directory}: {reason}", flush=True)

    for path in tracked("*.go"):
        inside = any(Path(path).is_relative_to(m) for m in modules)
        if not inside and path not in FIXTURES and not any(Path(path).is_relative_to(d) for d in PARKED):
            failures.append(path)
            print(f"FAIL {path}: Go source outside every module, fixture list and parked list", flush=True)

    print(f"{'FAILED' if failures else 'PASSED'}: {len(modules)} modules, {len(FIXTURES)} fixtures, {len(PARKED)} parked", flush=True)
    for name in dict.fromkeys(failures):
        print(f"  failed: {name}", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
