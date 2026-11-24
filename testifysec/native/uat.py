# jade:ring local
"""HC-01: real compiled executable and native library, synthetic signed fixtures."""
import argparse
from datetime import datetime, timezone
import json
import os
import platform
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--go", default="go")
parser.add_argument("--bun", default="bun")
parser.add_argument("--report", required=True, type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parent
assertions = []
with tempfile.TemporaryDirectory(prefix="hardened-native-") as temp:
    work = Path(temp)
    bundle = work / "bundle"
    subprocess.run(["python3", str(root / "build.py"), "--go", args.go, "--bun", args.bun, "--output", str(bundle)], check=True)
    env = dict(os.environ, GOWORK="off", ROOKERY_TEST_FIXTURES=str(work / "fixtures"))
    subprocess.run([args.go, "test", "-count=1", "./..."], cwd=root, env=env, check=True)
    manifest = json.loads((bundle / "manifest.json").read_text())
    # Minimal environment and foreign cwd: no npm/Node/Go/Bun executable on PATH.
    runtime = {"PATH": "/nonexistent", "HOME": str(work / "home"), "TMPDIR": str(work)}
    def check(name, data, code, predicate):
        result = subprocess.run([str(bundle / "rookery-verify")], input=data, capture_output=True, cwd=work, env=runtime, timeout=30)
        passed = result.returncode == code and predicate(result)
        assertions.append({"id": "HC-01." + name, "passed": passed, "exitCode": result.returncode})
    valid = (work / "fixtures/valid.json").read_bytes()
    check("offline-valid", valid, 0, lambda r: json.loads(r.stdout)["ok"] is True)
    (work / "probe.js").write_text("throw new Error('repository preload executed')")
    (work / "bunfig.toml").write_text('preload = ["./probe.js"]\n')
    check("repository-preload-disabled", valid, 0, lambda r: json.loads(r.stdout)["ok"] is True)
    runtime["BUN_OPTIONS"] = "--preload " + str(work / "probe.js")
    runtime["NODE_OPTIONS"] = "--require " + str(work / "probe.js")
    check("environment-preload-disabled", valid, 0, lambda r: json.loads(r.stdout)["ok"] is True)
    check("wrong-key", (work / "fixtures/invalid.json").read_bytes(), 1, lambda r: json.loads(r.stdout)["ok"] is False)
    changed = json.loads(valid)
    changed["envelope"]["payload"] = "dGFtcGVyZWQ="
    check("tampered", json.dumps(changed).encode(), 1, lambda r: json.loads(r.stdout)["ok"] is False)
    check("duplicate-json", valid.rstrip()[:-1] + b',"threshold":1}', 1, lambda r: json.loads(r.stdout)["ok"] is False)
    check("case-alias", valid.rstrip()[:-1] + b',"Threshold":1}', 1, lambda r: json.loads(r.stdout)["ok"] is False)
    check("oversize", b"x" * (4 * 1024 * 1024 + 1), 2, lambda r: not r.stdout)
    name = next(n for n in manifest["files"] if n.startswith("librookery"))
    marker = work / "unexpected-library-load"
    alternate = work / "alternate.c"
    alternate.write_text('''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
__attribute__((constructor)) static void loaded(void) {
  FILE *f = fopen(MARKER, "w"); if(f) { fputs("loaded", f); fclose(f); }
}
uint32_t RookeryABIVersion(void) { return 1; }
char *RookeryVerify(void *input, size_t length) { return strdup("{\\"abiVersion\\":1,\\"ok\\":true}"); }
void RookeryFree(void *output) { free(output); }
'''.replace("MARKER", json.dumps(str(marker))))
    subprocess.run(["cc", "-dynamiclib" if platform.system() == "Darwin" else "-shared", "-fPIC", str(alternate), "-o", str(bundle / name)], check=True)
    check("library-substitution", valid, 2, lambda r: not r.stdout and not marker.exists())
    (bundle / "rookery-runtime").write_bytes(Path("/bin/echo").read_bytes())
    check("runtime-substitution", valid, 2, lambda r: not r.stdout)
    report = {"story": "HC-01", "timestamp": datetime.now(timezone.utc).isoformat(), "runtime": manifest,
              "assertions": assertions, "limitations": ["Synthetic public-key fixtures; no live platform identity.", "Component CLI only; not upstream OpenCode bootstrap.", "Protected installation required; digest check is not concurrent-writer isolation.", "Darwin is a development build; native launcher's own OS loader protection not qualified.", "Workers must not invoke the internal runtime under controller authority.", "No runtime package tools on PATH; network containment is a later phase."]}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    raise SystemExit(0 if all(a["passed"] for a in assertions) else 1)
