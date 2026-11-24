"""HC-00: verify the complete imported source tree without network access."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from datetime import datetime, timezone

root = Path(__file__).resolve().parents[2]


def git_object(kind, value):
    return hashlib.sha1(kind + b" " + str(len(value)).encode() + b"\0" + value).digest()


def tree(path):
    entries = []
    for item in path.iterdir():
        if path == root and item.name == "testifysec":
            continue
        mode = item.lstat().st_mode
        if stat.S_ISLNK(mode):
            entries.append((item.name.encode(), b"120000", git_object(b"blob", os.fsencode(os.readlink(item)))))
        elif stat.S_ISDIR(mode):
            entries.append((item.name.encode() + b"/", b"40000", tree(item)))
        elif stat.S_ISREG(mode):
            entries.append((item.name.encode(), b"100755" if mode & 0o111 else b"100644", git_object(b"blob", item.read_bytes())))
        else:
            raise ValueError(f"unsupported source entry: {item}")
    return git_object(b"tree", b"".join(mode + b" " + name.rstrip(b"/") + b"\0" + digest for name, mode, digest in sorted(entries)))


if len(sys.argv) != 2:
    raise SystemExit("usage: python3 testifysec/uat/import.py /absolute/report.json")
actual = tree(root).hex()
expected = (root / "testifysec/upstream.tree").read_text().strip()
report = {
    "story": "HC-00", "scope": "pinned upstream import, excluding TestifySec overlay",
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "revision": subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip(),
    "upstreamRevision": (root / "testifysec/upstream.commit").read_text().strip(),
    "assertions": [{"id": "HC-00.exact-tree", "passed": actual == expected, "expected": expected, "observed": actual}],
    "limitations": ["Import integrity only; not runtime hardening or release provenance."],
}
output = Path(sys.argv[1])
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report))
raise SystemExit(0 if actual == expected else 1)
