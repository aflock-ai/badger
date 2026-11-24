"""Check the Lean model's citations against the repository it sits in. The formal step's own
script, never the commit's (proof holes are the axiom audit's job, formal-audit.lean).

    python3 -I -B .pushgate/steps/formal-cite.py <repo root> <model dir>         # exit 1 if stale
    python3 -I -B .pushgate/steps/formal-cite.py <repo root> <model dir> --fix   # rewrite sha256s

A citation is `-- cite: <path from the repository root>:<start>-<end> sha256:<hex>` (or
`:<line>`). The digest is sha256 over the cited lines, each followed by a newline, the
convention the platform's own models use. A changed, moved or deleted line fails the check,
so the AsBuilt transcription is re-read whenever the Go it describes changes.
"""
import hashlib
import re
import sys
from pathlib import Path

CITE = re.compile(r"--\s*cite:\s*(\S+?):(\d+)(?:-(\d+))?\s+sha256:([0-9a-f]+)\s*$")


def digest(ROOT, path, start, end):
    lines = (ROOT / path).read_text().split("\n")
    if (ROOT / path).read_text().endswith("\n"):
        lines = lines[:-1]
    if not 1 <= start <= end <= len(lines):
        return None
    return hashlib.sha256("".join(l + "\n" for l in lines[start - 1:end]).encode()).hexdigest()


def main(ROOT, HERE, fix):
    bad, cites = [], 0
    for lean in sorted(HERE.glob("**/*.lean")):
        if ".lake" in lean.parts:
            continue
        text = lean.read_text().split("\n")
        changed = False
        for i, line in enumerate(text):
            m = CITE.search(line)
            if not m:
                if "cite:" in line:
                    bad.append(f"{lean.relative_to(HERE)}:{i + 1}: malformed citation")
                continue
            cites += 1
            path, start = m.group(1), int(m.group(2))
            end = int(m.group(3) or start)
            if ROOT not in (ROOT / path).resolve().parents or not (ROOT / path).is_file():
                bad.append(f"{lean.relative_to(HERE)}:{i + 1}: {path} does not exist")
                continue
            want = digest(ROOT, path, start, end)
            if want is None:
                bad.append(f"{lean.relative_to(HERE)}:{i + 1}: {path}:{start}-{end} is past the end of the file")
            elif want != m.group(4):
                if fix:
                    text[i] = line[:m.start(4)] + want + line[m.end(4):]
                    changed = True
                else:
                    bad.append(f"{lean.relative_to(HERE)}:{i + 1}: {path}:{start}-{end} changed since it was cited")
        if changed:
            lean.write_text("\n".join(text))
    for b in bad:
        print(b, file=sys.stderr)
    if not cites:
        print("formal-cite: no citations found", file=sys.stderr)
        return 1
    print(f"formal-cite: {cites} citations, {len(bad)} problems")
    return 1 if bad else 0


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("usage: formal-cite.py <repo root> <model dir> [--fix]")
    root = Path(sys.argv[1]).resolve()
    sys.exit(main(root, (root / sys.argv[2]).resolve(), "--fix" in sys.argv[3:]))
