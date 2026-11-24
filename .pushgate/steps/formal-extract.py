"""Extract paths of a commit from its git objects, byte for byte, for the formal step.

    python3 -I -B formal-extract.py <commit> <dest dir> <path>...

Unlike git archive, nothing in the commit can change what is written: .gitattributes
(export-ignore, export-subst, eol, filters) is not consulted, and every blob is written exactly as
stored. A symbolic link or a submodule anywhere in the paths is refused.
"""
import os
import subprocess
import sys


def main(commit, dest, paths):
    tree = subprocess.run(["git", "ls-tree", "-r", "-z", "--full-tree", commit, "--", *paths],
                          check=True, capture_output=True).stdout
    entries = []
    for rec in tree.split(b"\0"):
        if not rec:
            continue
        meta, path = rec.split(b"\t", 1)
        mode, kind, oid = meta.split(b" ")
        path = path.decode()
        if kind != b"blob" or mode not in (b"100644", b"100755"):
            sys.exit(f"formal-extract: {path} is a {kind.decode()} (mode {mode.decode()}); refused")
        parts = path.split("/")
        if any(p in ("", ".", "..") for p in parts):
            sys.exit(f"formal-extract: {path} is not a plain relative path")
        entries.append((path, oid))
    if not entries:
        sys.exit(f"formal-extract: nothing at {' '.join(paths)} in {commit}")
    cat = subprocess.Popen(["git", "cat-file", "--batch"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    for path, oid in entries:
        cat.stdin.write(oid + b"\n")
        cat.stdin.flush()
        header = cat.stdout.readline().split()
        size = int(header[2])
        data = cat.stdout.read(size)
        cat.stdout.read(1)
        out = os.path.join(dest, path)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "xb") as f:
            f.write(data)
    cat.stdin.close()
    if cat.wait() != 0:
        sys.exit("formal-extract: git cat-file failed")


if __name__ == "__main__":
    if len(sys.argv) < 4:
        sys.exit("usage: formal-extract.py <commit> <dest dir> <path>...")
    main(sys.argv[1], sys.argv[2], sys.argv[3:])
