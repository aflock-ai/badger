"""The model's modules, for the formal step.

    python3 -I -B formal-order.py --modules <commit> <model dir>   # every module the commit has
    python3 -I -B formal-order.py <source dir> <module>...         # in dependency order

--modules lists every .lean file under the model dir in the commit (NUL-delimited, so no path is
quoted or lost) as a module name, and refuses any path that is not a plain Lean module name.

Reads each module's header (the `import` lines before its first command, comments skipped) and
prints the modules in dependency order. An import that is neither Init nor one of the named
modules, or a cycle, is refused. A header that hides an import only makes its compile fail.
"""
import re
import subprocess
import sys
from pathlib import Path


def imports(path):
    text = re.sub(r"/-.*?-/", " ", path.read_text(), flags=re.S)
    text = re.sub(r"--[^\n]*", " ", text)
    out = []
    words = text.split()
    i = 0
    while i < len(words):
        if words[i] == "prelude":
            i += 1
        elif words[i] == "import" and i + 1 < len(words):
            out.append(words[i + 1])
            i += 2
        else:
            break
    return out


def main(src, mods):
    deps = {}
    for m in mods:
        deps[m] = imports(Path(src) / (m.replace(".", "/") + ".lean"))
        for d in deps[m]:
            if d not in mods and d != "Init" and not d.startswith("Init."):
                sys.exit(f"formal-order: {m} imports {d}, which is neither Init nor the model")
    order, state = [], {}

    def visit(m):
        if state.get(m) == "done":
            return
        if state.get(m) == "open":
            sys.exit(f"formal-order: import cycle through {m}")
        state[m] = "open"
        for d in deps[m]:
            if d in deps:
                visit(d)
        state[m] = "done"
        order.append(m)

    for m in sorted(mods):
        visit(m)
    print("\n".join(order))


MODULE_PATH = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(/[A-Za-z_][A-Za-z0-9_]*)*\.lean")


def modules(commit, model):
    out = subprocess.run(["git", "ls-tree", "-r", "-z", "--name-only", "--full-tree", commit, "--", model],
                         check=True, capture_output=True).stdout
    names = []
    for raw in out.split(b"\0"):
        if not raw:
            continue
        path = raw.decode("utf-8", "surrogateescape")
        if not path.startswith(model + "/"):
            sys.exit(f"formal-order: {path!r} is outside {model}")
        rel = path[len(model) + 1:]
        # Anything named like a Lean source is a module and must have a plain name; a file whose
        # name only differs in case or extra suffix would not be compiled, so refuse it too.
        if not rel.lower().rstrip().endswith(".lean"):
            continue
        if not MODULE_PATH.fullmatch(rel):
            sys.exit(f"formal-order: unsupported module name {rel!r}")
        names.append(rel[:-len(".lean")].replace("/", "."))
    if not names:
        sys.exit(f"formal-order: no Lean modules under {model}")
    print("\n".join(names))


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--modules":
        modules(sys.argv[2], sys.argv[3].rstrip("/"))
        sys.exit(0)
    if len(sys.argv) < 3:
        sys.exit("usage: formal-order.py <source dir> <module>...")
    main(sys.argv[1], sys.argv[2:])
