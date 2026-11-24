#!/bin/sh
# Check the platform contract locally, exactly as the pushgate "formal" step does
# (.pushgate/steps/formal.sh: build, axiom audit, vectors, citations, Go replay). Needs Lean
# 4.34.1 (lean-toolchain) on PATH. The step checks HEAD, not the working tree: commit first (after
# --write, commit what it wrote, then run it again).
#   sh testifysec/formal/contract/check.sh           # check
#   sh testifysec/formal/contract/check.sh --write   # regenerate vectors and citations first
set -eu
root=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$root"
if [ "${1:-}" = --write ]; then
  python3 -I -B .pushgate/steps/formal-cite.py . testifysec/formal/contract --fix
  (cd testifysec/formal/contract && lake build >&2 &&
    lake exe contract-vectors >vectors/contract-vectors.json.tmp &&
    mv vectors/contract-vectors.json.tmp vectors/contract-vectors.json)
fi
exec sh .pushgate/steps/formal.sh
