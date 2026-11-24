#!/bin/sh
# Pushgate step "formal": the platform contract (testifysec/formal/contract). Every check here is
# this script's, mounted read-only from the runner, never the commit's: a commit can change its
# model, its vectors and its tests, but not what this step demands of them.
# Everything it reads comes from the commit's git objects, never the working tree.
#   1. The model builds with Lean 4.34.1 (the image's, /opt/lean): every theorem, every mutant.
#      No Lake and no lakefile: lean compiles each module the commit has from a fresh extract of
#      its committed source, in dependency order (formal-order.py), and the step records each
#      .olean's sha256 right after it is built and its processes are reaped. An .olean that changes
#      afterwards, or goes missing, fails the step.
#   2. formal-audit.lean (this runner's), run by lean itself, reads those .olean files as data
#      without importing them (so none of the commit's code runs), replays every
#      declaration through the kernel on top of Init, and finds no constant under Contract
#      depending on any axiom but propext, Quot.sound and Classical.choice (no sorry or
#      native_decide, however written), and every headline theorem present.
#   3. The vectors the model generates are byte for byte the committed ones (compared in a fresh
#      directory made after the generator is reaped).
#   4. formal-cite.py (this runner's) finds every citation still matching the Go it cites.
#   5. The Go replays every vector through this runner's harness (formal-harness/), run in scratch
#      copies of the packages with the commit's own test files removed; each test must report PASS.
# The commit's own code runs in three places here: Lean while the model builds, the vector
# generator, and the Go packages under test. Between phases, inside the runner's container only,
# the step kills every process but itself and the container's init, so nothing the commit started
# can tamper with a later phase, and every file a later phase reads is written fresh after that.
#
# The boundary, plainly: this step guarantees that a commit cannot skip, fake, or tamper across
# phases with its checks. The commit's own code acting maliciously within its own build or test
# phase (an #eval or initialize in the model while it compiles, an init() in the Go under test)
# is out of scope for this step and covered by diff review, as is a commit that weakens the
# model's own statements. Per-phase containers (#175) narrow this; they cannot remove it, because
# each phase still runs the commit's code.
# `remote.sh` runs this on a worker in a clean checkout of the pushed commit. Locally:
# testifysec/formal/contract/check.sh.
set -eu
steps=$(cd "$(dirname "$0")" && pwd)
model=testifysec/formal/contract
# The image's Lean. FORMAL_LEAN_BIN exists only for formal_test.sh, which points it at its shims so
# the runner's real Lean cannot shadow them; the runner never sets it.
lean_bin=${FORMAL_LEAN_BIN:-/opt/lean/bin}
PATH=$lean_bin:$PATH
fail() { echo "formal: $*" >&2; exit 1; }
# reap: in the runner's container (docker run --init: PID 1 is docker-init, this script is its
# child), kill every process but PID 1 and this one, then check none is left. Never on a host,
# where kill -1 would reach every process of the account.
in_container=false
if [ -f /.dockerenv ] && [ "$(cat /proc/1/comm 2>/dev/null)" = docker-init ] && [ "$PPID" = 1 ]; then
  in_container=true
else
  echo "formal: not in the runner's container; leftover processes are not reaped between phases" >&2
fi
reap() {
  $in_container || return 0
  # Listed in this shell, not a subshell, which would list itself. A killed process stays in /proc
  # until docker-init reaps it, so look again a few times.
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    kill -KILL -1 2>/dev/null || true
    left=
    for d in /proc/[0-9]*; do
      p=${d#/proc/}
      case $p in 1 | "$$") ;; *) [ -d "$d" ] && left="$left $p" ;; esac
    done
    [ -z "$left" ] && return 0
    sleep 0.1
  done
  fail "processes left after a phase: $left"
}
# Every input comes from the commit's git objects (the checkout's .git is mounted read-only), never
# from the working tree, and each phase gets a fresh extract made after the previous phase's
# processes are reaped: code the commit ran earlier can change files, not what later phases read.
head=$(git rev-parse --verify HEAD^{commit}) || fail "not in a git checkout"
# Go, pinned before any of the commit's code runs: the binary and its GOROOT as found now, and no
# persisted configuration ever (GOENV=off), so a go env file written by an earlier phase cannot
# move GOROOT, GOFLAGS or anything else. GOTOOLCHAIN=local: no toolchain switch either.
gobin=$(command -v go) || fail "no go on PATH"
goroot=$(GOENV=off GOTOOLCHAIN=local "$gobin" env GOROOT) || fail "go env GOROOT failed"
gorun() { GOENV=off GOROOT="$goroot" GOTOOLCHAIN=local GOWORK=off GOFLAGS=-mod=readonly "$gobin" "$@"; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
extract() { # extract <dir> <path>...: the commit's blobs, fresh and byte for byte (formal-extract.py:
  # no .gitattributes export-ignore or export-subst, no symbolic link, no submodule)
  dir=$1; shift
  mkdir "$dir"
  python3 -I -B "$steps/formal-extract.py" "$head" "$dir" "$@" || fail "could not extract $* from the commit"
}
want=$(git show "$head:$model/lean-toolchain" | sed -n 's/^leanprover\/lean4:v//p')
[ "$want" = 4.34.1 ] || fail "lean-toolchain pins '$want'; the image has 4.34.1"
case $(lean --version) in *"version $want,"*) ;; *) fail "need Lean $want on PATH" ;; esac
sha() { python3 -I -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$1"; }
fresh() { mktemp -d "$tmp/fresh.XXXXXXXX"; }  # a directory no earlier phase could know or plant
# The model's modules, as the commit has them.
modules=$(python3 -I -B "$steps/formal-order.py" --modules "$head" "$model") || fail "the model's module names are not supported"
extract "$tmp/order" "$model"
# shellcheck disable=SC2086 # one argument per module name
order=$(python3 -I -B "$steps/formal-order.py" "$tmp/order/$model" $modules) || fail "the model's imports do not resolve"

# 1. Build (the commit's Lean runs), one module at a time from its committed source. LEAN_PATH is
# the build directory, which lean searches before its own library, so after every compile it must
# hold exactly the .olean files built so far (each still the one its own compile wrote) and
# nothing else: no file a compile planted, such as an Init/*.olean for a later import to pick up.
out=$tmp/olean
mkdir "$out"
# What was built and each .olean's sha256 live in this shell's memory only, never in a file a
# compile could rewrite.
manifest=
verify() { # the build directory holds exactly the expected .olean files, unchanged
  have=$(cd "$out" && find . ! -type d -print | sort)
  want_=$(printf '%s\n' "$manifest" | sed '/^$/d' | cut -d' ' -f1 | sort)
  [ "$have" = "$want_" ] || fail "the build directory is not exactly what was built"
  # A here-document, not a pipe: fail must stop this shell, not a subshell.
  while read -r f h; do
    [ -n "$f" ] || continue
    [ -f "$out/$f" ] && [ ! -L "$out/$f" ] && [ "$(sha "$out/$f")" = "$h" ] || fail "an .olean changed after it was built: $f"
  done <<MANIFEST
$manifest
MANIFEST
}
for m in $order; do
  rel=$(printf '%s' "$m" | tr . /).lean
  src=$(fresh)/src
  extract "$src" "$model/$rel"
  mkdir -p "$out/$(dirname "$rel")"
  (cd "$src/$model" && LEAN_PATH="$out" lean -R . -o "$out/${rel%.lean}.olean" "$rel") >"$tmp/build.log" 2>&1 ||
    { tail -40 "$tmp/build.log" >&2; fail "$m does not build"; }
  reap
  [ -f "$out/${rel%.lean}.olean" ] && [ ! -L "$out/${rel%.lean}.olean" ] || fail "$m left no .olean"
  manifest="$manifest
./${rel%.lean}.olean $(sha "$out/${rel%.lean}.olean")"
  verify
done

# 2. Audit (none of the commit's code runs).
log=$(fresh)/audit.log
# shellcheck disable=SC2086 # one argument per module name
(cd "$tmp" && lean --run "$steps/formal-audit.lean" "$out" $modules) >"$log" 2>&1 ||
  { cat "$log" >&2; fail "the axiom audit failed"; }
grep -q '^audit: ok ' "$log" || { cat "$log" >&2; fail "the axiom audit reported nothing"; }
cat "$log"

# 3. Vectors (the commit's generator runs), against the committed file.
gen=$(fresh)
extract "$gen/src" "$model/Main.lean"
verify
(cd "$gen/src/$model" && LEAN_PATH="$out" lean --run Main.lean) >"$gen/vectors.json" || fail "contract-vectors failed"
reap
[ -f "$gen/vectors.json" ] && [ ! -L "$gen/vectors.json" ] || fail "the generator's output is not a plain file"
cmpdir=$(fresh)
cp "$gen/vectors.json" "$cmpdir/generated.json"
git show "$head:$model/vectors/contract-vectors.json" >"$cmpdir/committed.json"
if ! cmp -s "$cmpdir/generated.json" "$cmpdir/committed.json"; then
  diff "$cmpdir/committed.json" "$cmpdir/generated.json" | head -40 >&2 || true
  fail "$model/vectors/contract-vectors.json is not what the model generates (check.sh --write)"
fi

# 4. Citations, over a fresh extract.
cite=$(fresh)/tree
extract "$cite" testifysec  # a citation may point anywhere under testifysec/
python3 -I -B "$steps/formal-cite.py" "$cite" "$model"

# 5. The Go replay (the code under test runs), each package in a fresh extract with the commit's
# test files out and this runner's harness in, reading the committed vectors. GOFLAGS is set, not
# inherited: an inherited -run=^$ or -short would pass with nothing run.
replay() { # replay <module> <package dir> <harness file> <test>...
  mod=$1 pkg=$2 harness=$3; shift 3
  go=$(fresh)
  rmdir "$go"
  extract "$go" testifysec/connectors testifysec/broker testifysec/platform
  dir=$go/testifysec/$mod/$pkg
  [ -d "$dir" ] || fail "$mod/$pkg is not a directory"
  find "$dir" -maxdepth 1 -name '*_test.go' -exec rm -f {} +
  cp "$steps/formal-harness/$harness" "$dir/formal_contract_test.go"
  git show "$head:$model/vectors/contract-vectors.json" >"$go/vectors.json"
  # Earlier phases ran the commit's code with the build and module caches writable. In the runner's
  # container the build cache is emptied first; everywhere the module cache must still match go.sum.
  if $in_container; then gorun clean -cache >/dev/null 2>&1 || fail "could not empty the Go build cache"; fi
  (cd "$go/testifysec/$mod" && gorun mod verify) >/dev/null 2>&1 || fail "the Go module cache does not match go.sum for $mod"
  # go mod verify skips local replacements: each must resolve inside this fresh extract, never to a
  # directory an earlier phase could have written.
  (cd "$go/testifysec/$mod" && gorun mod edit -json) >"$go/mod.json" 2>/dev/null || fail "go mod edit -json failed for $mod"
  python3 -I -c 'import json, os, sys
root = os.path.realpath(sys.argv[2])
for r in json.load(open(sys.argv[1])).get("Replace") or []:
    p = r["New"]["Path"]
    if r["New"].get("Version"):
        continue
    full = os.path.realpath(os.path.join(sys.argv[3], p))
    if os.path.commonpath([root, full]) != root:
        sys.exit("formal: %s replaces %s with a path outside the commit: %s" % (sys.argv[4], r["Old"]["Path"], p))
' "$go/mod.json" "$go" "$go/testifysec/$mod" "$mod" || fail "$mod replaces a module with a path outside the commit"
  rc=0
  (cd "$go/testifysec/$mod" && CONTRACT_VECTORS="$go/vectors.json" \
    gorun test -count=1 -v -run '^TestContractVectors' "./$pkg/") >"$go/go.log" 2>&1 || rc=$?
  reap
  [ -f "$go/go.log" ] && [ ! -L "$go/go.log" ] || fail "the replay's log is not a plain file"
  gl=$(fresh)/go.log
  cp "$go/go.log" "$gl"
  [ "$rc" = 0 ] || { tail -40 "$gl" >&2; fail "the Go disagrees with the vectors in $mod/$pkg"; }
  for t in "$@"; do
    grep -q -- "^--- PASS: $t " "$gl" || { tail -40 "$gl" >&2; fail "$t did not run and pass"; }
  done
}
replay connectors internal/marking marking_test.go TestContractVectorsTables TestContractVectorsDominates \
  TestContractVectorsJoin TestContractVectorsFlow
replay broker vzbackend vzbackend_test.go TestContractVectorsAdmission
echo "formal: model, audit, vectors, citations and Go agree"
