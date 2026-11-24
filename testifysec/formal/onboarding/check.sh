#!/bin/sh
# Check the onboarding model: build, no proof holes, axiom audit, vectors current. Needs Lean
# 4.34.1 (lean-toolchain) on PATH.
#   sh testifysec/formal/onboarding/check.sh           # check
#   sh testifysec/formal/onboarding/check.sh --write   # regenerate vectors/onboarding-vectors.json
set -eu
cd "$(dirname "$0")"
lake build >&2
if grep -rnwE 'sorry|native_decide|admit' Main.lean Onboarding.lean Onboarding; then
  echo "check: proof hole or kernel bypass in the sources" >&2
  exit 1
fi
audit=$(lake env lean Onboarding/Audit.lean)
want=$(grep -c '^#print axioms' Onboarding/Audit.lean)
got=$(printf '%s\n' "$audit" | grep -c 'depends on axioms\|does not depend on any axioms' || true)
if [ "$got" -ne "$want" ] || printf '%s\n' "$audit" | grep -q 'sorryAx\|ofReduceBool\|error'; then
  printf '%s\n' "$audit" >&2
  echo "check: axiom audit failed ($got of $want results)" >&2
  exit 1
fi
if printf '%s\n' "$audit" | grep 'depends on axioms' | grep -v 'axioms: \[\(propext\|Quot.sound\|Classical.choice\)\(, \(propext\|Quot.sound\|Classical.choice\)\)*\]$'; then
  echo "check: a result rests on an axiom outside propext, Quot.sound, Classical.choice" >&2
  exit 1
fi
lake exe onboarding-vectors >vectors/onboarding-vectors.json.tmp
if [ "${1:-}" = --write ]; then
  mv vectors/onboarding-vectors.json.tmp vectors/onboarding-vectors.json
elif ! cmp -s vectors/onboarding-vectors.json.tmp vectors/onboarding-vectors.json; then
  rm -f vectors/onboarding-vectors.json.tmp
  echo "check: vectors/onboarding-vectors.json is stale; run check.sh --write and commit it" >&2
  exit 1
fi
rm -f vectors/onboarding-vectors.json.tmp
echo "check: ok ($want headline results audited, vectors current)"
