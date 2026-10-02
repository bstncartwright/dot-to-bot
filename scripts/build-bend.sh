#!/bin/sh
# Compile with the inspected Bend 2 source checkout. No installer or remote code.
set -eu
: "${BEND_SOURCE:?Set BEND_SOURCE to a Bend 2 checkout}"
expected=7d24b8d0235cb9781140512c0f163c48ea84a719
actual=$(git -C "$BEND_SOURCE" rev-parse HEAD)
[ "$actual" = "$expected" ] || { echo 'Unexpected Bend compiler revision' >&2; exit 1; }
cd "$(dirname "$0")/.."
proof_output=$(bun "$BEND_SOURCE/bend2/main.ts" PROOF.bend)
printf "%s\n" "$proof_output"
case "$proof_output" in
  *"SOME PROOFS FAIL"*) exit 1 ;;
  *"ALL PROOFS CHECK"*) ;;
  *) echo "Proof gate did not confirm success" >&2; exit 1 ;;
esac
rm -f bend/policy
bun "$BEND_SOURCE/bend2/main.ts" bend/policy.bend -o bend/policy
