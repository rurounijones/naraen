#!/usr/bin/env bash
# Mutation testing with gremlins (config in .gremlins.yaml).
#
# With a commit as the argument, or in BASE, only the lines changed since BASE are mutated, so
# a push is judged on what it changed in minutes instead of on the whole
# module. Without one, or when it is not a commit this checkout has (a new
# branch or tag reports all zeros), every mutant is tested. The scheduled and
# release runs leave BASE empty, which is what catches a change that weakens a
# test for code that did not change, as the diff run cannot see that.
set -euo pipefail

base="${1:-${BASE:-}}"
if [ -n "$base" ] && ! git cat-file -e "${base}^{commit}" 2>/dev/null; then
  echo "mutation: BASE '$base' is not a commit here, testing every mutant"
  base=""
fi

if [ -z "$base" ]; then
  exec scripts/tool.sh gremlins unleash
fi

# gremlins fails a run with no mutant to test, since its efficacy is then 0%,
# so a change to no Go code at all passes here without running it.
if ! git diff --name-only "$base" -- '*.go' | grep -qv '_test\.go$'; then
  echo "mutation: no Go source changed since $base, nothing to mutate"
  exit 0
fi

echo "mutation: testing the lines changed since $base"
out="$(mktemp)"
trap 'rm -f "$out"' EXIT
status=0
scripts/tool.sh gremlins unleash --diff "$base" 2>&1 | tee "$out" || status=$?
# Changed lines with no mutable operator (a comment, a rename) leave nothing
# to judge, which is not a failure.
if [ "$status" -ne 0 ] && grep -q '^Killed: 0, Lived: 0, Not covered: 0$' "$out"; then
  echo "mutation: the changed lines hold no mutant, nothing to judge"
  exit 0
fi
exit "$status"
