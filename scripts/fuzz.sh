#!/usr/bin/env bash
# Runs every Fuzz* target for $FUZZTIME (default 20s). Go can fuzz only one
# target per invocation, so enumerate them. Fails on the first crash; new
# crashers are written under testdata/fuzz/ and must be committed.
set -euo pipefail

fuzztime="${FUZZTIME:-20s}"
status=0

while IFS= read -r pkg; do
  for target in $(go test -list '^Fuzz' "$pkg" | grep '^Fuzz' || true); do
    echo "==> $pkg $target ($fuzztime)"
    go test "$pkg" -run='^$' -fuzz="^${target}\$" -fuzztime="$fuzztime" || status=1
  done
done < <(go list ./...)

exit "$status"
