#!/usr/bin/env bash
# Branch coverage per package using gobco (Go's own tooling has no branch
# coverage). Fails unless every package reports 100%. Packages without tests
# or without branches are skipped.
set -euo pipefail

# gobco builds in temp copies of the tree, where VCS stamping cannot work.
export GOFLAGS="${GOFLAGS:-} -buildvcs=false"

status=0
for dir in $(go list -f '{{.Dir}}' ./... ); do
  rel="./${dir#"$(pwd)"/}"
  [ -n "$(ls "$dir"/*.go 2>/dev/null)" ] || continue
  out="$(scripts/tool.sh gobco -branch "$rel" 2>&1)" || { echo "$out"; status=1; continue; }
  line="$(grep '^Branch coverage:' <<<"$out" || true)"
  [ -n "$line" ] || continue
  echo "$rel $line"
  cov="${line#Branch coverage: }"
  if [ "${cov%%/*}" != "${cov##*/}" ]; then
    grep -v '^ok\|^Branch coverage' <<<"$out" | grep . || true
    status=1
  fi
done
exit "$status"
