#!/usr/bin/env bash
# Branch coverage per package using gobco (Go's own tooling has no branch
# coverage). Fails unless every package reports 100%. Packages without tests
# or without branches are skipped, as are packages that hold only test code,
# which have nothing to measure.
#
# gobco copies the module to a temporary directory and builds and links a test
# binary there for each package, which costs 20 to 30 seconds for a package
# with a large dependency graph however few branches it has. The packages are
# measured in parallel (BRANCHCOV_JOBS at a time, default one per CPU), each
# one's output is kept together, and the report is printed in package order.
set -euo pipefail

# gobco builds in temp copies of the tree, where VCS stamping cannot work.
export GOFLAGS="${GOFLAGS:-} -buildvcs=false"

root="$(pwd)"
results="$(mktemp -d)"
trap 'rm -rf "$results"' EXIT
export root results

# check measures one package directory and writes its report to a file of its
# own. It returns non-zero if the package fails or is not fully covered.
check() {
  set -uo pipefail
  local dir="$1" rel report out line cov
  rel="./${dir#"$root"/}"
  report="${rel#./}"
  report="$results/${report//\//_}"
  out="$(scripts/tool.sh gobco -branch "$rel" 2>&1)" || { echo "$out" >"$report"; return 1; }
  line="$(grep '^Branch coverage:' <<<"$out" || true)"
  [ -n "$line" ] || return 0
  echo "$rel $line" >"$report"
  cov="${line#Branch coverage: }"
  if [ "${cov%%/*}" != "${cov##*/}" ]; then
    { grep -v '^ok\|^Branch coverage' <<<"$out" | grep . || true; } >>"$report"
    return 1
  fi
}
export -f check

status=0
go list -f '{{if or .GoFiles .CgoFiles}}{{.Dir}}{{end}}' ./... | grep . |
  xargs -P "${BRANCHCOV_JOBS:-$(nproc)}" -I{} bash -c 'check "$1"' _ {} || status=1

# Every package with branches leaves a report, so none at all means the
# measuring did not happen, which must not pass.
reports=("$results"/*)
if [ ! -e "${reports[0]}" ]; then
  echo "branchcov: no branch coverage was reported" >&2
  exit 1
fi
cat "${reports[@]}"
exit "$status"
