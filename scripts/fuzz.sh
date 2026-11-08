#!/usr/bin/env bash
# Runs every Fuzz* target for $FUZZTIME (default 20s). Go can fuzz only one
# target per invocation, so enumerate them. Fails on the first crash; new
# crashers are written under testdata/fuzz/ and must be committed.
#
# With a commit as the argument, or in BASE, only the packages that changed since BASE are
# fuzzed, counting a package as changed when it or any package of this module
# that it imports changed, because a parser fuzzed in one package runs the
# code of the others. A change to go.mod or go.sum, to this script, or a
# BASE that is not a commit in this checkout (a new branch or tag reports all
# zeros) fuzzes everything. The scheduled and release runs leave BASE empty.
set -euo pipefail

fuzztime="${FUZZTIME:-20s}"
status=0
base="${1:-${BASE:-}}"
module="$(go list -m)"

if [ -n "$base" ] && ! git cat-file -e "${base}^{commit}" 2>/dev/null; then
  echo "fuzz: BASE '$base' is not a commit here, fuzzing every package"
  base=""
fi

declare -A changed=()
if [ -n "$base" ]; then
  while IFS= read -r file; do
    case "$file" in
      go.mod | go.sum | scripts/fuzz.sh) base="" ; break ;;
    esac
    dir="$(dirname "$file")"
    # A new crasher or corpus entry belongs to the package that owns testdata.
    changed["${dir%%/testdata*}"]=1
  done < <(git diff --name-only "$base")
fi

# affected reports whether the package or a module package it imports changed.
affected() {
  [ -z "$base" ] && return 0
  local rel dep
  for dep in "$1" $(go list -f '{{join .Deps " "}}' "$1" | tr ' ' '\n' | grep "^${module}/" || true); do
    rel="${dep#"$module"}"
    rel="${rel#/}"
    [ -n "${changed[${rel:-.}]:-}" ] && return 0
  done
  return 1
}

while IFS= read -r pkg; do
  targets="$(go test -list '^Fuzz' "$pkg" | grep '^Fuzz' || true)"
  [ -n "$targets" ] || continue
  if ! affected "$pkg"; then
    echo "==> $pkg unchanged since $base, skipped"
    continue
  fi
  for target in $targets; do
    echo "==> $pkg $target ($fuzztime)"
    go test "$pkg" -run='^$' -fuzz="^${target}\$" -fuzztime="$fuzztime" || status=1
  done
done < <(go list ./...)

exit "$status"
