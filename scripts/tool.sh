#!/usr/bin/env bash
# Runs a Go tool pinned in tools/go.mod. The tools are their own module so
# that their dependencies stay out of the server's module graph, and with it
# out of vulnerability scans, Dependabot and dependency review of the server.
# `go tool -n` builds the tool in that module and prints its path; the tool
# then runs here, in the caller's directory, against the server module.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
name="$1"
shift
bin="$(go -C "$root/tools" tool -n "$name")"
exec "$bin" "$@"
