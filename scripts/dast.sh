#!/usr/bin/env bash
# Needs jq, git, git-lfs and ssh on the host.
# Dynamic security testing against the real server running under compose.
# Every tool is a blocking gate: any finding at or above the configured level
# fails the script. Requires Docker.
set -euo pipefail

cd "$(dirname "$0")/.."
compose=(docker compose -f docker-compose.yml)
mkdir -p dast-reports
chmod 777 dast-reports # ZAP runs as a non-root user

# A stack that was already up (the developer's, or the devcontainer's own,
# which shares its network namespace) is left running; one this script
# started is removed again.
if [ -z "$("${compose[@]}" ps -q s3)" ]; then
  cleanup() { "${compose[@]}" --profile dast down -v --remove-orphans >/dev/null 2>&1 || true; }
  trap cleanup EXIT
fi

"${compose[@]}" up -d --build --wait naraen

# The stack must work end to end before it is scanned: a server that failed
# to reach its storage would hide every finding behind the Batch API.
scripts/smoke.sh

# HTTPS: ZAP API scan from the OpenAPI spec, then a baseline scan.
"${compose[@]}" --profile dast run --rm zap-api
"${compose[@]}" --profile dast run --rm zap-baseline

# HTTPS: protocol and cipher posture (TLS 1.3 only, no weak suites).
rm -f dast-reports/testssl.json
"${compose[@]}" --profile dast run --rm testssl
# Fail on any MEDIUM or worse finding. Certificate trust findings are expected
# because the development certificate is self-signed.
bad="$(jq -c '.[] | select((.severity=="MEDIUM" or .severity=="HIGH" or .severity=="CRITICAL") and (.id | startswith("cert") | not))' < dast-reports/testssl.json)"
if [ -n "$bad" ]; then
  echo "testssl.sh findings:" >&2
  echo "$bad" >&2
  exit 1
fi

# HTTPS: template-based checks.
# nuclei exits 0 even with findings, so any reported finding fails the run.
# self-signed-ssl is excluded in the compose file: the development certificate
# is self-signed by design.
nuclei_out="$("${compose[@]}" --profile dast run --rm nuclei 2>&1)"
echo "$nuclei_out"
if grep -Eq '^\[[^]]+\] \[[^]]+\] \[(info|low|medium|high|critical)\]' <<<"$nuclei_out"; then
  echo "nuclei reported findings" >&2
  exit 1
fi

# SSH: algorithm posture, checked against .ssh-audit/naraen.policy.
"${compose[@]}" --profile dast run --rm ssh-audit
