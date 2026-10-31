#!/usr/bin/env bash
# Needs jq on the host.
# Dynamic security testing against the real server running under compose.
# Every tool is a blocking gate: any finding at or above the configured level
# fails the script. Requires Docker.
#
# Nothing is bind-mounted. Each tool's inputs are streamed into its container
# as a tar and its reports copied out through the Docker API, so the script
# runs the same from the host and from inside the devcontainer, whose paths
# the Docker host cannot see.
set -euo pipefail

cd "$(dirname "$0")/.."
# Git Bash on Windows would rewrite container paths such as /zap into C:/...
export MSYS_NO_PATHCONV=1
compose=(docker compose -f docker-compose.yml)
dast=("${compose[@]}" --profile dast)
tools=(zap-api zap-baseline testssl nuclei ssh-audit)
mkdir -p dast-reports
# Each tool's inputs are staged here before they are streamed in.
stage="$(mktemp -d)"

# A stack that was already up (the developer's, or the devcontainer's own) is
# left running; one this script started is removed again.
started=""
[ -n "$("${compose[@]}" ps -q s3)" ] || started=1
cleanup() {
  rm -rf "$stage"
  "${dast[@]}" rm -fsv "${tools[@]}" >/dev/null 2>&1 || true
  if [ -n "$started" ]; then "${dast[@]}" down -v --remove-orphans >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

"${compose[@]}" up -d --build --wait naraen client

# The stack must work end to end before it is scanned: a server that failed
# to reach its storage would hide every finding behind the Batch API. The
# walkthrough runs from the client container, which resolves the stack's
# names without touching the host's hosts file.
"${compose[@]}" exec -T client naraen-smoke

# run <service> [<dir> <container dir> <uid>]: creates the tool's container,
# streams dir into container dir owned by uid (the tool's user, which may need
# to write there), then runs it attached and returns its status.
run() {
  local svc="$1" id
  "${dast[@]}" rm -fsv "$svc" >/dev/null 2>&1 || true
  "${dast[@]}" create "$svc" >/dev/null 2>&1
  id="$("${dast[@]}" ps -aq "$svc")"
  if [ $# -gt 1 ]; then
    tar -c --owner="$4" --group="$4" -C "$(dirname "$2")" "$(basename "$2")" | docker cp -a -q - "$id:$3"
  fi
  docker start -a "$id"
}

# report <service> <path>: copies a report out of the tool's container.
report() { docker cp -q "$("${dast[@]}" ps -aq "$1"):$2" dast-reports/; }

# HTTPS: ZAP API scan from the OpenAPI spec, authenticated, then a baseline
# scan. Each endpoint gets the credential its real clients present, and
# .zap/auth_hook.py makes ZAP send it: for the Batch API, the writer's token
# for example/repo, minted over SSH from the client like any developer's; for
# the CI token exchange, an OIDC token for example/repo from the dev issuer,
# as a CI job gets one; for the GitHub webhook, a signature over each body
# with the dev webhook secret, as GitHub signs deliveries. The tokens reach
# the ZAP container's environment and the secret its work directory, never a
# file in dast-reports, which CI uploads.
token="$("${compose[@]}" exec -T client ssh naraen git-lfs-authenticate example/repo upload | jq -r .header.Authorization)"
case "$token" in Bearer\ ?*) ;; *) echo "no token from git-lfs-authenticate" >&2; exit 1 ;; esac
export NARAEN_DAST_TOKEN="$token"
oidc="$("${compose[@]}" exec -T client curl -fsS "http://oidc:8080/token?audience=naraen-dev&repository_id=1&repository=example/repo" | jq -r .value)"
case "$oidc" in ey?*) ;; *) echo "no token from the dev OIDC issuer" >&2; exit 1 ;; esac
export NARAEN_DAST_OIDC_TOKEN="Bearer $oidc"
# ZAP requires /zap/wrk, which its image lacks, and writes its reports there.
mkdir -p "$stage/zap-api/wrk" "$stage/zap-baseline/wrk" "$stage/ssh-audit/policy"
cp api/openapi.yaml .zap/rules.tsv .zap/auth_hook.py .zap/sign_webhook.js test/testdata/devkeys/webhook.secret "$stage/zap-api/wrk/"
cp .zap/rules.tsv "$stage/zap-baseline/wrk/"
cp .ssh-audit/naraen.policy "$stage/ssh-audit/policy/"
since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
rc=0
run zap-api "$stage/zap-api/wrk" /zap 1000 || rc=$?
report zap-api /zap/wrk/zap-api.html
[ "$rc" -eq 0 ] || exit "$rc"
# The scan must have got past authentication at every endpoint: a credential
# ZAP failed to send, or one the server refused, would leave every request at
# a 401 and the scan passing for the wrong reason. A webhook delivery got past
# its signature check when it was applied or refused only as malformed.
logs="$("${compose[@]}" logs --no-log-prefix --since "$since" naraen)"
issued="$(grep -c '"msg":"links issued".*"identity":"writer"' <<<"$logs" || true)"
exchanged="$(grep -c '"msg":"token issued".*"identity":"workload:1"' <<<"$logs" || true)"
signed="$(grep -cE '"msg":"webhook applied"|"msg":"webhook refused".*"reason":"malformed"' <<<"$logs" || true)"
if [ "$issued" -eq 0 ] || [ "$exchanged" -eq 0 ] || [ "$signed" -eq 0 ]; then
  echo "the authenticated ZAP scan did not pass authentication: $issued Batch requests, $exchanged token exchanges, $signed webhook deliveries" >&2
  exit 1
fi
echo "authenticated ZAP scan: $issued Batch requests, $exchanged CI token exchanges and $signed webhook deliveries passed authentication"

rc=0
run zap-baseline "$stage/zap-baseline/wrk" /zap 1000 || rc=$?
report zap-baseline /zap/wrk/zap-baseline.html
[ "$rc" -eq 0 ] || exit "$rc"

# HTTPS: protocol and cipher posture (TLS 1.3 only, no weak suites).
rm -f dast-reports/testssl.json
run testssl
report testssl /tmp/testssl.json
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
nuclei_out="$(run nuclei 2>&1)"
echo "$nuclei_out"
if grep -Eq '^\[[^]]+\] \[[^]]+\] \[(info|low|medium|high|critical)\]' <<<"$nuclei_out"; then
  echo "nuclei reported findings" >&2
  exit 1
fi

# SSH: algorithm posture, checked against .ssh-audit/naraen.policy.
run ssh-audit "$stage/ssh-audit/policy" / 0
