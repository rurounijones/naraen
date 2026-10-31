#!/usr/bin/env bash
# Needs git, git-lfs, ssh and curl.
# End-to-end check of the compose stack (docker compose up -d) with real
# clients: the writer pushes a new LFS object through SSH authentication, the
# Batch API and a signed S3 upload; the reader clones and pulls it back; the
# reader's own push is refused. Then a CI job with no SSH key exchanges a
# token from the dev OIDC issuer for a read-only LFS token, pulls over HTTPS,
# and has its push refused. It is also the README's walkthrough.
#
# Runs anywhere that resolves the stack's service names naraen, s3 and oidc:
# the client container (as naraen-smoke), the devcontainer, or the host with
# "127.0.0.1 naraen s3 oidc" in its hosts file.
set -euo pipefail

host=naraen
# Native Windows git-lfs cannot open Git Bash's /c/... paths; pwd -W gives
# C:/... there, which every tool here understands.
abs() { (cd "$1" && { pwd -W 2>/dev/null || pwd; }); }
# The client image installs this script outside the repository and points
# NARAEN_DEVKEYS at its copy of the dev keys.
keys="${NARAEN_DEVKEYS:-$(abs "$(dirname "$0")/..")/test/testdata/devkeys}"
work="$(abs "$(mktemp -d)")"
trap 'rm -rf "$work"' EXIT
cd "$work"

# ssh refuses private keys that others can read, and git keeps no file modes.
for k in writer reader; do install -m 600 "$keys/$k" "$k"; done
# The dev host key is fixed, so it is trusted up front rather than on first use.
echo "[$host]:2222 $(cut -d' ' -f1,2 "$keys/ssh_host_ed25519_key.pub")" >known_hosts

# lfs <identity> <repo>: point a repo's LFS at the local server as identity.
lfs() {
  git -C "$2" config lfs.url "ssh://git@$host:2222/example/repo"
  git -C "$2" config http.sslCAInfo "$keys/tls.crt"
  # Git for Windows defaults to schannel, and git-lfs then ignores sslCAInfo.
  git -C "$2" config http.sslBackend openssl
  git -C "$2" config lfs.locksverify false
  git -C "$2" config core.sshCommand "ssh -i '$work/$1' -o IdentitiesOnly=yes -o UserKnownHostsFile='$work/known_hosts'"
}

git init -q --bare -b main origin.git
git init -q -b main src
lfs writer src
git -C src lfs install --local >/dev/null
git -C src lfs track '*.bin' >/dev/null
# New bytes on every run, so the upload is never skipped as already stored.
head -c 1048576 /dev/urandom >src/asset.bin
git -C src add .gitattributes asset.bin
git -C src -c user.name=smoke -c user.email=smoke@example.invalid commit -q -m asset
git -C src remote add origin "$work/origin.git"
git -C src push -q origin main
echo "writer pushed asset.bin ($(git -C src lfs ls-files -l | cut -c1-12)...)"

GIT_LFS_SKIP_SMUDGE=1 git clone -q origin.git dst
lfs reader dst
git -C dst lfs pull
cmp src/asset.bin dst/asset.bin
echo "reader pulled the same bytes"

head -c 1024 /dev/urandom >dst/other.bin
git -C dst add other.bin
git -C dst -c user.name=smoke -c user.email=smoke@example.invalid commit -q -m other
if git -C dst lfs push origin main >push.log 2>&1; then
  echo "the reader's push was accepted" >&2
  exit 1
fi
# The reader holds only a read grant, so the server refuses to issue an
# upload token at the SSH step, before any Batch request.
if ! grep -q 'request refused' push.log; then
  echo "the reader's push failed for another reason:" >&2
  cat push.log >&2
  exit 1
fi
echo "reader's push refused: $(grep -m1 'request refused' push.log)"

# CI, as a GitHub Actions job would: an OIDC token for this repository from
# the issuer, exchanged for a read-only LFS token used over HTTPS.
oidc="$(curl -fsS "http://oidc:8080/token?audience=naraen-dev&repository_id=1&repository=example/repo" | sed -E 's/.*"value":"([^"]+)".*/\1/')"
lfs_header="$(curl -fsS --cacert "$keys/tls.crt" -X POST -H "Authorization: Bearer $oidc" "https://$host:8443/example/repo/ci/token" | sed -E 's/.*"Authorization":"([^"]+)".*/\1/')"
case "$lfs_header" in Bearer\ ?*) ;; *) echo "the CI token exchange returned no token" >&2; exit 1 ;; esac
https=(-c "lfs.url=https://$host:8443/example/repo" -c "http.extraHeader=Authorization: $lfs_header"
  -c "http.sslCAInfo=$keys/tls.crt" -c http.sslBackend=openssl -c lfs.locksverify=false)
GIT_LFS_SKIP_SMUDGE=1 git clone -q origin.git ci
git -C ci "${https[@]}" lfs pull
cmp src/asset.bin ci/asset.bin
echo "CI job pulled the same bytes with an exchanged OIDC token"

head -c 1024 /dev/urandom >ci/ci.bin
git -C ci add ci.bin
git -C ci -c user.name=smoke -c user.email=smoke@example.invalid commit -q -m ci
# No prompt for other credentials may hide the refusal.
if GIT_TERMINAL_PROMPT=0 git -C ci "${https[@]}" lfs push origin main >ci-push.log 2>&1; then
  echo "the CI job's push was accepted" >&2
  exit 1
fi
# The exchanged token is for downloads, so the Batch API answers 401.
if ! grep -q 'unauthorized' ci-push.log; then
  echo "the CI job's push failed for another reason:" >&2
  cat ci-push.log >&2
  exit 1
fi
echo "CI job's push refused: $(grep -m1 'unauthorized' ci-push.log)"
