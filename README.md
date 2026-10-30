# naraen

A self-hosted Git LFS server that keeps code on GitHub but stores large files in Amazon S3. Developers authenticate with the SSH keys they already use for GitHub, GitHub decides what they may access, and file bytes go directly between the client and S3, so the server itself only handles small control requests.

> **Status:** early. `git lfs push` and `git lfs pull` work end to end over SSH authentication, the Batch API and pre-signed S3 URLs that bind each upload to its SHA-256 and size. CI workloads exchange an OIDC token for a read-only LFS token at `/{owner}/{repo}/ci/token`. Signed GitHub webhooks for removed members, removed collaborators and deleted deploy keys revoke access at once. The GitHub provider's network sync and the per-person download budget are not built yet. Until the provider is, the datastore is loaded from a snapshot file.

## Goals

- Move 1 TB+ of LFS assets, mostly short-lived feature-branch files, off GitHub's metered LFS storage.
- No new credentials for developers: their existing GitHub SSH key is their identity, and GitHub is the source of truth for access.
- CI pipelines can download without a GitHub seat.
- Treat the stored files as critical intellectual property: least privilege, full audit trail, usage metrics and anomaly alerts, and exhaustive testing.

**Non-goals:** HTTPS username/password/token sign-in for developers, the LFS locks API, and carrying file bytes through the server.

## Architecture

A single Go binary runs an SSH listener (port 22) and an HTTPS listener (port 443). Files live in one S3 bucket, with one top-level folder per repo.

```mermaid
flowchart LR
  Dev["Developer (git-lfs)"] -- "SSH 22: authenticate" --> Srv["LFS server (Go)"]
  Dev -- "HTTPS 443: Batch API" --> Srv
  CI["CI runner"] -- "OIDC token or deploy key" --> Srv
  Dev -- "file bytes via pre-signed URL" --> S3[("S3 bucket")]
  CI -- "file bytes via pre-signed URL" --> S3
  Srv -- "authorization provider" --> GH["GitHub API"]
  GH -. "webhooks (optional)" .-> Srv
  S3 -- "CloudTrail, EventBridge, SQS" --> Srv
  Srv -- "OTLP" --> OO["OpenObserve"]
```

```mermaid
sequenceDiagram
  participant Dev as Developer (git-lfs)
  participant Srv as LFS server
  participant S3 as S3 bucket
  Dev->>Srv: ssh git@host git-lfs-authenticate org/repo upload
  Note over Srv: key fingerprint to identity, grant check (in-memory snapshot)
  Srv-->>Dev: href, Bearer token (15 min)
  Dev->>Srv: POST /org/repo/objects/batch
  Srv-->>Dev: per-object pre-signed S3 URLs (15 min)
  Dev->>S3: PUT or GET file bytes directly
```

## Authentication and authorization

- **Developers** are identified by the SHA-256 fingerprint of their SSH public key, resolved against an in-memory datastore. The SSH layer never contacts GitHub.
- **CI** uses either GitHub Actions OIDC (verified against a registered workload-trust entry, read-only, no secrets) or a repo deploy key.
- **Authorization** is split in two halves that never call each other. The *request path* (SSH, token issuance, Batch API) only reads an immutable datastore snapshot and fails closed. A pluggable *provider* (GitHub first) keeps the datastore populated. The linter enforces that request-path packages cannot import `internal/provider`.
- Tokens are HMAC-SHA256 signed, bound to a repo ID and operation, and live 15 minutes. Every Batch request re-checks the token's identity and grant against the current snapshot, so revocations apply to new links at once.
- Only organisation members and deploy keys can authenticate. Outside collaborators are given no access, because the provider loads SSH keys only for org members.

## Security

| Threat | Control |
| --- | --- |
| SSH sign-in bypass (CVE-2024-45337) | `golang.org/x/crypto` >= 0.31.0 enforced by a test; identity taken only from the callback's returned permissions |
| Wrong-repo access | Strict path normalization, resolution to repo ID, tokens bound to repo and operation, OID validation |
| Stale access | Periodic full sync, tokens re-checked against the current snapshot on every request, requests refused when the snapshot exceeds its maximum age |
| Provider bug | Snapshots validated before swap; unusual drops, additions or level raises rejected until an operator approves; webhook deltas can only remove access |
| Leaked URL | 15-minute expiry; full URLs and tokens never logged (a Semgrep rule with its own test cases) |
| Unattributed access | An audit record for every sign-in, refusal and token issued, with identity, key fingerprint, remote address and reason; each token carries an ID that ties later requests to its issue. Refusals and issues are also OTLP metrics for real-time alerts |
| Man in the middle | TLS 1.3 minimum; modern-only SSH KEX, ciphers and MACs |

## Testing and quality gates

All security gates are blocking in CI.

| Area | Tools |
| --- | --- |
| Unit and race | `go test -race -shuffle=on`; 100% line coverage (go-test-coverage) and 100% branch coverage (gobco) required |
| Fuzzing | Go native fuzzing on every client-input parser |
| Mutation | gremlins, every mutant must be killed (100% line coverage already covers every mutant in code) |
| SAST | gosec, CodeQL (`security-extended`), Semgrep with custom rules, golangci-lint, nilaway |
| SCA | govulncheck, OSV-Scanner, Dependabot, dependency review |
| Secrets | gitleaks |
| Container | Trivy, hadolint; distroless nonroot runtime image |
| DAST | ZAP (API and baseline), Nuclei, testssl.sh, ssh-audit |
| Supply chain | OpenSSF Scorecard, actions pinned by SHA; releases only from main after every gate passes; static-PIE binaries and a multi-arch image, both signed with cosign, with SBOMs and GitHub build provenance |

## Development

Everything runs in a container; no host Go toolchain is required.

1. Open the repo in VS Code and choose **Reopen in Container** (builds the `dev` stage of the `Dockerfile`), or build it yourself: `docker build --target dev -t naraen-dev .`
2. Run tasks with [go-task](https://taskfile.dev): `task --list`.

| Task | Purpose |
| --- | --- |
| `task check` | Fast gate: format, tidy, lint, nilaway, coverage, vuln, SAST, secrets |
| `task ci` | `check` plus fuzz, mutation, integration, image scan and DAST |
| `task test`, `task cover` | Unit tests, line and branch coverage gates |
| `task fuzz`, `task mutation` | Fuzzing (`FUZZTIME=5m`) and mutation testing |
| `task integration` | The access matrix with real git, git-lfs and OpenSSH against the built server and a signature-checking local S3 (`docker compose up -d s3`), plus upload-integrity checks of the signed links |
| `task image`, `task scan`, `task dast` | Build the runtime image, scan it, run DAST |
| `task build`, `task release-check` | Release binaries for this platform, or validate the release config and build every target, in `dist/` |

### Try it locally

`docker compose up naraen` starts the server in development mode. It loads `test/testdata/snapshot.json`, which accepts the two committed development keys in `test/testdata/devkeys/`: `writer` may upload and download `example/repo`, and `reader` may only download. The keys are public on purpose, and only that snapshot accepts them.

```sh
chmod 600 test/testdata/devkeys/writer
ssh -p 2222 -i test/testdata/devkeys/writer -o IdentitiesOnly=yes git@localhost git-lfs-authenticate example/repo upload
# {"href":"https://localhost:8443/example/repo","header":{"Authorization":"Bearer v1.dev...."},"expires_in":900}
```

The host key is ephemeral in development mode, so ssh asks you to trust it on every restart.

The href in the answer comes from `NARAEN_PUBLIC_URL`, which defaults to localhost in development mode; set it to the name other machines reach the server by before trying from one.

To use it from a repository, set `lfs.url` to `ssh://git@localhost:2222/example/repo`. Point `GIT_SSH_COMMAND` at the key, for example `ssh -i test/testdata/devkeys/writer -o IdentitiesOnly=yes`. The compose service has no storage configured, so `git lfs push` then authenticates and the Batch API answers 503 "storage not configured". `test/integration/lfs_test.go` shows a complete setup with SeaweedFS: a bucket, signer credentials and `NARAEN_S3_ENDPOINT`.

### Configuration

Configuration is by environment variable. Secrets are never put in the environment, only the paths of the files that hold them:

- `NARAEN_TOKEN_KEYS_FILE`: one `<id> <hex>` token key per line, at least 32 bytes each. The first line mints; later lines only verify, so a rotated key stays listed until its tokens expire.
- `NARAEN_SSH_HOST_KEY_FILE`: the SSH host private key.
- `NARAEN_TLS_CERT_FILE` and `NARAEN_TLS_KEY_FILE`: the TLS certificate and key.
- `NARAEN_PUBLIC_URL`: the HTTPS origin clients reach the Batch API at, such as `https://lfs.example.com`. `git-lfs-authenticate` returns it with the repo path appended. Only an origin is accepted: no path, query, fragment or userinfo.
- `NARAEN_OTLP_ENDPOINT`: the OTLP/HTTP base URL, such as `https://openobserve.internal:5080/api/default`. Metrics go to `/v1/metrics` under it, pushed every 15 seconds; log records go to `/v1/logs`, in batches, as well as to stdout. Both are flushed on shutdown. Optional; without it nothing is exported, logs go to stdout only, and a warning is logged at startup. It must be https, except to a loopback address.
- `NARAEN_OTLP_HEADERS_FILE`: optional, one `Name: value` header per line sent with every export, typically the ingestion credential.
- `NARAEN_S3_BUCKET`: the bucket holding every repo's objects, each repo under a top-level folder named by its ID, so lifecycle rules, replication and audit selectors can address a repo by prefix. The name is an S3 name without dots, so virtual-hosted TLS works.
- `NARAEN_S3_ENDPOINT`: optional; replaces the AWS S3 endpoint, with path-style addressing, for S3-compatible storage such as SeaweedFS. It must be https, except to a loopback address.
- `AWS_REGION` and the AWS SDK's default credential chain: the instance role on EC2, or a shared credentials file named by `AWS_SHARED_CREDENTIALS_FILE` elsewhere. The region must be set; the signer needs `s3:GetObject` and `s3:PutObject` on the objects and `s3:ListBucket` on the bucket. Without the last, S3 answers 403 instead of 404 for a missing object, and uploads of new objects fail. The server never lists the bucket, but a compromised one could, so log `ListObjects` as a CloudTrail data event and alert on any call from its role.
- `NARAEN_GITHUB_WEBHOOK_SECRET_FILE`: optional, the secret GitHub signs webhook deliveries with (at least 20 bytes). With it, `/webhooks/github` applies removals at once; without it the route is not served and removals wait for the next full sync.
- `NARAEN_DEV=true`: allow any of the above to be missing and use ephemeral key material instead, with the public URL defaulting to `https://localhost:<HTTPS port>`. Without a bucket the Batch API answers 503. Without it the server refuses to start unless the token keys, host key, TLS files, public URL and bucket are all set. A snapshot file that lists the public development keys is refused unless `NARAEN_DEV=true`.
- `NARAEN_SSH_CONN_BURST` and `NARAEN_SSH_CONN_INTERVAL`: the per-source SSH connection rate limit, by default a burst of 20 and then one connection per 200ms. A source is an IPv4 address or an IPv6 /64. Raise them where many clients share one address, such as an office NAT or CI egress.
- `NARAEN_SSH_ADDR`, `NARAEN_HTTPS_ADDR`, `NARAEN_SNAPSHOT_FILE`, `NARAEN_SNAPSHOT_MAX_AGE`.

## Known limitations

- Plain S3 egress roughly matches GitHub's bandwidth price; savings come mainly from storage.
- A pre-signed PUT is limited to 5 GB; Git LFS basic transfer has no multipart support.
- Every LFS operation depends on one instance.
- Access removed on GitHub stops new links only at the next full sync (up to about 15 minutes; webhooks shorten this). Links already issued stay valid for up to 15 minutes more, and S3 checks a link only when a transfer starts, so a transfer already running finishes. The worst case from revocation to the last byte is therefore about 30 minutes plus the length of one transfer.
- Change limits on full syncs mean a large real change (a reorg, a mass offboarding) is held back until an operator approves it; if nobody does, the snapshot goes stale and the server refuses all requests.

## License

GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
