---
title: Configuration
weight: 10
description: Every environment variable the server reads.
---

The server is configured entirely by environment variables. Settings that hold secrets name a file instead; the secret itself is never read from the environment. A malformed value stops the server at startup.

A _duration_ uses Go syntax, such as `90s`, `15m` or `1h`.

## Listeners and identity

| Variable | Default | Description |
| --- | --- | --- |
| `NARAEN_SSH_ADDR` | `:22` | SSH listen address. |
| `NARAEN_HTTPS_ADDR` | `:443` | HTTPS listen address. |
| `NARAEN_PUBLIC_URL` | none | The HTTPS origin clients reach the Batch API at, such as `https://lfs.example.com`. Only an origin is accepted: no path, query, fragment or userinfo. Required unless `NARAEN_DEV=true`, when it defaults to `https://localhost:<HTTPS port>`. |
| `NARAEN_TOKEN_KEYS_FILE` | none | File of token keys, one `<id> <hex secret>` per line, at least 32 bytes each. The first line signs new tokens; later lines only verify. Also signs the saved permissions snapshot. Required unless `NARAEN_DEV=true`. |
| `NARAEN_SSH_HOST_KEY_FILE` | none | The SSH host private key. Required unless `NARAEN_DEV=true`. |
| `NARAEN_TLS_CERT_FILE`, `NARAEN_TLS_KEY_FILE` | none | TLS certificate and key. Set both or neither. The certificate is required unless `NARAEN_DEV=true`. The minimum TLS version is 1.3. |
| `NARAEN_DEV` | `false` | `true` allows any of the above to be missing and uses ephemeral key material instead. A snapshot file that lists the public development keys is refused unless this is `true`. |

## Storage

| Variable | Default | Description |
| --- | --- | --- |
| `NARAEN_S3_BUCKET` | none | The bucket holding every repository's objects. A name of 3 to 63 lowercase letters, digits and hyphens, with no dots. Required unless `NARAEN_DEV=true`; without a bucket in development mode, the Batch API answers 503. |
| `NARAEN_S3_ENDPOINT` | AWS | Replaces the AWS S3 endpoint, with path-style addressing, for S3-compatible storage. Must be `https`, except to a loopback address, or to any address in development mode. |
| `AWS_REGION` | none | Required. The server uses the AWS SDK's default credential chain. |
| `AWS_SHARED_CREDENTIALS_FILE` | SDK default | Credentials file for hosts with no instance role. |

## Permissions

| Variable | Default | Description |
| --- | --- | --- |
| `NARAEN_SNAPSHOT_FILE` | none | Load permissions from a JSON file instead of a provider. See [Permissions snapshot format]({{< relref "snapshot-format" >}}). An alternative to the GitHub provider; setting both is an error. |
| `NARAEN_SNAPSHOT_MAX_AGE` | `1h` | The oldest a snapshot may be before the server refuses all requests. A positive duration. |
| `NARAEN_GITHUB_ORG` | none | The GitHub organisation to sync. |
| `NARAEN_GITHUB_APP_ID` | none | The GitHub App's ID. |
| `NARAEN_GITHUB_INSTALLATION_ID` | none | The App's installation ID. |
| `NARAEN_GITHUB_APP_KEY_FILE` | none | The App's PEM private key. |
| `NARAEN_SYNC_INTERVAL` | `15m` | Time between full syncs. At least `1m`. |
| `NARAEN_OIDC_AUDIENCE` | none | The custom audience CI jobs request OIDC tokens for. Unset means CI token exchange is not set up. |
| `NARAEN_GITHUB_API_URL` | `https://api.github.com` | The REST API base URL, for GitHub Enterprise and tests. `https`, except to a loopback address. |
| `NARAEN_GITHUB_JWKS_URL` | GitHub Actions' key set | Where Actions' OIDC signing keys are fetched. `https`, except to a loopback address. |
| `NARAEN_GITHUB_WEBHOOK_SECRET_FILE` | none | File holding the secret GitHub signs deliveries with, at least 20 bytes. Unset means `/webhooks/github` is not served. |

`NARAEN_GITHUB_ORG`, `NARAEN_GITHUB_APP_ID`, `NARAEN_GITHUB_INSTALLATION_ID` and `NARAEN_GITHUB_APP_KEY_FILE` are all required together, or all absent.

## SSH limits

| Variable | Default | Description |
| --- | --- | --- |
| `NARAEN_SSH_CONN_BURST` | `20` | Connections a source may open at once before the rate applies. A positive integer. |
| `NARAEN_SSH_CONN_INTERVAL` | `200ms` | Time between connections once the burst is spent. A positive duration. |

## Telemetry

| Variable | Default | Description |
| --- | --- | --- |
| `NARAEN_OTLP_ENDPOINT` | none | OTLP/HTTP base URL, without a trailing slash. `https`, except to a loopback address. Unset means nothing is exported and logs go to stdout only. |
| `NARAEN_OTLP_HEADERS_FILE` | none | File of `Name: value` headers, one per line, sent with every export. |
