---
title: HTTP API
weight: 20
description: The endpoints served on the HTTPS listener.
---

The machine-readable description is `api/openapi.yaml` in the repository. Every endpoint is served over TLS 1.3 or later.

The server's timeouts are 5 s to read request headers, 30 s to read a request, 30 s to write a response, and 60 s idle.

## Probes

| Endpoint | Description |
| --- | --- |
| `GET /healthz` | `200` while the process is up. |
| `GET /readyz` | `200` when the server holds a fresh permissions snapshot, `503` otherwise. |

The probes are not traced.

## `POST /{owner}/{repo}/objects/batch`

The Git LFS Batch API. Authenticated with `Authorization: Bearer <token>`, where the token came from `git-lfs-authenticate` or the CI exchange. The token must be for this repository and for the operation requested. Content type is `application/vnd.git-lfs+json`.

### Request

| Field | Type | Description |
| --- | --- | --- |
| `operation` | `upload` or `download` | Required. |
| `transfers` | array of strings | Optional. Must include `basic` when present. |
| `hash_algo` | `sha256` | Optional. |
| `objects` | array | Required, 1 to 1000 entries. |
| `objects[].oid` | string | Exactly 64 lowercase hexadecimal characters. |
| `objects[].size` | integer | 0 to 5,368,709,120 (5 GiB). |

### Response

`200` with `transfer: "basic"` and one entry per distinct object, in request order. Each entry has `oid`, `size`, `authenticated` and either `actions` or `error`.

- `actions.upload` or `actions.download` holds `href` (a pre-signed S3 URL valid for 15 minutes), `header` (headers the client must send; upload links sign `x-amz-checksum-sha256`) and `expires_at`.
- `actions` is absent for an upload of an object that is already stored.
- `error.code` is `404` when a requested download is not stored, `422` when its stored size differs from the request, and `500` when storage failed.

### Status codes

| Code | Meaning |
| --- | --- |
| `200` | Answered. |
| `401` | Missing or invalid token, a token for another repository or operation, or an unknown repository. All look the same. |
| `403` | The token is valid but the current grant no longer allows the operation. |
| `422` | Invalid request body. |
| `503` | The permissions snapshot is not ready or is stale, or storage is not configured. |

## `POST /{owner}/{repo}/ci/token`

Exchanges a CI workload's OIDC token for a read-only LFS token.

Send the OIDC token as `Authorization: Bearer <jwt>`. The token must be signed with RS256 (keys of 2048 bits or more) or ES256, verified against the trusted issuer's key set by `kid`, and carry exactly the configured audience. The claim that names the repository, `repository_id` for GitHub Actions, must identify the repository in the URL.

### Response

`200` with the shape `git-lfs-authenticate` prints:

```json
{"href":"https://lfs.example.com/ORG/REPO","header":{"Authorization":"Bearer v1...."},"expires_in":900}
```

| Code | Meaning |
| --- | --- |
| `401` | Missing, malformed, expired or untrusted OIDC token. |
| `403` | A valid token for another repository, or no workload grant on this one. |
| `503` | The permissions snapshot is not ready or is stale. |

## `POST /webhooks/github`

Served only when `NARAEN_GITHUB_WEBHOOK_SECRET_FILE` is set. The body is authenticated by the `X-Hub-Signature-256` header, an HMAC-SHA256 of the body under the webhook secret. The body may be at most 1 MiB.

The `X-GitHub-Event` header names the event. These remove access at once:

- `organization` with action `member_removed`
- `member` with a removal action
- `deploy_key` with action `deleted`

Every other event is accepted and ignored.

| Code | Meaning |
| --- | --- |
| `202` | Accepted. |
| `400` | Malformed payload. |
| `401` | Bad signature. |
| `413` | Body over 1 MiB. |
