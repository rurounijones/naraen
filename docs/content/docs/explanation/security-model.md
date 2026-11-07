---
title: Security model
weight: 70
description: The threats naraen defends against and the control behind each.
---

The files stored are treated as sensitive, so the design assumes least privilege, a full audit trail and refusal when in doubt. Each row names a threat, the control, and where it is tested.

| Threat | Control | Tested in |
| --- | --- | --- |
| SSH sign-in bypass (CVE-2024-45337) | `golang.org/x/crypto` 0.31.0 or later, and identity taken only from the successful callback's permissions | `test/attack` |
| Forged CI identity | Signature checked against the issuer keys recorded in the trust entry, RS256 (2048 bits or more) or ES256 only, `kid` required, claims checked against the same entry, the repository in the token must match the URL | `internal/oidc`, `test/integration` |
| Forged webhook | HMAC signature checked before the payload is read, and only removals applied | `internal/provider/github`, `test/integration` |
| Edited tokens or URLs, swapped upload bytes | Tokens are HMAC-signed and bound to a repository ID and operation, rechecked on every Batch request. Upload links sign the SHA-256 and length, and stored objects get no upload link | `internal/token`, `internal/batch`, `test/attack` |
| Wrong-repository access | Strict path normalization, resolution to a repository ID, tokens bound to that ID, OID format validation | `internal/pathnorm`, `internal/batch` |
| Repository probing | One `401` for an unknown repository and a bad token | `internal/batch` |
| Stale or over-broad grants | Fail-closed snapshot, staleness limit, validation before a swap, grant rechecked on every Batch request | `internal/datastore`, `test/integration` |
| Altered or replayed permissions file | Signed copy, verified against the token keys, with its own signing domain. A copy older than the one loaded is ignored, a future time refused, and an old one ages out at the staleness limit | `internal/persist`, `test/integration` |
| Connection flooding (DHEat, CVE-2002-20001) | Per-source connection rate limit, total and per-source concurrency caps, a handshake deadline and a connection lifetime | `internal/sshd` |
| Oversized or malformed requests | Body, object-count and size caps, server timeouts | `internal/batch`, `internal/httpapi` |
| Leaked URL | 15-minute expiry and full URLs never logged | semgrep rule |
| Unattributed access | Audit records and traces for every sign-in, refusal and token, with identity, token ID and reason | `internal/sshd`, `internal/httpapi` |

## Choices that follow from the threats

- **The provider never sees the request path's credentials**, and the request path never imports the provider. The linter enforces the boundary.
- **Tokens and S3 URLs are short-lived**, so revocation is bounded by the numbers in [Staleness and revocation]({{< relref "staleness-and-revocation" >}}).
- **Every parser of client-supplied input has a fuzz target.**
- **All security gates are blocking** in the project's checks: vulnerability, static analysis and secret scans, fuzzing, mutation testing and dynamic scanning.

## Out of scope

The server does not protect the bucket's configuration or the network layer. Many sources together can still use the SSH connection cap; that is the network's job.
