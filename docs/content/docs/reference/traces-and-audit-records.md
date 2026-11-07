---
title: Traces and audit records
weight: 50
description: What is traced, which attributes spans and logs carry, and the refusal reasons.
---

## What is traced

Every call is traced and none is sampled away, because the server handles only a few control requests per transfer.

| Trace | Contents |
| --- | --- |
| Each HTTPS request, except the health probes | One span per Batch object, holding its S3 request. |
| Each SSH connection that reaches the handshake | One span per command. |
| Each provider full sync | One span per GitHub API request. |

Trace context is neither read from clients, who are untrusted, nor sent to GitHub or S3. `X-Forwarded-For` is dropped before a span records the client address, because no proxy sits in front of the server.

## Attributes

Spans and log records carry these attributes. Unlike metric labels, they may hold unbounded values.

| Attribute | Meaning |
| --- | --- |
| `lfs.identity`, `lfs.identity_type` | Who the request belongs to. |
| `lfs.fingerprint` | SHA-256 fingerprint of the SSH key. |
| `lfs.repo`, `lfs.repo_id` | Repository path and ID. |
| `lfs.operation` | `upload` or `download`. |
| `lfs.command` | The SSH command. |
| `lfs.token_id` | The token's ID. Ties a token's issue over SSH to the Batch requests that use it. |
| `lfs.request_id` | The request ID. |
| `lfs.reason` | Why a request was refused. |
| `lfs.oid`, `lfs.size` | The object and its size. |
| `lfs.outcome` | The link outcome for an object. |
| `lfs.issuer` | The OIDC issuer for a CI exchange. |
| `lfs.provider` | The permissions provider for a sync. |
| `lfs.event`, `lfs.delivery` | The webhook event and delivery ID. |
| `lfs.objects`, `lfs.links`, `lfs.bytes` | Totals for a Batch request. |

Log records written during a request carry its `trace_id` and `span_id`, on stdout and over OTLP.

## Audit records

The server writes an audit record for every SSH sign-in, every refusal with its reason, and every token issued. A token record includes the token ID, the key fingerprint and the remote address. The same events are recorded as metrics.

Full object URLs and tokens are never logged.

## Refusal reasons {#refusal-reasons}

| Reason | Cause |
| --- | --- |
| `not_ready` | No permissions snapshot is loaded yet. |
| `stale` | The snapshot is older than the maximum age. |
| `unknown_key` | The key's fingerprint is not in the datastore. |
| `bad_path` | The repository path is malformed. |
| `unknown_repo` | The path matches no repository. |
| `unknown_identity` | The key's identity is missing. |
| `inactive_identity` | The identity is deactivated. |
| `insufficient_grant` | The grant does not allow the operation. |
| `bad_operation` | The operation is neither `upload` nor `download`. |

A `git-lfs-transfer` attempt and a failed handshake are recorded on the span only, because Git LFS makes the first attempt every time and scanners fail handshakes constantly.
