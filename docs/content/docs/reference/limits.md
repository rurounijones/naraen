---
title: Limits and lifetimes
weight: 60
description: The fixed numbers the server enforces.
---

## Lifetimes

| Item | Value |
| --- | --- |
| LFS bearer token | 15 minutes |
| Pre-signed S3 URL | 15 minutes |
| Full sync interval | 15 minutes by default, at least 1 minute |
| Snapshot maximum age | 1 hour by default |
| Metrics export interval | 15 seconds |

## Requests

| Item | Limit |
| --- | --- |
| Objects per Batch request | 1000 |
| Object size | 5 GiB (a pre-signed PUT cannot exceed it) |
| Object ID | Exactly 64 lowercase hexadecimal characters |
| Repository path | 200 characters |
| Webhook body | 1 MiB |

## Snapshot change limits {#snapshot-change-limits}

Each full sync is compared with the live snapshot. For each kind of change, a sync may make up to a fixed slack plus a share of the live count; over that, the sync is rejected.

| Kind of change | Slack | Share of live count |
| --- | --- | --- |
| Identities or grants removed | 10 | 20% |
| Identities or grants added | 10 | 50% |
| Grants whose level is raised | 10 | 10% |

An empty snapshot is never accepted. The first snapshot after a start has no baseline and is checked only for being non-empty.

## SSH

See [SSH interface]({{< relref "ssh-commands#limits" >}}).
