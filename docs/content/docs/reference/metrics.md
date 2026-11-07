---
title: Metrics
weight: 40
description: The OpenTelemetry metrics the server records.
---

Metrics are pushed over OTLP every 15 seconds when [export is configured]({{< relref "../how-to/export-telemetry" >}}). Labels are bounded: object IDs, IP addresses and request IDs go on traces and logs, never on metric labels.

| Metric | Type | Unit | Labels | Counts |
| --- | --- | --- | --- | --- |
| `lfs.links.issued` | counter | `{object}` | `operation`, `repo`, `user`, `outcome` | Objects answered by the Batch API, by outcome. |
| `lfs.bytes.requested` | counter | `By` | `operation`, `repo`, `user` | Bytes covered by the links issued. The earliest signal of a transfer. |
| `lfs.object.size` | histogram | `By` | `operation`, `repo` | Size of each object a link was issued for. |
| `lfs.tokens.issued` | counter | `{token}` | `operation`, `repo`, `user` | Bearer tokens issued by `git-lfs-authenticate` and the CI exchange. |
| `lfs.auth.failures` | counter | `{failure}` | `reason`, `identity_type` | SSH sign-ins and requests refused. |
| `lfs.ssh.connections.rejected` | counter | `{connection}` | `reason` | SSH connections closed before the handshake. |
| `lfs.datastore.age` | gauge | `s` | none | Age of the permissions snapshot. |
| `lfs.sync.failures` | counter | `{sync}` | `reason` | Provider full syncs that failed or were rejected. |
| `lfs.sync.rate_limit_wait` | counter | `s` | none | Seconds the provider held back requests for the source's rate limit. |
| `lfs.snapshot.save_failures` | counter | `{save}` | none | Failed saves of the permissions snapshot to the bucket. |

The `repo` label is the repository's ID, not its path, so a rename does not split a series.

## Label values

| Label | Values |
| --- | --- |
| `operation` | `upload`, `download` |
| `outcome` | `issued`, `present` (upload skipped, already stored), `missing` (download refused, not stored), `mismatch` (download refused, stored size differs), `error` (storage failed) |
| `reason` on `lfs.auth.failures` | The [refusal reasons]({{< relref "traces-and-audit-records#refusal-reasons" >}}) |
| `reason` on `lfs.ssh.connections.rejected` | `rate`, `concurrency` |
| `reason` on `lfs.sync.failures` | `failed`, `rate_limited`, `rejected` |
| `identity_type` | `person`, `deploy_key`, `workload`, or `unknown` when no identity could be resolved |
