---
title: Observability
weight: 80
description: Why the server emits what it does, and how to use it for alerting and investigation.
---

Metrics are real-time and drive alerting. Traces and logs are for investigation. The server exports all three directly over OTLP/HTTP to one configured endpoint, and without one it logs to stdout only. See [How to export telemetry]({{< relref "../how-to/export-telemetry" >}}).

## Metrics: the earliest signal

Link issuance is the earliest signal of a transfer, ahead of the transfer itself, so the byte counter `lfs.bytes.requested` counts what links were issued for, not what S3 delivered. A person pulling far more than usual shows up at the Batch request. See [Metrics]({{< relref "../reference/metrics" >}}).

Labels stay bounded. Object IDs, IP addresses and request IDs are only on traces and logs.

## Traces: every call

No trace is sampled away, because the server handles only a few control requests per transfer. A token's issue over SSH and the Batch requests that use it are joined by the token ID. See [Traces and audit records]({{< relref "../reference/traces-and-audit-records" >}}).

## Delivery

Export uses a bounded in-memory queue with retries, which absorbs short outages without affecting LFS requests. When the queue is full, telemetry is dropped before a request is delayed.

## Suggested alerts

These conditions can be built on the metrics:

- A person's download volume far above their 30-day baseline or over a fixed ceiling.
- Bulk downloads from a repository the person has not used before.
- Repeated refused sign-ins from one key or address.
- `lfs.datastore.age` above half of `NARAEN_SNAPSHOT_MAX_AGE`, or `lfs.sync.failures` rising.
- A CI identity touching repositories other than its own.
- Metrics stopping altogether. Use an alarm outside the telemetry system, so an outage there is not mistaken for quiet.
