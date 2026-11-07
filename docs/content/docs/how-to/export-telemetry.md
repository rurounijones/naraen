---
title: Export metrics, traces and logs
weight: 60
description: Send the server's OpenTelemetry data to a collector such as OpenObserve.
---

The server exports with OTLP over HTTP. Without it, the server records metrics, writes logs to stdout only, and logs a warning at startup.

## Point the server at your collector

```sh
NARAEN_OTLP_ENDPOINT=https://openobserve.internal:5080/api/default
NARAEN_OTLP_HEADERS_FILE=/run/naraen/otlp-headers
```

The endpoint is a base URL with no trailing slash. Metrics go to `/v1/metrics` under it, spans to `/v1/traces` and log records to `/v1/logs`. It must be `https`, except to a loopback address.

Put the ingestion credential in the headers file, one `Name: value` header per line:

```
Authorization: Basic dXNlcjpwYXNz
```

## What you get

Metrics are pushed every 15 seconds. Spans and logs are sent in batches, and everything is flushed on shutdown. A bounded in-memory queue absorbs short outages without affecting LFS requests.

See the [metrics reference]({{< relref "../reference/metrics" >}}) and the [traces and audit records reference]({{< relref "../reference/traces-and-audit-records" >}}).

## Suggested alerts

- `lfs.datastore.age` above half the staleness limit.
- Any increase in `lfs.sync.failures`, especially with reason `rejected`.
- Any increase in `lfs.snapshot.save_failures`.
- A person's `lfs.bytes.requested` far above their usual volume.
- Repeated `lfs.auth.failures` from one key or address.

Also alert from outside the collector when metrics stop arriving, so a collector outage is not mistaken for quiet.
