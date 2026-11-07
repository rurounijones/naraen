---
title: Raise the SSH connection rate limit
weight: 80
description: Allow more connections where many clients share one address.
---

Each source address may open a burst of 20 SSH connections and then one every 200 ms. A source is an IPv4 address or an IPv6 /64. Connections over the rate are closed before the handshake. Each Git LFS operation opens two connections, so an office NAT or a CI egress address can reach the limit.

Raise it with:

```sh
NARAEN_SSH_CONN_BURST=100
NARAEN_SSH_CONN_INTERVAL=50ms
```

Watch `lfs.ssh.connections.rejected` with reason `rate` to see whether clients are being limited. The concurrency caps of 256 connections in total and 8 per source are not configurable.
