---
title: SSH interface
weight: 30
description: The commands the SSH listener accepts and its connection limits.
---

The SSH listener accepts public-key authentication only. The username (conventionally `git`) carries no identity: the offered key's SHA-256 fingerprint is looked up in the permissions snapshot, and the first offered key that is found and active is accepted. Only modern key exchange, cipher and MAC algorithms are enabled.

## Commands

A command is a single line with fields separated by single spaces.

| Command | Result |
| --- | --- |
| `git-lfs-authenticate <path> <operation>` | Prints JSON with `href` (the Batch API address for the repository), a `header` holding a bearer token, and `expires_in` (900 seconds). `<operation>` is `upload` or `download`. |
| `git-lfs-transfer <path> <operation>` | Refused as unsupported, so that Git LFS falls back to `git-lfs-authenticate`. |

`<path>` is the repository path, such as `ORG/REPO`, at most 200 characters. It is normalized before lookup (case, a trailing `.git`, `..`, encoded slashes) and resolved to a repository ID through canonical paths and recorded aliases, so a renamed repository keeps working under its old path.

Any other command, and any interactive session, is refused.

## Limits

| Limit | Value |
| --- | --- |
| Concurrent connections, total | 256 |
| Concurrent connections per source | 8 |
| New connections per source | A burst of 20, then one per 200 ms (configurable) |
| Handshake deadline | 10 seconds |
| Connection lifetime | 1 minute |
| Sessions per connection | 4 |

A source is an IPv4 address or an IPv6 /64. A connection over the rate or concurrency limit is closed before the handshake and counted in `lfs.ssh.connections.rejected`.
