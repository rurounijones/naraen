---
title: Permissions snapshot format
weight: 70
description: The datastore model and the JSON file read by NARAEN_SNAPSHOT_FILE.
---

The permissions snapshot is the neutral model the request path decides against. A provider fills it; `NARAEN_SNAPSHOT_FILE` loads one from a file, which is how tests and the local stack work.

## Entities

| Entity | Fields |
| --- | --- |
| `meta` | `provider`, `version`, `synced_at` |
| `identities[]` | `id`, `kind` (`person`, `deploy_key` or `workload`), `name`, `active` |
| `keys[]` | `fingerprint` (`SHA256:...`), `type`, `identity_id` |
| `repos[]` | `id`, `path`, optional aliases for previous paths |
| `grants[]` | `identity_id`, `repo_id`, `level` |
| `trusts[]` | `issuer`, `audience`, `jwks`, `repo_claim`, `max_level` |

Each key fingerprint belongs to exactly one identity. A repository ID may contain only letters, digits, hyphens and underscores, because it names the repository's folder in the bucket.

## Levels

Levels are written by name, never by number, and are ordered from least to most privileged:

`none`, `read`, `write`, `maintain`, `admin`

Download needs `read`. Upload needs `write`.

## Workload trust

A trust entry lets CI tokens from one issuer into the datastore. It holds the issuer's name, the exact audience required, the issuer's signing keys as a JWKS document (so verification makes no network call), the claim that names the repository, and the highest level a token may be given, which is `read`.

The workload is an identity like any other. A trust for a repository comes with an identity named `workload:<repo ID>` of kind `workload` and a read grant on that repository. Removing the grant or the identity stops new tokens, and the Batch API rechecks it on every request.

## Example

```json
{
  "meta": {"provider": "file", "version": "dev", "synced_at": "2026-01-01T00:00:00Z"},
  "identities": [
    {"id": "writer", "kind": "person", "name": "Dev writer", "active": true}
  ],
  "keys": [
    {"fingerprint": "SHA256:3gzqoh0HmPR7wXovKf0R5jO41Aoyu2f06LgDx8LQY8s", "type": "ssh-ed25519", "identity_id": "writer"}
  ],
  "repos": [
    {"id": "1", "path": "example/repo"}
  ],
  "grants": [
    {"identity_id": "writer", "repo_id": "1", "level": "write"}
  ],
  "trusts": []
}
```

## Saved copy

When the GitHub provider runs with a bucket and token keys, each change is saved as `access-permissions-snapshot.json` at the bucket's root. The file is signed with the token keys. A server restores it at startup if the signature verifies against any listed key and the copy is within the maximum age. See [Staleness and revocation]({{< relref "../explanation/staleness-and-revocation" >}}).
