---
title: The authorization model
weight: 40
description: The datastore, how decisions are made from it, and how providers fill it.
---

## The datastore

Authorization decisions are made against a neutral, in-memory snapshot. Its entities are described in [Permissions snapshot format]({{< relref "../reference/snapshot-format" >}}): identities, their keys, repositories with path aliases, grants, and workload trusts.

The snapshot is immutable. Updates build a new one and swap it in atomically, so readers see either the old or the new, never a half-built one.

## How a decision is made

1. The key's fingerprint is looked up. Missing or inactive means refuse.
2. The repository path is normalized and resolved to a repository ID through canonical paths and aliases. Missing means refuse.
3. The identity's grant is compared with the operation: download needs `read`, upload needs `write`.

Every step is a memory lookup, so there is no network call that can fail or be slow, and anything not in the datastore is denied.

A repository is identified by its numeric GitHub ID, not its path. A rename leaves the ID, and with it the storage folder and the metric series, unchanged, and the old path is kept as an alias.

## The GitHub provider

The provider is the only code that talks to GitHub. It reads:

| Datastore entity | GitHub source |
| --- | --- |
| People and keys | Organisation members and each member's public keys |
| Deploy keys | Each repository's deploy keys, each becoming an identity with a read or write grant on its own repository |
| Repositories | The repositories the GitHub App is installed on |
| Grants | One paged collaborator listing per repository, which returns every user's effective permission including team and organisation base access |
| Workload trust | The GitHub Actions OIDC issuer, the configured audience, and `repository_id` as the repository claim |

Listing collaborators per repository, instead of checking each person against each repository, keeps a full sync to about one call per repository page plus one per member. Conditional requests make unchanged pages nearly free.

The GitHub App is the provider's only credential. It needs read access to organisation members, repository metadata and repository administration. See [How to create the GitHub App]({{< relref "../how-to/create-the-github-app" >}}).

## Two ways to change the datastore

- A **full sync** builds a complete new snapshot off to the side, validates it, and swaps it in. It runs at startup and on a schedule, every 15 minutes by default.
- A **delta** applies a small change to the live snapshot, typically from a webhook: revoke a key, drop a grant, deactivate an identity. Deltas can only remove access. Widening it happens only through a full sync. A delta that arrives while a full sync runs is replayed on top of the sync's result, so the sync cannot undo it.

## Validation before a swap

A new snapshot is compared with the live one by difference, not by count: identities and grants removed or added, and grant levels raised. Each is allowed a small fixed slack plus a share of the live count, with raises held tightest. See [Limits]({{< relref "../reference/limits#snapshot-change-limits" >}}).

A sync over any limit is rejected and alerted on, so a provider bug or a partial API outage cannot silently wipe or widen access. An empty snapshot is never accepted. After a reviewed rejection an operator can approve the next swap once. See [How to recover from a rejected sync]({{< relref "../how-to/recover-from-a-rejected-sync" >}}).

## Rules

- The server refuses all requests, and reports not ready, until it holds a snapshot.
- Providers only write the datastore. They never sign tokens, issue S3 URLs or see the request path's credentials.
- One provider is selected per deployment, in configuration.
