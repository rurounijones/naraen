---
title: Staleness and revocation
weight: 50
description: How quickly removed access stops working, and what happens when syncing stops.
---

## The staleness limit

If no full sync has succeeded within the maximum age (`NARAEN_SNAPSHOT_MAX_AGE`, one hour by default), the server refuses all requests and reports not ready, rather than serve access it can no longer vouch for. It alerts well before that point: `lfs.datastore.age` should be watched at half the limit.

Age is measured from the server's own clock at the moment the sync began reading, never from a timestamp in the data. A restart does not extend the limit, and a snapshot that claims to be from the future is refused.

## How long revoked access lasts

| Event | Without webhooks | With webhooks |
| --- | --- | --- |
| Member removed from the organisation | Next full sync, up to the sync interval (15 minutes by default) | Within seconds |
| Deploy key deleted | Next full sync | Within seconds |
| Repository permission, team or base permission changed | Next full sync | Next full sync |
| Key added | Next full sync | Next full sync |

Webhooks only remove access. Changes with no matching webhook wait for the next full sync.

Two further delays follow a revocation:

- The Batch API rechecks every token against the current snapshot, so a token's lifetime adds nothing.
- Pre-signed URLs already issued stay valid for up to 15 minutes, and S3 checks a URL only when a transfer starts.

The worst case is therefore about the sync interval plus 15 minutes, plus the length of one transfer.

## Surviving a restart

Each change to the snapshot is saved to the bucket as `access-permissions-snapshot.json`, signed with the token keys. At startup the server restores the copy if its signature verifies against any listed key and it is within the maximum age. It then serves immediately instead of waiting for GitHub.

The saved copy changes what the server needs from GitHub at startup, not how far it trusts a sync:

- A copy is not a baseline for validation. The first sync after a start is checked only for being non-empty, because a restart would otherwise be the only way past a rejected change.
- Saves are asynchronous and not retried. A removal made just before a crash, or while saving fails, can reappear after a restart until the next sync. `lfs.snapshot.save_failures` counts failures.
- Anything that fails the checks leaves the server not ready until a full sync succeeds.

A copy that was altered or replaced in the bucket is refused because it does not verify. Write access to the bucket cannot grant access.
