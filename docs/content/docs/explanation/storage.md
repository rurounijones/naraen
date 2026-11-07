---
title: Storage layout
weight: 60
description: How objects are laid out in the bucket and what the server needs from it.
---

## One bucket, one folder per repository

All repositories share one bucket, named by `NARAEN_S3_BUCKET`. Each repository has a top-level folder named by its repository ID, and objects are keyed:

```
{repo ID}/{oid[0:2]}/{oid[2:4]}/{oid}
```

The ID is the repository's stable GitHub ID, so a rename leaves its folder in place. A new repository needs no new bucket and no restart, because the folder appears when the provider syncs the repository. There is no list of repositories allowed storage: the GitHub App's installation scope decides.

Repository IDs may hold only letters, digits, hyphens and underscores, because they become part of an object key.

A shared bucket gives each repository a key prefix, which lifecycle rules, replication and audit logging can address. It does not give per-repository billing. Per-repository storage comes from S3 Inventory and transfers from the server's metrics and S3 access logs.

## What the server needs

The server signs URLs; it never moves bytes. Its role needs:

| Permission | Why |
| --- | --- |
| `s3:PutObject`, `s3:GetObject` on the bucket's objects | To sign upload and download URLs |
| `s3:ListBucket` on the bucket | Without it S3 answers 403 instead of 404 for a missing object, and the server must tell which objects are stored |
| `kms:GenerateDataKey`, `kms:Decrypt` on the bucket's key | Only if the bucket uses SSE-KMS |

It needs no delete permission. The server never lists the bucket, so any `ListObjects` call from its role is a signal worth alerting on.

The server also reads and writes the one object `access-permissions-snapshot.json` at the bucket's root.

## Recommended bucket settings

The server does not configure the bucket. These settings are what the design assumes:

- Block Public Access on, and a bucket policy that denies non-TLS requests.
- SSE-KMS with a customer-managed key and S3 Bucket Keys, so every decrypt is logged and disabling the key cuts off all access.
- Versioning on, with old versions expiring and incomplete multipart uploads aborted.
- Replication to a bucket in a separate account that no role in this system can delete from.

## Limits

A pre-signed PUT is limited to 5 GiB and Git LFS's basic transfer has no multipart support, so a single object cannot exceed that. Nothing removes stored objects: files from deleted branches stay stored.
