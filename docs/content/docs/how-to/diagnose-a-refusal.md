---
title: Diagnose a refusal
weight: 100
description: Find out why the server refused a sign-in, token or Batch request.
---

Every refusal produces an audit record with a reason. The same reason appears on the request's trace and as a label on the `lfs.auth.failures` metric. To find one:

1. Get the time of the failure and, if you have it, the key fingerprint. Show yours with `ssh-keygen -lf ~/.ssh/id_ed25519.pub`.
2. Search the server's logs for records with `lfs.reason` set around that time.
3. Match the reason:

| Reason | Meaning | Fix |
| --- | --- | --- |
| `not_ready` | The server has no permissions snapshot yet. | Wait for the first sync, or check the provider's configuration and credentials. |
| `stale` | The snapshot is older than `NARAEN_SNAPSHOT_MAX_AGE`. | Find out why syncs fail, using `lfs.sync.failures`. |
| `unknown_key` | The key's fingerprint is not in the datastore. | Add the key to your GitHub account and wait for the next sync. Check that your SSH agent offers that key. |
| `bad_path` | The repository path in the command is malformed. | Check `lfs.url` in `.lfsconfig`. |
| `unknown_repo` | No repository with that path exists in the datastore. | Check the path, and that the GitHub App is installed on the repository. |
| `unknown_identity` | The key's identity is missing. | Wait for the next sync. |
| `inactive_identity` | The identity is deactivated. | Check the person's membership on GitHub. |
| `insufficient_grant` | The grant does not allow the operation. Download needs read; upload needs write. | Change the person's access on GitHub. |
| `bad_operation` | The operation is neither `upload` nor `download`. | Update Git LFS. |

On the HTTPS side, a missing or invalid token, a token for another repository or operation, and an unknown repository all answer the same `401`, so the response never reveals whether a repository exists. Use the server's records, not the response, to tell them apart.
