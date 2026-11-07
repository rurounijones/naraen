---
title: Give CI read access
weight: 40
description: Let a CI pipeline download LFS files, with GitHub Actions OIDC or a deploy key.
---

CI pipelines can download LFS files without taking a GitHub seat. They are read-only unless a deploy key was created with write access.

## GitHub Actions, with no secrets

1. Pick a custom audience, for example `naraen`, and set it on the server:

   ```sh
   NARAEN_OIDC_AUDIENCE=naraen
   ```

   With it set, every sync registers GitHub Actions as a trusted token issuer with its current signing keys, and gives each repository a CI workload identity with read access.

2. Allow the job to request an OIDC token:

   ```yaml
   permissions:
     id-token: write
     contents: read
   ```

3. In the job, request a token for that audience and exchange it for an LFS token:

   ```yaml
   - name: Pull LFS files
     run: |
       oidc=$(curl -fsS -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
         "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=naraen" | jq -r .value)
       lfs=$(curl -fsS -X POST -H "Authorization: Bearer $oidc" \
         "https://lfs.example.com/${GITHUB_REPOSITORY}/ci/token")
       git config lfs.url "$(jq -r .href <<<"$lfs")"
       git config http.extraHeader "Authorization: $(jq -r .header.Authorization <<<"$lfs")"
       git lfs pull
   ```

The token must name the repository in the URL, so a job can only fetch its own repository's files. The returned LFS token lasts 15 minutes.

## Other CI systems, with a deploy key

1. Add a deploy key to the repository on GitHub. The provider loads it as an identity scoped to that repository, read-only unless the key has write access.
2. Store the private key in your CI system's secret store.
3. Use the key as the SSH identity, with the repository's `.lfsconfig`, exactly as a developer would.

The key appears in the server's permissions after the next sync, or at once if the server receives [webhooks]({{< relref "enable-webhooks" >}}) for deleted keys. Deleting the key on GitHub removes access the same way.

## Take access away

Remove the grant or the identity on GitHub. New tokens stop at the next sync, and the Batch API rechecks every request against the current permissions.
