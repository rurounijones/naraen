---
title: Authentication
weight: 30
description: How developers, CI jobs and webhooks prove who they are.
---

## Developers: SSH keys

An SSH server sees only the public key a client offers. The `git@` username carries no identity, and GitHub has no API that answers "who owns this key". naraen resolves the problem on its own side: the provider loads each organisation member's keys and each repository's deploy keys into the datastore, and the SSH layer looks up the offered key's SHA-256 fingerprint there. GitHub allows a key on only one account or repository, so every fingerprint belongs to exactly one identity. The SSH layer never contacts GitHub.

The consequences:

- Developers add an SSH key to their GitHub account once. They can keep using HTTPS for code.
- A newly added key is unknown until the next full sync.
- Commit-signing keys are never loaded.
- Outside collaborators are not organisation members, so they have no identity and get no access.

Identity is taken only from the permissions returned by the successful key callback. Go's SSH library can invoke that callback for keys the client does not hold (CVE-2024-45337), so the server requires `golang.org/x/crypto` 0.31.0 or later, and the attack scenario tests cover a key swap.

## CI: GitHub Actions

A job requests GitHub's OIDC token for the configured audience and exchanges it at `POST /{owner}/{repo}/ci/token` for a read-only LFS token. No secret is stored in the CI system.

The server verifies the token against the _workload trust_ entry the provider registered for the repository:

- The signature, using the issuer's signing keys as recorded in the entry. Only RS256 (keys of 2048 bits or more) and ES256 are accepted, keys are chosen by `kid`, and no other algorithm is honoured.
- The issuer, the exact audience and the expiry.
- The claim that names the repository, `repository_id`, which must be the repository in the URL.

The workload is an identity like any other. A trust is accompanied by the identity `workload:<repo ID>` and a read grant, and the exchange checks that grant. The Batch API checks it again on every request.

## CI: other systems

A repository's GitHub deploy key is loaded into the datastore as an identity scoped to that repository. It is read-only unless the deploy key has write access. CI systems other than GitHub Actions keep the key in their secret store and use it for SSH like a developer's key.

Neither path uses a GitHub seat.

## Webhooks

GitHub signs each webhook delivery with an HMAC-SHA256 of the body, in `X-Hub-Signature-256`. The server verifies it with the shared secret before reading the payload. Webhooks can only remove access, so a replayed or forged delivery at worst denies a request. See [How to enable webhooks]({{< relref "../how-to/enable-webhooks" >}}).

## Tokens

LFS bearer tokens are HMAC-signed by the server, and bound to a repository ID and an operation. They expire after 15 minutes. A token file may list several keys, the first of which signs, so a key can be rotated without invalidating tokens in use. See [How to rotate token keys]({{< relref "../how-to/rotate-token-keys" >}}).
