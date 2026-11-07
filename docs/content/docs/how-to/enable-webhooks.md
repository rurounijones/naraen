---
title: Enable webhooks for instant removals
weight: 50
description: Make removed members, collaborators and deploy keys lose access at once instead of at the next sync.
---

Webhooks are optional. The scheduled sync is the baseline; webhooks only shorten the delay, most valuably when someone leaves the organisation.

## Set a webhook secret

Generate a secret of at least 20 bytes and put it in a file:

```sh
openssl rand -hex 32 > webhook-secret
```

```sh
NARAEN_GITHUB_WEBHOOK_SECRET_FILE=/run/naraen/webhook-secret
```

Without this setting the `/webhooks/github` route is not served.

## Add the webhook on GitHub

In the GitHub App's settings (or the organisation's), add a webhook:

- **Payload URL:** `https://lfs.example.com/webhooks/github`
- **Content type:** `application/json`
- **Secret:** the same value as the file.
- **Events:** organization, member and deploy key.

## What it does

The server checks each delivery's `X-Hub-Signature-256`, then applies only removals: an organisation member removed, a collaborator removed, or a deploy key deleted. Every other event is accepted and ignored. A delivery can only remove access, so a replayed or reordered one can at worst deny until the next sync.

Changes with no webhook, such as a change to the organisation's base permission, wait for the next full sync.
