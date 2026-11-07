---
title: Create the GitHub App
weight: 30
description: Register the GitHub App the provider uses to read members, keys and permissions.
---

The GitHub provider reads your organisation through a GitHub App. The App is the provider's only credential.

## Register the App

1. In your organisation's settings, go to **Developer settings → GitHub Apps → New GitHub App**.
2. Give it any name and a homepage URL.
3. Under **Repository permissions**, grant read-only access to **Administration** (needed to list deploy keys) and **Metadata**.
4. Under **Organization permissions**, grant read-only access to **Members**.
5. Leave webhooks off unless you want [instant removals]({{< relref "enable-webhooks" >}}). Those use a separate webhook secret.
6. Create the App, then generate a private key and download the PEM file.

## Install it

Install the App on the organisation, choosing the repositories whose LFS files the server should store. The server stores objects for exactly the repositories the App can see, so the installation scope is the list of repositories allowed storage.

Note three values: the organisation login, the App ID, and the installation ID. The installation ID is in the URL of the installation's settings page.

## Configure the server

```sh
NARAEN_GITHUB_ORG=acme
NARAEN_GITHUB_APP_ID=123456
NARAEN_GITHUB_INSTALLATION_ID=7890123
NARAEN_GITHUB_APP_KEY_FILE=/run/naraen/github-app.pem
```

All four are required together; a partial set stops the server at startup. The server runs a full sync at startup and every `NARAEN_SYNC_INTERVAL` (default `15m`, minimum `1m`).

## Who gets access

Only organisation members and repository deploy keys can sign in. Outside collaborators are not members, so they have no identity and no access, even if they are collaborators on a repository. See [Authorization model]({{< relref "../explanation/authorization-model" >}}).

## GitHub Enterprise

Set `NARAEN_GITHUB_API_URL` and `NARAEN_GITHUB_JWKS_URL` to your instance's REST API and Actions OIDC key set.
