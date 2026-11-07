---
title: Architecture
weight: 10
description: The parts of naraen and why the server never carries file bytes.
---

naraen is a Git LFS server for teams whose code lives on GitHub. Large files are stored in one S3 bucket. Developers sign in with the SSH keys they already use for GitHub, GitHub decides what they may reach, and file bytes travel directly between the client and S3. The server handles only small control requests.

## The parts

A single Go binary runs two listeners and a background sync.

- **SSH listener.** Authenticates the offered public key and answers `git-lfs-authenticate` with a short-lived bearer token.
- **HTTPS listener.** Serves the Batch API, the CI token exchange, the health probes and, when configured, the GitHub webhook.
- **Permissions datastore.** An in-memory snapshot of identities, keys, repositories and grants. Every access decision is a lookup in it.
- **Provider.** Fills the datastore from GitHub on a schedule. It is the only code that knows about GitHub.
- **Storage.** One S3 bucket. The server only signs URLs for it.

## Two halves that never call each other

The _request path_ (SSH, token issuance, Batch API) only reads the datastore and makes no network call to decide access. The _provider_ only writes the datastore. They meet at the snapshot.

This separation has three effects:

- A request is decided against one immutable snapshot, so it is fast and consistent within the request.
- Access fails closed. Anything absent from the snapshot is denied.
- The request path has no knowledge of GitHub. A source outage cannot slow requests, and a source's rate limits do not reach them. The linter forbids request-path packages from importing the provider.

See [The authorization model]({{< relref "authorization-model" >}}).

## Why bytes bypass the server

Git LFS 3.x first tries `git-lfs-transfer`, which sends every byte through the SSH connection. naraen refuses it, so clients fall back to `git-lfs-authenticate`, which returns the address of the Batch API and a token. The Batch API then returns one pre-signed S3 URL per file, and the client moves the bytes directly.

The server therefore needs little CPU, memory or bandwidth, and its cost does not grow with the volume of data. It also means the controls that matter for the files themselves, such as encryption, versioning and replication, belong to S3.

## Where state lives

The server keeps no local state. The permissions snapshot is rebuilt by a full sync, and a signed copy saved in the bucket lets a restarted server serve before its first sync completes. See [Staleness and revocation]({{< relref "staleness-and-revocation" >}}). Tokens are self-contained, so any instance holding the token keys can verify them.
