---
title: Push and pull a large file
weight: 10
description: Start a local stack, push an LFS file through the server to storage, and pull it back.
---

In this tutorial you start a complete naraen stack on your machine, push a one-megabyte file with Git LFS, and clone it back. You will see the same steps a developer takes against a real deployment.

You need Docker with Compose, and a checkout of the naraen repository. You do not need a Go toolchain.

## Start the stack

From the repository root, run:

```sh
docker compose up -d
```

This starts four containers on a private network, each reachable by name:

- `s3`, a local S3-compatible store with a bucket named `naraen-dev`.
- `naraen`, the server in development mode. SSH is on `naraen:2222` and the Batch API on `https://naraen:8443`.
- `oidc`, a stand-in for GitHub Actions' token issuer. You use it in the second half.
- `client`, a developer's machine with `git`, `git-lfs`, `ssh` and `curl`.

The server loads a small permissions file with two developers. The `writer` key may upload and download `example/repo`, and the `reader` key may only download. The keys are committed to the repository on purpose; the server refuses them outside development mode.

Check that the server is ready:

```sh
docker compose exec client curl -fsS --cacert /usr/local/share/naraen/devkeys/tls.crt https://naraen:8443/readyz
```

If the command prints nothing and exits successfully, the server has a permissions snapshot and is serving.

## Push a file as the writer

Open a shell in the client container. It holds the `writer` key by default.

```sh
docker compose exec client bash
```

Create a repository and point its LFS address at the server:

```sh
git init demo && cd demo
git config -f .lfsconfig lfs.url ssh://git@naraen:2222/example/repo
git lfs track '*.psd'
head -c 1000000 /dev/urandom > art.psd
git add . && git commit -m 'Add art'
```

The `.lfsconfig` file is committed with the repository, so every clone uses the same LFS server.

Add a local remote and push:

```sh
git init --bare ~/origin.git && git remote add origin ~/origin.git
git push origin main
```

The push uploads `art.psd` through the server to storage. Behind the scenes, Git LFS opened an SSH connection, asked for a token with `git-lfs-authenticate`, sent a Batch request, and then uploaded the file straight to S3 with a pre-signed link.

## Pull it back

Clone the repository elsewhere:

```sh
cd .. && git clone ~/origin.git copy
```

Git LFS downloads `art.psd` the same way, in reverse. Compare the two copies:

```sh
cmp demo/art.psd copy/art.psd && echo identical
```

## Try a CI job

A CI job has no SSH key. It gets an OIDC token from its platform and exchanges it for a read-only LFS token. The `oidc` container plays the part of GitHub Actions.

```sh
oidc=$(curl -fsS 'http://oidc:8080/token?audience=naraen-dev&repository_id=1&repository=example/repo' | sed -E 's/.*"value":"([^"]+)".*/\1/')
curl -fsS --cacert "$NARAEN_DEVKEYS/tls.crt" -X POST -H "Authorization: Bearer $oidc" https://naraen:8443/example/repo/ci/token
```

The answer has the same shape as `git-lfs-authenticate`'s:

```json
{"href":"https://naraen:8443/example/repo","header":{"Authorization":"Bearer v1.dev...."},"expires_in":900}
```

Use the returned header to pull:

```sh
git -c lfs.url=https://naraen:8443/example/repo \
    -c "http.extraHeader=Authorization: Bearer v1.dev...." lfs pull
```

Replace `v1.dev....` with the token you received. This token is read-only, so a push with it is refused.

## Check the whole path in one command

The repository includes a script that does all of this and also checks that the `reader` and the CI job are refused when they try to push:

```sh
docker compose exec client naraen-smoke
```

## What you have learned

You started a server, used it as a developer and as a CI job, and saw that file bytes never pass through the server. To go further:

- [Connect a repository to the server]({{< relref "../how-to/connect-a-repository" >}}) for a real deployment.
- [How a transfer works]({{< relref "../explanation/how-a-transfer-works" >}}) for what happened in each step.
