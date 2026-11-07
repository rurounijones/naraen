---
title: Configure the server for production
weight: 20
description: The settings and secret files a production server needs.
---

The server reads its settings from environment variables. Secrets are never put in the environment; the variables name the files that hold them. Without `NARAEN_DEV=true`, the server refuses to start unless every required setting is present, so a production server cannot run on throwaway keys.

## Create the secret files

1. **Token keys.** One line per key, `<id> <hex secret>`, with at least 32 bytes of secret each. For example:

   ```sh
   echo "k1 $(openssl rand -hex 32)" > token-keys
   ```

2. **SSH host key.** An Ed25519 private key:

   ```sh
   ssh-keygen -t ed25519 -N '' -f ssh_host_ed25519_key
   ```

   Publish its fingerprint, or sign it with an SSH CA, so developers can [verify it]({{< relref "connect-a-repository" >}}).

3. **TLS certificate and key** for the public host name, for example from Let's Encrypt.

## Set the environment

```sh
NARAEN_PUBLIC_URL=https://lfs.example.com
NARAEN_TOKEN_KEYS_FILE=/run/naraen/token-keys
NARAEN_SSH_HOST_KEY_FILE=/run/naraen/ssh_host_ed25519_key
NARAEN_TLS_CERT_FILE=/run/naraen/tls.crt
NARAEN_TLS_KEY_FILE=/run/naraen/tls.key
NARAEN_S3_BUCKET=acme-lfs
AWS_REGION=us-east-1
```

`NARAEN_PUBLIC_URL` is the name clients use for the Batch API. `git-lfs-authenticate` returns it, so it must be an `https` origin with no path.

The server listens on ports 22 (SSH) and 443 (HTTPS) by default. Change them with `NARAEN_SSH_ADDR` and `NARAEN_HTTPS_ADDR`.

## Give the server AWS access

The server uses the AWS SDK's default credential chain: the instance role on EC2, or the file named by `AWS_SHARED_CREDENTIALS_FILE` elsewhere. The role needs:

- `s3:GetObject` and `s3:PutObject` on the objects in the bucket.
- `s3:ListBucket` on the bucket. Without it, S3 answers 403 instead of 404 for a missing object, and uploads of new objects fail.
- With a customer-managed KMS key on the bucket, `kms:GenerateDataKey` and `kms:Decrypt` on that key.

It needs no delete permission. The server never lists the bucket, so log `ListObjects` as a CloudTrail data event and alert on any call from the server's role.

## Choose where permissions come from

Pick one source:

- The GitHub provider, which is the normal choice. See [Create the GitHub App]({{< relref "create-the-github-app" >}}).
- `NARAEN_SNAPSHOT_FILE`, a JSON file of identities, keys, repos and grants, for testing. See [Permissions snapshot format]({{< relref "../reference/snapshot-format" >}}).

Setting both is an error.

## Check readiness

```sh
curl -fsS https://lfs.example.com/readyz
```

The server answers 503 until it holds a snapshot. See [Staleness and revocation]({{< relref "../explanation/staleness-and-revocation" >}}).

All settings are listed in the [configuration reference]({{< relref "../reference/configuration" >}}).
