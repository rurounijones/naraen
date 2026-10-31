# Development keys

Everything in this folder is public on purpose, so that `docker compose up` gives a working local server whose identity stays the same across restarts, and so that a git-lfs client on any machine can use it without editing anything.

## Client keys

The fingerprints of these SSH key pairs are in `../snapshot.json`, the snapshot that compose's naraen service loads.

| Key | Identity | Grant on `example/repo` |
| --- | --- | --- |
| `writer` | `writer` | write (upload and download) |
| `reader` | `reader` | read (download only) |

Only that snapshot file accepts them, and only in development mode: a server started without `NARAEN_DEV=true` refuses any snapshot that lists either key (`devKeyFingerprints` in `cmd/naraen`). Never add them to a GitHub account or a real snapshot.

## Server identity

| File | What it is |
| --- | --- |
| `ssh_host_ed25519_key` | The server's SSH host key, `SHA256:ece12yWlKcAsYMpwTau1lNvkQ5prkwdrUoIov2UX3vc` |
| `oidc.key` | The development OIDC issuer's ES256 signing key (`cmd/naraen-dev-oidc`, compose's `oidc` service). The dev snapshot's trust entry holds its public half |
| `webhook.secret` | The GitHub webhook secret compose's naraen service verifies deliveries with, and DAST signs them with |
| `tls.crt`, `tls.key` | A self-signed ECDSA P-256 certificate for `localhost`, `naraen`, `127.0.0.1` and `::1`, valid until October 2036. Clients trust it with `git config http.sslCAInfo` |

A server started without `NARAEN_DEV=true` refuses the host key and certificate (`devHostKeyFingerprint` and `devCertSHA256` in `cmd/naraen`), because anyone who reads this repo could impersonate a server that used them. It also refuses a snapshot whose trust entries hold the OIDC key (`devOIDCKeyX`), because anyone could mint CI tokens it accepts. And it refuses to start with the webhook secret (`devWebhookSecretSHA256`), because anyone could sign deliveries that revoke access.

## Tests

`cmd/naraen`'s `TestDevSnapshotFixture` checks that the client keys, the snapshot and the refusal list agree, `TestDevServerIdentity` does the same for the host key and certificate, `TestDevOIDCTrust` for the OIDC key and the snapshot's trust entry, and `TestDevWebhookSecret` for the webhook secret. Git does not keep file modes other than the executable bit, so `chmod 600` a private key before ssh will use it.
