# Development keys

These SSH key pairs are public on purpose. Their fingerprints are in `../snapshot.json`, the snapshot that `docker compose up naraen` loads, so a git-lfs client on any machine can authenticate against a local server without editing anything.

| Key | Identity | Grant on `example/repo` |
| --- | --- | --- |
| `writer` | `writer` | write (upload and download) |
| `reader` | `reader` | read (download only) |

Only that snapshot file accepts them, and only in development mode: a server started without `NARAEN_DEV=true` refuses any snapshot that lists either key (`devKeyFingerprints` in `cmd/naraen`). Never add them to a GitHub account or a real snapshot.

`cmd/naraen`'s `TestDevSnapshotFixture` checks that the keys, the snapshot and the refusal list agree. Git does not keep file modes other than the executable bit, so `chmod 600` the private key before ssh will use it.
