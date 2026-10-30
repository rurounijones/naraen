# Development keys

These SSH key pairs are public on purpose. Their fingerprints are in `../snapshot.json`, the snapshot that `docker compose up naraen` loads, so a git-lfs client on any machine can authenticate against a local server without editing anything.

| Key | Identity | Grant on `example/repo` |
| --- | --- | --- |
| `writer` | `writer` | write (upload and download) |
| `reader` | `reader` | read (download only) |

Only that snapshot file accepts them. A server reads a snapshot file only when `NARAEN_SNAPSHOT_FILE` is set, and in production the provider fills the datastore from GitHub, so these keys grant nothing there. Never add them to a GitHub account or a real snapshot.

`cmd/naraen`'s `TestDevSnapshotFixture` checks that the keys and the snapshot agree. Git does not keep file modes other than the executable bit, so `chmod 600` the private key before ssh will use it.
