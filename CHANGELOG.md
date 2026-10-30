# Changelog

All notable changes to naraen are recorded in this file, for the people who run it. The commit history holds the reasoning behind each one.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The first release has not been cut yet, so everything so far is listed as added.

### Added

- Git LFS `push` and `pull` over SSH authentication, the Batch API and pre-signed S3 URLs, so file bytes go directly between the client and S3. Clients that try pure-SSH transfer are refused and fall back to `git-lfs-authenticate`.
- Developer sign-in with the SSH keys they already use on GitHub, and bearer tokens that last 15 minutes and are bound to one repo and operation.
- Upload links that bind each object to its SHA-256 and size, so S3 rejects bytes that do not match.
- Storage in one S3 bucket (`NARAEN_S3_BUCKET`), with one top-level folder per repo named by its repo ID.
- Read-only CI access without stored secrets, by exchanging a GitHub Actions OIDC token at `/{owner}/{repo}/ci/token`.
- Signed GitHub webhooks (`/webhooks/github`) that revoke access at once for removed members, removed collaborators and deleted deploy keys.
- Fail-closed authorization from an in-memory snapshot, with every Batch request rechecked against it. Requests are refused until there is a snapshot and once the snapshot is older than its maximum age.
- Validation before each snapshot swap, which rejects a sync that changes identities or grants by an unusually large amount.
- An audit record for every SSH sign-in, refusal and token issued.
- Optional OTLP export (`NARAEN_OTLP_ENDPOINT`) of metrics and logs.
- SSH connection limits per source and in total, including a rate limit configurable with `NARAEN_SSH_CONN_BURST` and `NARAEN_SSH_CONN_INTERVAL`.
- Static Linux binaries and a container image for amd64 and arm64, both signed with cosign, with SBOMs and GitHub build provenance. Releases are made only from `main` after every gate passes.

[Unreleased]: https://github.com/rurounijones/naraen/commits/main
