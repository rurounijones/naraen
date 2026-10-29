# Changelog

All notable changes to naraen are recorded in this file, for the people who run it. The commit history holds the reasoning behind each one.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The first release has not been cut yet, so everything so far is listed as added.

### Added

- Fail-closed authorization from an in-memory snapshot. Requests are refused until there is a snapshot and once the snapshot is older than its maximum age.
- Validation before each snapshot swap, which rejects a sync that changes identities or grants by an unusually large amount.

[Unreleased]: https://github.com/rurounijones/naraen/commits/main
