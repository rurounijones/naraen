# Contributing

Develop inside the devcontainer (or any container built from the `dev` stage of the `Dockerfile`); no host Go toolchain is needed.

- `task check` is the fast gate: format, lint, nilaway, race tests, 100% line and branch coverage, vulnerability, SAST and secret scans.
- `task docs` builds the documentation site in `docs/` (Hugo and Docsy, laid out by Diátaxis) and fails on any warning, including a broken link; `task docs-serve` serves it on port 1313. Document what the code does, not its history or plans, and update the page when a change alters behaviour it describes.
- `task ci` adds fuzzing, mutation testing, integration tests, image scans and DAST.
- All security gates are blocking. Do not add `//nolint` without an explanation.
- Code on the request path (`authz`, `sshd`, `batch`, `token`, `httpapi`, `oidc`, `datastore`) must not import `internal/provider`; the linter enforces it. A provider's webhook handler is mounted on `httpapi` from `main` as a plain `http.Handler`.
- Every parser of client-supplied input needs a fuzz target.
- A change the people running the server would notice, such as a feature, a new setting or a fix, adds an entry under `[Unreleased]` in `CHANGELOG.md` in the same commit. Tests, tooling and CI do not need one.

## Commit messages

The diff shows what changed. The message exists to say what the diff cannot: why. Long bodies are welcome; a commit with a real design consequence should read like a short essay, not a label.

- **Subject:** imperative, sentence case, no trailing period, no `feat:`/`fix:` prefixes, about 70 characters at most. Say the outcome, not the mechanics ("Reject expired tokens before the SSH handshake").
- **Body:** separated from the subject by a blank line and wrapped at about 72 columns. Omit it only when the subject says everything, such as a typo or a version bump.
- **Order the body as:**
  1. The problem and its impact: who or what was affected, and why it was worth fixing now.
  2. The approach, in plain English, so a reviewer can check the code does what you intend.
  3. Why this approach: the alternatives you rejected and the trade-offs you accepted, including downsides.
  4. Anything deliberately left out, and follow-ups.
- **Do not narrate the diff.** A list of files or functions touched is noise unless it explains a reason. Record concrete identifiers that cannot be derived from the code: CVE or advisory IDs, ports, limits, measured numbers.
- **One logical change per commit.** If the body keeps growing past one idea, split the commit. Docs and tests go in with the change they describe.
- **Stand alone.** Do not rely on an issue or earlier discussion to explain the change; links are extras. Cite other commits by SHA and one-line summary.
- **Security-relevant changes** state the threat or the invariant being protected, and name the test that proves the control.

Pull requests follow the same rules: the title is the subject, the description is the body, and the PR template's "Why" section is where the reasoning goes.
