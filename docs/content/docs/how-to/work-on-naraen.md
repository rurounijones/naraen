---
title: Run the checks and build these docs
weight: 110
description: Run the project's quality gates and build this documentation site.
---

Everything runs in the devcontainer, or in any container built from the `dev` stage of the `Dockerfile`. No host Go toolchain is needed.

## Run the checks

```sh
docker compose run --rm dev task check
```

`task check` is the fast gate: format, lint, nil-safety analysis, race tests with 100% line and branch coverage, vulnerability, SAST and secret scans, and a release build. `task ci` adds fuzzing, mutation testing, integration tests, image scans and DAST. All security gates are blocking.

To test only what you changed, pass a base commit: `task mutation -- origin/main` mutates only the lines changed since it, and `task fuzz -- origin/main` fuzzes only the packages that changed or import a changed package. CI does the same for a push or pull request and runs everything on its schedule and for a release.

List every task with `task --list`.

## Build and preview these docs

```sh
docker compose run --rm dev task docs
docker compose run --rm dev task docs-serve
```

`task docs` builds the site into `docs/public/` and fails on warnings. `task docs-serve` serves it with live reload on port 1313.

The site is a Hugo site that uses the Docsy theme as a Hugo module. Hugo, Dart Sass and the modules are pinned, and no Node.js is needed.

## Where a page goes

Each page belongs to one Diátaxis section under `docs/content/docs/`. Tutorials teach through a guided result. How-to guides solve one task. Reference describes facts only. Explanation gives background. If a page starts to do two jobs, split it.
