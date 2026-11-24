<!--
SPDX-FileCopyrightText: 2026 The P4 Language Consortium

SPDX-License-Identifier: Apache-2.0
-->

# CI caches

Native CI uses `ccache-v2-` keys scoped to architecture, OS, compiler, and build
configuration. Bazel uses `bazel-v2-` keys scoped to architecture, runner image,
and Bazel version, so compiler upgrades get fresh toolchain detection.

Both append a `main` or `pr-<number>` scope followed by the run ID and attempt.
Successful jobs save a fresh cache. PRs first restore their newest compatible
cache, then fall back to a compatible main cache.

## Daily cleanup

The Cache maintenance workflow uses the shared
[`p4lang/.github` cache retention action](https://github.com/p4lang/.github/tree/main/CI/cache-retention)
to keep the newest main cache per key/version and prune duplicate or closed-PR
caches. It removes least-recently-used PR caches to target 2 GB of PR storage
and 9 GB total. Main caches are retained even if those targets cannot be met.
Only `ccache-v2-` and `bazel-v2-` keys are managed; other caches count toward the
total but are not deleted by this workflow.

Run the workflow manually with `dry-run` enabled to preview cleanup. Scheduled
runs apply the policy automatically.
