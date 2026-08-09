# ADR 0009 — Maintain our own lockfile pattern list

Status: accepted · 2026-08-09

## Context

We must know which filenames to look for *before* asking osv-scanner anything:
the history walk needs pathspecs, and `git ls-tree` output needs filtering.

The obvious move is to take the list from the source. osv-scanner exposes no
way to enumerate its extractors. osv-scalibr's `extractor/filesystem/list`
package offers registries and `FileRequired(path) bool` predicates — which need
candidate paths you do not have yet, so they cannot be inverted into a list.
Importing osv-scalibr for this would also pull containerd, docker and protobuf
into a binary that has no dependencies
([ADR 0007](0007-go-with-zero-dependencies.md)).

## Decision

`defaultLockfilePatterns` is copied from the published supported-lockfiles
list. `LOCKFILE_PATTERNS` overrides it at runtime, so a newly supported file can
be scanned without waiting for a rebuild.

## Consequences

- The list drifts if osv-scanner adds an extractor and nobody notices. The
  override is the mitigation, and `TestIsLockfile` pins the matcher.
- Blobs on `HEAD` must be filtered in Go: `git log` accepts `*name` pathspecs at
  any depth, `git ls-tree` does not. When that filter was missing, every README
  and Dockerfile in every tree was handed to osv-scanner as a lockfile —
  5662 "lockfile versions" for 14 repos.
