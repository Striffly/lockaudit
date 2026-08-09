# ADR 0004 — Scan every copy of a project, local and remote

Status: accepted · 2026-08-09 (supersedes an earlier "the GitLab copy wins" rule)

## Context

The same project is commonly reachable several ways: a local clone, its GitLab
origin, a GitHub fork. The first design skipped the local copy when a forge
copy existed, on the theory that the forge is authoritative and rescanning is
waste.

That was wrong on both counts. The forge copy is not a superset — it is missing
every commit that was never pushed, which is exactly where a hasty
`npm install` tends to live. And the "waste" does not exist: whatever the two
copies share is the same content, hence the same blob hash, hence one scan.

## Decision

Every copy is inventoried and walked. Deduplication happens one layer down, on
lockfile content ([ADR 0002](0002-deduplicate-history-by-blob-hash.md)).

A local clone of a remote project is additionally reused as
`git clone --reference … --dissociate`, so the bare clone transfers only what
is missing. Every remote a local clone knows about seeds its own project, not
just the first one: a checkout with `origin` = fork and `upstream` = original
holds objects for both.

Forks and upstreams are separate projects and are meant to appear separately.

## Consequences

- Cost of a duplicate copy: one history walk, zero extra scans.
- Unpushed commits are covered.
- Cache paths are `<host>/<group>/<project>.git`, so two projects with the same
  name in different groups — or a fork and its upstream — cannot collide. The
  host comes from the clone URL, not the API URL, which differ on GitHub.
