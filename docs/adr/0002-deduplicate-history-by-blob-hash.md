# ADR 0002 — Deduplicate history by git blob hash

Status: accepted · 2026-08-09

## Context

The point of this tool is exposure that has already ended: a package
compromised in 2023 and updated away in 2024 is invisible on `HEAD`, but its
`postinstall` ran back then.

That means scanning history. Naively, "check out every commit and scan it" —
which for a repo with 500 commits touching `package-lock.json` is 500 scans of
maybe 40 genuinely different files.

## Decision

Walk history once per repo with `git log --all --reflog --no-abbrev --raw`,
which emits the blob SHA of every version of every lockfile **and** the commit
that carried it in a single pass. Keep the distinct blobs, keyed by
`(blob hash, filename)`, and scan each exactly once.

Lockfiles outside any repository are keyed the same way: we reproduce git's own
blob id, `sha1("blob <len>\0" + content)`, rather than a plain SHA-256, so a
loose file and its committed twin collapse into one scan instead of two.

## Consequences

- Cost tracks distinct content, not commits: 14 repos came out at 256 distinct
  lockfile versions.
- Commit attribution is free from the same output, which is what lets the
  report date an exposure and separate "still on HEAD" from "past exposure".
- The filename is part of the key because osv-scanner picks its extractor from
  the name: identical bytes named `package-lock.json` and `foo.json` are not
  the same scan.
- One `git cat-file --batch` process per repo, fed the hashes it needs, instead
  of one process per blob.
