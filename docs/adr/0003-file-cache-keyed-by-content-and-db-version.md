# ADR 0003 — File cache keyed by content hash and OSV database version

Status: accepted · 2026-08-09

## Context

Runs are meant to be repeatable and interruptible: a scan you cannot cut short
is a scan you postpone. Between two runs, almost nothing changes — the same
lockfile versions, the same results.

A cache keyed by path would be wrong (the same content lives at many paths, in
many repos, in many sources). A cache with no notion of database version would
be dangerous: a "clean" verdict from last week would keep hiding an advisory
published since.

## Decision

A directory tree, no database:

```
<cache>/results/<osv-db-version>/<hash-prefix>/<hash>-<filename>.json
```

The database fingerprint is part of the **path**, so refreshing the OSV
databases invalidates every entry at once. Superseded generations are pruned
after a week.

Each result is written with `os.CreateTemp` + `os.Rename` — atomic on the same
filesystem.

## Consequences

- No SQLite, so no cgo and no 400k-line pure-Go driver.
- No writer goroutine, no lock, no contention: every worker writes its own
  file.
- **The atomic rename is the resume mechanism.** An interrupted run never
  leaves a half-written result that a later run would trust, so rerunning
  redoes only what was unfinished. Cold 23 s, warm 0.08 s on the same scope.
- A cache hit is an `os.Stat`; 20k of them cost about 50 ms.
- Hash-prefix subdirectories keep any single directory from reaching 100k
  entries.
