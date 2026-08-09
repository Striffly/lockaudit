# ADR 0005 — Few large osv-scanner batches, bisected on failure

Status: superseded by
[ADR 0010](0010-triage-broken-lockfiles-before-scanning.md) · 2026-08-09

The database-load measurement below holds. The conclusion drawn from it does not:
matching cost per lockfile turned out to dominate it above ~64 files a batch, and
bisecting a failed batch turned out to be the single most expensive thing the
scanner did. Kept as written, per the practice in [the index](README.md).

## Context

Measured on osv-scanner 2.5.0: loading the npm database costs about 11 s of CPU
**per process**, warm cache or not (`~/.cache/osv-scalibr/npm/all.zip`, ~220 MB,
~226k records). Process startup itself is noise next to that.

So the cost of a scan is roughly `11 s × number of processes`, and the
intuitive optimisation — one process per file, nicely parallel — is the worst
possible layout.

Second measured fact: a single unparseable lockfile makes osv-scanner abort the
**entire** invocation and emit no JSON at all. Not a partial result — nothing.
Real histories contain truncated files and files with conflict markers
committed by mistake.

## Decision

As few processes as possible, as large as possible: roughly one per worker,
with a floor of 64 files per batch. Blobs are extracted to scratch space in
waves bounded by bytes on disk, because a decade of `package-lock.json` history
is several GB.

A batch that fails is bisected until the culprits are isolated to single files,
which are reported as unscannable and skipped.

## Consequences

- Anyone "optimising" this by spawning more, smaller processes makes it
  dramatically slower. The floor exists to stop that.
- One poison file costs `log2(n)` extra invocations instead of the whole run.
- Unscannable files are visible in the report rather than silently absent —
  a file we could not parse is not a file we know is clean.
