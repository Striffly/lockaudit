# ADR 0010 — Triage broken lockfiles before scanning, and cap batch size

Status: accepted · 2026-08-09
Supersedes the batch sizing and failure handling of
[ADR 0005](0005-few-large-osv-scanner-batches.md).

## Context

ADR 0005 sized batches from one measurement — 11 s of CPU to load the npm
database, per process — and concluded "as few, as large as possible". A run over
~400 repositories and 17 520 distinct lockfile versions showed what that misses.

Three things came out of measuring it properly on an idle machine:

**Matching costs ~1.5 s per lockfile**, or ~3 ms per package entry, and dwarfs the
database load at any batch size above a few dozen files. At 350 files a batch a
worker holds one batch for the best part of an hour. The database load is not the
dominant cost. It stopped being the thing worth optimising once batches passed
~64 files.

**Bisection was the real bill.** 3 of 40 lockfiles sampled at random from one
machine's history fail to parse — truncated, or with conflict markers committed
by mistake. A batch with k of them costs about `log2(k)+2` times the whole batch,
and every one of those re-runs pays the full matching cost. On the run above,
bisection was most of the time spent.

**Cancellation looked identical to corruption.** A cancelled context fails every
invocation, so bisection walked the batch after Ctrl-C blaming each file in turn.
The interrupted run reported 200 perfectly good lockfiles as unscannable.

And one flag turned out to be useful for something other than what it does:
`--offline-vulnerabilities` without `--offline` loads no database (see
[the behaviour notes](../osv-scanner-behaviour.md)) but still extracts and parses
every input, at ~0.14 s per lockfile, failing on exactly the files a real scan
would fail on.

## Decision

**Triage, then scan.** Every batch is first run through an extraction-only pass.
The files osv-scanner names on stderr are dropped and reported; the pass repeats
until clean, because one pass does not name every culprit. The expensive scan
then runs once, over input known to parse.

**Bisection stays, demoted.** It handles failures that name nothing, and it
returns empty-handed rather than assigning blame once the context is cancelled.

**64 files per batch, fixed.** More batches than workers, with the pool bounded
by a semaphore — an osv-scanner process holds a whole ecosystem database in
memory, so one per batch would exhaust it.

## Consequences

- The database load is back to ~11% overhead. That is the price, and it is paid
  knowingly, for the next two points.
- A batch of 64 finishes in a minute or two, so the progress line moves and an
  interruption loses at most 64 files of work instead of 350.
- A broken lockfile costs one cheap pass instead of several expensive ones.
- The scanner is invoked in a mode that is documented here as dangerous. It is
  guarded by type: `scanExtract` results are never stored or reported, and
  `canaryCheck` still proves the real path consults a database.
- Unscannable files are named with their repo, path and commit, not just a
  basename. "unscannable lockfile package-lock.json" was equally true of
  thousands of files.

## Still open

Cost scales with package entries, not files, and successive versions of one
lockfile repeat nearly all of their packages. Matching unique
`(ecosystem, name, version)` triples once per run instead of once per lockfile
would cut the dominant cost by an order of magnitude.

Resolved by [ADR 0011](0011-match-distinct-packages-not-lockfiles.md), which
also reuses this ADR's extraction-only pass as the inventory, so triage became
free.
