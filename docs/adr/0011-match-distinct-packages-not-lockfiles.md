# ADR 0011 — Match distinct packages, not lockfiles

Status: accepted · 2026-08-09
Resolves the "still open" note in
[ADR 0010](0010-triage-broken-lockfiles-before-scanning.md).

## Context

[ADR 0010](0010-triage-broken-lockfiles-before-scanning.md) measured where the
time goes and named the ceiling it could not move: osv-scanner spends ~3 ms per
**package entry** and nothing per file. Deduplicating history to distinct
lockfile *contents* ([ADR 0002](0002-deduplicate-history-by-blob-hash.md)) does
nothing about that, because two lockfile versions one commit apart are distinct
contents holding almost identical package lists.

Measured on one real history: 215 819 package entries across 261 distinct
lockfile versions were **6 146 distinct `(ecosystem, name, version)` triples** —
a factor of 35. Every one of the other 34 copies was a database lookup paid
again for an answer already known.

Three facts made a different arrangement possible, all verified on 2.5.0:

- `--all-packages` returns the full package inventory per input file, not just
  what matched.
- Reading a lockfile without loading a database costs ~0.14 s against ~1.5 s for
  a real scan, using the extraction-only mode from ADR 0010.
- osv-scanner reads a CycloneDX SBOM as an input and matches its purls offline.
  Compared against scanning the same two lockfiles directly: **127 finding groups
  in common, none missing, none extra.**

## Decision

Scan in two passes, and deduplicate between them.

1. **Read.** An extraction-only pass over each batch returns what every lockfile
   contains. No database is loaded. This is also the triage pass from ADR 0010 —
   the files it cannot parse are the files a real scan cannot parse — so it costs
   nothing extra.
2. **Match.** The distinct triples of the whole run, minus everything earlier
   waves already resolved, are written into a CycloneDX document and scanned
   offline. Sharded by ecosystem, because a process only loads the databases it
   is asked about.
3. **Join.** Each lockfile's result is reassembled from its own packages, and
   cached per blob exactly as before, so [ADR 0003](0003-file-cache-keyed-by-content-and-db-version.md)
   and resume-after-Ctrl-C are untouched.

We now own the purl strings and the join. We still own **no matching logic**,
which is what [ADR 0001](0001-delegate-detection-to-osv-scanner.md) was about:
version-range semantics stay entirely inside osv-scanner.

**Nothing is concluded from silence.** Three ways the fast path can fail to
answer, and all three fall back to scanning the file whole rather than reporting
it clean:

- an ecosystem we cannot build a correct purl for (an OS package needs distro
  qualifiers a lockfile cannot supply);
- a purl submitted and not returned, checked per run with `--all-packages`;
- an ecosystem with no local database, which is its own bug below.

## Consequences

- A cold run over 261 lockfile versions went from ~520 s to 88 s, finding the
  identical 48 vulnerabilities. Warm, it is 6 s.
- **A missing database no longer passes silently.** Verified: an ecosystem with
  no local database makes osv-scanner print an error, exit 0, and return zero
  vulnerabilities for every package *after* the one that triggered it — one Hex
  dependency zeroed the npm findings that followed it in the same invocation.
  That was a live false negative in the old arrangement, where warm-up only
  downloaded the ecosystems present in the first batch of the first wave.
  Databases are now fetched per ecosystem, from the inventory, so the set of
  databases matches the set of ecosystems the run contains — and the marker is
  treated as a hard failure of the whole invocation.
- The old sequential warm-up pass is gone. It was 164 s of the 217 s a run took,
  scanning 64 files at full price to fetch a database as a side effect.
- The canary now goes through **both** paths. A self-check that only proves the
  path we no longer take proves nothing.
- The purl table is ours to keep correct. Wrong entries cost speed, not
  coverage, because of the round-trip check — but a *new* ecosystem appearing
  upstream will quietly take the slow path until it is added.
- Progress is reported in two stages, reading then matching, which is honest
  about what is happening and moves far more often than one bar over batches.
- The ~3 ms/package constant is a floor, not a law: it was measured on two
  modern lockfiles, and on 6 146 distinct packages drawn from a decade of
  history it degrades to ~14 ms/package — old versions carry hundreds of
  advisories each, and the matcher's cost follows the advisory volume, not the
  package count. Shard size does not move this (identical wall time at 500 and
  at 3 073 packages per shard, for opposite reasons), so the shard floor is set
  from the constants and left alone. The remaining ceiling is osv-scanner's own
  matching, not our arrangement of it.
