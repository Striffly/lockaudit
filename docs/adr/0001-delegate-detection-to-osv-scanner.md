# ADR 0001 — Delegate detection to the osv-scanner CLI

Status: accepted · 2026-08-09

## Context

Deciding whether `lodash@4.17.20` is affected by an advisory means owning
version-range semantics for every ecosystem — npm's semver, Python's PEP 440,
Maven's ordering, Go's pseudo-versions. Getting one of them subtly wrong
produces a false negative, which on a security tool is worse than no tool at
all: it is a clean report you believe.

Three options were on the table: our own matcher against the OSV data, the
osv-scalibr library in-process, or shelling out to the osv-scanner binary.

osv-scalibr's offline matcher (`localmatcher`) is an `internal` package and
cannot be imported. Using the library would mean reimplementing the matching
ourselves anyway, on top of pulling containerd, docker and protobuf into a
binary that currently has no dependencies at all.

## Decision

Shell out to `osv-scanner`, in offline mode, and parse its JSON.

We own the inventory, the history, the deduplication and the report. It owns
"is this package version affected".

## Consequences

- A hard external dependency on the binary, checked at startup with an
  actionable install message.
- ~11 s of CPU per process spent loading the npm database, cached or not, which
  is what forces [ADR 0005](0005-few-large-osv-scanner-batches.md).
- Its flag behaviour is ours to work around, not to trust — see the
  `--offline` trap in [docs/osv-scanner-behaviour.md](../osv-scanner-behaviour.md), which silently returned
  clean results on a malicious lockfile.
- A canary lockfile with a known advisory goes through the same code path once
  per run. If it comes back clean, the run aborts: a scanner matching against
  an empty database must never look like a clean audit.
