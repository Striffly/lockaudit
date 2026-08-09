# ADR 0008 — Report to a file; partial is never clean

Status: accepted · 2026-08-09

## Context

A finding here is not something you act on in the next thirty seconds. A
malware hit in a 2024 commit means rotating tokens, checking timers, reading
shell history — work that spans days and involves other people. Terminal
scrollback is the wrong place for it.

Separately: a run can be interrupted, and an interrupted run has partial
coverage. The failure mode to avoid is a report that looks clean because the
scan stopped early.

## Decision

A Markdown report is written to `./lockaudit-report.md` on every run, by
default — not behind a flag. It carries everything: every commit of every
occurrence, every failed unit, the malware checklist. Terminal output is the
same content truncated to fit a screen; `--json` and `--sarif` remain for CI.

`Ctrl-C` produces a report of what was scanned, marked `INTERRUPTED`, stating
how many lockfile versions were never looked at. Findings still exit `1`; an
interrupted run that found nothing exits `130`, never `0`.

## Consequences

- The tool writes a file into the working directory by default. `--report -`
  disables it; the path is gitignored.
- Interruption is cheap and safe, which is the point — combined with
  [ADR 0003](0003-file-cache-keyed-by-content-and-db-version.md), rerunning
  resumes.
- `TestInterruptedReportIsNotClean` pins the rule in both output formats.
