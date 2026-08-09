# Architecture decision records

Why this tool is built the way it is. One file per decision, written when the
decision was made and left alone afterwards — a superseded ADR is marked
superseded, not edited into agreement with the code.

Read these before "fixing" something that looks wrong: several of them are
deliberate trades that cost something obvious to buy something less obvious.

| # | Decision | Status |
|---|---|---|
| [0001](0001-delegate-detection-to-osv-scanner.md) | Delegate detection to the osv-scanner CLI | accepted |
| [0002](0002-deduplicate-history-by-blob-hash.md) | Deduplicate history by git blob hash | accepted |
| [0003](0003-file-cache-keyed-by-content-and-db-version.md) | File cache keyed by content hash and OSV database version | accepted |
| [0004](0004-scan-every-copy-of-a-project.md) | Scan every copy of a project, local and remote | accepted |
| [0005](0005-few-large-osv-scanner-batches.md) | Few large osv-scanner batches, bisected on failure | superseded by 0010 |
| [0006](0006-history-coverage-boundaries.md) | History coverage boundaries | accepted |
| [0007](0007-go-with-zero-dependencies.md) | Go, with zero third-party dependencies | accepted |
| [0008](0008-report-to-a-file-partial-is-never-clean.md) | Report to a file; partial is never clean | accepted |
| [0009](0009-maintain-our-own-lockfile-pattern-list.md) | Maintain our own lockfile pattern list | accepted |
| [0010](0010-triage-broken-lockfiles-before-scanning.md) | Triage broken lockfiles before scanning, and cap batch size | accepted |
| [0011](0011-match-distinct-packages-not-lockfiles.md) | Match distinct packages, not lockfiles | accepted |

Verified osv-scanner behaviour these decisions depend on:
[osv-scanner-behaviour.md](../osv-scanner-behaviour.md).
