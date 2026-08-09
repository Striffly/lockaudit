# ADR 0007 — Go, with zero third-party dependencies

Status: accepted · 2026-08-09

## Context

The work is a concurrent pipeline over subprocesses: API pagination, git
plumbing, blob extraction, scanner invocations. It is I/O and process bound
with a lot of independent units.

## Decision

Go, and nothing in `go.mod` but the standard library.

`net/http` covers both forge APIs. `os/exec` covers git and osv-scanner.
`encoding/json` covers the OSV output, JSON and SARIF. Terminal colours are
seven ANSI constants. The cache is a directory tree
([ADR 0003](0003-file-cache-keyed-by-content-and-db-version.md)), so no SQLite
driver.

## Consequences

- One static binary, `go build`, no toolchain beyond Go and git.
- Nothing to audit in a supply-chain auditing tool — a dependency here would be
  a genuinely awkward thing to explain.
- Costs paid: a hand-rolled `.env` parser, a hand-rolled glob matcher for git's
  pathspec semantics (`*` crosses slashes), a hand-rolled progress line. All
  small, all tested.
- Terminal width is not queried (that needs an ioctl or `golang.org/x/term`);
  the progress line is capped at 78 columns instead.
