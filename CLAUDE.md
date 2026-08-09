# CLAUDE.md

Working notes for this repository.

## Commits

Gitmoji + English, imperative mood, no trailing period:

```
<emoji> <Summary in the imperative>
```

Examples:

```
✨ Add SARIF export
🐛 Filter ls-tree output to lockfiles only
⚡️ Batch blobs per worker to amortise OSV database loading
♻️ Move the pipeline into internal/scan
📝 Document the content-hash cache
✅ Cover severity classification of MAL- advisories
🔒️ Scrub the GitLab token from git error output
```

Common ones here: `✨` feature, `🐛` fix, `⚡️` performance, `♻️` refactor,
`📝` docs, `✅` tests, `🔒️` security, `🔧` config, `🚚` move/rename,
`🔥` remove code.

Body only when the *why* is not obvious from the diff. Reference the
osv-scanner behaviour you worked around, not the code you wrote.

## No real names in the code

Code, comments, tests and shipped config (`.env.example`) use **placeholders
only** — never a real account, organisation, client, project or machine path.
`acme/legacy`, `bigcorp/*`, `someone/a-project`, `/srv/projects/tool`,
`~/projects`. Not the account this happens to be developed under, and not the
directory layout of the machine it was written on.

The reason is not tidiness. A bug found while auditing real repositories gets
its regression test written from the case that produced it, and the names in
that case are the names of clients and private groups. Committing them
publishes a list of who someone works with, in a repository whose whole subject
is other people's security. Genericise the case, keep the bug.

The README is the exception: badge and star-history URLs must carry the real
repository slug or they do not resolve.

## Where things are written down

- `docs/adr/` — why the architecture is what it is. Read the relevant one
  before changing a design decision; add a new ADR rather than editing an
  accepted one.
- `docs/osv-scanner-behaviour.md` — verified quirks of the scanner binary,
  each of which has already caused a bug here.
- `README.md` — user-facing usage only. It must stay short, and it must not
  link to this file.

## Invariants

- **Never write to the user's repositories.** Only `remote -v`, `log`,
  `ls-tree`, `cat-file`. Clones and scratch space live in the cache directory.
- **Never log a forge token.** It reaches git as an argument only, never a
  repo config, and every error string passes through `scrubToken` for every
  configured forge.
- **A failed unit must not fail the run.** Broken repo, dead token, empty
  project: log, count, continue, and surface the count in the report.
- **Partial coverage is never presented as a clean result.** An interrupted run
  still reports what it scanned, but says so and states how many lockfile
  versions were never looked at. `TestInterruptedReportIsNotClean` pins this in
  both the terminal and the Markdown output.
- **Cache keys include the OSV database version.** A stale "clean" verdict
  hiding a newly published advisory is a security bug, not a cache miss.
- **Every copy of a project is scanned — local, GitLab, GitHub.** Content
  hashing deduplicates whatever they share; skipping one would only lose the
  commits that copy alone has. Forks and upstreams are separate projects and
  are meant to appear separately.
