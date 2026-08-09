# ADR 0006 — History coverage boundaries

Status: accepted · 2026-08-09

## Context

"Scan the whole history" has no single meaning in git. Branches, tags,
remote-tracking refs, dangling commits, merge/pull request refs and
merge-only changes are all separately reachable, at very different costs.

## Decision

Covered by default:

- `git log --all --reflog` — every branch, tag and remote-tracking branch, plus
  commits left dangling by a rebase or an amend. A lockfile you rebased away
  still triggered an install when it existed.
- Bare clones fetch `+refs/heads/*` and tags.
- Directories with no `.git` that contain a lockfile: current state only, no
  history.

Not covered by default:

- **Branches behind unmerged merge/pull requests.** On a repo you merely
  contribute to, those are thousands of other people's branches you never
  installed. `FETCH_ALL_REFS=1` / `--all-refs` fetches them.
- **A blob introduced solely by a merge resolution.** `--raw` diffs against the
  first parent only. Covering it means `-m`, which explodes output volume on
  large repos for a rare case.

## Consequences

- The default is "everything that was ever on this machine or in this project",
  not "everything that exists on the forge".
- The two gaps are documented rather than silently accepted, and the second one
  is partly compensated: blobs on `HEAD` that the history walk missed are still
  registered.
