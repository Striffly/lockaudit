# osv-scanner behaviour worth remembering

Verified against osv-scanner 2.5.0. None of it is in the documentation, and all
of it has cost this codebase at least one bug.

Read this before changing a flag, a batch size, or the fallback path — the
decisions built on top of it are in [the ADRs](adr/).

### `--offline`, never `--offline-vulnerabilities` alone

`--offline-vulnerabilities` on its own **does not load the cached databases**.
It exits 0 and reports `results: []` on a lockfile that `--offline` flags as
malicious. Silent false negative, the worst possible failure for this tool.

`--offline-vulnerabilities` is only used in the download pass, because
`--download-offline-databases` needs the network that `--offline` forbids.

`canaryCheck` in `osv.go` guards this: every scanning run pushes a knowingly
vulnerable lockfile (`lodash@4.17.20`) through the same code path and aborts if
it comes back clean. If that canary ever fires spuriously, check whether the
advisories for that version were withdrawn before changing the flag.

### Where the time actually goes

Measured on an idle 16-core machine, `--offline`, warm database, 37 real
`package-lock.json` files averaging ~450 packages each:

| | cost |
|---|---|
| database load, per process | ~11s of CPU, cached or not |
| matching, per lockfile | ~1.5s |
| matching, per package entry | ~3ms |
| extraction only, per lockfile | ~0.14s |
| a lockfile with 0 packages | 0.18s total — the database is loaded lazily |

Two things follow, and they pull in opposite directions. The database load wants
few, huge batches. Anything that reports progress, and anything that survives an
interruption, wants small ones. `splitBatches` settles at 64 files: ~11% overhead
for results that land every minute or two instead of once an hour.

The per-package figure is the real ceiling: the local matcher walks the
ecosystem's advisories per package, so cost scales with **package entries**, not
with files. A decade of history over ~400 repos is millions of entries even after
lockfile-level deduplication.

### One bad file kills the whole batch

A single unparseable lockfile makes osv-scanner abort the **entire**
invocation and emit no JSON at all — not a partial result, nothing. Real
histories are full of them: 3 of 40 lockfiles sampled at random from one machine's
history were truncated or conflict-marked.

It does name them on stderr first, and they fail during *extraction*, before any
database is loaded:

```
Error during extraction: (extracting as javascript/packagelockjson)
	path/to/package-lock.json: could not extract: json: cannot unmarshal bool …
```

So `scanWithFallback` triages the batch with an extraction-only pass (see below),
drops what it names, and pays for the real scan once. One pass does not
necessarily name every culprit — a file only reaches an extractor once the files
before it stop aborting the run — so triage repeats until it comes back clean.

Bisection is still there for failures that name nothing, but it is the last
resort, not the strategy: bisecting a batch with k bad files costs roughly
log2(k)+2 times the whole batch.

### `--offline-vulnerabilities` alone is a fast lockfile parser

The silent false negative above has one legitimate use. Because it loads no
database, `--offline-vulnerabilities --no-resolve` extracts and parses every
input at ~0.14s per lockfile — a tenth of a real scan — and reproduces exactly
the extraction failures a real scan would hit.

That is `scanExtract` in `osv.go`, and it is only ever used to find broken files.
Its findings are always empty and must never be cached or reported: doing so is
the false negative this whole page opens with.

### A missing ecosystem database silently zeroes the rest of the batch

Ask osv-scanner about an ecosystem whose database is not cached and it prints
this, **exits 0, and still returns results**:

```
Error during extraction: (extracting as vulnmatch/osvlocal) unable to fetch
OSV database: no offline version of the OSV database is available
```

The results are the trap. Matching stops at the package that triggered it, and
every package *after* it in the same invocation comes back with zero
vulnerabilities. Verified: one `pkg:hex/phoenix@1.4.0` placed before a batch of
npm packages zeroed the npm findings; placed after, they were unaffected.

`missingDBMarker` in `osv.go` therefore turns that stderr into a hard failure of
the whole invocation whenever the mode is `scanOffline`. Parseable output is not
the same as trustworthy output.

This also means the set of downloaded databases must match the set of ecosystems
a run contains. `--download-offline-databases` only fetches what it happens to
encounter, so warming up from a sample of files leaves every ecosystem that
appears later without one. `ensureDatabases` drives one download per ecosystem
found by the inventory pass, and proves each one afterwards by matching offline.

### A one-component SBOM fetches exactly one ecosystem's database

`-L bom.cdx.json` holding a single `pkg:hex/phoenix@1.4.0`, with
`--download-offline-databases`, creates `~/.cache/osv-scalibr/Hex/`. That is how
databases are provisioned per ecosystem without needing a real lockfile of each
kind on disk.

### CycloneDX in, findings out — and it is exact

`--format json --all-packages` returns the **full** package inventory per input
file, not just what matched. Feed those packages back in as a CycloneDX document
and osv-scanner matches them offline, keyed by `(ecosystem, name, version)` in
its output — the same triple the inventory reported, no purl parsing needed on
the way back.

Checked against scanning the same two lockfiles directly: **127 finding groups in
common, none missing, none extra.**

The extractor is chosen by **basename**, so the file has to be called
`bom.cdx.json`; `-L /tmp/whatever.json` gives
`could not determine extractor suitable to this file`. `-S` also works and warns
that it is deprecated in favour of `-L`.

Purl forms that were verified to round-trip, which is the awkward half:

| ecosystem | OSV name | purl |
|---|---|---|
| npm, scoped | `@babel/core` | `pkg:npm/%40babel/core@7.4.3` |
| Maven | `group:artifact` | `pkg:maven/group/artifact@2.14.1` |
| Packagist | `vendor/name` | `pkg:composer/vendor/name@v1.0.2` |
| Go | `github.com/gin-gonic/gin` | `pkg:golang/github.com/gin-gonic/gin@1.6.3` |

`@` must be percent-encoded inside a name or it reads as the start of the
version, which rules out `url.PathEscape` — it leaves `@` alone.

### Database location

`~/.cache/osv-scalibr/`, **not** `~/.cache/osv-scanner/`. The name in the path
is the library, not the tool. `osvCacheDir()` checks both.

### `-L` accepts an extractor prefix, but we do not use it

`-L 'package-lock.json:/abs/path'` works (an unknown name gives
`could not determine extractor, requested <name>`). We deliberately skip it and
materialise each blob under its **original basename** instead, so osv-scanner
picks the extractor itself and there is no name mapping to keep in sync.

### The supported-lockfile list is ours to maintain

osv-scanner exposes no way to enumerate its extractors. osv-scalibr's
`extractor/filesystem/list` package only offers registries and
`FileRequired(path) bool` predicates — which need candidate paths you do not
have yet, so they cannot be inverted into a list. Importing osv-scalibr for
this would pull containerd, docker and protobuf into a binary that currently
has zero dependencies.

`defaultLockfilePatterns` in `git.go` is copied from the published
supported-lockfiles list. `LOCKFILE_PATTERNS` overrides it without a rebuild.

### `git ls-tree` takes no `*` pathspec

`git log -- '*package-lock.json'` matches at any depth, `ls-tree` does not.
HEAD blobs must be filtered in Go via `isLockfile`, otherwise every README and
Dockerfile in the tree is handed to osv-scanner as a lockfile.
