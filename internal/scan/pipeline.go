// Package scan implements the supply-chain audit: inventory, history walk,
// deduplicated scanning and reporting.
package scan

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type config struct {
	Sources            []string
	LocalRoots         []string
	ExcludePaths       []string
	GitlabURL          string
	GitlabToken        string
	GithubURL          string
	GithubToken        string
	GithubAffiliations string
	IncludeArchived    bool
	FetchAllRefs       bool
	Threshold          severity
	ScanHistory        bool
	Workers            int
	NetworkWorkers     int
	DBMaxAge           time.Duration
	CacheDir           string
	TmpDir             string
	OsvBin             string
	LockfilePatterns   []string
	WaveBytes          int64
}

// Run parses configuration, performs the audit and prints the report.
// It returns the process exit code: 0 clean, 1 findings above the threshold,
// 2 configuration or fatal error, 130 interrupted.
func Run() int {
	cfg, opts, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		return 2
	}
	prog = newProgress(os.Stderr, !opts.noProgress && isTTY(os.Stderr))
	defer prog.close()
	slog.SetDefault(slog.New(slog.NewTextHandler(prog.logWriter(), &slog.HandlerOptions{
		Level: map[bool]slog.Level{true: slog.LevelDebug, false: slog.LevelInfo}[opts.verbose],
	})))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rep, err := scanAll(ctx, cfg, opts)
	prog.close() // clean line before the report, whichever way we exit
	if err != nil {
		slog.Error("scan failed", "err", err)
		return 2
	}
	if rep == nil { // dry run
		return 0
	}

	// The file is written first so the terminal recap can point at it, and so an
	// unwritable path is reported instead of being papered over by a summary.
	written := opts.reportOut
	if opts.reportOut != "" {
		if err := writeMarkdown(opts.reportOut, rep); err != nil {
			slog.Error("writing report", "path", opts.reportOut, "err", err)
			written = ""
		}
	}
	writeTerminal(os.Stdout, rep, newPalette(os.Stdout), written)
	if opts.jsonOut != "" {
		if err := writeJSON(opts.jsonOut, rep); err != nil {
			slog.Error("writing json", "err", err)
		}
	}
	if opts.sarifOut != "" {
		if err := writeSARIF(opts.sarifOut, rep); err != nil {
			slog.Error("writing sarif", "err", err)
		}
	}
	// Findings win over the interruption: a CI job that saw malware must fail
	// loudly, not report "incomplete". 130 is for an interrupted run that found
	// nothing — which proves nothing, and the report says so.
	if len(rep.Findings) > 0 {
		return 1
	}
	if rep.Interrupted {
		return 130
	}
	return 0
}

// ---- inventory job ----

// job is one repository to walk, whatever it came from.
type job struct {
	Source    string // gitlab | local
	Name      string
	Dir       string // where git runs; filled after cloning for gitlab jobs
	CloneURL  string
	Reference string // local clone to seed objects from
	Ref       string // default branch, "" means HEAD
}

type blobKey struct{ Hash, Filename string }

type blobInfo struct {
	RepoDir string                 // git repo to extract the blob from
	File    string                 // set instead of RepoDir for a loose file on disk
	Occ     map[string]*Occurrence // keyed by source|repo|path
}

func scanAll(ctx context.Context, cfg *config, opts *options) (*Report, error) {
	started := time.Now()
	osvVersion, err := checkOsvScanner(cfg.OsvBin)
	if err != nil {
		return nil, err
	}
	lockfilePatterns = cfg.LockfilePatterns
	prog.step(1, 3, "inventory")
	prog.stage("building inventory", 0)

	excl := newExcluder(cfg.ExcludePaths)
	if self := selfRepoPath(); self != "" {
		excl.add(self) // never audit ourselves; we live under the scanned roots
		slog.Debug("self-excluded", "path", self)
	}

	var errs errorList
	var remotes []remoteProject
	var localRepos []localRepo
	var looseFiles []string
	var excluded []string

	// The three sources are independent — two HTTP APIs and a filesystem walk —
	// and the work after them needs all three anyway, so they run together. Doing
	// them in turn cost the walk's ~15s on top of the API calls for nothing.
	//
	// A dead token on one forge must not throw away the rest of the audit, which
	// is why each one records its own failure and returns what it did get.
	var srcWG sync.WaitGroup
	var srcMu sync.Mutex
	source := func(name string, list func() ([]remoteProject, error)) {
		srcWG.Add(1)
		go func() {
			defer srcWG.Done()
			ps, err := list()
			srcMu.Lock()
			defer srcMu.Unlock()
			if err != nil {
				errs.add(fmt.Errorf("%s inventory incomplete: %w", name, err))
			}
			slog.Info(name+" inventory", "projects", len(ps))
			remotes = append(remotes, ps...)
		}()
	}
	if slices(cfg.Sources, "gitlab") {
		source("gitlab", func() ([]remoteProject, error) {
			return newGitlabClient(cfg.GitlabURL, cfg.GitlabToken).listProjects(ctx, cfg.IncludeArchived)
		})
	}
	if slices(cfg.Sources, "github") {
		source("github", func() ([]remoteProject, error) {
			return newGithubClient(cfg.GithubURL, cfg.GithubToken).
				listProjects(ctx, cfg.GithubAffiliations, cfg.IncludeArchived)
		})
	}
	if len(cfg.LocalRoots) > 0 {
		srcWG.Add(1)
		go func() {
			defer srcWG.Done()
			repos, loose, skip := findLocalRepos(ctx, cfg.LocalRoots, excl)
			srcMu.Lock()
			defer srcMu.Unlock()
			localRepos, looseFiles, excluded = repos, loose, skip
			slog.Info("local inventory", "repos", len(repos),
				"loose_lockfiles", len(loose), "excluded", len(skip))
		}()
	}
	prog.note("apis and local roots")
	srcWG.Wait()
	// Order depends on which goroutine finished first, and the report lists
	// projects, so sort for a reproducible run.
	sort.Slice(remotes, func(i, j int) bool {
		if remotes[i].Source != remotes[j].Source {
			return remotes[i].Source < remotes[j].Source
		}
		return remotes[i].Name < remotes[j].Name
	})

	// Index remote projects by normalised URL so a local checkout of the same
	// project can be recognised and reused to seed its clone.
	byKey := map[string]remoteProject{}
	for _, p := range remotes {
		for _, k := range []string{normalizeRemote(p.HTTPURL), normalizeRemote(p.SSHURL)} {
			if k != "" {
				byKey[k] = p
			}
		}
	}

	if !slices(cfg.Sources, "local") {
		looseFiles = nil // they only exist locally
	}

	// A local checkout of a GitLab project is reused as a --reference so the
	// clone transfers almost nothing over the network.
	//
	// Both copies are then scanned. Deduplication happens one layer down, on
	// lockfile CONTENT: whatever the two copies share is one blob hash and gets
	// scanned once regardless. Skipping the local copy would buy nothing and
	// would lose the commits that were never pushed.
	reference := map[string]string{}
	var jobs []job
	scanLocal := slices(cfg.Sources, "local")

	for _, lr := range localRepos {
		// Every matching remote, not just the first: a clone with origin=fork
		// and upstream=original holds objects for both projects and can seed
		// either clone. Stopping at the first match silently made the second
		// one download everything from scratch.
		for _, k := range lr.Keys {
			if _, ok := byKey[k]; !ok {
				continue
			}
			if _, seen := reference[k]; !seen {
				reference[k] = filepath.Join(lr.Path, ".git")
			}
		}
		if scanLocal {
			jobs = append(jobs, job{Source: "local", Name: lr.Path, Dir: lr.Path})
		}
	}

	for _, p := range remotes {
		if p.Empty {
			continue
		}
		if excl.matchName(p.Source, p.Name) {
			excluded = append(excluded, p.Source+":"+p.Name)
			continue
		}
		// Host comes from the clone URL, not from the configured API URL: on
		// GitHub they differ (api.github.com), and on self-hosted GitLab the
		// API host is what keeps two forges from colliding in the cache.
		dest := filepath.Join(cfg.CacheDir, "repos", hostOf(p.HTTPURL), p.Name+".git")
		jobs = append(jobs, job{
			Source:    p.Source,
			Name:      p.Name,
			Dir:       dest,
			CloneURL:  p.CloneURL,
			Reference: reference[normalizeRemote(p.HTTPURL)],
			Ref:       p.DefaultBranch,
		})
	}

	var stats Stats
	for _, j := range jobs {
		switch j.Source {
		case "gitlab":
			stats.ReposGitlab++
		case "github":
			stats.ReposGithub++
		default:
			stats.ReposLocal++
		}
	}
	stats.ReposScanned = len(jobs)
	stats.LooseFiles = len(looseFiles)

	if opts.dryRun {
		printDryRun(ctx, cfg, jobs, looseFiles, excluded, stats)
		return nil, ctx.Err()
	}

	// ---- stage 1+2: acquire and walk history, overlapped ----
	registry := map[blobKey]*blobInfo{}
	var regMu sync.Mutex

	addLooseFiles(ctx, looseFiles, registry, &errs)

	prog.step(2, 3, "history")
	prog.stage("cloning and walking repos", len(jobs))
	ready := make(chan job, len(jobs))
	var acquire sync.WaitGroup
	netSem := make(chan struct{}, cfg.NetworkWorkers)
	for _, j := range jobs {
		if j.Source == "local" {
			ready <- j // local repos start being walked while clones are still running
			continue
		}
		acquire.Add(1)
		go func(j job) {
			defer acquire.Done()
			select {
			case netSem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-netSem }()
			if err := cloneOrFetchBare(ctx, j.CloneURL, j.Dir, j.Reference, cfg.FetchAllRefs); err != nil {
				errs.add(fmt.Errorf("%s: %s", j.Name,
					scrubToken(scrubToken(err.Error(), cfg.GitlabToken), cfg.GithubToken)))
				return
			}
			if !cfg.ScanHistory {
				ready <- j
				return
			}
			if isShallow(j.Dir) {
				if _, err := runGit(ctx, j.Dir, "fetch", "--unshallow", "--quiet", "origin"); err != nil {
					slog.Debug("unshallow failed", "repo", j.Name)
				}
			}
			ready <- j
		}(j)
	}
	go func() { acquire.Wait(); close(ready) }()

	var walkers sync.WaitGroup
	for range cfg.Workers {
		walkers.Add(1)
		go func() {
			defer walkers.Done()
			for j := range ready {
				if ctx.Err() != nil {
					return
				}
				prog.note(baseName(j.Name))
				occs, head, err := walkRepo(ctx, j, cfg.ScanHistory)
				prog.inc(1)
				if err != nil {
					errs.add(fmt.Errorf("%s: %v", j.Name, err))
				}
				regMu.Lock()
				for _, o := range occs {
					k := blobKey{o.Hash, filepath.Base(o.Path)}
					bi := registry[k]
					if bi == nil {
						bi = &blobInfo{RepoDir: j.Dir, Occ: map[string]*Occurrence{}}
						registry[k] = bi
					}
					ok := j.Source + "|" + j.Name + "|" + o.Path
					occ := bi.Occ[ok]
					if occ == nil {
						occ = &Occurrence{Source: j.Source, Repo: j.Name, Path: o.Path}
						bi.Occ[ok] = occ
					}
					if head[o.Hash] != "" {
						occ.OnHead = true
					}
					if o.Commit.SHA != "" {
						occ.Commits = append(occ.Commits, Commit{
							SHA: o.Commit.SHA, Unix: o.Commit.Unix,
							Date: fmtDate(o.Commit.Unix), Author: o.Commit.Author,
							Subject: o.Commit.Subject,
						})
					}
				}
				regMu.Unlock()
			}
		}()
	}
	walkers.Wait()
	stats.UniqueBlobs = len(registry)
	slog.Info("history walked", "unique_lockfile_versions", len(registry))
	// Only now is the run's real size known, so only now can an overall bar be
	// honest about its denominator.
	prog.step(3, 3, "lockfiles")
	prog.goal(len(registry))

	// ---- stage 3: scan the blobs we have never seen ----
	//
	// Ctrl-C does NOT throw the run away. Everything already scanned is in the
	// cache, so we report on it and say the coverage is partial; the next run
	// picks up exactly where this one stopped. Discarding it would punish the
	// user for interrupting a scan that had already found something.
	results, hits, scanned, skipped, err := resolveBlobs(ctx, cfg, opts, registry, &errs)
	interrupted := ctx.Err() != nil || errors.Is(err, context.Canceled)
	if err != nil && !interrupted {
		return nil, err
	}
	stats.CacheHits, stats.Scanned = hits, scanned
	// An unscannable file was looked at and rejected, not skipped by the
	// interruption: it must not make a completed run read as partial forever.
	stats.Pending = len(registry) - hits - scanned - skipped
	stats.Duration = elapsed(time.Since(started))

	rep := &Report{
		GeneratedAt: time.Now().Format(time.RFC3339),
		OsvVersion:  osvVersion.String(),
		DBVersion:   dbFingerprint(osvCacheDir()),
		Threshold:   cfg.Threshold.String(),
		Interrupted: interrupted,
		Stats:       stats,
		Errors:      errs.strings(),
		Excluded:    excluded,
	}
	rep.Findings = buildFindings(registry, results, cfg.Threshold)
	for _, f := range rep.Findings {
		if f.Malware {
			rep.Stats.Malware++
		}
	}
	return rep, nil
}

// gitBlobHash computes the id git would give this content: SHA-1 over
// "blob <len>\0<content>". Using git's own formula rather than a plain digest
// is what lets a loose file and the identical file committed in some repo
// collapse to ONE cache entry and ONE scan.
func gitBlobHash(data []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00", len(data))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// addLooseFiles registers lockfiles that belong to no repository. Having no
// history, they can only ever be current exposure.
func addLooseFiles(ctx context.Context, files []string, registry map[blobKey]*blobInfo, errs *errorList) {
	for _, f := range files {
		if ctx.Err() != nil {
			return
		}
		data, err := os.ReadFile(f)
		if err != nil {
			errs.add(fmt.Errorf("reading %s: %w", f, err))
			continue
		}
		k := blobKey{Hash: gitBlobHash(data), Filename: filepath.Base(f)}
		bi := registry[k]
		if bi == nil {
			bi = &blobInfo{File: f, Occ: map[string]*Occurrence{}}
			registry[k] = bi
		}
		dir := filepath.Dir(f)
		bi.Occ["local|"+dir+"|"+filepath.Base(f)] = &Occurrence{
			Source: "local", Repo: dir, Path: filepath.Base(f), OnHead: true,
		}
	}
}

// walkRepo returns every lockfile blob in the repo's history (or just its tip)
// plus the set of blobs currently on the default branch.
func walkRepo(ctx context.Context, j job, history bool) ([]blobOccurrence, map[string]string, error) {
	head := headBlobs(ctx, j.Dir, j.Ref)
	if !history {
		occs := make([]blobOccurrence, 0, len(head))
		for h, p := range head {
			occs = append(occs, blobOccurrence{Hash: h, Path: p})
		}
		return occs, head, nil
	}
	occs, err := historyBlobs(ctx, j.Dir)
	// Blobs on HEAD that history missed (merge-only introductions) still count.
	seen := map[string]bool{}
	for _, o := range occs {
		seen[o.Hash] = true
	}
	for h, p := range head {
		if !seen[h] {
			occs = append(occs, blobOccurrence{Hash: h, Path: p})
		}
	}
	return occs, head, err
}

// resolveBlobs turns blob keys into scan results, hitting the cache first and
// materialising only what is genuinely unknown.
//
// Work is done in waves bounded by bytes on disk, not by count: extracting
// every distinct package-lock.json of a decade of history at once can be
// several GB. Within a wave, batches are as few and large as possible because
// an osv-scanner process spends ~11s of CPU loading the npm database before it
// looks at anything.
// Alongside the results it returns how many blobs were cache hits, how many
// were scanned now, and how many were looked at and found unscannable — the
// last so the caller can tell "never reached" apart from "reached and broken".
func resolveBlobs(ctx context.Context, cfg *config, opts *options, registry map[blobKey]*blobInfo, errs *errorList) (map[blobKey]*blobResult, int, int, int, error) {
	dbVer := dbFingerprint(osvCacheDir())
	c, err := newCache(cfg.CacheDir, dbVer)
	if err != nil {
		return nil, 0, 0, 0, err
	}

	results := map[blobKey]*blobResult{}
	var todo []blobKey
	hits := 0
	for k := range registry {
		if r, ok := c.get(k.Hash, k.Filename); ok {
			results[k] = r
			hits++
			continue
		}
		todo = append(todo, k)
	}
	sort.Slice(todo, func(i, j int) bool { // group by repo: one cat-file process each
		if registry[todo[i]].RepoDir != registry[todo[j]].RepoDir {
			return registry[todo[i]].RepoDir < registry[todo[j]].RepoDir
		}
		return todo[i].Hash < todo[j].Hash
	})
	prog.advance(hits) // a cache hit is a settled lockfile version like any other
	slog.Info("blob resolution", "cache_hits", hits, "to_scan", len(todo))
	if len(todo) == 0 {
		return results, hits, 0, 0, nil
	}
	// The wave directory is scratch space, and an interrupted run would
	// otherwise leave a few hundred MB of extracted lockfiles behind.
	defer os.RemoveAll(filepath.Join(cfg.TmpDir, "wave"))

	needDownload := dbVer == "" || opts.refreshDB || dbStale(cfg)
	canaryDone := false
	scanned, skipped := 0, 0
	sc := &scanner{bin: cfg.OsvBin}

	// Package-level state, deliberately spanning every wave: one project's
	// history is spread across waves, and it is the same few hundred packages
	// throughout. matched holds what a triple resolved to (nil-Groups included,
	// so a clean package is not looked up twice); unmatchable holds the triples
	// osv-scanner would not take through a purl, whose files fall back.
	matched := map[pkgID]*scannedPackage{}
	unmatchable := map[pkgID]bool{}
	dbReady := map[string]bool{}

	for start := 0; start < len(todo); {
		if ctx.Err() != nil {
			return results, hits, scanned, skipped, ctx.Err()
		}
		// Every activity long enough to be noticed announces itself. Leaving the
		// previous stage on screen at 100% while something else runs reads as a
		// hang — a full bar claiming to be the current work is worse than no bar.
		prog.stage("extracting lockfile versions", len(todo)-start)
		wave, next, bytes, err := materialize(ctx, cfg, registry, todo, start)
		if err != nil {
			return results, hits, scanned, skipped, err
		}
		if len(wave) == 0 {
			break
		}
		slog.Info("scanning wave", "files", len(wave), "mib", bytes>>20,
			"progress", fmt.Sprintf("%d/%d", start, len(todo)))

		paths := make([]string, 0, len(wave))
		for p := range wave {
			paths = append(paths, p)
		}
		sort.Strings(paths)

		todoPaths := remaining(paths, results, wave)
		var mu sync.Mutex
		inv := map[string][]pkgID{} // path -> what it contains
		bad := map[string]bool{}    // could not be parsed at all
		direct := map[string]bool{} // has to go through a full direct scan
		unscannable := func(p string) {
			bad[p] = true
			k := wave[p]
			errs.add(fmt.Errorf("unscannable lockfile: %s", describeBlob(k, registry[k])))
			// A file nobody can parse is still a file we are done with: leaving
			// it out of the counter would strand the bar short of its total for
			// the rest of the run.
			prog.advance(1)
			skipped++
		}

		// ---- read what every lockfile contains (cheap, no database) ----
		//
		// Phase timings are logged because the cost model behind this whole
		// arrangement is measured, not assumed: if reading ever stops being ten
		// times cheaper than matching, the arrangement is wrong.
		prog.stage("reading lockfile versions", len(todoPaths))
		phase := time.Now()
		runBatches(ctx, cfg.Workers, splitBatches(todoPaths), func(b []string) {
			got, unparseable, err := sc.inventory(ctx, b)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if ctx.Err() == nil {
					// A failure it could not pin on a file. Scan these whole
					// rather than assume they hold nothing.
					slog.Warn("inventory failed, scanning directly", "files", len(b), "err", err)
					for _, p := range b {
						direct[p] = true
					}
				}
				return
			}
			for p, ids := range got {
				inv[p] = ids
			}
			for _, p := range unparseable {
				unscannable(p)
			}
			prog.inc(len(b) - len(unparseable))
		})
		if ctx.Err() != nil {
			return results, hits, scanned, skipped, ctx.Err()
		}
		slog.Info("lockfiles read", "files", len(todoPaths), "took", elapsed(time.Since(phase)))

		// ---- match each distinct package once, not once per lockfile ----
		fresh, ecosystems := freshPackages(inv, matched, unmatchable)
		entries := 0
		for _, ids := range inv {
			entries += len(ids)
		}
		if len(fresh) > 0 {
			phase = time.Now()
			// The databases to fetch are the ecosystems the inventory just found,
			// which is why this happens here and not before the run: osv-scanner
			// only downloads what it is asked about, and asking it about "the
			// first batch of the first wave" left every ecosystem that appeared
			// later without a database — silently.
			prog.stage("checking osv databases", len(ecosystems))
			failed, fetched := sc.ensureDatabases(ctx, ecosystems, cfg.TmpDir, needDownload, dbReady)
			for _, eco := range failed {
				// No database means nothing can be concluded about that
				// ecosystem, so it is reported rather than read as "clean".
				errs.add(fmt.Errorf("no offline OSV database for %s: its packages were not matched", eco))
				for i := range fresh {
					if fresh[i].Ecosystem == eco {
						unmatchable[fresh[i]] = true
					}
				}
			}
			if fetched {
				// The cache is keyed by database version, so a download mid-run
				// moves where results belong. Doing this before anything is
				// stored is what keeps a stale "clean" out of the new key.
				dbVer = dbFingerprint(osvCacheDir())
				if c2, err := newCache(cfg.CacheDir, dbVer); err == nil {
					c = c2
				}
				touchDBStamp(cfg)
			}
			needDownload = false

			// After the databases, never before: the canary needs one to pass,
			// and it is the proof that findings this run are real.
			if !canaryDone {
				prog.stage("self-checking the databases", 0)
				if err := sc.canaryCheck(ctx, cfg.TmpDir); err != nil {
					return results, hits, scanned, skipped, err
				}
				canaryDone = true
			}

			fresh = dropUnmatchable(fresh, unmatchable)

			// A lockfile is finished the moment its last package is, not when the
			// wave is. Without this, interrupting the matching phase threw away
			// the whole wave — measured: 260 of 261 files lost to a Ctrl-C that
			// arrived after most of the work was already done.
			waiting, holders := pendingPackages(inv, bad, direct, matched, unmatchable)
			settle := func(p string) {
				delete(waiting, p)
				if usesUnmatchable(inv[p], unmatchable) {
					direct[p] = true
					return
				}
				res := &blobResult{}
				for _, id := range inv[p] {
					if sp := matched[id]; sp != nil && len(sp.Groups) > 0 {
						res.Packages = append(res.Packages, *sp)
					}
				}
				storeResults(c, wave, map[string]*blobResult{p: res}, results, &scanned, errs)
			}
			resolved := func(ids []pkgID) {
				for _, id := range ids {
					for _, p := range holders[id] {
						if waiting[p]--; waiting[p] <= 0 {
							settle(p)
						}
					}
					delete(holders, id)
				}
			}

			prog.stage("matching distinct packages", len(fresh))
			runBatches(ctx, cfg.Workers, shardPackages(fresh, cfg.Workers), func(sh []pkgID) {
				got, lost, err := sc.matchPurls(ctx, sh, cfg.TmpDir)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					if ctx.Err() == nil {
						slog.Warn("package matching failed, scanning files directly",
							"packages", len(sh), "err", err)
						for _, id := range sh {
							unmatchable[id] = true
						}
						resolved(sh)
					}
					return
				}
				for id, p := range got {
					matched[id] = p
				}
				// Submitted and not returned: osv-scanner did not read that
				// purl, so nothing was learned about it and silence is not a
				// clean result. Its files take the direct path.
				//
				// Logged with examples, not just a count: every one of these
				// drags a whole lockfile into the slow path, so knowing which
				// purl form was refused is the difference between fixing it and
				// paying for it forever.
				for _, id := range lost {
					unmatchable[id] = true
				}
				if len(lost) > 0 {
					slog.Warn("purls not understood, those lockfiles fall back",
						"packages", len(lost), "ecosystem", sh[0].Ecosystem,
						"examples", samplePurls(lost, 5))
				}
				resolved(sh)
				prog.inc(len(sh))
			})
			slog.Info("packages matched", "distinct", len(fresh), "entries", entries,
				"dedup", fmt.Sprintf("%.1fx", float64(entries)/float64(max(1, len(fresh)))),
				"ecosystems", ecosystems, "took", elapsed(time.Since(phase)))
			if ctx.Err() != nil {
				return results, hits, scanned, skipped, ctx.Err()
			}
			// Anything still waiting had a package no shard reported on either
			// way. Nothing was learned about it, so it takes the direct path.
			for p := range waiting {
				direct[p] = true
			}
		}

		// ---- files whose packages were all already known ----
		for _, p := range todoPaths {
			if bad[p] || direct[p] {
				continue
			}
			if _, done := results[wave[p]]; done {
				continue
			}
			if usesUnmatchable(inv[p], unmatchable) {
				direct[p] = true
				continue
			}
			// No inventory entry means the file parsed and holds no packages,
			// which is a result, and one worth caching.
			res := &blobResult{}
			for _, id := range inv[p] {
				if sp := matched[id]; sp != nil && len(sp.Groups) > 0 {
					res.Packages = append(res.Packages, *sp)
				}
			}
			storeResults(c, wave, map[string]*blobResult{p: res}, results, &scanned, errs)
		}

		// ---- whatever the fast path could not settle, scan the old way ----
		if fb := remaining(keysOf(direct), results, wave); len(fb) > 0 {
			slog.Info("direct scan fallback", "files", len(fb))
			prog.stage("direct scan (slow path)", len(fb))
			runBatches(ctx, cfg.Workers, splitBatches(fb), func(b []string) {
				res, unparseable := sc.scanWithFallback(ctx, b, scanOffline)
				mu.Lock()
				defer mu.Unlock()
				prog.inc(len(b))
				storeResults(c, wave, res, results, &scanned, errs)
				for _, p := range unparseable {
					unscannable(p)
				}
			})
		}

		os.RemoveAll(filepath.Join(cfg.TmpDir, "wave"))
		start = next
	}
	c.prune(7 * 24 * time.Hour)
	return results, hits, scanned, skipped, ctx.Err()
}

// describeBlob names a lockfile version the way someone can act on it: the repo
// it lives in, the path inside it, and the commit that put it there. The blob id
// closes it out, because the same path in the same repo has many versions and
// only one of them is the broken one.
//
// "unscannable lockfile package-lock.json" was the previous message, and it was
// equally true of eight thousand files.
func describeBlob(k blobKey, info *blobInfo) string {
	if info == nil {
		return fmt.Sprintf("%s (blob %s)", k.Filename, shortBlob(k.Hash))
	}
	if info.File != "" { // a loose file: its path is the whole story
		return fmt.Sprintf("%s (blob %s)", shortenHome(info.File), shortBlob(k.Hash))
	}
	// Occ is a map, so pick deterministically: two runs over the same history
	// must produce the same report.
	keys := make([]string, 0, len(info.Occ))
	for kk := range info.Occ {
		keys = append(keys, kk)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return fmt.Sprintf("%s (blob %s)", k.Filename, shortBlob(k.Hash))
	}
	o := info.Occ[keys[0]]
	var b strings.Builder
	fmt.Fprintf(&b, "%s:%s %s", o.Source, shortenHome(o.Repo), o.Path)
	if c := earliestCommit(o.Commits); c.SHA != "" {
		fmt.Fprintf(&b, " @ %s (%s)", c.Short(), c.Date)
	}
	if n := len(keys) - 1; n > 0 {
		fmt.Fprintf(&b, " +%s", plural(n, "other location"))
	}
	fmt.Fprintf(&b, " (blob %s)", shortBlob(k.Hash))
	return b.String()
}

func earliestCommit(cs []Commit) Commit {
	var out Commit
	for _, c := range cs {
		if out.SHA == "" || (c.Unix != 0 && c.Unix < out.Unix) {
			out = c
		}
	}
	return out
}

func shortBlob(h string) string {
	if i := strings.Index(h, ":"); i >= 0 { // "sha256:…" for API-sourced content
		h = h[i+1:]
	}
	if len(h) > 10 {
		return h[:10]
	}
	return h
}

// runBatches runs fn over every batch with at most workers of them in flight.
// The bound is not about CPU: an osv-scanner process holds a whole ecosystem
// database in memory, so one per batch would exhaust it.
func runBatches[T any](ctx context.Context, workers int, batches [][]T, fn func([]T)) {
	if workers < 1 {
		workers = 1
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for _, b := range batches {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(b []T) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			fn(b)
		}(b)
	}
	wg.Wait()
}

// freshPackages is the deduplication: every distinct package this wave contains
// that no earlier wave has already resolved. It also reports the ecosystems
// involved, which is what decides the databases to fetch.
func freshPackages(inv map[string][]pkgID, matched map[pkgID]*scannedPackage, unmatchable map[pkgID]bool) ([]pkgID, []string) {
	seen := map[pkgID]bool{}
	ecos := map[string]bool{}
	var fresh []pkgID
	for _, ids := range inv {
		for _, id := range ids {
			if seen[id] || unmatchable[id] {
				continue
			}
			seen[id] = true
			if _, done := matched[id]; done {
				continue
			}
			fresh = append(fresh, id)
			ecos[id.Ecosystem] = true
		}
	}
	// Sorted so a run is reproducible and shards are stable between runs.
	sort.Slice(fresh, func(i, j int) bool {
		if fresh[i].Ecosystem != fresh[j].Ecosystem {
			return fresh[i].Ecosystem < fresh[j].Ecosystem
		}
		if fresh[i].Name != fresh[j].Name {
			return fresh[i].Name < fresh[j].Name
		}
		return fresh[i].Version < fresh[j].Version
	})
	list := make([]string, 0, len(ecos))
	for e := range ecos {
		list = append(list, e)
	}
	sort.Strings(list)
	return fresh, list
}

// shardPackages splits the work by ecosystem first, then across the workers.
//
// By ecosystem because a process only loads the databases it is asked about, and
// mixing npm with everything else would make every shard pay for every database.
//
// Then as few shards as the floor allows, at most one per worker. The two
// measured constants decide the floor, no per-machine tuning: a process pays
// ~11s of CPU to load a database and ~3ms per package after that, so a shard
// below ~4000 packages spends more time loading than matching. Splitting 6k
// packages into 13 shards of 500 was measured at 53s — thirteen database loads
// fighting over the same cores for 1.5s of work each; two shards of 3k do the
// same matching in a fraction of that.
func shardPackages(ids []pkgID, workers int) [][]pkgID {
	if workers < 1 {
		workers = 1
	}
	byEco := map[string][]pkgID{}
	var order []string
	for _, id := range ids {
		if _, ok := byEco[id.Ecosystem]; !ok {
			order = append(order, id.Ecosystem)
		}
		byEco[id.Ecosystem] = append(byEco[id.Ecosystem], id)
	}
	var out [][]pkgID
	for _, eco := range order {
		g := byEco[eco]
		size := max(minShardSize, (len(g)+workers-1)/workers)
		for i := 0; i < len(g); i += size {
			out = append(out, g[i:min(i+size, len(g))])
		}
	}
	return out
}

// minShardSize ≈ database load (~11s) ÷ matching cost (~3ms/package): below
// this, a process spends more time loading than working.
const minShardSize = 4000

// usesUnmatchable reports whether anything in this lockfile could not be settled
// by the deduplicated pass, in which case the file has to be scanned whole. One
// unknown package is enough: the alternative is a report that is quietly missing
// it.
func usesUnmatchable(ids []pkgID, unmatchable map[pkgID]bool) bool {
	for _, id := range ids {
		if unmatchable[id] {
			return true
		}
	}
	return false
}

// pendingPackages counts, per lockfile, how many of its packages are still
// unanswered, and indexes which lockfiles are waiting on each one. That is what
// lets a lockfile be cached as soon as its last package comes back instead of at
// the end of the wave — the difference between losing one shard to a Ctrl-C and
// losing a wave.
func pendingPackages(inv map[string][]pkgID, bad, direct map[string]bool,
	matched map[pkgID]*scannedPackage, unmatchable map[pkgID]bool,
) (waiting map[string]int, holders map[pkgID][]string) {
	waiting = map[string]int{}
	holders = map[pkgID][]string{}
	for p, ids := range inv {
		if bad[p] || direct[p] {
			continue
		}
		seen := map[pkgID]bool{}
		for _, id := range ids {
			if seen[id] || unmatchable[id] {
				continue
			}
			seen[id] = true
			if _, done := matched[id]; done {
				continue
			}
			waiting[p]++
			holders[id] = append(holders[id], p)
		}
	}
	return waiting, holders
}

// samplePurls renders a few refused packages as the purl that was actually sent,
// which is the string to reproduce with.
func samplePurls(ids []pkgID, n int) string {
	var out []string
	for _, id := range ids {
		if len(out) == n {
			break
		}
		p, ok := purlOf(id)
		if !ok {
			p = id.Ecosystem + "/" + id.Name + "@" + id.Version + " (no purl)"
		}
		out = append(out, p)
	}
	return strings.Join(out, " ")
}

// dropUnmatchable removes what there is no point asking about.
func dropUnmatchable(ids []pkgID, unmatchable map[pkgID]bool) []pkgID {
	out := ids[:0]
	for _, id := range ids {
		if !unmatchable[id] {
			out = append(out, id)
		}
	}
	return out
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func remaining(paths []string, done map[blobKey]*blobResult, wave map[string]blobKey) []string {
	var out []string
	for _, p := range paths {
		if _, ok := done[wave[p]]; !ok {
			out = append(out, p)
		}
	}
	return out
}

func storeResults(c *cache, wave map[string]blobKey, res map[string]*blobResult, out map[blobKey]*blobResult, scanned *int, errs *errorList) {
	for path, r := range res {
		k, ok := wave[path]
		if !ok {
			continue
		}
		out[k] = r
		*scanned++
		// advance, not inc: this is one lockfile version settled, and the stage
		// counter is measuring packages by the time this is called.
		prog.advance(1)
		if err := c.put(k.Hash, k.Filename, r); err != nil {
			errs.add(fmt.Errorf("cache write: %w", err))
		}
	}
}

// materialize extracts blobs to disk until the byte budget is spent, using one
// long-lived `git cat-file --batch` per repository. A budget of 0 means "all of
// it in one wave", which is the default (see WAVE_MB).
func materialize(ctx context.Context, cfg *config, registry map[blobKey]*blobInfo, todo []blobKey, start int) (map[string]blobKey, int, int64, error) {
	dir := filepath.Join(cfg.TmpDir, "wave")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, start, 0, err
	}
	budget := cfg.WaveBytes
	if budget <= 0 {
		budget = int64(1) << 62 // no cap: one wave, whatever it takes
	}
	wave := map[string]blobKey{}
	var total int64
	write := func(k blobKey, data []byte) error {
		d := filepath.Join(dir, strings.ReplaceAll(k.Hash, ":", "_"))
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
		p := filepath.Join(d, k.Filename)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			return err
		}
		wave[p] = k
		prog.inc(1)
		return nil
	}

	i := start
	for i < len(todo) && total < budget {
		// A loose file has no repo to batch with: copy it straight across.
		if info := registry[todo[i]]; info.RepoDir == "" {
			data, err := os.ReadFile(info.File)
			if err != nil {
				slog.Debug("loose file vanished", "path", info.File, "err", err)
			} else if err := write(todo[i], data); err == nil {
				total += int64(len(data))
			}
			i++
			continue
		}
		repo := registry[todo[i]].RepoDir
		var hashes []string
		byHash := map[string]blobKey{}
		j := i
		for j < len(todo) && registry[todo[j]].RepoDir == repo && total < budget {
			hashes = append(hashes, todo[j].Hash)
			byHash[todo[j].Hash] = todo[j]
			total += 256 * 1024 // rough guess, corrected below by real sizes
			j++
		}
		total -= int64(len(hashes)) * 256 * 1024
		var written int64
		err := catFileBatch(ctx, repo, hashes, func(hash string, data []byte) error {
			if err := write(byHash[hash], data); err != nil {
				return err
			}
			written += int64(len(data))
			return nil
		})
		if err != nil {
			slog.Debug("cat-file batch issue", "repo", repo, "err", err)
		}
		total += written
		i = j
	}
	return wave, i, total, nil
}

// buildFindings joins scan results back onto where and when each blob lived.
func buildFindings(registry map[blobKey]*blobInfo, results map[blobKey]*blobResult, threshold severity) []Finding {
	merged := map[string]*Finding{}

	for k, info := range registry {
		res := results[k]
		if res == nil || len(res.Packages) == 0 {
			continue
		}
		for _, pkg := range res.Packages {
			for _, g := range pkg.Groups {
				v := pickVuln(pkg.Vulnerabilities, g.IDs)
				sev := vulnSeverity(v, g.MaxSeverity)
				if !reportable(sev, threshold) {
					continue
				}
				id := v.ID
				if id == "" && len(g.IDs) > 0 {
					id = g.IDs[0]
				}
				fk := strings.Join([]string{pkg.Package.Ecosystem, pkg.Package.Name, pkg.Package.Version, id}, "|")
				f := merged[fk]
				if f == nil {
					ids := append([]string{}, g.IDs...)
					sort.Strings(ids)
					f = &Finding{
						Package: pkg.Package.Name, Version: pkg.Package.Version,
						Ecosystem: pkg.Package.Ecosystem, PrimaryID: id, IDs: ids,
						Severity: sev.String(), sev: sev, Malware: sev == sevMalware,
						Summary: v.Summary, URL: "https://osv.dev/vulnerability/" + id,
					}
					merged[fk] = f
				}
				for _, o := range info.Occ {
					f.Occurrences = mergeOccurrence(f.Occurrences, o)
					if o.OnHead {
						f.Current = true
					}
				}
			}
		}
	}

	out := make([]Finding, 0, len(merged))
	for _, f := range merged {
		for i := range f.Occurrences {
			sortCommits(f.Occurrences[i].Commits)
		}
		sort.Slice(f.Occurrences, func(i, j int) bool {
			a, b := f.Occurrences[i], f.Occurrences[j]
			if a.Source != b.Source {
				return a.Source < b.Source
			}
			if a.Repo != b.Repo {
				return a.Repo < b.Repo
			}
			return a.Path < b.Path
		})
		out = append(out, *f)
	}
	sortFindings(out)
	return out
}

// pickVuln returns the advisory carrying the group's identity. Malware records
// win outright: a group aliasing a MAL-* to a CVE must still be reported as
// malware, which is the difference between "update this" and "rotate your
// credentials".
func pickVuln(vulns []osvVuln, ids []string) osvVuln {
	inGroup := map[string]bool{}
	for _, id := range ids {
		inGroup[id] = true
	}
	var first osvVuln
	found := false
	for _, v := range vulns {
		if !inGroup[v.ID] {
			continue
		}
		if isMalwareID(v.ID) {
			return v
		}
		if !found {
			first, found = v, true
		}
	}
	if found {
		return first
	}
	if len(vulns) > 0 {
		return vulns[0]
	}
	return osvVuln{}
}

func mergeOccurrence(list []Occurrence, o *Occurrence) []Occurrence {
	for i := range list {
		if list[i].Source == o.Source && list[i].Repo == o.Repo && list[i].Path == o.Path {
			seen := map[string]bool{}
			for _, c := range list[i].Commits {
				seen[c.SHA] = true
			}
			for _, c := range o.Commits {
				if !seen[c.SHA] {
					list[i].Commits = append(list[i].Commits, c)
					seen[c.SHA] = true
				}
			}
			list[i].OnHead = list[i].OnHead || o.OnHead
			return list
		}
	}
	cp := *o
	cp.Commits = append([]Commit{}, o.Commits...)
	return append(list, cp)
}

func sortCommits(cs []Commit) {
	sort.Slice(cs, func(i, j int) bool { return cs[i].Unix > cs[j].Unix })
}

// ---- dry run ----

func printDryRun(ctx context.Context, cfg *config, jobs []job, loose, excluded []string, stats Stats) {
	p := newPalette(os.Stdout)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()

	fmt.Fprintf(w, "\n%s%sDRY RUN — inventory only, nothing will be scanned%s\n\n", p.bold, p.cyan, p.reset)
	fmt.Fprintf(w, "%sWould scan %d repositories (%d gitlab, %d github, %d local)%s\n",
		p.bold, len(jobs), stats.ReposGitlab, stats.ReposGithub, stats.ReposLocal, p.reset)
	for _, j := range jobs {
		note := ""
		if j.Source != "local" {
			note = " [clone to " + shortenHome(j.Dir) + "]"
			if j.Reference != "" {
				note += " (seeded from local copy)"
			}
		}
		fmt.Fprintf(w, "  %s%-7s%s %s%s%s%s\n", p.cyan, j.Source, p.reset, j.Name, p.dim, note, p.reset)
	}
	if len(loose) > 0 {
		fmt.Fprintf(w, "\n%s%d lockfiles outside any repository (current state only, no history)%s\n",
			p.bold, len(loose), p.reset)
		for i, f := range loose {
			if i == 20 {
				fmt.Fprintf(w, "  %s… %d more%s\n", p.dim, len(loose)-20, p.reset)
				break
			}
			fmt.Fprintf(w, "  %s%s%s\n", p.dim, f, p.reset)
		}
	}
	if len(excluded) > 0 {
		fmt.Fprintf(w, "\n%sExcluded %d%s\n", p.bold, len(excluded), p.reset)
		for _, e := range excluded {
			fmt.Fprintf(w, "  %s%s%s\n", p.dim, e, p.reset)
		}
	}

	// Counting blobs means walking history, which is free compared to scanning
	// and is the number that actually tells you how long a real run takes.
	local := 0
	for _, j := range jobs {
		if j.Source == "local" {
			local++
		}
	}
	if local == 0 {
		fmt.Fprintf(w, "\n%s(blob counting skipped: gitlab repos are not cloned in dry-run)%s\n\n", p.dim, p.reset)
		return
	}
	dbVer := dbFingerprint(osvCacheDir())
	c, err := newCache(cfg.CacheDir, dbVer)
	if err != nil {
		return
	}
	uniq := map[blobKey]bool{}
	hits := 0
	for _, j := range jobs {
		if j.Source != "local" || ctx.Err() != nil {
			continue
		}
		occs, _, _ := walkRepo(ctx, j, cfg.ScanHistory)
		for _, o := range occs {
			k := blobKey{o.Hash, filepath.Base(o.Path)}
			if uniq[k] {
				continue
			}
			uniq[k] = true
			if c.has(k.Hash, k.Filename) {
				hits++
			}
		}
	}
	fmt.Fprintf(w, "\n%sLocal repos: %d distinct lockfile versions, %d already cached, %d would be scanned%s\n\n",
		p.bold, len(uniq), hits, len(uniq)-hits, p.reset)
}

// ---- helpers ----

type errorList struct {
	mu   sync.Mutex
	list []string
}

func (e *errorList) add(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.list) < 200 {
		e.list = append(e.list, err.Error())
	}
	slog.Warn("recoverable error", "err", err)
}

func (e *errorList) strings() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string{}, e.list...)
}

func slices(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func scrubToken(s, token string) string {
	if token == "" {
		return s
	}
	return strings.ReplaceAll(s, token, "***")
}

func hostOf(rawURL string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(rawURL, "https://"), "http://")
	if i := strings.IndexAny(s, "/:"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return "unknown"
	}
	return s
}

func isShallow(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "shallow"))
	return err == nil
}

func userCacheDir() string {
	if d, err := os.UserCacheDir(); err == nil {
		return d
	}
	return filepath.Join(os.Getenv("HOME"), ".cache")
}

func shortenHome(p string) string {
	if h, err := os.UserHomeDir(); err == nil && strings.HasPrefix(p, h) {
		return "~" + p[len(h):]
	}
	return p
}

func dbStampPath(cfg *config) string { return filepath.Join(cfg.CacheDir, "db-stamp") }

func dbStale(cfg *config) bool {
	st, err := os.Stat(dbStampPath(cfg))
	return err != nil || time.Since(st.ModTime()) > cfg.DBMaxAge
}

func touchDBStamp(cfg *config) {
	os.MkdirAll(cfg.CacheDir, 0o755)
	os.WriteFile(dbStampPath(cfg), []byte(time.Now().Format(time.RFC3339)+"\n"), 0o644)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}
