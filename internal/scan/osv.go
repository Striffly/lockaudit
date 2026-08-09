package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// ---- osv-scanner JSON shapes (only the fields we consume) ----

type osvOutput struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"source"`
		Packages []scannedPackage `json:"packages"`
	} `json:"results"`
}

type scannedPackage struct {
	Package struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Vulnerabilities []osvVuln `json:"vulnerabilities"`
	Groups          []struct {
		IDs         []string `json:"ids"`
		Aliases     []string `json:"aliases"`
		MaxSeverity string   `json:"max_severity"`
	} `json:"groups"`
}

type osvVuln struct {
	ID               string          `json:"id"`
	Aliases          []string        `json:"aliases"`
	Summary          string          `json:"summary"`
	Details          string          `json:"details"`
	DatabaseSpecific json.RawMessage `json:"database_specific"`
}

// blobResult is what we cache: the scan of one lockfile content, nothing else.
type blobResult struct {
	Packages []scannedPackage `json:"packages"`
}

// ---- severity ----

type severity int

// The order is the report threshold: a finding is reported when its severity is
// at or above the configured one, so the scale must stay monotonic.
// sevAll is a threshold value only, never a finding's severity: it sits below
// sevUnknown so advisories that carry no severity at all still get reported.
const sevAll severity = -1

const (
	sevUnknown severity = iota
	sevLow
	sevModerate
	sevHigh
	sevCritical
	sevMalware // deliberately above CRITICAL: a MAL-* is an active compromise,
	// not a bug someone might exploit. It always surfaces, whatever the threshold.
)

var sevNames = map[severity]string{
	sevAll: "ALL", sevUnknown: "UNKNOWN", sevLow: "LOW", sevModerate: "MODERATE",
	sevHigh: "HIGH", sevCritical: "CRITICAL", sevMalware: "MALWARE",
}

func (s severity) String() string { return sevNames[s] }

func parseSeverity(s string) severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return sevCritical
	case "HIGH":
		return sevHigh
	case "MODERATE", "MEDIUM":
		return sevModerate
	case "LOW":
		return sevLow
	case "MALWARE", "MAL":
		return sevMalware
	case "ALL", "UNKNOWN":
		return sevAll
	}
	return sevUnknown
}

// reportable applies the threshold, which is a MINIMUM: a finding surfaces when
// it is at that level or above. Malware ignores the threshold entirely.
func reportable(sev, threshold severity) bool {
	return sev >= threshold || sev == sevMalware
}

func isMalwareID(id string) bool { return strings.HasPrefix(strings.ToUpper(id), "MAL-") }

// vulnSeverity resolves a severity from what the advisory actually carries.
// GitHub advisories put a word in database_specific.severity; everything else
// gets bucketed from the CVSS score osv-scanner already computed for the group.
func vulnSeverity(v osvVuln, groupMax string) severity {
	if isMalwareID(v.ID) {
		return sevMalware
	}
	for _, a := range v.Aliases {
		if isMalwareID(a) {
			return sevMalware
		}
	}
	if len(v.DatabaseSpecific) > 0 {
		var ds struct {
			Severity string `json:"severity"`
		}
		if json.Unmarshal(v.DatabaseSpecific, &ds) == nil {
			if s := parseSeverity(ds.Severity); s != sevUnknown {
				return s
			}
		}
	}
	if f, err := strconv.ParseFloat(groupMax, 64); err == nil {
		switch {
		case f >= 9.0:
			return sevCritical
		case f >= 7.0:
			return sevHigh
		case f >= 4.0:
			return sevModerate
		case f > 0:
			return sevLow
		}
	}
	return sevUnknown
}

// ---- running osv-scanner ----

type scanner struct {
	bin string
}

// scanMode picks which of osv-scanner's mutually exclusive offline behaviours
// an invocation wants.
type scanMode int

const (
	// scanOffline is the only mode whose findings may be trusted or cached.
	scanOffline scanMode = iota
	// scanDownload populates the local databases, which needs the network that
	// --offline forbids.
	scanDownload
	// scanExtract parses the lockfiles and matches nothing. It exists because
	// --offline-vulnerabilities on its own does not load the cached databases
	// (see docs/osv-scanner-behaviour.md) — useless for scanning, but exactly
	// what a parse check wants, at a tenth of the cost. Its results say
	// "no vulnerabilities" about every input and must never be stored.
	scanExtract
)

// missingDBMarker is how osv-scanner reports that it has no local database for
// an ecosystem it was asked about:
//
//	Error during extraction: (extracting as vulnmatch/osvlocal) unable to fetch
//	OSV database: no offline version of the OSV database is available
//
// It exits 0 and still prints results. Verified on 2.5.0: matching stops at the
// package that triggered it, and every package AFTER it in the same invocation
// comes back with zero vulnerabilities — a lockfile with a Hex dependency
// silently zeroed the npm findings that followed it. So this is treated as a
// hard failure of the whole invocation, never as a clean result.
const missingDBMarker = "no offline version of the OSV database is available"

// osvError keeps stderr attached to the failure: it is where osv-scanner names
// the inputs it choked on, and that name is what saves a bisection.
type osvError struct {
	err    error
	stderr string
}

func (e *osvError) missingDatabase() bool { return strings.Contains(e.stderr, missingDBMarker) }

func (e *osvError) Error() string {
	return fmt.Sprintf("osv-scanner: %v: %s", e.err, clipErr(e.stderr))
}

// clipErr keeps a failure quotable in a log line: the interesting part of an
// osv-scanner failure is its first lines, and a batch is dozens of files wide.
func clipErr(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "\n"); i >= 0 {
		s = s[:i] + " …"
	}
	return clip(s, 300)
}

// scanWithFallback is scanBatch plus damage control.
//
// osv-scanner aborts the WHOLE invocation when a single input fails to parse
// (verified: one corrupt package-lock.json among three produced no JSON at
// all). Since batches are large on purpose, one bad blob in git history would
// otherwise blank out thousands of results.
//
// It does, however, name the offending files on stderr before giving up, and
// they fail during extraction — before any database is loaded. So the batch is
// triaged first by an extraction-only pass, which costs ~0.1s per file against
// ~1.5s for a real scan, and the expensive pass then runs once over input known
// to parse. Bisection stays as the last resort for failures that name nothing.
//
// The alternative was bisecting the real scan, and it is not close: a batch
// holding k broken lockfiles costs about log2(k)+2 times the batch, and
// git history is full of lockfiles that were committed broken — 3 of 40 sampled
// at random here.
func (s *scanner) scanWithFallback(ctx context.Context, paths []string, mode scanMode) (map[string]*blobResult, []string) {
	good, bad := s.triage(ctx, paths)
	if len(good) == 0 {
		return map[string]*blobResult{}, bad
	}
	res, err := s.scanBatch(ctx, good, mode)
	if err == nil {
		return res, bad
	}
	// The reason is logged HERE, once, because bisection is about to spend
	// minutes rediscovering it one file at a time.
	slog.Warn("batch scan failed, bisecting", "files", len(good), "err", err)
	res, more := s.bisect(ctx, good, mode)
	return res, append(bad, more...)
}

// triage drops the lockfiles osv-scanner cannot parse, without paying for a
// database load to find out. It repeats because one pass does not necessarily
// name every culprit: each extractor reports its own failures, and a file only
// gets that far once the files before it have stopped aborting the run.
func (s *scanner) triage(ctx context.Context, paths []string) (good, bad []string) {
	good = paths
	for len(good) > 0 {
		_, err := s.scanBatch(ctx, good, scanExtract)
		if err == nil || ctx.Err() != nil {
			return good, bad
		}
		culprits := unextractable(err, good)
		if len(culprits) == 0 {
			// Something else went wrong. Leave the batch intact and let the
			// real pass, then bisection, judge it — silently dropping files
			// here would turn an infrastructure failure into a clean report.
			return good, bad
		}
		for _, p := range culprits {
			slog.Warn("unscannable lockfile, skipped", "path", p)
		}
		bad = append(bad, culprits...)
		good = without(good, culprits)
	}
	return nil, bad
}

// bisect isolates unnameable failures one file at a time.
func (s *scanner) bisect(ctx context.Context, paths []string, mode scanMode) (map[string]*blobResult, []string) {
	// A cancelled context fails every invocation, and bisecting that would walk
	// the whole batch declaring each file unscannable — an interrupted run once
	// reported 200 perfectly good lockfiles as corrupt this way.
	if ctx.Err() != nil {
		return map[string]*blobResult{}, nil
	}
	res, err := s.scanBatch(ctx, paths, mode)
	if err == nil {
		return res, nil
	}
	if ctx.Err() != nil {
		return map[string]*blobResult{}, nil
	}
	if len(paths) == 1 {
		slog.Warn("unscannable lockfile, skipped", "path", paths[0], "err", err)
		return map[string]*blobResult{}, paths
	}
	mid := len(paths) / 2
	left, badL := s.bisect(ctx, paths[:mid], mode)
	right, badR := s.bisect(ctx, paths[mid:], mode)
	for k, v := range right {
		left[k] = v
	}
	return left, append(badL, badR...)
}

// unextractable pulls the input paths osv-scanner blamed out of its stderr.
// The layout depends on how many files failed — several get one tab-indented
// line each, a single one is folded into the header line:
//
//	Error during extraction: (extracting as javascript/packagelockjson)
//		home/someone/wave/<hash>/package-lock.json: could not extract: json: …
//
//	Error during extraction: (extracting as javascript/pnpmlock) home/someone/wave/<hash>/pnpm-lock.yaml: could not extract: yaml: …
//
// The second form is why this searches for each batch path instead of parsing
// line by line: a line parser matched only the first form, silently skipped
// triage for single-culprit batches, and sent them into minutes of bisection.
// Paths come back relative to the walk root, hence the leading-slash trim.
func unextractable(err error, paths []string) []string {
	var oe *osvError
	if !errors.As(err, &oe) {
		return nil
	}
	var out []string
	for _, p := range paths {
		if strings.Contains(oe.stderr, strings.TrimPrefix(p, "/")+": could not extract") {
			out = append(out, p)
		}
	}
	return out
}

func without(paths, drop []string) []string {
	gone := make(map[string]bool, len(drop))
	for _, p := range drop {
		gone[p] = true
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if !gone[p] {
			out = append(out, p)
		}
	}
	return out
}

// run is the single place osv-scanner is executed. allPackages asks for the
// whole inventory rather than only what matched, which the inventory pass needs
// for attribution and the matching pass needs to prove every package it
// submitted came back.
func (s *scanner) run(ctx context.Context, mode scanMode, allPackages bool, paths []string) (osvOutput, error) {
	args := []string{"scan", "source", "--all-vulns", "--allow-no-lockfiles",
		"--verbosity", "error", "--format", "json"}
	if allPackages {
		args = append(args, "--all-packages")
	}
	switch mode {
	case scanDownload:
		args = append(args, "--offline-vulnerabilities", "--no-resolve", "--download-offline-databases")
	case scanExtract:
		args = append(args, "--offline-vulnerabilities", "--no-resolve")
	default:
		args = append(args, "--offline")
	}
	for _, p := range paths {
		args = append(args, "-L", p)
	}

	cmd := exec.CommandContext(ctx, s.bin, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	runErr := cmd.Run()

	var parsed osvOutput
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		// Exit code 1 just means "vulnerabilities found"; only an unparseable
		// stdout is a real failure.
		return osvOutput{}, &osvError{err: runErr, stderr: errb.String()}
	}
	// Parseable output is not the same as trustworthy output.
	if mode == scanOffline && strings.Contains(errb.String(), missingDBMarker) {
		return osvOutput{}, &osvError{err: runErr, stderr: errb.String()}
	}
	return parsed, nil
}

// ---- package-level deduplication ----
//
// Matching costs ~3ms per package entry and nothing per file, while successive
// versions of one lockfile repeat almost all of their packages: 12 789 entries
// over one project's history were 371 distinct triples. So the expensive pass
// runs once per distinct triple per run, not once per lockfile.

// pkgID is one (ecosystem, name, version) triple — the unit osv-scanner
// actually spends its time on.
type pkgID struct{ Ecosystem, Name, Version string }

// purlTypes maps OSV ecosystem names to Package-URL types.
//
// Only language ecosystems are listed. An OS package needs distro qualifiers
// that a lockfile cannot tell us, and a purl we cannot build correctly must send
// its file down the direct-scan path rather than be guessed at — a purl
// osv-scanner fails to read is a package silently never matched.
//
// Every entry here was verified to round-trip through osv-scanner's own SBOM
// reader, including the awkward ones: scoped npm (@babel/core), Maven's
// group:artifact, Packagist's vendor/name and Go's module paths. The round trip
// is also re-checked at runtime, per run, so a wrong entry costs speed instead
// of coverage.
var purlTypes = map[string]string{
	"npm": "npm", "PyPI": "pypi", "Go": "golang", "Maven": "maven",
	"crates.io": "cargo", "Packagist": "composer", "RubyGems": "gem",
	"NuGet": "nuget", "Hex": "hex", "Pub": "pub", "CRAN": "cran",
}

// purlOf builds the Package-URL for a triple, or reports that we cannot.
func purlOf(p pkgID) (string, bool) {
	t, ok := purlTypes[p.Ecosystem]
	if !ok || p.Name == "" || p.Version == "" {
		return "", false
	}
	name := p.Name
	if p.Ecosystem == "Maven" {
		// OSV names a Maven package "group:artifact"; a purl separates the
		// namespace with a slash.
		name = strings.Replace(name, ":", "/", 1)
	}
	segs := strings.Split(name, "/")
	for i, seg := range segs {
		segs[i] = purlEscape(seg)
	}
	return "pkg:" + t + "/" + strings.Join(segs, "/") + "@" + purlEscape(p.Version), true
}

// purlEscape percent-encodes one purl segment. Written out rather than reusing
// url.PathEscape, which leaves "@" alone — and an unescaped "@" in a scoped npm
// name is exactly where the version is supposed to start.
func purlEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// writeBOM materialises a CycloneDX document holding one component per triple.
// The basename matters: osv-scanner picks its SBOM extractor from it.
func writeBOM(dir string, ids []pkgID) (string, error) {
	type component struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Version string `json:"version"`
		Purl    string `json:"purl"`
		BomRef  string `json:"bom-ref"`
	}
	bom := struct {
		Format      string      `json:"bomFormat"`
		SpecVersion string      `json:"specVersion"`
		Version     int         `json:"version"`
		Components  []component `json:"components"`
	}{Format: "CycloneDX", SpecVersion: "1.6", Version: 1}
	for _, id := range ids {
		purl, ok := purlOf(id)
		if !ok {
			continue
		}
		bom.Components = append(bom.Components, component{
			Type: "library", Name: id.Name, Version: id.Version, Purl: purl, BomRef: purl,
		})
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	data, err := json.Marshal(bom)
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, "bom.cdx.json")
	return p, os.WriteFile(p, data, 0o600)
}

// inventory lists what every lockfile in the batch contains, without loading a
// database — ~0.14s per file against ~1.5s for a real scan. It doubles as the
// triage pass: the files it cannot parse are the files a real scan cannot parse,
// and it names them for the same reason (see scanWithFallback).
//
// A path that comes back with no entry contains no packages, which is a result.
func (s *scanner) inventory(ctx context.Context, paths []string) (map[string][]pkgID, []string, error) {
	good, bad := paths, []string(nil)
	for len(good) > 0 {
		out, err := s.run(ctx, scanExtract, true, good)
		if err == nil {
			return packagesByPath(out, good), bad, nil
		}
		if ctx.Err() != nil {
			return nil, bad, ctx.Err()
		}
		culprits := unextractable(err, good)
		if len(culprits) == 0 {
			return nil, bad, err // let the caller fall back to a direct scan
		}
		for _, p := range culprits {
			slog.Warn("unscannable lockfile, skipped", "path", p)
		}
		bad = append(bad, culprits...)
		good = without(good, culprits)
	}
	return map[string][]pkgID{}, bad, nil
}

// packagesByPath keys the inventory by the input path we asked about, which is
// not always the path osv-scanner echoes back.
func packagesByPath(out osvOutput, paths []string) map[string][]pkgID {
	byPath := make(map[string]string, len(paths))
	for _, p := range paths {
		byPath[strings.TrimPrefix(p, "/")] = p
	}
	inv := make(map[string][]pkgID, len(paths))
	unversioned := 0
	for _, r := range out.Results {
		key, ok := byPath[strings.TrimPrefix(r.Source.Path, "/")]
		if !ok {
			slog.Debug("osv inventory for unknown path", "path", r.Source.Path)
			continue
		}
		for _, p := range r.Packages {
			id := pkgID{p.Package.Ecosystem, p.Package.Name, p.Package.Version}
			// A dependency with no pinned version is dropped here, not carried
			// as something we failed to resolve. There is no version to compare
			// against a range, and osv-scanner agrees: a bare `django` in a
			// requirements.txt comes back with version "" and zero
			// vulnerabilities from a direct scan too. Treating it as unknown
			// instead sent every such file down the slow path for nothing —
			// measured at 620 of 4328 files in one wave.
			if id.Version == "" || id.Name == "" {
				unversioned++
				continue
			}
			inv[key] = append(inv[key], id)
		}
	}
	if unversioned > 0 {
		slog.Debug("unversioned dependencies ignored", "packages", unversioned)
	}
	return inv
}

// matchPurls scans a set of distinct triples and returns what each one matched.
//
// The second return is the triples that were submitted and did not come back:
// osv-scanner dropped the purl, so nothing can be concluded about them and their
// files have to be scanned directly instead. Silence is not a clean result.
func (s *scanner) matchPurls(ctx context.Context, ids []pkgID, tmpDir string) (map[pkgID]*scannedPackage, []pkgID, error) {
	if len(ids) == 0 {
		return map[pkgID]*scannedPackage{}, nil, nil
	}
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		return nil, nil, err
	}
	dir, err := os.MkdirTemp(tmpDir, "bom-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(dir)
	path, err := writeBOM(dir, ids)
	if err != nil {
		return nil, nil, err
	}

	out, err := s.run(ctx, scanOffline, true, []string{path})
	if err != nil {
		return nil, nil, err
	}
	matched := make(map[pkgID]*scannedPackage, len(ids))
	for _, r := range out.Results {
		for i := range r.Packages {
			p := &r.Packages[i]
			matched[pkgID{p.Package.Ecosystem, p.Package.Name, p.Package.Version}] = p
		}
	}
	var lost []pkgID
	for _, id := range ids {
		if _, ok := matched[id]; !ok {
			lost = append(lost, id)
		}
	}
	return matched, lost, nil
}

// ensureDatabases downloads the offline database of every ecosystem this run is
// about to ask about.
//
// osv-scanner only downloads what it happens to encounter, so warming up from
// "the first batch of the first wave" left every ecosystem that appeared later
// without a database — and a package with no database silently stops the matcher
// for everything after it. Driving the download from a one-component SBOM per
// ecosystem is what makes the set of databases match the set of ecosystems the
// run actually contains.
// ready records the ecosystems already proven present, so the probe is paid once
// per run rather than once per wave. refresh forces a download even for
// ecosystems that already work, which is what --refresh-db and a stale database
// stamp mean. fetched reports whether anything was actually downloaded, because
// the result cache is keyed by database version.
func (s *scanner) ensureDatabases(ctx context.Context, ecosystems []string, dir string, refresh bool, ready map[string]bool) (failed []string, fetched bool) {
	for _, eco := range ecosystems {
		prog.note(eco)
		prog.inc(1)
		if ready[eco] && !refresh {
			continue
		}
		probe := probePackage(eco)
		if probe == (pkgID{}) {
			// An ecosystem we cannot even name a package in. Its packages go
			// down the direct path, where osv-scanner picks the database itself.
			slog.Debug("no database probe for ecosystem", "ecosystem", eco)
			failed = append(failed, eco)
			continue
		}
		one := filepath.Join(dir, "db-"+purlEscape(eco))
		path, err := writeBOM(one, []pkgID{probe})
		if err != nil {
			failed = append(failed, eco)
			continue
		}
		// Probe offline first: downloading an ecosystem we already have costs a
		// network round trip and rewrites a 200 MB zip for nothing.
		_, err = s.run(ctx, scanOffline, false, []string{path})
		if err != nil || refresh {
			slog.Info("fetching osv database", "ecosystem", eco)
			if _, derr := s.run(ctx, scanDownload, false, []string{path}); derr != nil {
				slog.Warn("database download failed", "ecosystem", eco, "err", derr)
			} else {
				fetched = true
			}
			// Downloading is not the same as having: prove it.
			_, err = s.run(ctx, scanOffline, false, []string{path})
		}
		if err != nil {
			slog.Warn("no offline database for ecosystem", "ecosystem", eco, "err", err)
			failed = append(failed, eco)
		} else {
			ready[eco] = true
		}
		os.RemoveAll(one)
	}
	return failed, fetched
}

// probePackage is a package that exists in each ecosystem, used only to make
// osv-scanner fetch that ecosystem's database. The versions are deliberately old
// and real; nothing is concluded from the result, only from whether it ran.
func probePackage(ecosystem string) pkgID {
	name := map[string]string{
		"npm": "lodash", "PyPI": "django", "Go": "golang.org/x/text",
		"Maven": "org.apache.logging.log4j:log4j-core", "crates.io": "openssl",
		"Packagist": "drupal/core", "RubyGems": "rack", "NuGet": "Newtonsoft.Json",
		"Hex": "phoenix", "Pub": "http", "CRAN": "commonmark",
	}[ecosystem]
	if name == "" {
		return pkgID{}
	}
	return pkgID{Ecosystem: ecosystem, Name: name, Version: "1.0.0"}
}

// splitBatches cuts the work into fixed-size batches, more of them than there
// are workers.
//
// The size is a trade between two measured costs on 2.5.0: ~11s of CPU to load
// the npm database, paid once per process, and ~1.5s per lockfile after that. At
// 64 files a batch the database load is about 11% overhead — and results land
// every minute or two per worker instead of once an hour, which is the
// difference between a progress bar and a frozen screen. Nothing is lost when a
// run is interrupted mid-batch either: only that batch is.
func splitBatches(paths []string) [][]string {
	if len(paths) == 0 {
		return nil
	}
	out := make([][]string, 0, (len(paths)+batchSize-1)/batchSize)
	for i := 0; i < len(paths); i += batchSize {
		out = append(out, paths[i:min(i+batchSize, len(paths))])
	}
	return out
}

const batchSize = 64

// scanBatch runs osv-scanner over a set of materialised lockfiles and returns
// one result per input path.
//
// Offline is not an optimisation here, it is what makes parallelism legal: the
// match happens against local databases, so N processes cannot rate-limit each
// other against osv.dev.
//
// The flag is --offline, NOT --offline-vulnerabilities. Verified on 2.5.0:
// --offline-vulnerabilities on its own does not load the cached databases and
// silently reports zero findings on a lockfile that --offline flags as
// malicious. Only the download pass may use --offline-vulnerabilities, because
// --download-offline-databases needs the network that --offline forbids.
// canaryCheck exists to catch this class of failure if it ever changes again.
//
// --all-vulns disables osv-scanner's own "unimportant" filtering: severity
// filtering is ours to do, and a MAL-* must never be dropped upstream.
func (s *scanner) scanBatch(ctx context.Context, paths []string, mode scanMode) (map[string]*blobResult, error) {
	parsed, err := s.run(ctx, mode, false, paths)
	if err != nil {
		return nil, err
	}

	res := make(map[string]*blobResult, len(paths))
	for _, p := range paths {
		res[p] = &blobResult{} // absence of findings is a result worth caching
	}
	for _, r := range parsed.Results {
		key := r.Source.Path
		if _, ok := res[key]; !ok {
			if abs, err := filepath.Abs(key); err == nil {
				key = abs
			}
		}
		if br, ok := res[key]; ok {
			br.Packages = append(br.Packages, r.Packages...)
		} else {
			slog.Debug("osv result for unknown path", "path", r.Source.Path)
		}
	}
	return res, nil
}

// osvCacheDir is where the offline databases land. Confirmed empirically on
// 2.5.0, which logs "Loaded npm local db from ~/.cache/osv-scalibr/npm/all.zip"
// — note osv-scalibr, not osv-scanner. Older layouts are checked as a fallback.
func osvCacheDir() string {
	for _, name := range []string{"osv-scalibr", "osv-scanner"} {
		p := filepath.Join(userCacheDir(), name)
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return p
		}
	}
	return filepath.Join(userCacheDir(), "osv-scalibr")
}

// canaryLockfile pins a package version with long-standing public advisories.
// If scanning it comes back clean, the matcher is not actually consulting a
// database and every "no findings" this run would be a lie.
const canaryLockfile = `{"name":"canary","lockfileVersion":3,"packages":{` +
	`"":{"name":"canary"},` +
	`"node_modules/lodash":{"version":"4.17.20","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"}}}`

// canaryCheck fails the run rather than let it report a reassuring nothing.
// A vulnerability scanner that silently matches against an empty database is
// worse than no scanner at all, and that is precisely what osv-scanner does
// when handed the wrong offline flag or pointed at a missing cache.
// Both paths that can produce a finding are checked, because a self-check that
// only proves the path we no longer take proves nothing: the deduplicated pass
// (lockfile → packages → purls → match) and the direct pass it falls back to.
func (s *scanner) canaryCheck(ctx context.Context, tmpDir string) error {
	dir := filepath.Join(tmpDir, "canary")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, "package-lock.json")
	if err := os.WriteFile(p, []byte(canaryLockfile), 0o600); err != nil {
		return err
	}

	fail := func(how string) error {
		return fmt.Errorf("self-check failed: osv-scanner reported no vulnerability for a "+
			"knowingly vulnerable lockfile (%s), so the offline databases are not being "+
			"consulted. Run with --refresh-db, or check %s", how, osvCacheDir())
	}

	res, err := s.scanBatch(ctx, []string{p}, scanOffline)
	if err != nil {
		return fmt.Errorf("canary scan failed: %w", err)
	}
	if r := res[p]; r == nil || len(r.Packages) == 0 {
		return fail("scanning the file directly")
	}

	inv, bad, err := s.inventory(ctx, []string{p})
	if err != nil {
		return fmt.Errorf("canary inventory failed: %w", err)
	}
	if len(bad) > 0 || len(inv[p]) == 0 {
		return fail("reading the packages out of the file")
	}
	matched, lost, err := s.matchPurls(ctx, inv[p], tmpDir)
	if err != nil {
		return fmt.Errorf("canary package match failed: %w", err)
	}
	if len(lost) > 0 {
		return fail("matching the packages by purl: " + lost[0].Name + " did not come back")
	}
	for _, id := range inv[p] {
		if sp := matched[id]; sp != nil && len(sp.Groups) > 0 {
			return nil
		}
	}
	return fail("matching the packages by purl")
}

// osvVersions is what `osv-scanner --version` reports:
//
//	osv-scanner version: 2.5.0
//	osv-scalibr version: 0.4.5
//	commit: n/a
//	built at: n/a
//
// There is no machine-readable alternative — `--version` takes no --format,
// and the scan JSON carries no version at all — so the documented key: value
// block is the source, parsed as key/value rather than by cutting line one.
//
// osv-scalibr is worth recording next to the scanner: it is the library that
// decides which files are lockfiles and how they parse, so a report produced
// under a different scalibr can legitimately differ on identical input.
type osvVersions struct{ Scanner, Scalibr string }

func (v osvVersions) String() string {
	switch {
	case v.Scanner == "":
		return ""
	case v.Scalibr == "":
		return v.Scanner
	}
	return v.Scanner + " (scalibr " + v.Scalibr + ")"
}

func checkOsvScanner(bin string) (osvVersions, error) {
	out, err := exec.Command(bin, "--version").Output()
	if err != nil {
		return osvVersions{}, fmt.Errorf("%s not runnable: %w (install it: yay -S osv-scanner-bin, or go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest)", bin, err)
	}
	return parseOsvVersion(string(out)), nil
}

func parseOsvVersion(out string) osvVersions {
	var v osvVersions
	for _, line := range strings.Split(out, "\n") {
		k, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "osv-scanner version":
			v.Scanner = strings.TrimSpace(val)
		case "osv-scalibr version":
			v.Scalibr = strings.TrimSpace(val)
		}
	}
	// An unrecognised layout must not silently blank the field: keep the raw
	// first line so the report still says which binary produced it.
	if v.Scanner == "" {
		v.Scanner = strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
	}
	return v
}
