package scan

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestNormalizeRemote(t *testing.T) {
	want := "gitlab.com/grp/sub/proj"
	for _, in := range []string{
		"git@gitlab.com:grp/sub/proj.git",
		"https://GitLab.com/grp/sub/proj.git",
		"https://gitlab.com/grp/sub/proj/",
		"ssh://git@gitlab.com:2222/grp/sub/proj",
		"https://oauth2:glpat-secret@gitlab.com/grp/sub/proj.git",
	} {
		if got := normalizeRemote(in); got != want {
			t.Errorf("normalizeRemote(%q) = %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{"", "/home/me/repo", "../relative"} {
		if got := normalizeRemote(in); got != "" {
			t.Errorf("normalizeRemote(%q) = %q, want empty", in, got)
		}
	}
}

func TestSkipPath(t *testing.T) {
	for _, p := range []string{"node_modules/x/package-lock.json", "a/b/vendor/composer.lock", "vendor/x/go.mod"} {
		if !skipPath(p) {
			t.Errorf("%q should be skipped", p)
		}
	}
	for _, p := range []string{"package-lock.json", "apps/web/package-lock.json", "my-vendor-tool/go.mod"} {
		if skipPath(p) {
			t.Errorf("%q should NOT be skipped", p)
		}
	}
}

// Regression: ls-tree has no pathspec, so HEAD blobs are filtered in Go. When
// that filter was missing, every README and Dockerfile on HEAD was handed to
// osv-scanner as a lockfile.
func TestIsLockfile(t *testing.T) {
	for _, p := range []string{
		"package-lock.json", "apps/web/pnpm-lock.yaml", "sub/dir/Cargo.lock",
		"go.mod", "dev-requirements.txt", "src/MyApp.deps.json",
		"gradle/verification-metadata.xml",
	} {
		if !isLockfile(p) {
			t.Errorf("%q should be recognised as a lockfile", p)
		}
	}
	for _, p := range []string{"README.md", "Dockerfile", ".gitignore", "docker-compose.yml",
		"src/main.go", "LICENSE", "scripts/backup.sh"} {
		if isLockfile(p) {
			t.Errorf("%q must NOT be treated as a lockfile", p)
		}
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"*a.json", "x/y/a.json", true}, // '*' crosses slashes, like git pathspecs
		{"*a.json", "a.json", true},
		{"*a.json", "ba.json", true},
		{"*a.json", "a.jsonx", false},
		{"*requirements*.txt", "dev-requirements-ci.txt", true},
		{"*requirements*.txt", "requirements.md", false},
		{"go.mod", "go.mod", true},
		{"go.mod", "sub/go.mod", false},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.s); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pattern, c.s, got, c.want)
		}
	}
}

// A loose lockfile and the identical file committed somewhere must collapse to
// one cache entry, which only works if we reproduce git's own blob id exactly.
// The two constants are the well-known `git hash-object` outputs.
func TestGitBlobHash(t *testing.T) {
	if got := gitBlobHash(nil); got != "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391" {
		t.Errorf("empty blob = %s", got)
	}
	if got := gitBlobHash([]byte("hello\n")); got != "ce013625030ba8dba906f756967f9e9ca394464a" {
		t.Errorf("\"hello\\n\" blob = %s", got)
	}
}

func TestExcluder(t *testing.T) {
	e := newExcluder([]string{"/srv/projects/tool", "/home/*/tmp"})
	for _, p := range []string{
		"/srv/projects/tool",
		"/srv/projects/tool/sub/repo",
		"/home/bob/tmp/thing",
	} {
		if !e.match(p) {
			t.Errorf("%q should be excluded", p)
		}
	}
	if e.match("/srv/projects/other") {
		t.Error("unrelated path excluded")
	}
}

// Regression: forge project names are not filesystem paths. Running them
// through filepath.Abs resolved them against the working directory, so with
// lockaudit's own directory excluded — and lockaudit normally run from inside
// it — every single GitLab and GitHub project was silently excluded.
func TestExcluderNameIsNotAPath(t *testing.T) {
	self, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	e := newExcluder([]string{self, "bigcorp/*", "acme/legacy"})

	for _, n := range []string{"someone/a-project", "group/sub/project", "solo"} {
		if e.matchName("gitlab", n) {
			t.Errorf("project %q must not be excluded by a filesystem glob", n)
		}
	}
	for _, n := range []string{"bigcorp/a-site", "acme/legacy", "acme/legacy/sub"} {
		if !e.matchName("gitlab", n) {
			t.Errorf("project %q should be excluded", n)
		}
	}
}

// A forge group or a single forge project can be excluded, optionally scoped to
// one forge with the "gitlab:" / "github:" prefix the report itself prints.
// Naming one project must not take its siblings or its group with it.
func TestExcluderForgeGroups(t *testing.T) {
	e := newExcluder([]string{"acme", "gitlab:bigcorp/", "github:someone/a-project",
		"gitlab:someone/sub/one-project"})

	for _, c := range []struct {
		source, name string
		want         bool
	}{
		{"gitlab", "acme/web", true},          // whole group, any forge
		{"github", "acme/web/sub", true},      // nested subgroup too
		{"gitlab", "bigcorp/a-site", true},    // gitlab-scoped group
		{"github", "bigcorp/a-site", false},   // ...not on the other forge
		{"github", "someone/a-project", true}, // exact project
		{"github", "someone/another", false},  // sibling untouched
		{"gitlab", "acmecorp/web", false},     // prefix must not partial-match

		{"gitlab", "someone/sub/one-project", true},  // one project inside a subgroup
		{"gitlab", "someone/sub/other", false},       // its neighbour stays in
		{"gitlab", "someone/sub", false},             // and so does the group itself
		{"github", "someone/sub/one-project", false}, // gitlab-scoped, so not here
	} {
		if got := e.matchName(c.source, c.name); got != c.want {
			t.Errorf("%s:%s excluded=%v, want %v", c.source, c.name, got, c.want)
		}
	}
}

func TestSeverity(t *testing.T) {
	ghsa := osvVuln{ID: "GHSA-xxxx", DatabaseSpecific: json.RawMessage(`{"severity":"CRITICAL"}`)}
	if got := vulnSeverity(ghsa, "5.0"); got != sevCritical {
		t.Errorf("database_specific should win: got %v", got)
	}
	// A malware advisory outranks everything, threshold included.
	mal := osvVuln{ID: "MAL-2024-1234", DatabaseSpecific: json.RawMessage(`{"severity":"LOW"}`)}
	if got := vulnSeverity(mal, ""); got != sevMalware {
		t.Errorf("MAL- must classify as malware, got %v", got)
	}
	if got := vulnSeverity(osvVuln{ID: "CVE-1", Aliases: []string{"MAL-2024-9"}}, ""); got != sevMalware {
		t.Errorf("MAL- alias must classify as malware, got %v", got)
	}
	// No word anywhere: fall back to the CVSS score osv-scanner computed.
	for _, tc := range []struct {
		score string
		want  severity
	}{{"9.8", sevCritical}, {"7.5", sevHigh}, {"5.0", sevModerate}, {"2.1", sevLow}, {"", sevUnknown}} {
		if got := vulnSeverity(osvVuln{ID: "CVE-1"}, tc.score); got != tc.want {
			t.Errorf("score %q = %v, want %v", tc.score, got, tc.want)
		}
	}
	if sevMalware <= sevCritical {
		t.Error("malware must sort above critical")
	}
}

// The threshold is a MINIMUM: everything at that level and above is reported.
// Getting this backwards would silently hide critical findings.
func TestSeverityThreshold(t *testing.T) {
	for _, c := range []struct {
		sev, threshold severity
		want           bool
	}{
		{sevCritical, sevHigh, true}, // above the bar
		{sevHigh, sevHigh, true},     // the bar itself
		{sevModerate, sevHigh, false},
		{sevHigh, sevCritical, false},
		{sevCritical, sevCritical, true},
		{sevMalware, sevCritical, true},
		{sevMalware, sevMalware, true},
		{sevCritical, sevMalware, false}, // MALWARE means malware only
		{sevMalware, sevLow, true},       // malware always reported
		{sevUnknown, sevLow, false},      // no severity data: below LOW
		{sevUnknown, sevAll, true},       // …unless ALL
		{sevLow, sevAll, true},
	} {
		if got := reportable(c.sev, c.threshold); got != c.want {
			t.Errorf("%s at threshold %s: reported=%v, want %v",
				c.sev, c.threshold, got, c.want)
		}
	}
	if parseSeverity("ALL") != sevAll || parseSeverity("all") != sevAll {
		t.Error("ALL must parse as the report-everything threshold")
	}
	if parseSeverityOr("nonsense", sevHigh) != sevHigh || parseSeverityOr("", sevHigh) != sevHigh {
		t.Error("an unusable threshold must fall back to the default, not to zero")
	}
}

// `osv-scanner --version` is the only place either version number exists —
// the scan JSON has none — so its layout is worth pinning.
func TestParseOsvVersion(t *testing.T) {
	v := parseOsvVersion("osv-scanner version: 2.5.0\nosv-scalibr version: 0.4.5\ncommit: n/a\nbuilt at: n/a\n")
	if v.Scanner != "2.5.0" || v.Scalibr != "0.4.5" {
		t.Fatalf("parsed %+v", v)
	}
	if got := v.String(); got != "2.5.0 (scalibr 0.4.5)" {
		t.Errorf("String() = %q", got)
	}
	// An unknown layout must still identify the binary rather than go blank.
	if got := parseOsvVersion("something else entirely\n").Scanner; got != "something else entirely" {
		t.Errorf("fallback = %q", got)
	}
}

func TestSplitBatches(t *testing.T) {
	// Few files must not spawn one osv-scanner process each: the database load
	// dominates, so batches have a floor.
	if got := len(splitBatches(make([]string, 10))); got != 1 {
		t.Errorf("10 files = %d batches, want 1: the database load dominates", got)
	}
	if splitBatches(nil) != nil {
		t.Error("no files should mean no batches")
	}
	// A wave is thousands of files. Every one of them has to end up in exactly
	// one batch, and no batch may grow big enough to freeze the progress line
	// for an hour.
	b := splitBatches(make([]string, 5606))
	total := 0
	for _, x := range b {
		if len(x) > batchSize {
			t.Fatalf("batch of %d files exceeds the %d ceiling", len(x), batchSize)
		}
		total += len(x)
	}
	if total != 5606 {
		t.Errorf("batches cover %d files, want 5606", total)
	}
}

// Bisecting a batch to find its broken lockfiles costs several times the batch
// itself, and osv-scanner already names them. This pins the parse, because the
// day it stops matching we silently fall back to paying that cost.
func TestUnextractableNamesTheCulprits(t *testing.T) {
	paths := []string{"/wave/aaa/package-lock.json", "/wave/bbb/package-lock.json", "/wave/ccc/yarn.lock"}
	err := &osvError{err: errors.New("exit status 127"), stderr: "" +
		"Error during extraction: (extracting as javascript/packagelockjson) \n" +
		"\twave/aaa/package-lock.json: could not extract: json: cannot unmarshal bool into string\n" +
		"\twave/ccc/yarn.lock: could not extract: unexpected token\n"}

	got := unextractable(err, paths)
	want := []string{"/wave/aaa/package-lock.json", "/wave/ccc/yarn.lock"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("unextractable = %v, want %v", got, want)
	}
	if left := without(paths, got); !reflect.DeepEqual(left, []string{"/wave/bbb/package-lock.json"}) {
		t.Errorf("without = %v, want the one good file", left)
	}

	// A single culprit is folded into the header line instead of getting its
	// own. Missing that form sent whole batches into bisection for nothing.
	inline := &osvError{err: errors.New("exit status 127"), stderr: "Error during extraction: " +
		"(extracting as javascript/pnpmlock) wave/ccc/yarn.lock: could not extract: yaml: line 7241: could not find expected ':'\n"}
	if got := unextractable(inline, paths); !reflect.DeepEqual(got, []string{"/wave/ccc/yarn.lock"}) {
		t.Errorf("inline single-culprit form: got %v", got)
	}
	// A failure that blames nothing must not be read as "nothing was wrong",
	// or the batch would be retried unchanged forever.
	if got := unextractable(&osvError{err: errors.New("killed"), stderr: "signal: killed"}, paths); got != nil {
		t.Errorf("unnamed failure yielded %v, want nil so bisection takes over", got)
	}
}

func TestMergeOccurrence(t *testing.T) {
	a := &Occurrence{Source: "local", Repo: "r", Path: "package-lock.json",
		Commits: []Commit{{SHA: "aaa"}}}
	b := &Occurrence{Source: "local", Repo: "r", Path: "package-lock.json",
		OnHead: true, Commits: []Commit{{SHA: "aaa"}, {SHA: "bbb"}}}
	list := mergeOccurrence(mergeOccurrence(nil, a), b)
	if len(list) != 1 {
		t.Fatalf("same file in same repo must merge, got %d occurrences", len(list))
	}
	if len(list[0].Commits) != 2 {
		t.Errorf("commits should union to 2, got %d", len(list[0].Commits))
	}
	if !list[0].OnHead {
		t.Error("OnHead must survive the merge")
	}
	c := &Occurrence{Source: "gitlab", Repo: "r", Path: "package-lock.json"}
	if len(mergeOccurrence(list, c)) != 2 {
		t.Error("different source must stay a separate occurrence")
	}
}

// An interrupted run reports what it managed to scan. The one thing it must
// never do is read like a clean bill of health, in either output.
func TestInterruptedReportIsNotClean(t *testing.T) {
	r := &Report{
		GeneratedAt: "2026-08-09T12:00:00Z", Threshold: "HIGH", Interrupted: true,
		Stats: Stats{UniqueBlobs: 100, CacheHits: 10, Scanned: 20, Pending: 70},
	}
	var term strings.Builder
	writeTerminal(&term, r, palette{}, "report.md")

	path := filepath.Join(t.TempDir(), "report.md")
	if err := writeMarkdown(path, r); err != nil {
		t.Fatal(err)
	}
	md, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	for name, out := range map[string]string{"terminal": term.String(), "markdown": string(md)} {
		if !strings.Contains(strings.ToUpper(out), "INTERRUPTED") {
			t.Errorf("%s output does not say the run was interrupted:\n%s", name, out)
		}
		if !strings.Contains(out, "70") {
			t.Errorf("%s output hides how much was never scanned", name)
		}
		if strings.Contains(out, "Nothing at or above") {
			t.Errorf("%s output claims a clean result after an interruption", name)
		}
	}
}

// The purl strings are the interface to osv-scanner's SBOM reader: a purl it
// cannot read is a package silently never matched. Every case here was verified
// to round-trip through osv-scanner 2.5.0 offline, so the strings are pinned.
func TestPurlOf(t *testing.T) {
	for _, c := range []struct {
		in   pkgID
		want string
	}{
		{pkgID{"npm", "lodash", "4.17.20"}, "pkg:npm/lodash@4.17.20"},
		// "@" must be escaped or it reads as the start of the version.
		{pkgID{"npm", "@babel/core", "7.4.3"}, "pkg:npm/%40babel/core@7.4.3"},
		{pkgID{"PyPI", "django", "3.0.0"}, "pkg:pypi/django@3.0.0"},
		{pkgID{"Go", "github.com/gin-gonic/gin", "1.6.3"}, "pkg:golang/github.com/gin-gonic/gin@1.6.3"},
		// OSV names a Maven package group:artifact; a purl uses a slash.
		{pkgID{"Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"},
			"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
		{pkgID{"Packagist", "dompdf/dompdf", "v1.0.2"}, "pkg:composer/dompdf/dompdf@v1.0.2"},
		{pkgID{"crates.io", "openssl", "0.10.30"}, "pkg:cargo/openssl@0.10.30"},
		{pkgID{"NuGet", "Newtonsoft.Json", "10.0.3"}, "pkg:nuget/Newtonsoft.Json@10.0.3"},
	} {
		got, ok := purlOf(c.in)
		if !ok || got != c.want {
			t.Errorf("purlOf(%v) = %q,%v want %q,true", c.in, got, ok, c.want)
		}
	}

	// An ecosystem we cannot build a correct purl for must say so, not guess:
	// its file goes down the direct-scan path instead.
	for _, in := range []pkgID{
		{"Debian:11", "curl", "7.74.0"},       // OS package, needs distro qualifiers
		{"npm", "lodash", ""},                 // no version, nothing to match
		{"npm", "", "1.0.0"},                  // no name
		{"SomethingNew", "whatever", "1.0.0"}, // ecosystem added upstream since
	} {
		if got, ok := purlOf(in); ok {
			t.Errorf("purlOf(%v) = %q, want refusal", in, got)
		}
	}
}

// A dependency with no pinned version — `django` on its own in a
// requirements.txt — must be dropped from the inventory, not carried as
// something we failed to resolve. osv-scanner reports it with version "" and
// zero vulnerabilities from a direct scan too, so treating it as unknown sent
// whole files down the slow path for nothing: 620 of 4328 in one measured wave.
func TestInventoryDropsUnversionedPackages(t *testing.T) {
	var out osvOutput
	const raw = `{"results":[{"source":{"path":"/wave/aaa/requirements.txt"},"packages":[
		{"package":{"name":"aiohttp","version":"3.11.8","ecosystem":"PyPI"}},
		{"package":{"name":"django","version":"","ecosystem":"PyPI"}},
		{"package":{"name":"","version":"1.0.0","ecosystem":"PyPI"}}]}]}`
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	inv := packagesByPath(out, []string{"/wave/aaa/requirements.txt"})
	want := []pkgID{{"PyPI", "aiohttp", "3.11.8"}}
	if got := inv["/wave/aaa/requirements.txt"]; !reflect.DeepEqual(got, want) {
		t.Errorf("inventory = %v, want only the pinned package %v", got, want)
	}
}

// The whole speed-up rests on asking about each distinct package once, so this
// pins that a package repeated across lockfiles, or already resolved by an
// earlier wave, is not asked about again.
func TestFreshPackages(t *testing.T) {
	lodash := pkgID{"npm", "lodash", "4.17.20"}
	django := pkgID{"PyPI", "django", "3.0.0"}
	old := pkgID{"npm", "left-pad", "1.3.0"}
	broken := pkgID{"Debian:11", "curl", "7.74.0"}

	inv := map[string][]pkgID{
		"a/package-lock.json": {lodash, old, lodash}, // repeated within one file
		"b/package-lock.json": {lodash, django},      // and across files
		"c/requirements.txt":  {django, broken},
	}
	matched := map[pkgID]*scannedPackage{old: {}} // resolved by an earlier wave
	unmatchable := map[pkgID]bool{broken: true}   // known hopeless

	fresh, ecos := freshPackages(inv, matched, unmatchable)
	want := []pkgID{django, lodash} // sorted by ecosystem then name
	if !reflect.DeepEqual(fresh, want) {
		t.Errorf("freshPackages = %v, want %v", fresh, want)
	}
	if !reflect.DeepEqual(ecos, []string{"PyPI", "npm"}) {
		t.Errorf("ecosystems = %v, want [PyPI npm]", ecos)
	}

	// One unresolved package is enough to send a whole lockfile to the direct
	// scan: the alternative is a report quietly missing it.
	if !usesUnmatchable(inv["c/requirements.txt"], unmatchable) {
		t.Error("a file containing an unmatchable package must fall back")
	}
	if usesUnmatchable(inv["a/package-lock.json"], unmatchable) {
		t.Error("a file whose packages are all matchable must not fall back")
	}
}

// Shards must not mix ecosystems: a process only loads the databases it is asked
// about, so a stray package drags its whole database into every shard. And a
// shard below minShardSize must not exist at all — each one pays a full database
// load, and thirteen loads for 1.5s of matching each was measured at 53s where
// two shards suffice.
func TestShardPackages(t *testing.T) {
	var ids []pkgID
	for i := range 8000 {
		ids = append(ids, pkgID{"npm", "p" + strconv.Itoa(i), "1.0.0"})
	}
	ids = append(ids, pkgID{"PyPI", "django", "3.0.0"})

	shards := shardPackages(ids, 16)
	total := 0
	for _, sh := range shards {
		total += len(sh)
		eco := sh[0].Ecosystem
		for _, id := range sh {
			if id.Ecosystem != eco {
				t.Errorf("shard mixes %s with %s", eco, id.Ecosystem)
			}
		}
	}
	if total != len(ids) {
		t.Errorf("shards cover %d packages, want %d", total, len(ids))
	}
	// 8000 npm bound by the 4000 floor, plus a lone PyPI package.
	if len(shards) != 3 {
		t.Errorf("got %d shards, want 3 (two npm at the floor + 1 PyPI)", len(shards))
	}

	// A handful of packages must not become one process per package.
	if small := shardPackages(ids[:20], 16); len(small) != 1 {
		t.Errorf("20 packages over 16 workers = %d shards, want 1", len(small))
	}

	// Huge runs still spread over every worker rather than queueing at the floor.
	var big []pkgID
	for i := range 160000 {
		big = append(big, pkgID{"npm", "q" + strconv.Itoa(i), "1.0.0"})
	}
	if got := len(shardPackages(big, 16)); got != 16 {
		t.Errorf("160k packages over 16 workers = %d shards, want 16", got)
	}
}

// A missing ecosystem database makes osv-scanner print an error, exit 0, and
// return zero vulnerabilities for every package after the one that triggered it.
// Treating that output as a result is a silent false negative, so it has to be
// an error even though the JSON parsed.
func TestMissingDatabaseIsAFailure(t *testing.T) {
	e := &osvError{err: errors.New("exit status 0"), stderr: "Error during extraction: " +
		"(extracting as vulnmatch/osvlocal) unable to fetch OSV database: " +
		"no offline version of the OSV database is available\n"}
	if !e.missingDatabase() {
		t.Error("a missing offline database must be recognised as such")
	}
	if (&osvError{stderr: "some other problem"}).missingDatabase() {
		t.Error("unrelated stderr must not read as a missing database")
	}
}

// The status line is clipped to the terminal width, and it is coloured. Those
// two facts fight: an escape sequence is made of runes, so clipping the finished
// string cuts the visible text short by however many bytes of colour precede it,
// and can sever a sequence halfway — leaving the terminal in a colour nothing
// ever tells it to leave. Clipping happens on visible width instead, which is
// what this pins.
func TestRenderClipsOnVisibleWidth(t *testing.T) {
	const red, reset = "\033[31m", "\033[0m"
	spans := []span{{"abcde", red}, {"fghij", ""}}

	// Well inside the width: everything survives, colour included.
	if got, want := render(spans, 20), red+"abcde"+reset+"fghij"; got != want {
		t.Errorf("render = %q, want %q", got, want)
	}

	// Clipped mid-way: 7 visible runes, and the escape bytes must not count
	// towards them.
	got := render(spans, 7)
	if visible := stripANSI(got); len([]rune(visible)) != 7 {
		t.Errorf("render clipped to %d visible runes (%q), want 7", len([]rune(visible)), visible)
	}
	if strings.Count(got, red) != strings.Count(got, reset) {
		t.Errorf("unbalanced colour in %q: every colour must be closed", got)
	}

	// Clipped inside the first span: still balanced, still ends in an ellipsis
	// rather than a half-written escape sequence.
	got = render(spans, 3)
	if v := stripANSI(got); !strings.HasSuffix(v, "…") || len([]rune(v)) != 3 {
		t.Errorf("render(3) visible = %q, want 3 runes ending in an ellipsis", v)
	}

	// No colour configured (NO_COLOR, or output redirected) writes no escapes at
	// all, so a piped run stays greppable.
	if got := render([]span{{"plain", ""}}, 20); got != "plain" {
		t.Errorf("uncoloured render = %q, want %q", got, "plain")
	}
}

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\033' {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			i++ // the 'm'
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// The terminal is a recap and the file is the report. Findings, commits and
// failures belong in exactly one of the two, or people read neither.
func TestTerminalIsARecapOnly(t *testing.T) {
	r := &Report{
		GeneratedAt: "2026-08-09T12:00:00Z", Threshold: "HIGH",
		Stats:  Stats{UniqueBlobs: 3, Scanned: 3},
		Errors: []string{"unscannable lockfile: gitlab:acme/web app/package-lock.json @ abc12345 (2021-04-02)"},
		Findings: []Finding{{
			Package: "a-bad-package", Version: "1.2.3", Ecosystem: "npm", Malware: true,
			sev: sevMalware, Severity: "MALWARE", PrimaryID: "MAL-0000-1",
			Occurrences: []Occurrence{{Source: "gitlab", Repo: "acme/web", Path: "package-lock.json",
				Commits: []Commit{{SHA: "abc12345def", Date: "2021-04-02", Unix: 1617321600}}}},
		}},
	}
	var term strings.Builder
	writeTerminal(&term, r, palette{}, "lockaudit-report.md")
	got := term.String()

	for _, detail := range []string{"a-bad-package", "MAL-0000-1", "abc12345", "acme/web"} {
		if strings.Contains(got, detail) {
			t.Errorf("terminal recap leaks %q; detail belongs to the report only:\n%s", detail, got)
		}
	}
	// It still has to say that something was found, and where to read it.
	for _, must := range []string{"1 malware finding", "1 unit failed", "lockaudit-report.md"} {
		if !strings.Contains(got, must) {
			t.Errorf("terminal recap is missing %q:\n%s", must, got)
		}
	}

	path := filepath.Join(t.TempDir(), "report.md")
	if err := writeMarkdown(path, r); err != nil {
		t.Fatal(err)
	}
	md, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// ...and the report has to carry every detail the recap dropped, including
	// the repo and commit behind a failed unit.
	for _, must := range []string{"a-bad-package", "MAL-0000-1", "abc12345", "acme/web"} {
		if !strings.Contains(string(md), must) {
			t.Errorf("report is missing %q", must)
		}
	}
}

// TestHistoryWalk is the load-bearing test: it builds a real repo where a
// lockfile is added, changed, then cleaned up, and checks we recover every
// version with its commits — including the one that only exists in the past.
func TestHistoryWalk(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	ctx := context.Background()

	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=t@e",
			"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=t@e")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(dir, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	git("init", "-q", "-b", "main")
	write("package-lock.json", `{"v":1}`)
	write("node_modules/dep/package-lock.json", `{"vendored":true}`)
	git("add", "-A")
	git("commit", "-qm", "add lockfile")
	write("package-lock.json", `{"v":2}`)
	git("commit", "-qam", "bump")
	write("package-lock.json", `{"v":3}`)
	git("commit", "-qam", "bump again")

	occs, err := historyBlobs(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	hashes := map[string]bool{}
	for _, o := range occs {
		if o.Path != "package-lock.json" {
			t.Errorf("vendored path leaked into results: %q", o.Path)
		}
		if o.Commit.SHA == "" || o.Commit.Unix == 0 {
			t.Errorf("occurrence %v lost its commit metadata", o)
		}
		hashes[o.Hash] = true
	}
	if len(hashes) != 3 {
		t.Fatalf("want 3 distinct lockfile versions in history, got %d", len(hashes))
	}

	head := headBlobs(ctx, dir, "")
	if len(head) != 1 {
		t.Fatalf("want 1 lockfile on HEAD, got %d", len(head))
	}
	for h := range head {
		if !hashes[h] {
			t.Error("HEAD blob missing from history walk")
		}
		delete(hashes, h)
	}
	if len(hashes) != 2 {
		t.Errorf("want 2 past-only versions, got %d", len(hashes))
	}

	// cat-file --batch must return exactly the bytes we committed.
	var got []string
	all := []string{}
	for h := range hashes {
		all = append(all, h)
	}
	if err := catFileBatch(ctx, dir, all, func(_ string, data []byte) error {
		got = append(got, string(data))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("cat-file returned %d blobs, want 2", len(got))
	}
	for _, g := range got {
		if g != `{"v":1}` && g != `{"v":2}` {
			t.Errorf("unexpected blob content %q", g)
		}
	}
}
