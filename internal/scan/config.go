package scan

import (
	"bufio"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type options struct {
	dryRun     bool
	verbose    bool
	refreshDB  bool
	noProgress bool
	reportOut  string
	jsonOut    string
	sarifOut   string
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// loadConfig resolves settings from .env, then the environment, then flags.
// Flags win, because that is what you reach for when overriding a stored config
// for one run.
func loadConfig() (*config, *options, error) {
	var (
		envFile   = flag.String("env", ".env", "path to the .env file")
		sources   = flag.String("sources", "", "comma list: gitlab,github,local (overrides SOURCES)")
		localOnly = flag.Bool("local-only", false, "shorthand for --sources local")
		gitlabOn  = flag.Bool("gitlab-only", false, "shorthand for --sources gitlab")
		githubOn  = flag.Bool("github-only", false, "shorthand for --sources github")
		allRefs   = flag.Bool("all-refs", false, "also fetch merge/pull request refs (slow on repos you only contribute to)")
		roots     = flag.String("roots", "", "comma list of local roots (overrides LOCAL_ROOTS)")
		sevFlag   = flag.String("severity", "", "minimum severity to report, that level and above: ALL|LOW|MODERATE|HIGH|CRITICAL|MALWARE (MAL-* always reported)")
		noHistory = flag.Bool("no-history", false, "scan only current HEAD, not the whole history")
		workers   = flag.Int("workers", 0, "parallel scan workers (default: CPU count)")
		netW      = flag.Int("network-workers", 0, "parallel git clones (default 8)")
		tmpDir    = flag.String("tmpdir", "", "where blobs are extracted (default: <cache>/tmp)")
		reportOut = flag.String("report", "", "write the full report as Markdown to this path (default REPORT_FILE, or ./lockaudit-report.md; \"-\" disables)")
		jsonOut   = flag.String("json", "", "write the report as JSON to this path")
		sarifOut  = flag.String("sarif", "", "write the report as SARIF to this path")
		dryRun    = flag.Bool("dry-run", false, "print the deduplicated inventory and exit")
		refreshDB = flag.Bool("refresh-db", false, "force a re-download of the OSV databases")
		noProg    = flag.Bool("no-progress", false, "disable the progress line")
		verbose   = flag.Bool("v", false, "debug logging")
		excludes  multiFlag
	)
	flag.Var(&excludes, "exclude", "path, forge group or forge project to exclude, "+
		"repeatable, e.g. /abs/path, group, group/project, gitlab:group/project (adds to EXCLUDE_PATHS)")
	flag.Parse()

	loadDotEnv(*envFile)

	cfg := &config{
		Sources:         splitList(envOr("SOURCES", "gitlab,local")),
		LocalRoots:      splitList(os.Getenv("LOCAL_ROOTS")),
		ExcludePaths:    splitList(os.Getenv("EXCLUDE_PATHS")),
		GitlabURL:       envOr("GITLAB_URL", "https://gitlab.com"),
		GitlabToken:     os.Getenv("GITLAB_TOKEN"),
		GithubURL:       envOr("GITHUB_API_URL", "https://api.github.com"),
		GithubToken:     os.Getenv("GITHUB_TOKEN"),
		IncludeArchived: envBool("INCLUDE_ARCHIVED", true),
		FetchAllRefs:    envBool("FETCH_ALL_REFS", false),
		GithubAffiliations: envOr("GITHUB_AFFILIATIONS",
			"owner,collaborator,organization_member"),
		Threshold:        parseSeverityOr(envOr("SEVERITY_THRESHOLD", "HIGH"), sevHigh),
		ScanHistory:      envBool("SCAN_HISTORY", true),
		Workers:          atoiOr(os.Getenv("WORKERS"), runtime.NumCPU()),
		NetworkWorkers:   atoiOr(os.Getenv("NETWORK_WORKERS"), 8),
		DBMaxAge:         time.Duration(atoiOr(os.Getenv("DB_MAX_AGE_HOURS"), 24)) * time.Hour,
		CacheDir:         expandHome(envOr("CACHE_DIR", filepath.Join(userCacheDir(), "lockaudit"))),
		OsvBin:           envOr("OSV_SCANNER_BIN", "osv-scanner"),
		LockfilePatterns: defaultLockfilePatterns,
		// 0 means one wave, however big it has to be, and that is the default:
		// every extra wave repays a fixed cost — the OSV databases are reloaded
		// for its own matching pass — and disk is the cheap resource here. One
		// real run of ~11k lockfile versions extracted 2.4 GB of scratch under
		// CACHE_DIR, released as soon as the wave is done. Set WAVE_MB to cap it
		// on a machine where that is not free.
		WaveBytes: int64(atoiOr(os.Getenv("WAVE_MB"), 0)) << 20,
	}
	if v := splitList(os.Getenv("LOCKFILE_PATTERNS")); len(v) > 0 {
		cfg.LockfilePatterns = v
	}

	if *sources != "" {
		cfg.Sources = splitList(*sources)
	}
	if *localOnly {
		cfg.Sources = []string{"local"}
	}
	if *gitlabOn {
		cfg.Sources = []string{"gitlab"}
	}
	if *githubOn {
		cfg.Sources = []string{"github"}
	}
	if *allRefs {
		cfg.FetchAllRefs = true
	}
	if *roots != "" {
		cfg.LocalRoots = splitList(*roots)
	}
	if *sevFlag != "" {
		cfg.Threshold = parseSeverityOr(*sevFlag, cfg.Threshold)
	}
	if *noHistory {
		cfg.ScanHistory = false
	}
	if *workers > 0 {
		cfg.Workers = *workers
	}
	if *netW > 0 {
		cfg.NetworkWorkers = *netW
	}
	cfg.ExcludePaths = append(cfg.ExcludePaths, excludes...)
	cfg.TmpDir = *tmpDir
	if cfg.TmpDir == "" {
		// Default to the cache dir, not /tmp: /tmp is tmpfs on Arch, and a wave
		// of extracted lockfiles is measured in GB — filling RAM to save a few
		// seconds is a bad trade on a developer machine.
		cfg.TmpDir = filepath.Join(cfg.CacheDir, "tmp")
	}
	if cfg.Workers < 1 {
		cfg.Workers = 1
	}
	if cfg.NetworkWorkers < 1 {
		cfg.NetworkWorkers = 1
	}

	if err := validate(cfg); err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(cfg.TmpDir, 0o700); err != nil {
		return nil, nil, err
	}
	// The written report is the deliverable, not a side export: a terminal
	// scrollback is not somewhere you can re-read a malware finding tomorrow.
	// It is on by default; "-" is the way to opt out.
	report := envOr("REPORT_FILE", "lockaudit-report.md")
	if *reportOut != "" {
		report = *reportOut
	}
	if report == "-" {
		report = ""
	}
	return cfg, &options{
		dryRun: *dryRun, verbose: *verbose, refreshDB: *refreshDB, noProgress: *noProg,
		reportOut: expandHome(report), jsonOut: *jsonOut, sarifOut: *sarifOut,
	}, nil
}

// validate fails loudly rather than letting a typo produce an empty, reassuring
// report — the worst possible outcome for a security tool.
func validate(cfg *config) error {
	if len(cfg.Sources) == 0 {
		return fmt.Errorf("SOURCES is empty: set it to gitlab, local, or gitlab,local")
	}
	for _, s := range cfg.Sources {
		if s != "gitlab" && s != "github" && s != "local" {
			return fmt.Errorf("unknown source %q (want any of: gitlab, github, local)", s)
		}
	}
	if slices(cfg.Sources, "local") && len(cfg.LocalRoots) == 0 {
		return fmt.Errorf("SOURCES includes local but LOCAL_ROOTS is empty")
	}
	for _, r := range cfg.LocalRoots {
		if st, err := os.Stat(expandHome(r)); err != nil || !st.IsDir() {
			return fmt.Errorf("local root %q is not a readable directory", r)
		}
	}
	if slices(cfg.Sources, "gitlab") && cfg.GitlabToken == "" {
		return fmt.Errorf("SOURCES includes gitlab but GITLAB_TOKEN is unset (needs read_api + read_repository)")
	}
	if slices(cfg.Sources, "github") && cfg.GithubToken == "" {
		return fmt.Errorf("SOURCES includes github but GITHUB_TOKEN is unset (needs repo:read / classic `repo` scope)")
	}
	return nil
}

// A typo here would silently loosen or tighten what gets reported, so an
// unrecognised value is loud rather than quietly replaced by the default.
func parseSeverityOr(s string, def severity) severity {
	if strings.TrimSpace(s) == "" {
		return def
	}
	v := parseSeverity(s)
	if v == sevUnknown {
		slog.Warn("unrecognised severity, ignored", "value", s,
			"expected", "ALL|LOW|MODERATE|HIGH|CRITICAL|MALWARE", "using", def.String())
		return def
	}
	return v
}

func envBool(key string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}

// loadDotEnv fills in variables that are not already set in the environment, so
// an exported GITLAB_TOKEN keeps precedence over a stale one in the file.
func loadDotEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if i := strings.Index(v, " #"); i >= 0 { // trailing comment
			v = strings.TrimSpace(v[:i])
		}
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		if _, exists := os.LookupEnv(k); !exists {
			os.Setenv(k, v)
		}
	}
}
