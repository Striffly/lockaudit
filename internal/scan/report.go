package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// Commit is one commit that carried a given lockfile version.
type Commit struct {
	SHA     string `json:"sha"`
	Unix    int64  `json:"-"`
	Date    string `json:"date"`
	Author  string `json:"author"`
	Subject string `json:"subject"`
}

func (c Commit) Short() string {
	if len(c.SHA) > 8 {
		return c.SHA[:8]
	}
	return c.SHA
}

// Occurrence is "this vulnerable package was in this file, in this repo".
type Occurrence struct {
	Source  string   `json:"source"` // gitlab | local
	Repo    string   `json:"repo"`
	Path    string   `json:"path"`
	OnHead  bool     `json:"on_head"`
	Commits []Commit `json:"commits"`
}

type Finding struct {
	Package     string       `json:"package"`
	Version     string       `json:"version"`
	Ecosystem   string       `json:"ecosystem"`
	PrimaryID   string       `json:"primary_id"`
	IDs         []string     `json:"ids"`
	Severity    string       `json:"severity"`
	sev         severity     `json:"-"`
	Malware     bool         `json:"malware"`
	Summary     string       `json:"summary"`
	URL         string       `json:"url"`
	Current     bool         `json:"currently_exposed"`
	Occurrences []Occurrence `json:"occurrences"`
}

type Report struct {
	GeneratedAt string    `json:"generated_at"`
	OsvVersion  string    `json:"osv_scanner_version"`
	DBVersion   string    `json:"osv_db_version"`
	Threshold   string    `json:"severity_threshold"`
	Interrupted bool      `json:"interrupted"`
	Stats       Stats     `json:"stats"`
	Findings    []Finding `json:"findings"`
	Errors      []string  `json:"errors,omitempty"`
	Excluded    []string  `json:"excluded,omitempty"`
}

type Stats struct {
	ReposScanned int    `json:"repos_scanned"`
	ReposGitlab  int    `json:"repos_gitlab"`
	ReposGithub  int    `json:"repos_github"`
	ReposLocal   int    `json:"repos_local"`
	LooseFiles   int    `json:"loose_lockfiles"`
	UniqueBlobs  int    `json:"unique_lockfile_versions"`
	CacheHits    int    `json:"cache_hits"`
	Scanned      int    `json:"newly_scanned"`
	Pending      int    `json:"never_scanned"` // >0 only after an interruption
	Malware      int    `json:"malware_findings"`
	Duration     string `json:"duration"`
}

// span is the window a lockfile version was in a repo, taken from the commits
// that carried it. "When was I exposed" is the question the whole history walk
// exists to answer, so it gets its own line in the report.
func (o Occurrence) span() (first, last string) {
	for _, c := range o.Commits {
		if c.Unix == 0 {
			continue
		}
		if first == "" || c.Date < first {
			first = c.Date
		}
		if c.Date > last {
			last = c.Date
		}
	}
	return
}

// ---- terminal ----

type palette struct{ reset, bold, dim, red, mag, yel, cyan, grn string }

func isTTY(w *os.File) bool {
	st, err := w.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func newPalette(w *os.File) palette {
	if !isTTY(w) || os.Getenv("NO_COLOR") != "" {
		return palette{}
	}
	return palette{
		reset: "\033[0m", bold: "\033[1m", dim: "\033[2m", red: "\033[31m",
		mag: "\033[35m", yel: "\033[33m", cyan: "\033[36m", grn: "\033[32m",
	}
}

func (p palette) sevColor(s severity) string {
	switch s {
	case sevMalware:
		return p.mag
	case sevCritical:
		return p.red
	case sevHigh:
		return p.yel
	default:
		return p.cyan
	}
}

const rule = "──────────────────────────────────────────────────────────────────────"

// writeTerminal prints the summary and nothing else. Every finding, every
// commit and every failure lives in the Markdown report, which is the artefact
// meant to be read and kept — a thousand findings scrolling past in a terminal
// is not a report, it is a reason to stop reading. reportPath is where that file
// went, "" when none was written.
func writeTerminal(w io.Writer, r *Report, p palette, reportPath string) {
	s := r.Stats
	mal, vulns := splitMalware(r.Findings)

	banner(w, p, "SUPPLY-CHAIN AUDIT", strings.TrimSpace(orDash(s.Duration)))

	if r.Interrupted {
		fmt.Fprintf(w, "  %s%s⚠  INTERRUPTED — partial results%s\n", p.bold, p.yel, p.reset)
		fmt.Fprintf(w, "     %s%d of %d lockfile versions were never scanned. What finished is%s\n",
			p.yel, s.Pending, s.UniqueBlobs, p.reset)
		fmt.Fprintf(w, "     %scached: rerun the same command and it resumes.%s\n\n", p.yel, p.reset)
	}

	field := func(k, format string, a ...any) {
		fmt.Fprintf(w, "  %s%-10s%s %s\n", p.dim, k, p.reset, fmt.Sprintf(format, a...))
	}
	sources := fmt.Sprintf("%s (%d gitlab · %d github · %d local)",
		plural(s.ReposScanned, "repo"), s.ReposGitlab, s.ReposGithub, s.ReposLocal)
	if s.LooseFiles > 0 {
		sources += " · " + plural(s.LooseFiles, "loose lockfile")
	}
	field("scope", "%s", sources)
	lock := fmt.Sprintf("%d versions · %d cached · %d scanned", s.UniqueBlobs, s.CacheHits, s.Scanned)
	if s.Pending > 0 {
		lock += fmt.Sprintf(" · %s%d never looked at%s", p.yel, s.Pending, p.reset)
	}
	field("lockfiles", "%s", lock)
	field("engine", "osv-scanner %s · db %s · threshold %s%s%s",
		orDash(r.OsvVersion), orDash(shortDB(r.DBVersion)), p.bold, r.Threshold, p.reset)
	field("run", "%s", r.GeneratedAt)

	fmt.Fprintln(w)
	switch {
	case len(r.Findings) == 0 && r.Interrupted:
		fmt.Fprintf(w, "  %s┌ Nothing found in what was scanned — but the scan did not finish,%s\n", p.yel, p.reset)
		fmt.Fprintf(w, "  %s└ so this is not a clean bill of health.%s\n", p.yel, p.reset)
	case len(r.Findings) == 0:
		fmt.Fprintf(w, "  %s%s✓ Nothing at or above the %s threshold.%s\n", p.bold, p.grn, r.Threshold, p.reset)
	default:
		fmt.Fprintf(w, "  %s┌%s %s%s%s · %s%s at or above %s%s\n", p.dim, p.reset,
			p.bold+p.mag, plural(len(mal), "malware finding"), p.reset,
			p.bold+p.red, plural(len(vulns), "vulnerability", "vulnerabilities"), r.Threshold, p.reset)
		fmt.Fprintf(w, "  %s└ %s%s\n", p.dim, exposureSummary(r.Findings), p.reset)
		fmt.Fprintln(w)
		writeSeverityBars(w, r.Findings, p)
	}

	// Not one package is named here, on purpose. Which ones, in which repo, from
	// which commit, and what to rotate afterwards are all questions that need the
	// report open in front of you — printing them twice only splits attention.
	if len(mal) > 0 {
		fmt.Fprintf(w, "\n  %s%sMalware means an install may have executed it. The report says what to rotate.%s\n",
			p.bold, p.yel, p.reset)
	}

	if len(r.Errors) > 0 || len(r.Excluded) > 0 || reportPath != "" {
		fmt.Fprintf(w, "\n  %s%s%s\n", p.dim, rule, p.reset)
	}
	if len(r.Errors) > 0 {
		fmt.Fprintf(w, "  %s%s⚠ %s failed%s%s — each one is named in the report%s\n",
			p.bold, p.yel, plural(len(r.Errors), "unit"), p.reset, p.yel, p.reset)
	}
	if len(r.Excluded) > 0 {
		fmt.Fprintf(w, "  %s%s excluded by configuration%s\n", p.dim, plural(len(r.Excluded), "project"), p.reset)
	}
	if reportPath != "" {
		fmt.Fprintf(w, "  %sfull report%s %s%s%s\n", p.dim, p.reset, p.bold, reportPath, p.reset)
	}
	fmt.Fprintln(w)
}

// banner draws the title box with the run duration flush right inside it.
func banner(w io.Writer, p palette, title, right string) {
	width := len([]rune(rule))
	left := "  " + title
	pad := max(1, width-len([]rune(left))-len([]rune(right))-2)
	edge := p.bold + p.cyan
	fmt.Fprintf(w, "\n%s╭%s╮%s\n", edge, rule, p.reset)
	fmt.Fprintf(w, "%s│%s%s%s%s%s%s  %s│%s\n", edge, p.reset,
		p.bold, left, p.reset, strings.Repeat(" ", pad), p.dim+right+p.reset, edge, p.reset)
	fmt.Fprintf(w, "%s╰%s╯%s\n\n", edge, rule, p.reset)
}

// writeSeverityBars is the shape of the result at a glance: which severities
// dominate, without reading a single finding.
func writeSeverityBars(w io.Writer, fs []Finding, p palette) {
	count := map[severity]int{}
	most := 0
	for _, f := range fs {
		count[f.sev]++
		most = max(most, count[f.sev])
	}
	const barWidth = 34
	for _, sev := range []severity{sevMalware, sevCritical, sevHigh, sevModerate, sevLow, sevUnknown} {
		n := count[sev]
		if n == 0 {
			continue
		}
		// One cell minimum, so a single malware finding is still visible next to
		// a thousand highs.
		cells := max(1, n*barWidth/most)
		c := p.sevColor(sev)
		fmt.Fprintf(w, "  %s%-9s%s %s%s%s%s %s%d%s\n", c, sev, p.reset,
			c, strings.Repeat("█", cells), p.dim, strings.Repeat("░", barWidth-cells), p.reset+c, n, p.reset)
	}
}

func section(w io.Writer, p palette, color, title string, lines ...string) {
	fmt.Fprintf(w, "\n%s%s── %s %s%s\n", p.bold, color, title,
		strings.Repeat("─", max(0, len([]rune(rule))-len([]rune(title))-4)), p.reset)
	for _, l := range lines {
		if l != "" {
			fmt.Fprintf(w, "%s%s%s\n", p.dim, l, p.reset)
		}
	}
}

// exposureSummary is the line that decides what you do next: something on HEAD
// is a fix, something purely historical is an incident to investigate.
func exposureSummary(fs []Finding) string {
	current := 0
	for _, f := range fs {
		if f.Current {
			current++
		}
	}
	return fmt.Sprintf("%d still on HEAD, %d past only", current, len(fs)-current)
}

func severityBreakdown(fs []Finding) string {
	count := map[severity]int{}
	for _, f := range fs {
		count[f.sev]++
	}
	var parts []string
	for _, s := range []severity{sevMalware, sevCritical, sevHigh, sevModerate, sevLow, sevUnknown} {
		if count[s] > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", s, count[s]))
		}
	}
	return strings.Join(parts, " · ")
}

// plural appends "s" unless an irregular plural is given ("vulnerability",
// "vulnerabilities").
func plural(n int, word string, irregular ...string) string {
	if n == 1 {
		return "1 " + word
	}
	if len(irregular) > 0 {
		return fmt.Sprintf("%d %s", n, irregular[0])
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// baseName labels a repo on the progress line: a full path is mostly leading
// directories that are identical for every repo in the run.
func baseName(s string) string {
	if i := strings.LastIndexAny(strings.TrimRight(s, "/"), "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// shortDB keeps the database fingerprint recognisable without spending a line
// on it: it only ever matters as "same as last run" or "not".
func shortDB(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

func splitMalware(fs []Finding) (mal, vuln []Finding) {
	for _, f := range fs {
		if f.Malware {
			mal = append(mal, f)
		} else {
			vuln = append(vuln, f)
		}
	}
	return
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// sortFindings orders by malware first, then severity, then whether it is still
// live, then source and package — deterministic output for diffing runs.
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.sev != b.sev {
			return a.sev > b.sev
		}
		if a.Current != b.Current {
			return a.Current
		}
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		return a.PrimaryID < b.PrimaryID
	})
}

// ---- written report ----

// writeMarkdown is the report you keep. The terminal output is for the moment
// the scan ends; this is what you re-read next week, attach to an incident
// ticket, or diff against the previous run. It carries EVERYTHING — no
// truncated commit lists, no elided errors — because the whole point of a file
// is that it does not have to fit on a screen.
func writeMarkdown(path string, r *Report) error {
	var b strings.Builder
	s := r.Stats
	mal, vulns := splitMalware(r.Findings)

	b.WriteString("# Supply-chain audit\n\n")
	if r.Interrupted {
		b.WriteString("> **⚠ INTERRUPTED — these results are partial.**\n>\n")
		fmt.Fprintf(&b, "> %d lockfile versions were never scanned. Everything that finished is\n", s.Pending)
		b.WriteString("> cached: rerunning the same command resumes rather than starting over.\n\n")
	}

	b.WriteString("| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| Generated | %s |\n", r.GeneratedAt)
	fmt.Fprintf(&b, "| Duration | %s |\n", orDash(s.Duration))
	fmt.Fprintf(&b, "| Scope | %s (%d gitlab, %d github, %d local), %s |\n",
		plural(s.ReposScanned, "repo"), s.ReposGitlab, s.ReposGithub, s.ReposLocal,
		plural(s.LooseFiles, "loose lockfile"))
	fmt.Fprintf(&b, "| Lockfile versions | %d distinct across all history (%d cached, %d newly scanned) |\n",
		s.UniqueBlobs, s.CacheHits, s.Scanned)
	fmt.Fprintf(&b, "| Threshold | %s and above (malware always) |\n", r.Threshold)
	fmt.Fprintf(&b, "| Engine | osv-scanner %s, database `%s` |\n", orDash(r.OsvVersion), orDash(shortDB(r.DBVersion)))
	fmt.Fprintf(&b, "| Findings | %s, %s — %s |\n\n",
		plural(len(mal), "malware finding"),
		plural(len(vulns), "vulnerability", "vulnerabilities"),
		exposureSummary(r.Findings))

	if len(r.Findings) == 0 {
		if r.Interrupted {
			b.WriteString("Nothing found **in what was scanned** — but the scan did not finish, so\n" +
				"this is not a clean bill of health.\n")
		} else {
			fmt.Fprintf(&b, "Nothing at or above the %s threshold.\n", r.Threshold)
		}
	} else {
		// A summary table first: on a real machine the detail below runs to
		// hundreds of lines, and the triage question ("what is still live?")
		// should be answerable without scrolling through all of it.
		fmt.Fprintf(&b, "%s\n\n## Summary\n\n", severityBreakdown(r.Findings))
		b.WriteString("| severity | package | ecosystem | state | seen in |\n|---|---|---|---|---|\n")
		for _, f := range r.Findings {
			state := "past only"
			if f.Current {
				state = "**on HEAD**"
			}
			fmt.Fprintf(&b, "| %s | `%s@%s` | %s | %s | %s |\n",
				f.Severity, f.Package, f.Version, f.Ecosystem, state,
				plural(len(f.Occurrences), "location"))
		}
	}

	if len(mal) > 0 {
		b.WriteString("\n## Malware\n\n")
		b.WriteString("Known-malicious packages: not a bug someone might exploit, but code\n" +
			"published to steal from whoever installed it.\n")
		for _, f := range mal {
			markdownFinding(&b, f)
		}
		markdownAdvice(&b, mal)
	}
	if len(vulns) > 0 {
		b.WriteString("\n## Vulnerabilities\n")
		for _, f := range vulns {
			markdownFinding(&b, f)
		}
	}

	if len(r.Errors) > 0 {
		fmt.Fprintf(&b, "\n## Failed units (%d)\n\n", len(r.Errors))
		b.WriteString("Coverage is partial for these. A failed unit never aborts the run.\n\n")
		for _, e := range r.Errors {
			fmt.Fprintf(&b, "- %s\n", e)
		}
	}
	if len(r.Excluded) > 0 {
		fmt.Fprintf(&b, "\n## Excluded by configuration (%d)\n\n", len(r.Excluded))
		for _, e := range r.Excluded {
			fmt.Fprintf(&b, "- `%s`\n", e)
		}
	}

	b.WriteString("\n---\n\n**Scope limit:** this audits *dependencies*, not this machine. " +
		"It cannot tell you whether anything executed, and finding nothing here is not " +
		"evidence that the host is clean.\n")

	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func markdownFinding(b *strings.Builder, f Finding) {
	state := "past exposure only"
	if f.Current {
		state = "**still present on HEAD**"
	}
	// The advisory id is part of the heading: the same package version can
	// appear several times under different advisories, and identical headings
	// make the anchors collide.
	fmt.Fprintf(b, "\n### %s@%s — %s (%s)\n\n", f.Package, f.Version, f.Severity, f.PrimaryID)
	fmt.Fprintf(b, "%s · ecosystem `%s` · %s\n\n", state, f.Ecosystem, strings.Join(f.IDs, ", "))
	if f.Summary != "" {
		fmt.Fprintf(b, "%s\n\n", strings.TrimSpace(f.Summary))
	}
	fmt.Fprintf(b, "<%s>\n", f.URL)

	for _, o := range f.Occurrences {
		head := ""
		if o.OnHead {
			head = " — on HEAD"
		}
		fmt.Fprintf(b, "\n**%s** · `%s/%s`%s\n\n", o.Source, shortenHome(o.Repo), o.Path, head)
		if first, last := o.span(); first != "" {
			if first == last {
				fmt.Fprintf(b, "Exposed on %s, %s.\n\n", first, plural(len(o.Commits), "commit"))
			} else {
				fmt.Fprintf(b, "Exposed %s → %s, %s.\n\n", first, last, plural(len(o.Commits), "commit"))
			}
		}
		if len(o.Commits) == 0 {
			b.WriteString("Current state only — this file belongs to no repository, so there is no\n" +
				"history to date the exposure from.\n")
			continue
		}
		b.WriteString("| commit | date | author | subject |\n|---|---|---|---|\n")
		for _, c := range o.Commits {
			fmt.Fprintf(b, "| `%s` | %s | %s | %s |\n",
				c.Short(), c.Date, mdCell(c.Author), mdCell(c.Subject))
		}
	}
}

func markdownAdvice(b *strings.Builder, mal []Finding) {
	past := 0
	for _, f := range mal {
		if !f.Current {
			past++
		}
	}
	b.WriteString("\n### What a malware finding actually means\n\n")
	b.WriteString("These packages were in the dependency tree. If install or build ran while\n" +
		"they were, their postinstall scripts ran with your user's rights — that is how\n" +
		"Shai-Hulud-style worms harvest credentials. Removing the package does not undo it.\n\n")
	if past > 0 {
		fmt.Fprintf(b, "**%d of these are past exposures**: clean today, but the install ran back then.\n\n", past)
	}
	b.WriteString("Worth checking, in rough order of blast radius:\n\n" +
		"- [ ] rotate npm / PyPI / crates.io publish tokens, and any CI tokens\n" +
		"- [ ] rotate SSH and GPG keys, check `~/.ssh/authorized_keys`\n" +
		"- [ ] rotate whatever sat in `.env` files and shell history at the time\n" +
		"- [ ] look for unexpected systemd user timers, cron jobs, shell rc additions\n" +
		"- [ ] check for repos or gists published from your accounts around those dates\n")
}

// mdCell keeps a commit subject from breaking out of its table row.
func mdCell(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(truncate(s, 120), "|", "\\|"), "`", "'")
}

// ---- machine formats ----

func writeJSON(path string, r *Report) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// writeSARIF emits the minimum SARIF 2.1.0 a CI viewer needs: one rule per
// advisory, one result per occurrence so each repo/lockfile gets its own row.
func writeSARIF(path string, r *Report) error {
	type sarifRule struct {
		ID               string            `json:"id"`
		Name             string            `json:"name"`
		ShortDescription map[string]string `json:"shortDescription"`
		FullDescription  map[string]string `json:"fullDescription"`
		HelpURI          string            `json:"helpUri"`
		Properties       map[string]any    `json:"properties"`
	}
	type sarifResult struct {
		RuleID    string            `json:"ruleId"`
		Level     string            `json:"level"`
		Message   map[string]string `json:"message"`
		Locations []any             `json:"locations"`
	}

	rules := map[string]sarifRule{}
	var results []sarifResult
	for _, f := range r.Findings {
		if _, ok := rules[f.PrimaryID]; !ok {
			rules[f.PrimaryID] = sarifRule{
				ID:               f.PrimaryID,
				Name:             f.PrimaryID,
				ShortDescription: map[string]string{"text": fmt.Sprintf("%s %s@%s", f.Severity, f.Package, f.Version)},
				FullDescription:  map[string]string{"text": orDash(f.Summary)},
				HelpURI:          f.URL,
				Properties: map[string]any{
					"severity": f.Severity, "malware": f.Malware,
					"tags": []string{"supply-chain", strings.ToLower(f.Severity)},
				},
			}
		}
		level := "warning"
		if f.sev >= sevHigh {
			level = "error"
		}
		for _, o := range f.Occurrences {
			state := "past exposure"
			if o.OnHead {
				state = "still present on HEAD"
			}
			results = append(results, sarifResult{
				RuleID: f.PrimaryID,
				Level:  level,
				Message: map[string]string{"text": fmt.Sprintf("%s@%s (%s) in %s [%s] — %s",
					f.Package, f.Version, f.Ecosystem, o.Repo, o.Source, state)},
				Locations: []any{map[string]any{
					"physicalLocation": map[string]any{
						"artifactLocation": map[string]any{"uri": o.Path},
					},
				}},
			})
		}
	}
	ruleList := make([]sarifRule, 0, len(rules))
	for _, v := range rules {
		ruleList = append(ruleList, v)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })

	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name":           "lockaudit",
				"informationUri": "https://github.com/google/osv-scanner",
				"rules":          ruleList,
			}},
			"results": results,
		}},
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func fmtDate(unix int64) string {
	if unix == 0 {
		return "----------"
	}
	return time.Unix(unix, 0).UTC().Format("2006-01-02")
}
