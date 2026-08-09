package scan

import (
	"context"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// normalizeRemote turns any git remote URL into a stable identity key so a repo
// found on disk can be recognised as the same thing the GitLab API listed.
//
//	git@gitlab.com:grp/proj.git
//	https://GitLab.com/grp/proj.git/
//	ssh://git@gitlab.com:2222/grp/proj
//	https://oauth2:TOKEN@gitlab.com/grp/proj
//
// all collapse to "gitlab.com/grp/proj". Returns "" for local paths, which are
// identified by their filesystem path instead.
func normalizeRemote(raw string) string {
	s := strings.TrimSpace(raw)
	// A filesystem path is a remote too (git clone /some/repo), but it has no
	// host, so it can never identify the same project as a GitLab URL.
	if s == "" || strings.HasPrefix(s, "/") || strings.HasPrefix(s, ".") || strings.HasPrefix(s, "~") {
		return ""
	}
	for _, p := range []string{"ssh://", "git://", "https://", "http://", "git+ssh://"} {
		s = strings.TrimPrefix(s, p)
	}
	// credentials / user part
	if i := strings.LastIndex(s, "@"); i >= 0 && i < len(s)-1 {
		s = s[i+1:]
	}
	// scp-style "host:path" -> "host/path"; also strips ":2222" ssh ports
	if i := strings.IndexByte(s, ':'); i >= 0 {
		rest := s[i+1:]
		host := s[:i]
		if j := strings.IndexByte(rest, '/'); j >= 0 && isAllDigits(rest[:j]) {
			rest = rest[j+1:] // it was a port
		}
		s = host + "/" + strings.TrimPrefix(rest, "/")
	}
	if !strings.Contains(s, "/") {
		return "" // local path or nonsense
	}
	s = strings.TrimSuffix(strings.TrimSuffix(strings.TrimRight(s, "/"), ".git"), "/")
	return strings.ToLower(s)
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// localRepo is a git repository found on disk.
type localRepo struct {
	Path string
	Keys []string // normalised remotes
}

// findLocalRepos walks the roots looking for repositories AND for lockfiles
// that belong to no repository at all.
//
// The loose ones matter: a directory someone unpacked, ran `npm install` in and
// never put under version control is exactly where a compromised dependency
// hides with no trace. They have no history, so they can only ever show current
// exposure.
//
// Nested repos are kept (a repo checked out inside another is a real case
// here), but vendored dependency trees are pruned — walking node_modules is
// most of the wall clock of a naive walk and can only find third-party copies.
func findLocalRepos(ctx context.Context, roots []string, excl *excluder) ([]localRepo, []string, []string) {
	var repos []localRepo
	var loose []string
	var excluded []string
	seen := map[string]bool{}

	for _, root := range roots {
		abs, err := filepath.Abs(expandHome(root))
		if err != nil {
			slog.Warn("bad local root", "root", root, "err", err)
			continue
		}
		err = filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				slog.Debug("walk error", "path", p, "err", err)
				return nil // unreadable dir must not abort the whole walk
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !d.IsDir() {
				if isLockfile(p) && !skipPath(p) && !excl.match(filepath.Dir(p)) {
					loose = append(loose, p)
				}
				return nil
			}
			name := d.Name()
			if name == "node_modules" || name == "vendor" || name == ".venv" ||
				name == "venv" || name == "bower_components" {
				return fs.SkipDir
			}
			if name != ".git" {
				return nil
			}
			repo := filepath.Dir(p)
			if seen[repo] {
				return fs.SkipDir
			}
			seen[repo] = true
			if excl.match(repo) {
				excluded = append(excluded, repo)
				return fs.SkipDir
			}
			repos = append(repos, localRepo{Path: repo, Keys: remoteKeys(ctx, repo)})
			return fs.SkipDir // nothing of interest inside .git itself
		})
		if err != nil {
			slog.Warn("walk aborted", "root", abs, "err", err)
		}
	}
	sort.Slice(repos, func(i, j int) bool { return repos[i].Path < repos[j].Path })
	sort.Strings(excluded)

	// A lockfile inside a repository is already covered by that repository's
	// history walk, which knows strictly more (every past version, not just the
	// current one). Only what belongs to no repo is scanned as a loose file.
	kept := loose[:0]
	for _, f := range loose {
		if !underAny(f, repos) {
			kept = append(kept, f)
		}
	}
	sort.Strings(kept)
	return repos, kept, excluded
}

func underAny(file string, repos []localRepo) bool {
	for _, r := range repos {
		if strings.HasPrefix(file, r.Path+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// excluder matches a repo path against user globs. A glob is tested against the
// path and each of its parents, so a glob naming a directory excludes
// everything under it without the user having to write "/**".
type excluder struct{ globs []string }

func newExcluder(globs []string) *excluder {
	e := &excluder{}
	for _, g := range globs {
		if g = strings.TrimSpace(expandHome(g)); g != "" {
			e.globs = append(e.globs, strings.TrimRight(g, "/"))
		}
	}
	return e
}

func (e *excluder) add(g string) {
	if g = strings.TrimSpace(expandHome(g)); g != "" {
		e.globs = append(e.globs, strings.TrimRight(g, "/"))
	}
}

// matchName applies the globs to a forge project path ("group/sub/project").
//
// Deliberately not match(): a project name is not a filesystem path, and
// running it through filepath.Abs resolved it against the working directory.
// Since lockaudit excludes its own directory and is normally run from inside
// it, "<group>/<project>" became "<lockaudit dir>/<group>/<project>", whose
// parent walk hit the self-exclusion — silently excluding every GitLab and
// GitHub project on the forge.
// A glob may be scoped to one forge with a "gitlab:" or "github:" prefix —
// the exact form the report and --dry-run print, so an entry can be copied
// straight out of the output into EXCLUDE_PATHS.
func (e *excluder) matchName(source, name string) bool {
	for _, g := range e.globs {
		if src, rest, ok := strings.Cut(g, ":"); ok && (src == "gitlab" || src == "github") {
			if src != source {
				continue
			}
			g = strings.TrimRight(rest, "/")
		}
		if g == "" {
			continue
		}
		// Each parent group too, so "org" or "org/team" excludes everything
		// beneath it without writing "/**".
		for p := strings.Trim(name, "/"); p != ""; {
			if g == p {
				return true
			}
			if ok, _ := path.Match(g, p); ok {
				return true
			}
			i := strings.LastIndex(p, "/")
			if i < 0 {
				break
			}
			p = p[:i]
		}
	}
	return false
}

// match applies the globs to a filesystem path and to each of its parents, so
// excluding a directory excludes everything below it.
func (e *excluder) match(p string) bool {
	abs, err := filepath.Abs(p)
	if err != nil {
		abs = p
	}
	for p := abs; ; p = filepath.Dir(p) {
		for _, g := range e.globs {
			if g == p {
				return true
			}
			if ok, _ := filepath.Match(g, p); ok {
				return true
			}
		}
		if parent := filepath.Dir(p); parent != p {
			continue
		}
		return false
	}
}

// selfRepoPath finds the repository this binary was built from, so the tool
// never reports on itself. It lives under the user's scanned roots, and a
// finding about our own fixtures would be pure noise. Belt and braces with the
// EXCLUDE_PATHS entry: this keeps holding if the .env is rewritten.
func selfRepoPath() string {
	var cands []string
	if exe, err := os.Executable(); err == nil {
		cands = append(cands, filepath.Dir(exe))
	}
	if wd, err := os.Getwd(); err == nil {
		cands = append(cands, wd)
	}
	for _, start := range cands {
		for p := start; ; p = filepath.Dir(p) {
			if _, err := os.Stat(filepath.Join(p, "go.mod")); err == nil {
				if _, err := os.Stat(filepath.Join(p, ".git")); err == nil {
					return p
				}
			}
			if parent := filepath.Dir(p); parent != p {
				continue
			}
			break
		}
	}
	return ""
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, p[2:])
		}
	}
	return p
}
