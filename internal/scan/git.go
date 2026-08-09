package scan

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// defaultLockfilePatterns are git pathspecs, one per filename osv-scanner
// knows how to extract (list taken from its supported-lockfiles documentation
// — the binary offers no way to enumerate its extractors, so this list is ours
// to keep in sync; LOCKFILE_PATTERNS in the config overrides it without a
// rebuild when a new ecosystem lands).
//
// A leading '*' makes git match the name at any depth (its default pathspec
// matching is fnmatch without FNM_PATHNAME), so one pattern covers both
// `package-lock.json` and `sub/dir/package-lock.json`.
//
// We never parse any of these ourselves: osv-scanner picks the extractor from
// the basename, which is why blobs are materialised under their original name.
var defaultLockfilePatterns = []string{
	// JavaScript
	"*package-lock.json", "*yarn.lock", "*pnpm-lock.yaml", "*bun.lock",
	// PHP / Rust / Go / Dart / Elixir / C++ / R
	"*composer.lock", "*Cargo.lock", "*go.mod", "*pubspec.lock", "*mix.lock",
	"*conan.lock", "*renv.lock",
	// Python
	"*requirements*.txt", "*poetry.lock", "*Pipfile.lock", "*uv.lock", "*pdm.lock",
	"*pylock.toml",
	// Ruby
	"*Gemfile.lock", "*gems.locked",
	// Java
	"*pom.xml", "*gradle.lockfile", "*buildscript-gradle.lockfile",
	"*gradle/verification-metadata.xml",
	// .NET
	"*packages.lock.json", "*packages.config", "*deps.json",
	// Haskell
	"*cabal.project.freeze", "*stack.yaml.lock",
}

// lockfilePatterns is what the current run uses; main may replace it from config.
var lockfilePatterns = defaultLockfilePatterns

// skipDirs are path components that mean "vendored copy of someone else's
// dependency tree". A package-lock.json under node_modules/ is a transitive
// artefact, not a project manifest: scanning it multiplies work without adding
// a single distinct finding.
var skipDirs = []string{"node_modules/", "vendor/", ".venv/", "venv/", "bower_components/", "third_party/"}

// globMatch implements the subset of pathspec matching we rely on: '*' matches
// anything, slashes included. That is what git does for a pathspec without
// FNM_PATHNAME, so `*package-lock.json` matches at any depth. `ls-tree` takes
// no pathspec of that flavour, so we filter its output ourselves — otherwise
// every README and Dockerfile on HEAD gets treated as a lockfile.
func globMatch(pattern, s string) bool {
	star, sIdx, pIdx, match := -1, 0, 0, 0
	for sIdx < len(s) {
		switch {
		case pIdx < len(pattern) && pattern[pIdx] == s[sIdx]:
			pIdx++
			sIdx++
		case pIdx < len(pattern) && pattern[pIdx] == '*':
			star, match = pIdx, sIdx
			pIdx++
		case star >= 0:
			pIdx = star + 1
			match++
			sIdx = match
		default:
			return false
		}
	}
	for pIdx < len(pattern) && pattern[pIdx] == '*' {
		pIdx++
	}
	return pIdx == len(pattern)
}

func isLockfile(path string) bool {
	for _, pat := range lockfilePatterns {
		if globMatch(pat, path) {
			return true
		}
	}
	return false
}

func skipPath(p string) bool {
	q := "/" + p
	for _, d := range skipDirs {
		if strings.Contains(q, "/"+d) {
			return true
		}
	}
	return false
}

// gitCmd builds a git invocation that cannot be influenced by the repo it reads
// and cannot prompt: safe.directory sidesteps ownership refusals on repos owned
// by another uid, and the terminal prompt is disabled so a repo needing
// credentials fails fast instead of hanging the pipeline forever.
func gitCmd(ctx context.Context, dir string, args ...string) *exec.Cmd {
	full := []string{"-c", "safe.directory=*", "-c", "core.fsmonitor=false"}
	if dir != "" {
		full = append(full, "-C", dir)
	}
	cmd := exec.CommandContext(ctx, "git", append(full, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=", "GCM_INTERACTIVE=never")
	return cmd
}

func runGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := gitCmd(ctx, dir, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

// remoteKeys returns the normalised keys of every remote URL of a repo.
func remoteKeys(ctx context.Context, dir string) []string {
	out, err := runGit(ctx, dir, "remote", "-v")
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var keys []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if k := normalizeRemote(f[1]); k != "" && !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	return keys
}

// extraRefspecs fetch the branches behind merge/pull requests. They are off by
// default: on a repo you merely contribute to, they are thousands of other
// people's branches you never installed. Turn them on when you want the
// branches you opened and then deleted to count as exposure too.
var extraRefspecs = []string{
	"+refs/merge-requests/*/head:refs/merge-requests/*/head", // GitLab
	"+refs/pull/*/head:refs/pull/*/head",                     // GitHub
}

// cloneOrFetchBare materialises a remote project into the cache. Bare: we only
// ever read history, a worktree would be pure disk cost. `reference` points at
// an existing local clone of the same remote when we found one — the network
// then transfers only the objects that copy lacks. --dissociate copies the
// borrowed objects in, so the cache stays valid if that local clone is deleted.
//
// The refspec is explicit: every branch, not just the default one.
func cloneOrFetchBare(ctx context.Context, cloneURL, dest, reference string, allRefs bool) error {
	refspecs := []string{"+refs/heads/*:refs/heads/*"}
	if allRefs {
		refspecs = append(refspecs, extraRefspecs...)
	}
	if _, err := os.Stat(filepath.Join(dest, "HEAD")); err == nil {
		args := append([]string{"fetch", "--quiet", "--prune", "--tags", "origin"}, refspecs...)
		_, err := runGit(ctx, dest, args...)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	args := []string{"clone", "--bare", "--quiet"}
	if reference != "" {
		args = append(args, "--reference-if-able", reference, "--dissociate")
	}
	args = append(args, cloneURL, dest)
	if _, err := runGit(ctx, "", args...); err != nil {
		os.RemoveAll(dest) // a half-written bare clone would be treated as usable next run
		return err
	}
	if allRefs {
		args := append([]string{"fetch", "--quiet", "origin"}, extraRefspecs...)
		if _, err := runGit(ctx, dest, args...); err != nil {
			slog.Debug("merge/pull request refs unavailable", "dest", dest)
		}
	}
	return nil
}

// blobOccurrence is one (blob, path) pair seen in one commit.
type blobOccurrence struct {
	Hash   string
	Path   string
	Commit Commit
}

// historyBlobs walks the whole reachable history once and returns every
// distinct version of every lockfile, with the commits that carried it.
//
// The single `git log --all --raw` does the heavy lifting: its `:mode mode
// oldsha newsha STATUS\tpath` lines already contain the blob SHA, so we never
// need a `ls-tree` per commit. One process per repo, streamed.
//
// --all covers every branch, remote-tracking branch and tag, not just the
// default branch. --reflog adds commits that are no longer reachable from any
// ref — the lockfile you rebased or amended away still ran an install when it
// existed, so it counts as exposure. Bare clones have no reflog, which makes it
// a no-op there.
func historyBlobs(ctx context.Context, dir string) ([]blobOccurrence, error) {
	args := []string{"log", "--all", "--reflog", "--no-abbrev", "--raw", "--no-renames",
		"--format=%x00%H%x1f%ct%x1f%an%x1f%s", "--"}
	args = append(args, lockfilePatterns...)

	cmd := gitCmd(ctx, dir, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var out []blobOccurrence
	var cur Commit
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // long subjects / long paths
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "\x00") {
			f := strings.SplitN(line[1:], "\x1f", 4)
			if len(f) == 4 {
				ts, _ := strconv.ParseInt(f[1], 10, 64)
				cur = Commit{SHA: f[0], Unix: ts, Author: f[2], Subject: f[3]}
			}
			continue
		}
		if !strings.HasPrefix(line, ":") {
			continue
		}
		// ":100644 100644 <old> <new> M\tpath"
		tab := strings.IndexByte(line, '\t')
		if tab < 0 {
			continue
		}
		meta := strings.Fields(line[:tab])
		if len(meta) < 5 {
			continue
		}
		newSHA := meta[3]
		if isZeroSHA(newSHA) { // deletion
			continue
		}
		path := line[tab+1:]
		if skipPath(path) {
			continue
		}
		out = append(out, blobOccurrence{Hash: newSHA, Path: path, Commit: cur})
	}
	io.Copy(io.Discard, stdout)
	if err := cmd.Wait(); err != nil {
		return out, fmt.Errorf("git log: %w: %s", err, strings.TrimSpace(errb.String()))
	}
	return out, sc.Err()
}

func isZeroSHA(s string) bool { return strings.Trim(s, "0") == "" }

// headBlobs returns the blobs present on the current tip — those are "still
// exposed today", everything else is "was exposed at some point".
func headBlobs(ctx context.Context, dir, ref string) map[string]string {
	if ref == "" {
		ref = "HEAD"
	}
	out, err := runGit(ctx, dir, "ls-tree", "-r", ref)
	if err != nil {
		return nil
	}
	res := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		tab := strings.IndexByte(line, '\t')
		if tab < 0 {
			continue
		}
		f := strings.Fields(line[:tab])
		if len(f) < 3 || f[1] != "blob" {
			continue
		}
		path := line[tab+1:]
		if skipPath(path) || !isLockfile(path) {
			continue
		}
		res[f[2]] = path
	}
	return res
}

// catFileBatch writes the requested blobs to disk using ONE long-lived git
// process for the whole repo. The alternative — `git cat-file blob <sha>` per
// blob — costs one fork+exec per blob, which at ~10k blobs dominates the run.
//
// Protocol: one SHA per line on stdin, git answers "<sha> blob <size>\n" then
// <size> raw bytes then "\n". A missing object answers "<sha> missing\n".
func catFileBatch(ctx context.Context, dir string, hashes []string, dst func(hash string, data []byte) error) error {
	if len(hashes) == 0 {
		return nil
	}
	cmd := gitCmd(ctx, dir, "cat-file", "--batch")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		w := bufio.NewWriter(stdin)
		for _, h := range hashes {
			fmt.Fprintln(w, h)
		}
		w.Flush()
		stdin.Close()
	}()

	r := bufio.NewReaderSize(stdout, 256*1024)
	var firstErr error
	for range hashes {
		header, err := r.ReadString('\n')
		if err != nil {
			break
		}
		f := strings.Fields(header)
		if len(f) < 3 { // "<sha> missing"
			continue
		}
		size, err := strconv.Atoi(f[2])
		if err != nil {
			break
		}
		buf := make([]byte, size)
		if _, err := io.ReadFull(r, buf); err != nil {
			break
		}
		r.ReadByte() // trailing newline
		if err := dst(f[0], buf); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	io.Copy(io.Discard, stdout)
	cmd.Wait()
	return firstErr
}
