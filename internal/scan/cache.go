package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// cache memoises one osv-scanner result per distinct lockfile CONTENT.
//
// The key is the content hash, not the file path: the same package-lock.json
// shared by forty commits, three repos and both sources is scanned once, ever.
// That is the whole reason a full-history scan is affordable.
//
// It is a directory tree rather than SQLite on purpose: no cgo dependency, no
// single writer goroutine to funnel every worker through, no lock. Each result
// is written to a temp file and renamed, which is atomic on any sane
// filesystem — an interrupted run can never leave a half-written result that a
// later run would trust. That atomic rename IS the resume mechanism.
type cache struct {
	root      string // <cacheDir>/results
	dbVersion string
}

// dbFingerprint identifies the OSV database contents. It is part of the cache
// path, so refreshing the databases invalidates every entry automatically.
// Without this a "clean" verdict from last week would keep hiding an advisory
// published since — the exact failure mode a vulnerability cache must not have.
func dbFingerprint(osvCacheDir string) string {
	h := sha256.New()
	var lines []string
	_ = filepath.WalkDir(osvCacheDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(osvCacheDir, p)
		lines = append(lines, fmt.Sprintf("%s %d %d", rel, info.Size(), info.ModTime().Unix()))
		return nil
	})
	if len(lines) == 0 {
		return "" // databases not downloaded yet
	}
	sort.Strings(lines)
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func newCache(cacheDir, dbVersion string) (*cache, error) {
	if dbVersion == "" {
		dbVersion = "nodb"
	}
	c := &cache{root: filepath.Join(cacheDir, "results"), dbVersion: dbVersion}
	return c, os.MkdirAll(filepath.Join(c.root, dbVersion), 0o755)
}

func (c *cache) path(hash, filename string) string {
	prefix := hash
	if i := strings.IndexByte(prefix, ':'); i >= 0 { // "sha256:abc..."
		prefix = prefix[i+1:]
	}
	if len(prefix) < 2 {
		prefix = "00" + prefix
	}
	safe := strings.ReplaceAll(filename, string(os.PathSeparator), "_")
	return filepath.Join(c.root, c.dbVersion, prefix[:2],
		strings.ReplaceAll(hash, ":", "_")+"-"+safe+".json")
}

func (c *cache) has(hash, filename string) bool {
	_, err := os.Stat(c.path(hash, filename))
	return err == nil
}

func (c *cache) get(hash, filename string) (*blobResult, bool) {
	data, err := os.ReadFile(c.path(hash, filename))
	if err != nil {
		return nil, false
	}
	var r blobResult
	if json.Unmarshal(data, &r) != nil {
		return nil, false
	}
	return &r, true
}

func (c *cache) put(hash, filename string, r *blobResult) error {
	p := c.path(hash, filename)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), p)
}

// prune drops result trees from superseded database versions. They can never be
// read again — the version is in the path — so keeping them is pure disk rot.
// A week of grace in case of a database rollback.
func (c *cache) prune(maxAge time.Duration) {
	entries, err := os.ReadDir(c.root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || e.Name() == c.dbVersion {
			continue
		}
		info, err := e.Info()
		if err != nil || time.Since(info.ModTime()) < maxAge {
			continue
		}
		slog.Debug("pruning stale cache generation", "db_version", e.Name())
		os.RemoveAll(filepath.Join(c.root, e.Name()))
	}
}
