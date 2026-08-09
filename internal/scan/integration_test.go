package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMalwareControl is the end-to-end proof: a package with a real MAL-
// advisory, committed and then removed, must come back as MALWARE and as past
// exposure — through the deduplicated path, purls and all.
//
// It needs the osv-scanner binary and a populated npm database, so it is opt-in
// rather than part of `go test ./...`:
//
//	LOCKAUDIT_INTEGRATION=1 go test ./internal/scan -run TestMalwareControl -v
//
// Nothing is installed and nothing is executed. The control is a text file that
// names a package version; the point of this tool is that naming it in history
// is already the finding.
func TestMalwareControl(t *testing.T) {
	if os.Getenv("LOCKAUDIT_INTEGRATION") == "" {
		t.Skip("set LOCKAUDIT_INTEGRATION=1 (needs osv-scanner and the npm database)")
	}
	bin := envOr("OSV_SCANNER_BIN", "osv-scanner")
	if _, err := checkOsvScanner(bin); err != nil {
		t.Skipf("osv-scanner unavailable: %v", err)
	}

	// MAL-2022-1122, taken from the local npm database itself.
	const pkg, version = "arpan-package", "2.0.5"
	const advisory = "MAL-2022-1122"

	tmp := t.TempDir()
	lock := func(name, ver string) string {
		return `{"name":"ctl","lockfileVersion":3,"packages":{"":{"name":"ctl"},` +
			`"node_modules/` + name + `":{"version":"` + ver + `"}}}`
	}
	p := filepath.Join(tmp, "package-lock.json")
	if err := os.WriteFile(p, []byte(lock(pkg, version)), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	sc := &scanner{bin: bin}

	// Read the packages out without loading a database...
	inv, bad, err := sc.inventory(ctx, []string{p})
	if err != nil || len(bad) > 0 {
		t.Fatalf("inventory: %v, unparseable=%v", err, bad)
	}
	want := pkgID{"npm", pkg, version}
	if len(inv[p]) != 1 || inv[p][0] != want {
		t.Fatalf("inventory = %v, want exactly %v", inv[p], want)
	}

	// ...make sure the database is there, then match by purl.
	if failed, _ := sc.ensureDatabases(ctx, []string{"npm"}, tmp, false, map[string]bool{}); len(failed) > 0 {
		t.Skipf("no npm database available: %v", failed)
	}
	matched, lost, err := sc.matchPurls(ctx, inv[p], tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(lost) > 0 {
		t.Fatalf("purl did not round-trip: %v", lost)
	}
	sp := matched[want]
	if sp == nil || len(sp.Groups) == 0 {
		t.Fatalf("%s@%s came back clean; %s should have flagged it", pkg, version, advisory)
	}

	// And it has to survive classification as MALWARE, not as a plain finding.
	registry := map[blobKey]*blobInfo{
		{Hash: "h", Filename: "package-lock.json"}: {Occ: map[string]*Occurrence{
			"local|repo|package-lock.json": {Source: "local", Repo: "repo", Path: "package-lock.json"},
		}},
	}
	results := map[blobKey]*blobResult{
		{Hash: "h", Filename: "package-lock.json"}: {Packages: []scannedPackage{*sp}},
	}
	findings := buildFindings(registry, results, sevMalware)
	if len(findings) == 0 {
		t.Fatal("a MAL- advisory did not survive the MALWARE threshold")
	}
	f := findings[0]
	if !f.Malware || f.Package != pkg {
		t.Errorf("finding = %+v, want malware for %s", f, pkg)
	}
	if !strings.Contains(strings.Join(f.IDs, ","), advisory) {
		t.Errorf("finding IDs %v do not mention %s", f.IDs, advisory)
	}
	// Removed from HEAD in a later commit, so it is past exposure, not current.
	if f.Current {
		t.Error("a package absent from HEAD must not be reported as current exposure")
	}
}
