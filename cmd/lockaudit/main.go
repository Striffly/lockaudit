// Command lockaudit audits every lockfile version that ever existed in
// your projects against the OSV vulnerability and malware databases, so a
// dependency that was compromised at some point in the past still shows up even
// though today's lockfile is clean.
//
// The command is deliberately thin: everything lives in internal/scan so it can
// be tested without a process boundary.
package main

import (
	"os"

	"lockaudit/internal/scan"
)

func main() {
	os.Exit(scan.Run())
}
