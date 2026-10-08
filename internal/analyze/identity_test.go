package analyze

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The allowlist matches what identifies the item: a file's SHA-256, or a
// bundle's fingerprint, never the bundle's main executable.
func TestAllowlistContentKey(t *testing.T) {
	mainSHA := strings.Repeat("a", 64)
	fp := strings.Repeat("b", 64)
	list := filepath.Join(t.TempDir(), "allow.txt")
	os.WriteFile(list, []byte(mainSHA+" main executable\n"), 0o644)
	allow := LoadHashList(list)
	crit := []Finding{{ID: "hash-blocklist", Severity: Critical}}

	bundle := &Report{Format: "Application bundle", Hashes: Hashes{SHA256: mainSHA, Bundle: fp}, Findings: crit}
	if bundle.ContentKey() != fp || !bundle.IsBundle() {
		t.Fatalf("bundle content key %q", bundle.ContentKey())
	}
	applyScore(bundle, 60, allow)
	if bundle.Verdict != VerdictMalicious {
		t.Fatalf("bundle allowlisted by its main executable: %s", bundle.Verdict)
	}
	// Without a fingerprint a bundle has no key at all.
	if (&Report{Format: "Application bundle", Hashes: Hashes{SHA256: mainSHA}}).ContentKey() != "" {
		t.Fatal("bundle keyed by its main executable")
	}

	allow.Add(fp, "the bundle")
	bundle = &Report{Format: "Application bundle", Hashes: Hashes{SHA256: mainSHA, Bundle: fp}, Findings: crit}
	applyScore(bundle, 60, allow)
	if bundle.Verdict != VerdictClean || bundle.Findings[0].Title != "This app bundle is on your allowlist" {
		t.Fatalf("allowlisted bundle: %s %+v", bundle.Verdict, bundle.Findings)
	}

	file := &Report{Format: "Mach-O", Hashes: Hashes{SHA256: mainSHA}, Findings: crit}
	applyScore(file, 60, allow)
	if file.ContentKey() != mainSHA || file.Verdict != VerdictClean {
		t.Fatalf("allowlisted file: %s", file.Verdict)
	}
}
