package analyze

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The allowlist matches what vouches for every byte of the item: a file's
// SHA-256, or a bundle's contents digest, never the bundle's main
// executable or its (size-only) fingerprint.
func TestAllowlistTrustKey(t *testing.T) {
	mainSHA := strings.Repeat("a", 64)
	fp := strings.Repeat("b", 64)
	contents := strings.Repeat("c", 64)
	list := filepath.Join(t.TempDir(), "allow.txt")
	os.WriteFile(list, []byte(mainSHA+" main executable\n"+fp+" fingerprint\n"), 0o644)
	allow := LoadHashList(list)
	crit := []Finding{{ID: "hash-blocklist", Severity: Critical}}

	bundle := &Report{Format: "Application bundle", Hashes: Hashes{SHA256: mainSHA, Bundle: fp, BundleContents: contents}, Findings: crit}
	if bundle.ContentKey() != fp || bundle.TrustKey() != contents || !bundle.IsBundle() {
		t.Fatalf("bundle keys %q %q", bundle.ContentKey(), bundle.TrustKey())
	}
	applyScore(bundle, 60, allow)
	if bundle.Verdict != VerdictMalicious {
		t.Fatalf("bundle allowlisted by its main executable or fingerprint: %s", bundle.Verdict)
	}
	// Without a fingerprint or a contents digest a bundle has no key at all.
	nokey := &Report{Format: "Application bundle", Hashes: Hashes{SHA256: mainSHA}}
	if nokey.ContentKey() != "" || nokey.TrustKey() != "" {
		t.Fatal("bundle keyed by its main executable")
	}

	allow.Add(contents, "the bundle")
	bundle = &Report{Format: "Application bundle", Hashes: Hashes{SHA256: mainSHA, Bundle: fp, BundleContents: contents}, Findings: crit}
	applyScore(bundle, 60, allow)
	if bundle.Verdict != VerdictClean || bundle.Findings[0].Title != "This app bundle is on your allowlist" {
		t.Fatalf("allowlisted bundle: %s %+v", bundle.Verdict, bundle.Findings)
	}
	// The same fingerprint with other contents is not trusted.
	other := &Report{Format: "Application bundle", Hashes: Hashes{SHA256: mainSHA, Bundle: fp, BundleContents: strings.Repeat("d", 64)}, Findings: crit}
	applyScore(other, 60, allow)
	if other.Verdict != VerdictMalicious {
		t.Fatalf("same fingerprint, other contents: %s", other.Verdict)
	}

	file := &Report{Format: "Mach-O", Hashes: Hashes{SHA256: mainSHA}, Findings: crit}
	applyScore(file, 60, allow)
	if file.ContentKey() != mainSHA || file.TrustKey() != mainSHA || file.Verdict != VerdictClean {
		t.Fatalf("allowlisted file: %s", file.Verdict)
	}
}
