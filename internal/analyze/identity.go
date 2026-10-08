package analyze

import "github.com/danczar/binchk/internal/detect"

// IsBundle reports whether r is the analysis of an app bundle.
func (r *Report) IsBundle() bool { return r.Format == string(detect.AppBundle) }

// ContentKey is the hash that identifies what was analysed in the report
// index: a file's SHA-256, or an app bundle's fingerprint. A bundle is
// never keyed by its main executable alone, since other bundles can reuse
// it unchanged. Empty when it is unknown.
func (r *Report) ContentKey() string {
	if r.IsBundle() {
		return r.Hashes.Bundle
	}
	return r.Hashes.SHA256
}

// TrustKey is the hash the allowlist and Mark as safe use: a file's
// SHA-256, or an app bundle's contents digest, which covers every byte of
// every file in it. The fingerprint is not enough for trust: it records
// nested files' sizes only. Empty when it is unknown (a bundle too large
// to read in time), and then nothing allowlists the item.
func (r *Report) TrustKey() string {
	if r.IsBundle() {
		return r.Hashes.BundleContents
	}
	return r.Hashes.SHA256
}
