package analyze

import "github.com/danczar/binchk/internal/detect"

// IsBundle reports whether r is the analysis of an app bundle.
func (r *Report) IsBundle() bool { return r.Format == string(detect.AppBundle) }

// ContentKey is the hash that identifies what was analysed, for the
// allowlist and the report index: a file's SHA-256, or an app bundle's
// fingerprint. A bundle is never keyed by its main executable alone, since
// other bundles can reuse it unchanged. Empty when it is unknown.
func (r *Report) ContentKey() string {
	if r.IsBundle() {
		return r.Hashes.Bundle
	}
	return r.Hashes.SHA256
}
