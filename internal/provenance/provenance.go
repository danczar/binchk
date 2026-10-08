// Package provenance reads where a downloaded file came from, using the
// metadata browsers attach: com.apple.quarantine / kMDItemWhereFroms on
// macOS, user.xdg.origin.url on Linux, the Zone.Identifier stream on Windows.
package provenance

import "github.com/danczar/binchk/internal/analyze"

// Read never fails; missing metadata just yields an empty Provenance.
func Read(path string) analyze.Provenance { return read(path) }
