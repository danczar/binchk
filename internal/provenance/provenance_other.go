//go:build !darwin && !linux && !windows

package provenance

import "github.com/danczar/binchk/internal/analyze"

func read(path string) analyze.Provenance { return analyze.Provenance{} }
