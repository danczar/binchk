package analyze

import (
	"context"
	"fmt"
)

// Limits on how much attacker-controlled header tables a format analyser
// will walk. Real binaries sit far below them; reaching one is itself an
// anomaly and is reported as such.
const (
	maxSections      = 4096    // section or segment rows analysed per slice
	maxImportDescs   = 4096    // PE import descriptors
	maxImportThunks  = 1 << 16 // PE import thunks, all descriptors together
	maxImportNameLen = 1024
)

// fmtBudget bounds the work of one format analysis: ctx carries the engine
// deadline and left is how many more bytes entropy may hash. Section and
// segment ranges can overlap arbitrarily, so without the allowance a few
// thousand headers covering the same megabytes cost sections × size.
type fmtBudget struct {
	ctx    context.Context
	left   uint64
	capped bool // the allowance ran out and some ranges got no entropy
}

func newFmtBudget(ctx context.Context, size int) *fmtBudget {
	// Segments plus the sections inside them cover a normal file about twice.
	return &fmtBudget{ctx: ctx, left: 3*uint64(size) + 1<<20}
}

// entropy is entropyOf(b) charged against the allowance. Once that is spent
// it returns 0; once the deadline passes it returns the context's error.
func (bu *fmtBudget) entropy(b []byte) (float64, error) {
	if err := bu.ctx.Err(); err != nil {
		return 0, err
	}
	if uint64(len(b)) > bu.left {
		bu.capped = true
		return 0, nil
	}
	bu.left -= uint64(len(b))
	var h [256]uint64
	for off := 0; off < len(b); off += 1 << 20 {
		if err := bu.ctx.Err(); err != nil {
			return 0, err
		}
		histogram(b[off:min(off+1<<20, len(b))], &h)
	}
	return entropy(&h, uint64(len(b))), nil
}

// finish reports the limits this analysis ran into.
func (bu *fmtBudget) finish(res *formatResult, sections int) {
	if bu.capped {
		res.findings = append(res.findings, Finding{ID: "overlapping-sections", Title: "Section headers overlap heavily",
			Detail:   "Section and segment headers describe far more data than the file holds. Compilers never do this; it is a trick to stall analysis tools.",
			Severity: Medium, Category: "structure"})
	}
	if sections > maxSections {
		res.findings = append(res.findings, Finding{ID: "excess-sections", Title: "Unusually many section headers",
			Detail:   "Only the first entries were analysed.",
			Severity: Low, Category: "structure", Evidence: []string{fmt.Sprintf("%d headers", sections)}})
	}
}
