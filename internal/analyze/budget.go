package analyze

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"iter"
)

// Limits on how much attacker-controlled header tables a format analyser
// will walk. Real binaries sit far below them; reaching one is itself an
// anomaly and is reported as such.
const (
	maxSections       = 4096    // section or segment rows analysed per slice
	maxImportDescs    = 4096    // PE import descriptors
	maxImportThunks   = 1 << 16 // PE import thunks, all descriptors together
	maxImportNameLen  = 1024
	maxFatArches      = 8       // Mach-O slices parsed from a universal binary
	maxSigBlobs       = 64      // code-signature SuperBlob index entries
	maxInterpLen      = 4096    // PATH_MAX
	maxVersionEntries = 1 << 16 // ELF symbol version records and aux entries
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

// parserReader returns data as a reader for the standard library parsers
// (debug/buildinfo here) with the header fields that make them do unbounded
// work cleared; see peHeaderReader, fatHeaderReader, machoHeaderReader and
// elfHeaderReader.
func parserReader(data []byte) io.ReaderAt {
	var r io.ReaderAt
	switch {
	case bytes.HasPrefix(data, []byte("MZ")):
		r, _, _ = peHeaderReader(data)
	case bytes.HasPrefix(data, []byte("\xca\xfe\xba\xbe")):
		r, _, _ = fatHeaderReader(data)
	case bytes.HasPrefix(data, []byte("\x7fELF")):
		r, _ = elfHeaderReader(data)
	default:
		r, _ = machoHeaderReader(data)
	}
	return r
}

// patch replaces len(b) bytes of the file at off.
type patch struct {
	off int64
	b   []byte
}

// readerWith serves data with patches laid over it (later ones win). It
// lets the standard library parsers see header tables with the fields that
// would make them do unbounded work cleared, without copying the file.
func readerWith(data []byte, patches []patch) io.ReaderAt {
	if len(patches) == 0 {
		return bytes.NewReader(data)
	}
	return &patchedReader{data, patches}
}

type patchedReader struct {
	data    []byte
	patches []patch
}

func (p *patchedReader) ReadAt(b []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(p.data)) {
		return 0, io.EOF
	}
	n := copy(b, p.data[off:])
	for _, pa := range p.patches {
		if lo, hi := max(off, pa.off), min(off+int64(n), pa.off+int64(len(pa.b))); lo < hi {
			copy(b[lo-off:hi-off], pa.b[lo-pa.off:hi-pa.off])
		}
	}
	if n < len(b) {
		return n, io.EOF
	}
	return n, nil
}

// nameAllowance is how many bytes of string-table lookups a table of n bytes
// may cost. Tail-merged names are read more than once, but crafted tables
// whose entries all point at one long unterminated run cost entries × size.
func nameAllowance(n int) uint64 { return 8*uint64(n) + 1<<20 }

// namesFit charges to *left the bytes debug/elf or debug/macho read when
// looking up the NUL-terminated name at each offset in tab, and reports
// whether that stayed within *left.
func namesFit(tab []byte, offs iter.Seq[uint64], left *uint64) bool {
	for off := range offs {
		if off >= uint64(len(tab)) {
			continue
		}
		b := tab[off:min(off+*left, uint64(len(tab)))]
		n := bytes.IndexByte(b, 0)
		if n < 0 {
			n = len(b)
		}
		if cost := uint64(n) + 1; cost <= *left {
			*left -= cost
		} else {
			return false
		}
	}
	return true
}

// nameOffsets yields the uint32 at the start of each stride-byte entry in
// b: st_name, sh_name and n_strx all sit there.
func nameOffsets(b []byte, stride int, bo binary.ByteOrder) iter.Seq[uint64] {
	return func(yield func(uint64) bool) {
		for ; len(b) >= stride && stride >= 4; b = b[stride:] {
			if !yield(uint64(bo.Uint32(b))) {
				return
			}
		}
	}
}
