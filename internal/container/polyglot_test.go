package container

import (
	"context"
	"testing"
	"time"

	"github.com/danczar/binchk/internal/analyze"
)

// TestPolyglotInheritsNoTrust: a notarized image signature (or any
// contained bundle's) must never be credited to a polyglot's report.
func TestPolyglotInheritsNoTrust(t *testing.T) {
	eng, err := analyze.NewEngine(analyze.Options{Budget: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ok := true
	trusted := &analyze.Signature{Present: true, Signer: "Developer ID Application: X (ABCDE12345)", Verified: &ok, Notarized: true}
	for _, poly := range []bool{false, true} {
		r := &analyze.Report{}
		in := newInspector(context.Background(), eng, r, "Apple disk image")
		in.poly = poly
		in.imageSig = trusted
		in.sig = trusted
		in.imageChecked = make(chan struct{})
		close(in.imageChecked)
		in.findings = []analyze.Finding{{ID: "x", Severity: analyze.High}, {ID: "y", Severity: analyze.High}}
		in.finalize(time.Now())
		credited := r.Signature.Verified != nil
		if credited == poly {
			t.Errorf("poly=%v: signature credited=%v (%+v)", poly, credited, r.Signature)
		}
		if poly && r.Verdict != analyze.VerdictMalicious {
			t.Errorf("polyglot verdict %s score=%d", r.Verdict, r.Score)
		}
		if got := in.imageNotarized(); got == poly {
			t.Errorf("poly=%v: imageNotarized=%v", poly, got)
		}
	}
}
