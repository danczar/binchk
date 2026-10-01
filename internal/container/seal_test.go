package container

import (
	"context"
	"testing"
	"time"

	"github.com/danczar/binchk/internal/analyze"
)

func TestSealTrusted(t *testing.T) {
	yes, no := true, false
	dev := analyze.Signature{Signer: "Developer ID Application: Example (ABCDE12345)", TeamID: "ABCDE12345"}
	with := func(mod func(s *analyze.Signature)) analyze.Signature {
		s := dev
		mod(&s)
		return s
	}
	cases := []struct {
		name     string
		sealOK   *bool
		unsigned bool
		covered  bool
		sig      analyze.Signature
		want     bool
	}{
		{"verified developer seal", &yes, false, false, dev, true},
		{"gatekeeper accepted", &yes, false, false, with(func(s *analyze.Signature) { s.Gatekeeper = "accepted — Notarized Developer ID" }), true},
		{"notarized image", nil, false, true, analyze.Signature{}, true},
		{"seal not checked (error or budget)", nil, false, false, dev, false},
		{"seal broken", &no, false, false, dev, false},
		{"unsigned", &no, true, false, analyze.Signature{}, false},
		{"ad-hoc seal", &yes, false, false, analyze.Signature{AdHoc: true}, false},
		{"no signer (codesign -dvv failed)", &yes, false, false, analyze.Signature{}, false},
		{"gatekeeper rejected", &yes, false, false, with(func(s *analyze.Signature) { s.Gatekeeper = "rejected — Unnotarized Developer ID" }), false},
		{"certificate revoked", &yes, false, false, with(func(s *analyze.Signature) { s.Gatekeeper = "rejected — certificate revoked" }), false},
	}
	for _, c := range cases {
		if got := sealTrusted(c.sealOK, c.unsigned, c.covered, c.sig); got != c.want {
			t.Errorf("%s: sealTrusted = %v, want %v", c.name, got, c.want)
		}
	}
}

// Files held back for a bundle's seal keep their findings unless the seal
// is trusted, and are recorded (and lifted) either way.
func TestSealGateResolve(t *testing.T) {
	eng, err := analyze.NewEngine(analyze.Options{Budget: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	pending := func() *analyze.Report {
		r := &analyze.Report{Format: "Mach-O", EnginePending: true, Findings: []analyze.Finding{
			{ID: "stealer-cred-files", Severity: analyze.High},
			{ID: "api-keylogging", Severity: analyze.Medium},
		}}
		eng.Finalize(r)
		return r
	}
	for _, trusted := range []bool{false, true} {
		in := newInspector(context.Background(), eng, &analyze.Report{}, "Application bundle")
		g := &sealGate{pending: []pendingFile{{pending(), "Evil.app/Contents/Frameworks/engine.dylib", "bundled code"}}}
		in.resolve(g, trusted)
		if len(in.c.Files) != 1 || len(g.pending) != 0 {
			t.Fatalf("trusted=%v: files %d pending %d", trusted, len(in.c.Files), len(g.pending))
		}
		sev := map[string]analyze.Severity{}
		for _, f := range in.c.Files[0].Findings {
			sev[f.ID] = f.Severity
		}
		lifted := map[string]bool{}
		for _, f := range in.lifted {
			lifted[f.ID] = true
		}
		if trusted {
			if sev["stealer-cred-files"] != analyze.Info || sev["api-keylogging"] != analyze.Info || lifted["stealer-cred-files"] {
				t.Errorf("trusted: %v lifted %v", sev, lifted)
			}
		} else if sev["stealer-cred-files"] != analyze.High || sev["api-keylogging"] != analyze.Medium || !lifted["stealer-cred-files"] || !lifted["api-keylogging"] {
			t.Errorf("untrusted: %v lifted %v", sev, lifted)
		}
	}
}
