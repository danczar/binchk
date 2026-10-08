package bundleid

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The contents digest covers every byte: a same-size swap of a nested file
// leaves the fingerprint unchanged (it records sizes) but changes the
// contents digest, which is what trust is keyed by.
func TestContents(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links")
	}
	ctx := context.Background()
	app := makeVector(t, t.TempDir())
	d, main, err := Contents(ctx, app, "Vector")
	if err != nil {
		t.Fatal(err)
	}
	if main != VectorMainSHA256 || !isHex64(d) || d == VectorFingerprint {
		t.Fatalf("contents %s main %s", d, main)
	}
	if again, _, _ := Contents(ctx, makeVector(t, t.TempDir()), "Vector"); again != d {
		t.Errorf("rebuilt elsewhere: %s", again)
	}
	link := filepath.Join(t.TempDir(), "Linked.app")
	os.Symlink(app, link)
	if got, _, err := Contents(ctx, link, "Vector"); err != nil || got != d {
		t.Errorf("through a link: %s %v", got, err)
	}

	for _, c := range []struct{ name, path, data string }{
		{"same-size nested file", "Contents/Resources/a.txt", "alphX"},
		{"same-size seal", "Contents/_CodeSignature/CodeResources", "code resourceX\n"},
		{"same-size main executable", "Contents/MacOS/Vector", "vector main executablX\n"},
	} {
		app := makeVector(t, t.TempDir())
		if err := os.WriteFile(filepath.Join(app, c.path), []byte(c.data), 0o644); err != nil {
			t.Fatal(err)
		}
		got, gotMain, err := Contents(ctx, app, "Vector")
		if err != nil || got == d {
			t.Errorf("%s: contents digest unchanged (%v)", c.name, err)
		}
		if c.name == "same-size nested file" {
			if fp, _ := Fingerprint(app, gotMain); fp != VectorFingerprint {
				t.Errorf("%s: fingerprint changed too (%s); the test no longer shows the difference", c.name, fp)
			}
		}
	}

	if _, _, err := Contents(ctx, app, "Missing"); err == nil {
		t.Error("no main executable accepted")
	}
	if _, _, err := Contents(ctx, app, "../MacOS/Vector"); err == nil {
		t.Error("invalid main executable name accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := Contents(cancelled, app, "Vector"); err == nil {
		t.Error("cancelled context ignored")
	}
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func TestSummarizeLimit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links")
	}
	app := makeVector(t, t.TempDir())
	if s, ok := SummarizeLimit(app, 0); !ok || s != Summarize(app) {
		t.Fatalf("unlimited: %+v %v", s, ok)
	}
	if s, ok := SummarizeLimit(app, 15); !ok || s.Entries != 15 {
		t.Fatalf("exact limit: %+v %v", s, ok)
	}
	if s, ok := SummarizeLimit(app, 4); ok || s.Entries != 4 {
		t.Fatalf("over the limit: %+v %v", s, ok)
	}
}
