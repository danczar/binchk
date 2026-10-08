package watcher

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/danczar/binchk/internal/detect"
	"github.com/danczar/binchk/internal/findertag"
)

// binchk tags a file right after analysing it. That metadata-only change
// (an xattr write, which kqueue reports as an attribute change) must not be
// taken for a new download, or every flagged file would be analysed in a
// loop. The same goes for removing the tag (Mark as safe) and for app
// bundles, which are tagged on their directory.
func TestFinderTagWriteNotRedetected(t *testing.T) {
	dir := t.TempDir()
	w := startWatcher(t, dir)

	p := filepath.Join(dir, "download")
	if err := os.WriteFile(p, elfStub("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	expectFound(t, w, p)
	if err := findertag.Set(p, "Malicious"); err != nil {
		t.Fatal(err)
	}
	expectNothing(t, w)
	if err := findertag.Set(p, "Suspicious"); err != nil {
		t.Fatal(err)
	}
	if err := findertag.Clear(p); err != nil {
		t.Fatal(err)
	}
	expectNothing(t, w)

	app := filepath.Join(dir, "Tool.app")
	staging := filepath.Join(t.TempDir(), "Tool.app")
	os.MkdirAll(filepath.Join(staging, "Contents/MacOS"), 0o755)
	os.WriteFile(filepath.Join(staging, "Contents/MacOS/Tool"), elfStub("app"), 0o755)
	os.WriteFile(filepath.Join(staging, "Contents/Info.plist"), []byte("<plist/>"), 0o644)
	if err := os.Rename(staging, app); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-w.Found():
		if f.Path != app || f.Format != detect.AppBundle {
			t.Fatalf("got %+v", f)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("bundle never reported")
	}
	if err := findertag.Set(app, "Suspicious"); err != nil {
		t.Fatal(err)
	}
	expectNothing(t, w)
}
