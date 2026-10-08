package container

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// CFBundleExecutable must name a file directly inside Contents/MacOS; the
// Quick Look reader applies the same rule.
func TestMainExecutable(t *testing.T) {
	dir := t.TempDir()
	mk := func(name, exe string) string {
		app := filepath.Join(dir, name+".app")
		os.MkdirAll(filepath.Join(app, "Contents", "MacOS"), 0o755)
		os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(`<?xml version="1.0"?>
<plist version="1.0"><dict><key>CFBundleExecutable</key><string>`+exe+`</string></dict></plist>`), 0o644)
		return app
	}
	app := mk("Good", "Foo Helper")
	if p, ok := MainExecutable(app); !ok || p != filepath.Join(app, "Contents", "MacOS", "Foo Helper") {
		t.Fatalf("valid name: %q %v", p, ok)
	}
	for i, exe := range []string{"", ".", "..", "../x", "../../../benign-outside", "MacOS/x", "/bin/sh"} {
		app := mk("Bad"+string(rune('a'+i)), exe)
		if p, ok := MainExecutable(app); ok || p != "" {
			t.Errorf("CFBundleExecutable %q accepted: %q", exe, p)
		}
	}
	if _, ok := MainExecutable(filepath.Join(dir, "Missing.app")); ok {
		t.Error("bundle without Info.plist")
	}
	if runtime.GOOS != "windows" {
		// A symlinked Info.plist is not followed (nor by the reader).
		link := filepath.Join(dir, "Link.app")
		os.MkdirAll(filepath.Join(link, "Contents"), 0o755)
		os.Symlink(filepath.Join(app, "Contents", "Info.plist"), filepath.Join(link, "Contents", "Info.plist"))
		if _, ok := MainExecutable(link); ok {
			t.Error("followed a symlinked Info.plist")
		}
	}
}
