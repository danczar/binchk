package watcher

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/danczar/binchk/internal/config"
	"github.com/danczar/binchk/internal/detect"
)

func TestInBundle(t *testing.T) {
	for p, want := range map[string]bool{
		"/Users/a/Downloads/tool":                           false,
		"/Users/a/Downloads/Foo.app/Contents/MacOS/Foo":     true,
		"/Users/a/Downloads/x/Bar.framework/Versions/A/Bar": true,
		"/Users/a/Downloads/app.exe":                        false,
		"/Users/a/Downloads/My.App/Contents/MacOS/x":        true,
	} {
		if got := inBundle(p); got != want {
			t.Errorf("inBundle(%q) = %v, want %v", p, got, want)
		}
	}
}

// An app unpacked file by file must be reported once, as a bundle, only
// after it stops changing — never its individual files.
func TestBundleDetection(t *testing.T) {
	dir := t.TempDir()
	w, err := New([]config.WatchDir{{Path: dir}}, 100*time.Millisecond, nil, nil, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	app := filepath.Join(dir, "Foo.app")
	os.MkdirAll(filepath.Join(app, "Contents/MacOS"), 0o755)
	start := time.Now()
	for i := 0; i < 5; i++ { // slow "unzip"
		os.WriteFile(filepath.Join(app, "Contents", fmt.Sprintf("res%d", i)), []byte("x"), 0o644)
		time.Sleep(300 * time.Millisecond)
	}
	exe, _ := os.Executable()
	b, _ := os.ReadFile(exe)
	os.WriteFile(filepath.Join(app, "Contents/MacOS/Foo"), b, 0o755)
	os.WriteFile(filepath.Join(app, "Contents/Info.plist"), []byte("<plist/>"), 0o644)
	writesDone := time.Now()

	select {
	case f := <-w.Found():
		if f.Path != app || f.Format != detect.AppBundle {
			t.Fatalf("got %+v", f)
		}
		if time.Since(start) < writesDone.Sub(start) {
			t.Fatal("reported before writing finished")
		}
		t.Logf("reported %s after writes finished", time.Since(writesDone).Round(time.Millisecond))
	case <-time.After(10 * time.Second):
		t.Fatal("bundle never reported")
	}
	select {
	case f := <-w.Found():
		t.Fatalf("unexpected second report: %+v", f)
	case <-time.After(1500 * time.Millisecond):
	}
}

// elfStub is the smallest content detect.Sniff reports as ELF.
func elfStub(tail string) []byte {
	return append(append([]byte("\x7fELF"), make([]byte, 60)...), tail...)
}

func startWatcher(t *testing.T, dir string) *Watcher {
	t.Helper()
	w, err := New([]config.WatchDir{{Path: dir}}, 100*time.Millisecond, nil, nil, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go w.Run(ctx)
	time.Sleep(200 * time.Millisecond)
	return w
}

func expectFound(t *testing.T, w *Watcher, path string) {
	t.Helper()
	select {
	case f := <-w.Found():
		if f.Path != path {
			t.Fatalf("got %+v, want %s", f, path)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s never reported", path)
	}
}

func expectNothing(t *testing.T, w *Watcher) {
	t.Helper()
	select {
	case f := <-w.Found():
		t.Fatalf("unexpected report: %+v", f)
	case <-time.After(1500 * time.Millisecond):
	}
}

// oldFile creates an executable that was in the folder long before binchk
// started.
func oldFile(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, elfStub("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-270 * 24 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	return p
}

// Attribute changes (chmod, xattrs written by Finder tags, Spotlight or a
// read-only scan) on a file that predates the watcher must not report it.
func TestMetadataChangeOnExistingFileIgnored(t *testing.T) {
	dir := t.TempDir()
	p := oldFile(t, dir, "oldtool")
	w := startWatcher(t, dir)

	if err := os.Chmod(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("xattr", "-w", "com.example.test", "1", p).CombinedOutput(); err != nil {
			t.Fatalf("xattr: %v %s", err, out)
		}
	}
	expectNothing(t, w)
}

// Genuinely new downloads still arrive, including a browser renaming its
// partial file to the final name.
func TestNewFileFound(t *testing.T) {
	dir := t.TempDir()
	oldFile(t, dir, "oldtool")
	w := startWatcher(t, dir)

	p := filepath.Join(dir, "newtool")
	if err := os.WriteFile(p, elfStub("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	expectFound(t, w, p)

	part := filepath.Join(dir, "dl.crdownload")
	final := filepath.Join(dir, "dl")
	if err := os.WriteFile(part, elfStub("partial"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(part, final); err != nil {
		t.Fatal(err)
	}
	expectFound(t, w, final)

	// A later attribute change on a reported file is not a new download.
	if err := os.Chmod(final, 0o700); err != nil {
		t.Fatal(err)
	}
	expectNothing(t, w)
}

// An old file overwritten with new content, in place or by renaming a new
// file over it, is a new download.
func TestReplacedExistingFileFound(t *testing.T) {
	dir := t.TempDir()
	p := oldFile(t, dir, "tool")
	q := oldFile(t, dir, "tool2")
	staging := t.TempDir()
	w := startWatcher(t, dir)

	if err := os.WriteFile(p, elfStub("replaced in place"), 0o755); err != nil {
		t.Fatal(err)
	}
	expectFound(t, w, p)

	tmp := filepath.Join(staging, "tool2")
	if err := os.WriteFile(tmp, elfStub("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, q); err != nil {
		t.Fatal(err)
	}
	expectFound(t, w, q)
}

// known is bounded, and eviction drops the least recently used entries
// rather than forgetting everything at once.
func TestKnownEviction(t *testing.T) {
	w := &Watcher{known: map[string]*ident{}}
	w.remember("keep", &ident{size: 1})
	for i := 0; i <= maxKnown; i++ {
		w.remember(fmt.Sprint(i), &ident{size: 2})
		if i%1000 == 0 && !w.isKnown("keep", &ident{size: 1}) {
			t.Fatal("recently used entry evicted")
		}
	}
	if n := len(w.known); n > maxKnown || n < maxKnown/2 {
		t.Fatalf("len(known) = %d", n)
	}
	if _, ok := w.known["0"]; ok {
		t.Fatal("least recently used entry kept")
	}
	if _, ok := w.known[fmt.Sprint(maxKnown)]; !ok {
		t.Fatal("newest entry evicted")
	}
}
