package watcher

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
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
